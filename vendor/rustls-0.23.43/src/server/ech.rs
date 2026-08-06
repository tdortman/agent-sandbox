//! Server-side Encrypted Client Hello (ECH) support, per [RFC 9849].
//!
//! The server holds one or more [`EchKeys`] entries, each pairing an
//! `ECHConfig` with the HPKE private key that matches the public key
//! advertised inside that configuration.  When a client offers an
//! `encrypted_client_hello` extension, the server attempts to decrypt the
//! `ClientHelloInner` with the candidate configuration selected by
//! `config_id`.  A successful decryption replaces the outer client hello
//! with the reconstructed inner hello for the remainder of the handshake;
//! a failed decryption leaves the outer hello in place so that GREASE ECH
//! offers and misconfigured clients still connect.
//!
//! [RFC 9849]: https://www.rfc-editor.org/rfc/rfc9849

use crate::{
    common_state::CommonState,
    crypto::hpke::{EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkeSuite},
    enums::{AlertDescription, HandshakeType, ProtocolVersion},
    error::{EncryptedClientHelloError, Error, PeerMisbehaved},
    log::trace,
    msgs::{
        base::Payload,
        codec::{Codec, Reader},
        enums::ExtensionType,
        handshake::{
            ClientHelloPayload, EchConfigPayload, EncryptedClientHello, EncryptedClientHelloOuter,
            HandshakeMessagePayload, HandshakePayload, HpkeSymmetricCipherSuite,
        },
        message::{Message, MessagePayload},
    },
    pki_types::EchConfigListBytes,
};
use alloc::{boxed::Box, collections::BTreeSet, vec::Vec};
use core::fmt;

const ECH_EXTENSION_TYPE: u16 = 0xFE0D;
const ECH_OUTER_EXTENSIONS_TYPE: u16 = 0xFD00;

/// Key material for accepting encrypted client hellos.
///
/// The `ECHConfigList` bytes are the same configuration the server
/// distributes to clients (for example through rewritten DNS answers), and
/// `private_key` is the HPKE private key matching the public key advertised
/// in that configuration.  `hpke` must implement the suite selected inside
/// the configuration.
pub struct EchKeys {
    /// The selected `ECHConfig`, in its full wire encoding.
    config: EchConfigPayload,
    /// The HPKE implementation matching the configuration's cipher suite.
    hpke: &'static dyn Hpke,
    /// The HPKE private key for the configuration's public key.
    private_key: HpkePrivateKey,
}

impl EchKeys {
    /// Construct an `EchKeys` from a configuration list and matching private
    /// key.
    ///
    /// One configuration in `ech_config_list` must be compatible with `hpke`;
    /// the private key must correspond to that configuration's public key.
    ///
    /// # Errors
    ///
    /// Returns an error when the list contains no compatible configuration.
    pub fn new(
        ech_config_list: EchConfigListBytes<'_>,
        private_key: &[u8],
        hpke: &'static dyn Hpke,
    ) -> Result<Self, Error> {
        let configs =
            Vec::<EchConfigPayload>::read(&mut Reader::init(&ech_config_list)).map_err(|_| {
                Error::InvalidEncryptedClientHello(EncryptedClientHelloError::InvalidConfigList)
            })?;

        for config in configs {
            let contents = match &config {
                EchConfigPayload::V18(contents) => contents,
                EchConfigPayload::Unknown { .. } => continue,
            };

            if contents.has_unknown_mandatory_extension() || contents.has_duplicate_extension() {
                continue;
            }

            let key_config = &contents.key_config;
            for cipher_suite in &key_config.symmetric_cipher_suites {
                if cipher_suite.aead_id.tag_len().is_none() {
                    continue;
                }

                let suite = HpkeSuite {
                    kem: key_config.kem_id,
                    sym: *cipher_suite,
                };
                if hpke.suite() == suite {
                    return Ok(Self {
                        config,
                        hpke,
                        private_key: HpkePrivateKey::from(private_key.to_vec()),
                    });
                }
            }
        }

        Err(EncryptedClientHelloError::NoCompatibleConfig.into())
    }

    /// The `config_id` of the configuration, matched against the client's
    /// offer.
    fn config_id(&self) -> u8 {
        let EchConfigPayload::V18(contents) = &self.config else {
            unreachable!("EchKeys only stores supported configurations");
        };
        contents.key_config.config_id
    }

    /// The `SetupBaseR` `info` parameter for this configuration.
    fn hpke_info(&self) -> Vec<u8> {
        let mut info = Vec::with_capacity(128);
        info.extend_from_slice(b"tls ech\0");
        self.config.encode(&mut info);
        info
    }

    /// The full configuration, for the `retry_configs` extension.
    pub(crate) fn config_payload(&self) -> EchConfigPayload {
        self.config.clone()
    }
}

impl fmt::Debug for EchKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let EchConfigPayload::V18(contents) = &self.config else {
            return f.write_str("EchKeys { unknown config }");
        };
        f.debug_struct("EchKeys")
            .field("config_id", &contents.key_config.config_id)
            .field("public_name", &contents.public_name)
            .finish_non_exhaustive()
    }
}

/// State for one accepted ECH handshake, carried across a HelloRetryRequest.
pub(crate) struct EchHandshakeState {
    /// `ClientHelloInner.random` from the first inner hello.
    pub(crate) inner_random: [u8; 32],
    /// The HPKE opener context; reused to decrypt the retry payload.
    pub(crate) opener: Box<dyn HpkeOpener>,
    /// The accepted configuration id; must not change on retry.
    pub(crate) config_id: u8,
    /// The accepted cipher suite; must not change on retry.
    pub(crate) cipher_suite: HpkeSymmetricCipherSuite,
}

/// The result of accepting an ECH offer.
pub(crate) struct AcceptedEch {
    /// The reconstructed `ClientHelloInner` message.
    pub(crate) message: Message<'static>,
    /// Handshake state needed for retries and the acceptance confirmation.
    pub(crate) state: EchHandshakeState,
}

/// A successful first-leg decryption.
struct FirstLegAccepted {
    opener: Box<dyn HpkeOpener>,
    config_id: u8,
    cipher_suite: HpkeSymmetricCipherSuite,
    plaintext: Vec<u8>,
}

/// The outcome of examining one client hello for an ECH offer.
pub(crate) struct EchOutcome {
    /// Whether the client hello carried an `encrypted_client_hello` offer.
    pub(crate) offered: bool,
    /// The accepted inner hello, when decryption succeeded.
    pub(crate) accepted: Option<AcceptedEch>,
}

/// Attempt to accept an ECH offer in `m`, returning the inner client hello.
///
/// When the client did not offer ECH, no key matches, or decryption fails,
/// `accepted` is `None` and the handshake continues with the outer hello.
/// On the retry leg (`done_retry`), `ech` holds the state from the first
/// hello; a missing or inconsistent offer is then a fatal error, per
/// RFC 9849 section 7.1.1.
pub(crate) fn process_client_hello_ech(
    keys: &[EchKeys],
    m: &Message<'_>,
    done_retry: bool,
    ech: Option<EchHandshakeState>,
    common: &mut CommonState,
) -> Result<EchOutcome, Error> {
    let client_hello =
        require_handshake_msg!(m, HandshakeType::ClientHello, HandshakePayload::ClientHello)?;
    let outer = match &client_hello.encrypted_client_hello {
        Some(EncryptedClientHello::Outer(outer)) => outer,
        // No offer, or a malformed inner-type extension in the outer hello.
        _ => {
            return Ok(EchOutcome {
                offered: false,
                accepted: None,
            });
        }
    };
    let offered = true;

    let MessagePayload::Handshake { encoded, .. } = &m.payload else {
        return Ok(EchOutcome {
            offered,
            accepted: None,
        });
    };
    let raw = encoded.bytes();

    let (opener, config_id, cipher_suite, plaintext) = if done_retry {
        // A retry hello after an accepted offer must continue with the same
        // configuration and HPKE context (RFC 9849 section 7.1.1).
        let Some(mut state) = ech else {
            // ECH was rejected (or never offered) on the first hello; the
            // second hello's payload is not decrypted.
            return Ok(EchOutcome {
                offered,
                accepted: None,
            });
        };

        if outer.cipher_suite != state.cipher_suite || outer.config_id != state.config_id {
            return Err(fatal_alert(
                common,
                AlertDescription::IllegalParameter,
                PeerMisbehaved::InvalidEchClientHello,
                "ECH retry changed configuration",
            ));
        }
        if !outer.enc.0.is_empty() {
            return Err(fatal_alert(
                common,
                AlertDescription::IllegalParameter,
                PeerMisbehaved::InvalidEchClientHello,
                "ECH retry re-encapsulated",
            ));
        }

        let aad = client_hello_outer_aad(raw, outer).ok_or_else(|| {
            fatal_alert(
                common,
                AlertDescription::DecodeError,
                PeerMisbehaved::InvalidEchClientHello,
                "malformed outer hello for ECH retry",
            )
        })?;
        let plaintext = state.opener.open(&aad, &outer.payload.0).map_err(|_| {
            fatal_alert(
                common,
                AlertDescription::DecryptError,
                PeerMisbehaved::InvalidEchClientHello,
                "ECH retry decryption failed",
            )
        })?;
        (state.opener, state.config_id, state.cipher_suite, plaintext)
    } else {
        let Some(accepted) = try_decrypt(keys, raw, outer) else {
            // No candidate decrypted: ignore the extension and continue with
            // the outer hello (RFC 9849 section 7.1).
            return Ok(EchOutcome {
                offered,
                accepted: None,
            });
        };
        (
            accepted.opener,
            accepted.config_id,
            accepted.cipher_suite,
            accepted.plaintext,
        )
    };

    let hello = raw.get(4..).ok_or_else(|| {
        fatal_alert(
            common,
            AlertDescription::DecodeError,
            PeerMisbehaved::InvalidEchClientHello,
            "short handshake message",
        )
    })?;
    let inner = reconstruct_inner_hello(hello, client_hello, &plaintext, common)?;

    Ok(EchOutcome {
        offered,
        accepted: Some(AcceptedEch {
            message: inner.message,
            state: EchHandshakeState {
                inner_random: inner.random,
                opener,
                config_id,
                cipher_suite,
            },
        }),
    })
}

/// Try each key matching the offer's `config_id` until one decrypts.
fn try_decrypt(
    keys: &[EchKeys],
    raw: &[u8],
    outer: &EncryptedClientHelloOuter,
) -> Option<FirstLegAccepted> {
    let aad = client_hello_outer_aad(raw, outer)?;

    for key in keys {
        if key.config_id() != outer.config_id || key.hpke.suite().sym != outer.cipher_suite {
            continue;
        }

        let mut opener = key
            .hpke
            .setup_opener(
                &EncapsulatedSecret(outer.enc.0.clone()),
                &key.hpke_info(),
                &key.private_key,
            )
            .ok()?;

        if let Ok(plaintext) = opener.open(&aad, &outer.payload.0) {
            return Some(FirstLegAccepted {
                opener,
                config_id: key.config_id(),
                cipher_suite: outer.cipher_suite,
                plaintext,
            });
        }
    }

    None
}

/// Compute the `ClientHelloOuterAAD`: the outer hello with the ECH
/// ciphertext payload replaced by zeros (RFC 9849 section 5.2).
///
/// `raw` is the full handshake message including its four-byte header; the
/// AAD excludes the header.
fn client_hello_outer_aad(raw: &[u8], outer: &EncryptedClientHelloOuter) -> Option<Vec<u8>> {
    let hello = raw.get(4..)?;
    let layout = hello_layout(hello)?;

    let ech = layout
        .entries
        .iter()
        .find(|entry| entry.ty == ECH_EXTENSION_TYPE)?;

    let payload_len = outer.payload.0.len();
    if payload_len > ech.end - ech.start - 4 {
        return None;
    }

    let mut aad = hello.to_vec();
    let payload_start = ech.end - payload_len;
    aad[payload_start..ech.end].fill(0);
    Some(aad)
}

/// The result of reconstructing an inner hello.
struct ReconstructedInnerHello {
    message: Message<'static>,
    random: [u8; 32],
}

/// Reconstruct `ClientHelloInner` from the decrypted `EncodedClientHelloInner`.
///
/// This reverses the encoding described in RFC 9849 section 5.1: the empty
/// legacy session id is replaced with the outer hello's, and the
/// `ech_outer_extensions` marker is replaced with the referenced extensions
/// copied verbatim from the outer hello, so the reconstructed bytes match
/// the encoding the client hashed into its transcript.
fn reconstruct_inner_hello(
    outer_hello: &[u8],
    outer: &ClientHelloPayload,
    plaintext: &[u8],
    common: &mut CommonState,
) -> Result<ReconstructedInnerHello, Error> {
    let layout = hello_layout(plaintext).ok_or_else(|| {
        fatal_alert(
            common,
            AlertDescription::IllegalParameter,
            PeerMisbehaved::InvalidEchClientHello,
            "malformed encoded inner hello",
        )
    })?;

    // All bytes after the client hello must be zero padding.
    if plaintext[layout.hello_len..].iter().any(|byte| *byte != 0) {
        return Err(fatal_alert(
            common,
            AlertDescription::IllegalParameter,
            PeerMisbehaved::InvalidEchClientHello,
            "non-zero ECH padding",
        ));
    }

    let marker = layout
        .entries
        .iter()
        .find(|entry| entry.ty == ECH_OUTER_EXTENSIONS_TYPE);

    let mut out = Vec::with_capacity(plaintext.len() + 32);
    // Client version + random, then the restored session id.
    out.extend_from_slice(&plaintext[..34]);
    outer.session_id.encode(&mut out);
    // Cipher suites and compression methods, copied as-is.
    out.extend_from_slice(&plaintext[35..layout.ext_len_pos]);

    if let Some(marker) = marker {
        // Parse the referenced extension types.
        let referenced =
            Vec::<ExtensionType>::read(&mut Reader::init(&plaintext[marker.start + 4..marker.end]))
                .map_err(|_| {
                    fatal_alert(
                        common,
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::InvalidEchClientHello,
                        "malformed ech_outer_extensions",
                    )
                })?;

        validate_referenced(&referenced, outer_hello, common)?;

        let outer_layout = hello_layout(outer_hello).ok_or_else(|| {
            fatal_alert(
                common,
                AlertDescription::IllegalParameter,
                PeerMisbehaved::InvalidEchClientHello,
                "malformed outer hello",
            )
        })?;

        // Extensions before the marker, then the referenced extensions from
        // the outer hello in order, then the extensions after the marker.
        let mut extensions_len = marker.start - layout.ext_start;
        let outer_len = |entry: &&ExtEntry| entry.end - entry.start;
        for ty in &referenced {
            let entry = outer_layout
                .entries
                .iter()
                .find(|entry| entry.ty == u16::from(*ty))
                .ok_or_else(|| {
                    fatal_alert(
                        common,
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::InvalidEchClientHello,
                        "referenced extension missing from outer hello",
                    )
                })?;
            extensions_len += outer_len(&entry);
        }
        extensions_len += layout.hello_len - marker.end;

        // The reconstructed extensions length, written before the content.
        let new_len = u16::try_from(extensions_len).map_err(|_| {
            fatal_alert(
                common,
                AlertDescription::IllegalParameter,
                PeerMisbehaved::InvalidEchClientHello,
                "reconstructed extensions too long",
            )
        })?;
        out.extend_from_slice(&new_len.to_be_bytes());
        out.extend_from_slice(&plaintext[layout.ext_start..marker.start]);
        for ty in &referenced {
            let entry = outer_layout
                .entries
                .iter()
                .find(|entry| entry.ty == u16::from(*ty))
                .ok_or_else(|| {
                    fatal_alert(
                        common,
                        AlertDescription::IllegalParameter,
                        PeerMisbehaved::InvalidEchClientHello,
                        "referenced extension missing from outer hello",
                    )
                })?;
            out.extend_from_slice(&outer_hello[entry.start..entry.end]);
        }
        out.extend_from_slice(&plaintext[marker.end..layout.hello_len]);
    } else {
        // No compression: only the session id changed, so the extensions
        // block (including its length prefix) is copied as-is.
        out.extend_from_slice(&plaintext[layout.ext_len_pos..layout.hello_len]);
    }

    // The reconstructed hello must parse and satisfy the inner-hello checks.
    let inner = ClientHelloPayload::read(&mut Reader::init(&out)).map_err(|_| {
        fatal_alert(
            common,
            AlertDescription::IllegalParameter,
            PeerMisbehaved::InvalidEchClientHello,
            "reconstructed inner hello malformed",
        )
    })?;

    if !matches!(
        inner.encrypted_client_hello,
        Some(EncryptedClientHello::Inner)
    ) {
        return Err(fatal_alert(
            common,
            AlertDescription::IllegalParameter,
            PeerMisbehaved::InvalidEchClientHello,
            "inner hello missing inner ECH extension",
        ));
    }

    // ECH requires TLS 1.3; the inner hello must not offer anything below.
    let versions = inner.supported_versions.as_ref().ok_or_else(|| {
        fatal_alert(
            common,
            AlertDescription::IllegalParameter,
            PeerMisbehaved::InvalidEchClientHello,
            "inner hello missing supported_versions",
        )
    })?;
    if !versions.tls13 || versions.tls12 {
        return Err(fatal_alert(
            common,
            AlertDescription::IllegalParameter,
            PeerMisbehaved::InvalidEchClientHello,
            "inner hello offers TLS 1.2 or below",
        ));
    }

    let random = inner.random.0;

    // The transcript message is the full handshake encoding: type, u24
    // length, and the reconstructed hello bytes.
    let mut encoded = Vec::with_capacity(out.len() + 4);
    HandshakeType::ClientHello.encode(&mut encoded);
    crate::msgs::codec::u24(u32::try_from(out.len()).map_err(|_| {
        fatal_alert(
            common,
            AlertDescription::IllegalParameter,
            PeerMisbehaved::InvalidEchClientHello,
            "reconstructed inner hello too large",
        )
    })?)
    .encode(&mut encoded);
    encoded.extend_from_slice(&out);

    let message = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::Handshake {
            parsed: HandshakeMessagePayload(HandshakePayload::ClientHello(inner)),
            encoded: Payload::Owned(encoded),
        },
    };

    Ok(ReconstructedInnerHello { message, random })
}

/// Validate the `ech_outer_extensions` list against the outer hello.
fn validate_referenced(
    referenced: &[ExtensionType],
    outer_hello: &[u8],
    common: &mut CommonState,
) -> Result<(), Error> {
    let mut seen = BTreeSet::new();
    for ty in referenced {
        if !seen.insert(u16::from(*ty)) {
            return Err(fatal_alert(
                common,
                AlertDescription::IllegalParameter,
                PeerMisbehaved::InvalidEchClientHello,
                "duplicate referenced extension",
            ));
        }
        if u16::from(*ty) == ECH_EXTENSION_TYPE {
            return Err(fatal_alert(
                common,
                AlertDescription::IllegalParameter,
                PeerMisbehaved::InvalidEchClientHello,
                "ECH extension referenced in ech_outer_extensions",
            ));
        }
    }

    let outer_layout = hello_layout(outer_hello).ok_or_else(|| {
        fatal_alert(
            common,
            AlertDescription::IllegalParameter,
            PeerMisbehaved::InvalidEchClientHello,
            "malformed outer hello",
        )
    })?;

    // Every referenced extension must be present, and they must appear in
    // the outer hello in the same relative order as the list.
    let mut outer_match = outer_layout
        .entries
        .iter()
        .filter(|entry| referenced.iter().any(|ty| u16::from(*ty) == entry.ty));
    for ty in referenced {
        match outer_match.next() {
            Some(entry) if entry.ty == u16::from(*ty) => {}
            _ => {
                return Err(fatal_alert(
                    common,
                    AlertDescription::IllegalParameter,
                    PeerMisbehaved::InvalidEchClientHello,
                    "referenced extensions out of order or missing",
                ));
            }
        }
    }

    Ok(())
}

fn read_u16(bytes: &[u8], pos: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*bytes.get(pos)?, *bytes.get(pos + 1)?]))
}

fn fatal_alert(
    common: &mut CommonState,
    description: AlertDescription,
    why: PeerMisbehaved,
    log: &str,
) -> Error {
    trace!("{log}");
    common.send_fatal_alert(description, why)
}

/// The structural layout of a wire-format client hello.
struct HelloLayout {
    /// Offset of the u16 extensions length prefix.
    ext_len_pos: usize,
    /// Offset of the first extension entry.
    ext_start: usize,
    /// Offset just past the extensions block (the end of the hello).
    hello_len: usize,
    /// The extension entries.
    entries: Vec<ExtEntry>,
}

/// One extension entry within a client hello's extensions block.
struct ExtEntry {
    /// The raw extension type.
    ty: u16,
    /// Offset of the extension type field within the hello.
    start: usize,
    /// Offset just past the extension body.
    end: usize,
}

/// Structurally walk a wire-format client hello.
///
/// The walk relies only on length prefixes, so it works on both the outer
/// hello and the decrypted encoded inner hello.
fn hello_layout(hello: &[u8]) -> Option<HelloLayout> {
    let sid_len = usize::from(*hello.get(34)?);
    let mut pos = 35 + sid_len;

    let cs_len = usize::from(read_u16(hello, pos)?);
    pos += 2 + cs_len;

    let comp_len = usize::from(*hello.get(pos)?);
    pos += 1 + comp_len;

    let ext_len = usize::from(read_u16(hello, pos)?);
    let ext_len_pos = pos;
    let ext_start = pos + 2;
    let ext_end = ext_start.checked_add(ext_len)?;
    if ext_end > hello.len() {
        return None;
    }

    let mut entries = Vec::new();
    let mut p = ext_start;
    while p < ext_end {
        let ty = read_u16(hello, p)?;
        let len = usize::from(read_u16(hello, p + 2)?);
        let body_end = p.checked_add(4 + len)?;
        if body_end > ext_end {
            return None;
        }
        entries.push(ExtEntry {
            ty,
            start: p,
            end: body_end,
        });
        p = body_end;
    }

    Some(HelloLayout {
        ext_len_pos,
        ext_start,
        hello_len: ext_end,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_layout_rejects_truncated_hello() {
        assert!(hello_layout(&[0u8; 10]).is_none());
    }

    #[test]
    fn hello_layout_walks_extension_entries() {
        // ClientHello with empty session id, one cipher suite, one
        // compression method, and a single 4-byte extension.
        let mut hello = vec![0u8; 46];
        hello[34] = 0; // empty session id
        hello[35] = 2; // cipher suites length (1 suite)
        hello[37] = 1; // compression length (1 method)
        hello[38] = 0; // extensions length high byte
        hello[39] = 6; // extensions length low byte (4 + 2)
        let layout = hello_layout(&hello).expect("well-formed hello");
        assert_eq!(layout.hello_len, 46);
        assert_eq!(layout.ext_start, 40);
        assert_eq!(layout.entries.len(), 1);
        assert_eq!(layout.entries[0].ty, 0);
        assert_eq!(layout.entries[0].start, 40);
        assert_eq!(layout.entries[0].end, 46);
    }
}
