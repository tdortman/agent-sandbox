//! HPKE (RFC 9180) base mode for rustls ECH, backed by `ring` primitives.
//!
//! Both the sender half (seal) and the receiver half (open) of the [`Hpke`]
//! trait are implemented: the proxy seals encrypted client hellos when it
//! connects upstream with ECH, and opens them when it terminates downstream
//! ECH offers.  Key generation stays with the proxy's persistent ECH state
//! and returns an explicit "not supported" error here.
//!
//! The implementation follows rustls's own `aws-lc-rs` HPKE provider line
//! for line, with ring's agreement, HKDF, and AEAD primitives substituted.

use ring::{
    agreement::{EphemeralPrivateKey, UnparsedPublicKey, X25519, agree_ephemeral},
    hkdf::Prk,
    hmac,
    rand::SystemRandom,
};

use rustls::{
    Error, OtherError,
    crypto::hpke::{
        EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey, HpkePublicKey, HpkeSealer, HpkeSuite,
    },
    internal::msgs::{
        enums::{HpkeAead, HpkeKdf, HpkeKem},
        handshake::HpkeSymmetricCipherSuite,
    },
};

use std::{
    fmt,
    io::{Error as IoError, ErrorKind},
    sync::Arc,
};

const NONCE_LEN: usize = 12;
const SHA256_OUTPUT_LEN: usize = 32;

/// HPKE suite with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM.
pub static DHKEM_X25519_HKDF_SHA256_AES_128: RingHpke = RingHpke {
    suite: HpkeSuite {
        kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
        sym: HpkeSymmetricCipherSuite {
            kdf_id: HpkeKdf::HKDF_SHA256,
            aead_id: HpkeAead::AES_128_GCM,
        },
    },
    aead: &ring::aead::AES_128_GCM,
    key_len: 16,
};

/// HPKE suite with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-256-GCM.
pub static DHKEM_X25519_HKDF_SHA256_AES_256: RingHpke = RingHpke {
    suite: HpkeSuite {
        kem: HpkeKem::DHKEM_X25519_HKDF_SHA256,
        sym: HpkeSymmetricCipherSuite {
            kdf_id: HpkeKdf::HKDF_SHA256,
            aead_id: HpkeAead::AES_256_GCM,
        },
    },
    aead: &ring::aead::AES_256_GCM,
    key_len: 32,
};

/// The suites this provider can honour, for rustls ECH configuration
/// verification.
pub static ECH_SUPPORTED_SUITES: &[&dyn Hpke] = &[
    &DHKEM_X25519_HKDF_SHA256_AES_128,
    &DHKEM_X25519_HKDF_SHA256_AES_256,
];

/// Concrete HPKE instance for one suite.
pub struct RingHpke {
    suite: HpkeSuite,
    aead: &'static ring::aead::Algorithm,
    key_len: usize,
}

impl RingHpke {
    /// Derive the AEAD key, base nonce, and exporter secret (RFC 9180 5.1).
    fn key_schedule(&self, shared_secret: &[u8; SHA256_OUTPUT_LEN], info: &[u8]) -> KeySchedule {
        let suite_id = LabeledSuiteId::Hpke(self.suite);

        // Base mode: no PSK and an empty PSK ID.
        let psk_id_hash = labeled_extract(&suite_id, &[], Label::PskIdHash, &[]);

        let info_hash = labeled_extract(&suite_id, &[], Label::InfoHash, info);
        let mut key_schedule_context = Vec::with_capacity(1 + psk_id_hash.len() + info_hash.len());
        key_schedule_context.push(0x00); // mode_base
        key_schedule_context.extend_from_slice(&psk_id_hash);
        key_schedule_context.extend_from_slice(&info_hash);
        let secret = labeled_extract_prk(&suite_id, shared_secret, Label::Secret, &[]);
        let mut key = vec![0_u8; self.key_len];

        labeled_expand_into(
            &suite_id,
            &secret,
            Label::Key,
            &key_schedule_context,
            &mut key,
        );

        let mut base_nonce = [0_u8; NONCE_LEN];

        labeled_expand_into(
            &suite_id,
            &secret,
            Label::BaseNonce,
            &key_schedule_context,
            &mut base_nonce,
        );

        KeySchedule {
            aead: self.aead,
            key,
            base_nonce,
            seq_num: 0,
        }
    }
}

impl Hpke for RingHpke {
    fn seal(
        &self,
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Vec<u8>), Error> {
        let (enc, mut sealer) = self.setup_sealer(info, pub_key)?;
        Ok((enc, sealer.seal(aad, plaintext)?))
    }

    fn setup_sealer(
        &self,
        info: &[u8],
        pub_key: &HpkePublicKey,
    ) -> Result<(EncapsulatedSecret, Box<dyn HpkeSealer + 'static>), Error> {
        let (shared_secret, enc) = encap(pub_key)?;
        let key_schedule = self.key_schedule(&shared_secret, info);
        Ok((enc, Box::new(Sealer::new(key_schedule))))
    }

    fn open(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Vec<u8>, Error> {
        let mut opener = self.setup_opener(enc, info, secret_key)?;
        opener.open(aad, ciphertext)
    }

    fn setup_opener(
        &self,
        enc: &EncapsulatedSecret,
        info: &[u8],
        secret_key: &HpkePrivateKey,
    ) -> Result<Box<dyn HpkeOpener + 'static>, Error> {
        let shared_secret = decap(&enc.0, secret_key.secret_bytes())?;
        let key_schedule = self.key_schedule(&shared_secret, info);
        Ok(Box::new(Opener::new(key_schedule)))
    }

    fn generate_key_pair(&self) -> Result<(HpkePublicKey, HpkePrivateKey), Error> {
        Err(unsupported())
    }

    fn suite(&self) -> HpkeSuite {
        self.suite
    }
}

impl fmt::Debug for RingHpke {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.suite.fmt(formatter)
    }
}

/// A stateful HPKE sender context.
struct Sealer {
    key_schedule: KeySchedule,
}

impl Sealer {
    const fn new(key_schedule: KeySchedule) -> Self {
        Self { key_schedule }
    }
}

impl HpkeSealer for Sealer {
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        self.key_schedule.seal(aad, plaintext)
    }
}

impl fmt::Debug for Sealer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Sealer").finish()
    }
}

/// A stateful HPKE receiver context.
struct Opener {
    key_schedule: KeySchedule,
}

impl Opener {
    const fn new(key_schedule: KeySchedule) -> Self {
        Self { key_schedule }
    }
}

impl HpkeOpener for Opener {
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        self.key_schedule.open(aad, ciphertext)
    }
}

impl fmt::Debug for Opener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Opener").finish()
    }
}

/// The RFC 9180 sender context state.
struct KeySchedule {
    aead: &'static ring::aead::Algorithm,
    key: Vec<u8>,
    base_nonce: [u8; NONCE_LEN],
    seq_num: u32,
}

impl KeySchedule {
    /// Seal one message with the sequence-numbered nonce (RFC 9180 5.2).
    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.compute_nonce();
        self.increment_seq_num();
        let key = ring::aead::UnboundKey::new(self.aead, &self.key).map_err(unspecified_err)?;
        let key = ring::aead::LessSafeKey::new(key);
        let mut in_out = plaintext.to_vec();

        key.seal_in_place_append_tag(
            ring::aead::Nonce::assume_unique_for_key(nonce),
            ring::aead::Aad::from(aad),
            &mut in_out,
        )
        .map_err(unspecified_err)?;

        Ok(in_out)
    }

    /// Open one message with the sequence-numbered nonce (RFC 9180 5.2).
    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.compute_nonce();
        self.increment_seq_num();
        let key = ring::aead::UnboundKey::new(self.aead, &self.key).map_err(unspecified_err)?;
        let key = ring::aead::LessSafeKey::new(key);
        let mut in_out = ciphertext.to_vec();

        let plaintext = key
            .open_in_place(
                ring::aead::Nonce::assume_unique_for_key(nonce),
                ring::aead::Aad::from(aad),
                &mut in_out,
            )
            .map_err(unspecified_err)?;

        Ok(plaintext.to_vec())
    }

    /// XOR the base nonce with the sequence number (RFC 9180 5.2).
    fn compute_nonce(&self) -> [u8; NONCE_LEN] {
        let mut nonce = [0_u8; NONCE_LEN];
        nonce[NONCE_LEN - 4..].copy_from_slice(&self.seq_num.to_be_bytes());

        for (byte, base) in nonce.iter_mut().zip(&self.base_nonce) {
            *byte ^= base;
        }

        nonce
    }

    const fn increment_seq_num(&mut self) {
        self.seq_num = self.seq_num.wrapping_add(1);
    }
}

/// DHKEM(X25519, HKDF-SHA256) encapsulation (RFC 9180 4.1).
fn encap(
    recipient: &HpkePublicKey,
) -> Result<([u8; SHA256_OUTPUT_LEN], EncapsulatedSecret), Error> {
    let sk_e =
        EphemeralPrivateKey::generate(&X25519, &SystemRandom::new()).map_err(unspecified_err)?;

    let enc = sk_e.compute_public_key().map_err(unspecified_err)?;
    let pk_r = UnparsedPublicKey::new(&X25519, &recipient.0);
    let kem_context = [enc.as_ref(), pk_r.as_ref()].concat();

    let shared_secret = agree_ephemeral(sk_e, &pk_r, |dh| extract_and_expand(dh, &kem_context))
        .map_err(unspecified_err)?;

    Ok((shared_secret, EncapsulatedSecret(enc.as_ref().to_vec())))
}

/// DHKEM(X25519, HKDF-SHA256) decapsulation (RFC 9180 4.1).
///
/// The static receiver key is used through `x25519_dalek`, because ring
/// exposes no agreement private-key import or export.
fn decap(enc: &[u8], sk_r: &[u8]) -> Result<[u8; SHA256_OUTPUT_LEN], Error> {
    let key_error = || {
        Error::Other(OtherError(Arc::new(IoError::other(
            "ECH key agreement failed",
        ))))
    };

    let sk_r: [u8; 32] = sk_r.try_into().map_err(|_| key_error())?;
    let enc: [u8; 32] = enc.try_into().map_err(|_| key_error())?;
    let sk_r = x25519_dalek::StaticSecret::from(sk_r);
    let pk_e = x25519_dalek::PublicKey::from(enc);
    let shared = sk_r.diffie_hellman(&pk_e);

    // RFC 9180 4.1 requires decapsulation to fail on a non-contributory
    // shared secret; the all-zero identity point must never be used.
    if !shared.was_contributory() {
        return Err(key_error());
    }

    let pk_r = x25519_dalek::PublicKey::from(&sk_r).to_bytes();
    let kem_context = [enc, pk_r].concat();
    Ok(extract_and_expand(shared.as_bytes(), &kem_context))
}

/// `ExtractAndExpand` for the KEM context (RFC 9180 4.1).
fn extract_and_expand(dh: &[u8], kem_context: &[u8]) -> [u8; SHA256_OUTPUT_LEN] {
    let suite_id = LabeledSuiteId::Kem(HpkeKem::DHKEM_X25519_HKDF_SHA256);
    let eae_prk = labeled_extract_prk(&suite_id, &[], Label::EaePrk, dh);
    let mut shared_secret = [0_u8; SHA256_OUTPUT_LEN];

    labeled_expand_into(
        &suite_id,
        &eae_prk,
        Label::SharedSecret,
        kem_context,
        &mut shared_secret,
    );

    shared_secret
}

/// The HPKE labels from RFC 9180 section 4.
#[derive(Clone, Copy)]
enum Label {
    PskIdHash,
    InfoHash,
    Secret,
    Key,
    BaseNonce,
    EaePrk,
    SharedSecret,
}

impl Label {
    const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::PskIdHash => b"psk_id_hash",
            Self::InfoHash => b"info_hash",
            Self::Secret => b"secret",
            Self::Key => b"key",
            Self::BaseNonce => b"base_nonce",
            Self::EaePrk => b"eae_prk",
            Self::SharedSecret => b"shared_secret",
        }
    }
}

/// The suite ID is prefixed differently in the general HPKE context and the
/// KEM context (RFC 9180 section 4).
enum LabeledSuiteId {
    Hpke(HpkeSuite),
    Kem(HpkeKem),
}

impl LabeledSuiteId {
    fn encoded(&self) -> Vec<u8> {
        match self {
            Self::Hpke(suite) => [
                b"HPKE".as_slice(),
                &u16::from(suite.kem).to_be_bytes(),
                &u16::from(suite.sym.kdf_id).to_be_bytes(),
                &u16::from(suite.sym.aead_id).to_be_bytes(),
            ]
            .concat(),

            Self::Kem(kem) => [b"KEM".as_slice(), &u16::from(*kem).to_be_bytes()].concat(),
        }
    }
}

/// `LabeledExtract` (RFC 9180 4): HKDF-Extract over the labelled input key
/// material, returning the raw pseudorandom key.
fn labeled_extract(
    suite_id: &LabeledSuiteId,
    salt: &[u8],
    label: Label,
    ikm: &[u8],
) -> [u8; SHA256_OUTPUT_LEN] {
    let mut labeled_ikm = Vec::with_capacity(6 + 8 + label.as_bytes().len() + ikm.len());
    labeled_ikm.extend_from_slice(b"HPKE-v1");
    labeled_ikm.extend_from_slice(&suite_id.encoded());
    labeled_ikm.extend_from_slice(label.as_bytes());
    labeled_ikm.extend_from_slice(ikm);
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let mut tag = [0_u8; SHA256_OUTPUT_LEN];
    tag.copy_from_slice(hmac::sign(&key, &labeled_ikm).as_ref());
    tag
}

/// `LabeledExtract` returning a ring `Prk` for later expansion.
fn labeled_extract_prk(suite_id: &LabeledSuiteId, salt: &[u8], label: Label, ikm: &[u8]) -> Prk {
    Prk::new_less_safe(
        ring::hkdf::HKDF_SHA256,
        &labeled_extract(suite_id, salt, label, ikm),
    )
}

/// `LabeledExpand` (RFC 9180 4): HKDF-Expand over the labelled info string.
fn labeled_expand_into(
    suite_id: &LabeledSuiteId,
    prk: &Prk,
    label: Label,
    info: &[u8],
    out: &mut [u8],
) {
    let mut labeled_info = Vec::with_capacity(2 + 6 + 8 + label.as_bytes().len() + info.len());
    let output_len = u16::try_from(out.len()).expect("HPKE output length fits in u16");
    labeled_info.extend_from_slice(&output_len.to_be_bytes());
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(&suite_id.encoded());
    labeled_info.extend_from_slice(label.as_bytes());
    labeled_info.extend_from_slice(info);
    let info = [&labeled_info[..]];

    let okm = prk
        .expand(&info, HkdfLength(out.len()))
        .expect("HPKE label expansion");

    okm.fill(out).expect("HPKE label expansion output");
}

/// `ring::hkdf::KeyType` for a runtime output length.
struct HkdfLength(usize);

impl ring::hkdf::KeyType for HkdfLength {
    fn len(&self) -> usize {
        self.0
    }
}

fn unspecified_err(_: ring::error::Unspecified) -> Error {
    Error::Other(OtherError(Arc::new(IoError::other(
        "HPKE operation failed",
    ))))
}

fn unsupported() -> Error {
    Error::Other(OtherError(Arc::new(IoError::new(
        ErrorKind::Unsupported,
        "HPKE key generation is not supported by the proxy's provider; keys come from the \
         persisted ECH state",
    ))))
}

#[cfg(test)]
mod tests {
    use super::{DHKEM_X25519_HKDF_SHA256_AES_128, KeySchedule, labeled_extract};

    use rustls::{
        crypto::hpke::{Hpke, HpkePrivateKey, HpkePublicKey},
        internal::msgs::enums::HpkeKem,
    };

    fn hex(value: &str) -> Vec<u8> {
        let value = value
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect::<String>();

        (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("hex byte"))
            .collect()
    }

    /// RFC 9180 appendix A.1.1 base-mode vector, DHKEM(X25519, HKDF-SHA256),
    /// HKDF-SHA256, AES-128-GCM.
    const INFO: &str = "4f6465206f6e2061204772656369616e2055726e";

    const SHARED_SECRET: &str = "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc";
    const KEY: &str = "4531685d41d65f03dc48f6b8302c05b0";
    const BASE_NONCE: &str = "56d890e5accaaf011cff4b7d";
    const PT: &str = "4265617574792069732074727574682c20747275746820626561757479";
    const AAD: &str = "436f756e742d30";

    const CT: &str = "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9\
                     6d8770ac83d07bea87e13c512a";

    #[test]
    fn key_schedule_matches_rfc_9180_vector() {
        let mut shared_secret = [0_u8; 32];
        shared_secret.copy_from_slice(&hex(SHARED_SECRET));
        let schedule = DHKEM_X25519_HKDF_SHA256_AES_128.key_schedule(&shared_secret, &hex(INFO));
        assert_eq!(schedule.key, hex(KEY));
        assert_eq!(&schedule.base_nonce, hex(BASE_NONCE).as_slice());
    }

    #[test]
    fn seal_matches_rfc_9180_vector() {
        let mut shared_secret = [0_u8; 32];
        shared_secret.copy_from_slice(&hex(SHARED_SECRET));

        let mut schedule =
            DHKEM_X25519_HKDF_SHA256_AES_128.key_schedule(&shared_secret, &hex(INFO));

        let ciphertext = schedule.seal(&hex(AAD), &hex(PT)).expect("seal");
        assert_eq!(ciphertext, hex(CT));
    }

    #[test]
    fn eae_prk_label_uses_kem_suite_id() {
        // The `eae_prk` extraction must use the "KEM" suite ID prefix; a
        // "HPKE" prefix would diverge from RFC 9180 and from rustls's own
        // provider.
        let suite_id = super::LabeledSuiteId::Kem(HpkeKem::DHKEM_X25519_HKDF_SHA256);

        let eae_prk = labeled_extract(&suite_id, &[], super::Label::EaePrk, &[1, 2, 3]);

        let reference = {
            let mut labeled = b"HPKE-v1".to_vec();
            labeled.extend_from_slice(&suite_id.encoded());
            labeled.extend_from_slice(b"eae_prk");
            labeled.extend_from_slice(&[1, 2, 3]);

            let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &[]);
            let mut tag = [0_u8; 32];
            tag.copy_from_slice(ring::hmac::sign(&key, &labeled).as_ref());
            tag
        };

        assert_eq!(eae_prk, reference);
    }

    #[test]
    fn sealer_seals_with_static_vector_key_and_advances_nonce() {
        // ring cannot expose the generated X25519 seed, so the trait's
        // `generate_key_pair` fails closed; the RFC vector's public key
        // exercises the full sealer path against a known recipient.
        let pk_r = HpkePublicKey(hex(
            "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
        ));

        let info = hex(INFO);

        let (enc, mut sealer) = DHKEM_X25519_HKDF_SHA256_AES_128
            .setup_sealer(&info, &pk_r)
            .expect("sealer setup");

        assert_eq!(enc.0.len(), 32);
        let first = sealer.seal(b"aad", b"plaintext").expect("first seal");
        let second = sealer.seal(b"aad", b"plaintext").expect("second seal");
        assert_ne!(first, b"plaintext");

        // The sequence number feeds the nonce, so two seals differ even for
        // identical plaintext and AAD.
        assert_ne!(first, second);
    }

    #[test]
    fn opener_opens_sealed_messages_with_static_vector_key() {
        // The RFC 9180 appendix A.1.1 receiver keypair: sealing to `pk_r`
        // must be reversible with `sk_r` for the same info and AAD.
        let pk_r = HpkePublicKey(hex(
            "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d",
        ));

        let sk_r = HpkePrivateKey::from(hex(
            "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8",
        ));

        let info = hex(INFO);

        let (enc, mut sealer) = DHKEM_X25519_HKDF_SHA256_AES_128
            .setup_sealer(&info, &pk_r)
            .expect("sealer setup");

        let ciphertext = sealer.seal(b"aad", b"plaintext").expect("seal");

        let mut opener = DHKEM_X25519_HKDF_SHA256_AES_128
            .setup_opener(&enc, &info, &sk_r)
            .expect("opener setup");

        assert_eq!(
            opener.open(b"aad", &ciphertext).expect("open"),
            b"plaintext"
        );

        // The opener context is stateful: the second open uses the next
        // sequence-numbered nonce, so the first ciphertext fails closed.
        assert!(opener.open(b"aad", &ciphertext).is_err());

        // Key generation stays fail-closed; the proxy's keys come from the
        // persisted ECH state, never from the provider.
        assert!(
            DHKEM_X25519_HKDF_SHA256_AES_128
                .generate_key_pair()
                .is_err()
        );
    }

    #[test]
    fn nonce_xors_sequence_number() {
        let mut base_nonce = [0_u8; 12];
        base_nonce[..4].copy_from_slice(&[0x56, 0xD8, 0x90, 0xE5]);

        let schedule = KeySchedule {
            aead: &ring::aead::AES_128_GCM,
            key: vec![0; 16],
            base_nonce,
            seq_num: 0,
        };

        assert_eq!(&schedule.compute_nonce()[..4], &[0x56, 0xD8, 0x90, 0xE5]);
    }
}
