//! Persistent ECH key material and DNS configuration for the transparent proxy.

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use rama_tls_boring::core::x25519::X25519PrivateKey;

/// Directory containing the proxy's persistent ECH key and configuration.
pub const DEFAULT_ECH_STATE_DIR: &str = "/run/agent-sandbox";
const CONFIG_FILE: &str = "ech-config-list";
const PRIVATE_KEY_FILE: &str = "ech-private-key";
const PUBLIC_NAME: &[u8] = b"proxy.agent-sandbox.invalid";

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// ECH state loaded by the proxy for client-facing TLS and DNS rewriting.
///
/// The private key is persisted separately from the public `ECHConfigList`;
/// the configuration is regenerated from the key whenever the proxy starts.
pub struct EchState {
    pub config_list: Vec<u8>,
    pub private_key: [u8; 32],
}

/// Load the persisted ECH key or generate it atomically on first use.
///
/// The public configuration is regenerated from the private key on every load
/// so the two files cannot drift apart after a partially completed write.
///
/// # Errors
///
/// Returns an I/O error when the state directory or either state file cannot be
/// created, read, or updated, or when persisted key material is invalid.
pub fn load_or_generate(state_dir: &Path) -> io::Result<EchState> {
    fs::create_dir_all(state_dir)?;

    let config_path = state_dir.join(CONFIG_FILE);
    let private_key_path = state_dir.join(PRIVATE_KEY_FILE);

    let private_key = match fs::read(&private_key_path) {
        Ok(private_key) => Some(private_key),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };

    if let Some(private_key) = private_key {
        let private_key: [u8; 32] = private_key.try_into().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid ECH private key length")
        })?;

        let key =
            X25519PrivateKey::from_private_key_bytes(&private_key).map_err(io::Error::other)?;

        let public_key = key
            .public_key()
            .and_then(|public_key| public_key.public_key_bytes())
            .map_err(io::Error::other)?;

        let config_list = encode_config_list(&public_key);
        atomic_write(&config_path, &config_list)?;

        return Ok(EchState {
            config_list,
            private_key,
        });
    }

    let key = X25519PrivateKey::generate().map_err(io::Error::other)?;
    let private_key = key.private_key_bytes().map_err(io::Error::other)?;

    let public_key = key
        .public_key()
        .and_then(|public_key| public_key.public_key_bytes())
        .map_err(io::Error::other)?;

    if let Err(error) = create_if_missing(&private_key_path, &private_key, 0o600) {
        if error.kind() == io::ErrorKind::AlreadyExists {
            return load_or_generate(state_dir);
        }

        return Err(error);
    }

    let config_list = encode_config_list(&public_key);
    atomic_write(&config_path, &config_list)?;
    
    Ok(EchState {
        config_list,
        private_key,
    })
}

fn atomic_write(path: &Path, contents: &[u8]) -> io::Result<()> {
    let temporary_path = unique_temporary_path(path);

    let result = write_temporary_file(&temporary_path, contents, 0o644)
        .and_then(|()| fs::rename(&temporary_path, path));

    let _ = fs::remove_file(temporary_path);
    result
}

fn create_if_missing(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let temporary_path = unique_temporary_path(path);

    let result = write_temporary_file(&temporary_path, contents, mode)
        .and_then(|()| fs::hard_link(&temporary_path, path));

    let _ = fs::remove_file(temporary_path);

    result
}

fn write_temporary_file(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;

    file.write_all(contents)?;
    file.sync_all()
}

fn unique_temporary_path(path: &Path) -> PathBuf {
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let suffix = format!("tmp.{}.{}", std::process::id(), counter);
    path.with_extension(suffix)
}

/// Encode the proxy's ECH configuration in RFC 9849 wire format.
///
/// The result is an `ECHConfigList` containing one version `0xfe0d`
/// `ECHConfig` with config ID `1`, an X25519 KEM public key, the
/// `HKDF-SHA256/AES-128-GCM` cipher suite, the proxy's synthetic public name,
/// and no extensions. The outer two-byte length is the redundant list length
/// required by RFC 9848 for the DNS `ech` `SvcParam`.
fn encode_config_list(public_key: &[u8; 32]) -> Vec<u8> {
    let config_data_len = 1 + 2 + 2 + public_key.len() + 2 + 4 + 1 + 1 + PUBLIC_NAME.len() + 2;
    let config_len = 4 + config_data_len;
    let mut config = Vec::with_capacity(2 + config_len);

    push_u16(
        &mut config,
        u16::try_from(config_len).expect("ECH config length fits in u16"),
    );
    push_u16(&mut config, 0xFE0D);
    push_u16(
        &mut config,
        u16::try_from(config_data_len).expect("ECH config data length fits in u16"),
    );
    config.push(1);
    push_u16(&mut config, 0x0020);
    push_u16(
        &mut config,
        u16::try_from(public_key.len()).expect("ECH public key length fits in u16"),
    );
    config.extend_from_slice(public_key);
    push_u16(&mut config, 4);
    push_u16(&mut config, 1);
    push_u16(&mut config, 1);
    config.push(0);
    config.push(u8::try_from(PUBLIC_NAME.len()).expect("ECH public name length fits in u8"));
    config.extend_from_slice(PUBLIC_NAME);
    push_u16(&mut config, 0);
    config
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_config_matches_private_key() {
        let directory =
            std::env::temp_dir().join(format!("agent-sandbox-ech-state-{}", std::process::id()));

        let _ = fs::remove_dir_all(&directory);
        let first = load_or_generate(&directory).expect("generate ECH state");
        let second = load_or_generate(&directory).expect("load ECH state");
        assert_eq!(first.config_list, second.config_list);
        assert_eq!(first.private_key, second.private_key);
        let mut keys = rama_tls_boring::core::ssl::SslEchKeys::builder().expect("ECH key builder");

        keys.add_key(
            true,
            &first.config_list[2..],
            rama_tls_boring::core::hpke::HpkeKey::dhkem_p256_sha256(&first.private_key)
                .expect("HPKE key"),
        )
        .expect("valid ECH config");

        assert_eq!(
            usize::from(u16::from_be_bytes([
                first.config_list[0],
                first.config_list[1],
            ])),
            first.config_list.len() - 2
        );
        assert_eq!(first.config_list.len(), 80);
        fs::remove_dir_all(directory).expect("remove temporary directory");
    }

    #[test]
    fn concurrent_generation_publishes_one_complete_state() {
        let directory = std::env::temp_dir().join(format!(
            "agent-sandbox-ech-state-{}-concurrent",
            std::process::id()
        ));

        let _ = fs::remove_dir_all(&directory);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));

        let handles: [std::thread::JoinHandle<io::Result<EchState>>; 8] =
            std::array::from_fn(|_| {
                let barrier = std::sync::Arc::clone(&barrier);
                let directory = directory.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    load_or_generate(&directory)
                })
            });

        let states = handles
            .into_iter()
            .map(|handle| {
                handle
                    .join()
                    .expect("ECH state thread should not panic")
                    .expect("concurrent ECH state load should succeed")
            })
            .collect::<Vec<_>>();

        for state in states.iter().skip(1) {
            assert_eq!(state.private_key, states[0].private_key);
            assert_eq!(state.config_list, states[0].config_list);
        }

        fs::remove_dir_all(directory).expect("remove temporary directory");
    }
}
