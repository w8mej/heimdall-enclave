//! Persistent OHTTP identity for the local gateway fixture (DEFECT-F-93).
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use enclave_core::{err, error::EnclaveResult};
use enclave_crypto::ohttp::{decapsulate, encapsulate, gateway_keypair, KeyConfig};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct StoredKey {
    config: KeyConfig,
    secret: Vec<u8>,
}

/// Load an existing private identity, or exclusively create it with mode 0600.
/// Corrupt, insecure, mismatched or unreadable identities are never regenerated.
pub fn load_or_create(path: &Path, key_id: u8) -> EnclaveResult<(KeyConfig, Vec<u8>)> {
    let (config, secret) = gateway_keypair(key_id);
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut file) => {
            let key = StoredKey { config, secret };
            let bytes =
                serde_json::to_vec(&key).map_err(|e| err!(EIO, "GATEWAY_KEY_ENCODE", "{e}"))?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|e| err!(EIO, "GATEWAY_KEY_WRITE", "{e}"))?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(err!(EIO, "GATEWAY_KEY_CREATE", "{e}")),
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| err!(EIO, "GATEWAY_KEY_OPEN", "{e}"))?;
    let meta = file
        .metadata()
        .map_err(|e| err!(EIO, "GATEWAY_KEY_STAT", "{e}"))?;
    if !meta.is_file() || meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::geteuid() } {
        return Err(err!(EPERM, "GATEWAY_KEY_PERMISSIONS"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(32769)
        .read_to_end(&mut bytes)
        .map_err(|e| err!(EIO, "GATEWAY_KEY_READ", "{e}"))?;
    if bytes.len() > 32768 {
        return Err(err!(EINVAL, "GATEWAY_KEY_SIZE"));
    }
    let key: StoredKey =
        serde_json::from_slice(&bytes).map_err(|e| err!(EINVAL, "GATEWAY_KEY_PARSE", "{e}"))?;
    if key.config.key_id != key_id {
        return Err(err!(EINVAL, "GATEWAY_KEY_ID"));
    }
    let config = KeyConfig::parse(&key.config.render())?;
    let probe = b"depot-Gateway-Identity-Check-v1";
    if decapsulate(key_id, &key.secret, &encapsulate(&config, probe)?)? != probe {
        return Err(err!(EINVAL, "GATEWAY_KEY_MISMATCH"));
    }
    Ok((config, key.secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restart_preserves_identity_and_corruption_fails_closed() {
        let dir = std::env::temp_dir().join(format!("depot-f93-{}", enclave_core::rng::u64()));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("identity.json");
        let (a, _) = load_or_create(&path, 7).unwrap();
        assert_eq!(a, load_or_create(&path, 7).unwrap().0);
        assert!(load_or_create(&path, 8).is_err());
        std::fs::write(&path, b"corrupt").unwrap();
        assert!(load_or_create(&path, 7).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"corrupt");
        let link = dir.join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(load_or_create(&link, 7).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
