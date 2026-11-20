//! Track C `L1` Touch ID registration: one operator ceremony in which the
//! helper creates a fresh biometry-bound SEP key and signs custody's challenge
//! with it. Custody adopts the key only if that signature verifies with the
//! returned key, and seals it first. Simulated factors stand in for the helper.

use enclave_core::ipc::PeerCredentials;
use enclave_core::profile::Profile;
use enclave_custody_vaultd::biometric::{BiometricOutcome, BiometricPrompt, BiometricProvider};
use enclave_custody_vaultd::service::{
    EnrolledBiometricL1, VaultConfig, VaultHardware, VaultRequest, VaultResponse, VaultService, BIOMETRIC_L1_STORE,
};

fn me() -> PeerCredentials {
    PeerCredentials::local(enclave_core::ipc::geteuid(), unsafe { libc::getegid() })
}

fn service(profile: Profile, biometric: Option<Box<dyn BiometricProvider + Send>>, state_dir: Option<std::path::PathBuf>)
    -> std::sync::Arc<VaultService>
{
    let mut hw = VaultHardware::simulated(profile, enclave_crypto::time::now_unix()).unwrap();
    if let Some(b) = biometric { hw.biometric = b; }
    VaultService::start(VaultConfig { profile, state_dir, ..Default::default() }, hw).unwrap()
}

/// A helper that approves but returns no new key.
#[derive(Debug)]
struct NoKey(Box<dyn BiometricProvider + Send>);
impl BiometricProvider for NoKey {
    fn evaluate(&mut self, prompt: &BiometricPrompt) -> BiometricOutcome {
        match self.0.evaluate(prompt) {
            BiometricOutcome::Approved { sep_signature, visible_at_ns, approved_at_ns, .. } =>
                BiometricOutcome::Approved { sep_signature, visible_at_ns, approved_at_ns, enrolled_pubkey: None, enrolled_blob: None },
            other => other,
        }
    }
}

/// A helper that returns a different public key than the one that signed.
#[derive(Debug)]
struct SwappedKey(Box<dyn BiometricProvider + Send>);
impl BiometricProvider for SwappedKey {
    fn evaluate(&mut self, prompt: &BiometricPrompt) -> BiometricOutcome {
        match self.0.evaluate(prompt) {
            BiometricOutcome::Approved { sep_signature, visible_at_ns, approved_at_ns, enrolled_blob, .. } => {
                let other = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
                let pubkey = other.verifying_key().to_encoded_point(false).as_bytes().to_vec();
                BiometricOutcome::Approved { sep_signature, visible_at_ns, approved_at_ns, enrolled_pubkey: Some(pubkey), enrolled_blob }
            }
            other => other,
        }
    }
}

fn simulated_touch_id() -> Box<dyn BiometricProvider + Send> {
    VaultHardware::simulated(Profile::L1, enclave_crypto::time::now_unix()).unwrap().biometric
}

#[test]
fn l1_registers_touch_id_once_and_seals_the_key() {
    let dir = std::env::temp_dir().join(format!("l1-bio-{}", enclave_core::rng::u64()));
    std::fs::create_dir_all(&dir).unwrap();
    let svc = service(Profile::L1, None, Some(dir.clone()));
    let VaultResponse::BiometricEnrolled { sas } = svc.handle(&me(), VaultRequest::EnrollBiometricL1).unwrap() else {
        panic!("enrolled expected")
    };
    assert!(!sas.is_empty());
    let (_store, loaded) = enclave_core::sealed::SealedStore::open(&dir.join("custody"), BIOMETRIC_L1_STORE).unwrap();
    let enclave_core::sealed::Loaded::State(bytes) = loaded else { panic!("sealed record expected") };
    let record: EnrolledBiometricL1 = enclave_core::sealed::decode(&bytes).unwrap();
    assert!(p256::ecdsa::VerifyingKey::from_sec1_bytes(&record.bio_public_key).is_ok());
    assert!(!record.bio_key_blob.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn registration_is_l1_only_and_operator_only() {
    let l2 = service(Profile::L2, None, None);
    assert!(l2.handle(&me(), VaultRequest::EnrollBiometricL1).unwrap_err().is("BIOMETRIC_ENROLLMENT_L1_ONLY"));
    let l1 = service(Profile::L1, None, None);
    let foreign = PeerCredentials::local(enclave_core::ipc::geteuid() + 1, 0);
    assert!(l1.handle(&foreign, VaultRequest::EnrollBiometricL1).unwrap_err().is("ENROLL_ADMIN_ONLY"));
}

#[test]
fn an_approval_without_a_new_key_or_with_a_swapped_key_registers_nothing() {
    let svc = service(Profile::L1, Some(Box::new(NoKey(simulated_touch_id()))), None);
    assert!(svc.handle(&me(), VaultRequest::EnrollBiometricL1).unwrap_err().is("BIOMETRIC_ENROLLMENT_INCOMPLETE"));
    let svc = service(Profile::L1, Some(Box::new(SwappedKey(simulated_touch_id()))), None);
    let error = svc.handle(&me(), VaultRequest::EnrollBiometricL1).unwrap_err();
    assert!(!error.is("BIOMETRIC_ENROLLMENT_INCOMPLETE"), "a signature by another key must not verify: {error}");
}
