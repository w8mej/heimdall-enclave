//! Narrow root-authorized teardown routing, separate from deployment selection.
//!
//! This capability can identify only the explicit descriptor being stopped. It
//! reads no authority, inventory, pins, OAuth, runtime or other referenced file,
//! and intentionally does not compare the old signing mode with this build.
//! Loss of those admission inputs must not prevent removing the old jobs.
//!
//! It cannot become a CheckedDeploymentTarget, select a global context, approve
//! starts, confer credential/release authority or prove readiness/inactivity.
//! Consumers must offer only their closed teardown operations to a root caller,
//! retain cooperative maintenance exclusion and recheck around every effect.
//! The shared protected reader supplies the existing nofollow root-protection
//! boundary; concurrent hostile root administration is outside that boundary.

use super::{normal_path, overlap, read_protected_public, DeploymentTarget, MAX_DESCRIPTOR_BYTES};
use crate::{error::EnclaveResult, fail};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// An immutable teardown-only descriptor binding. No serialization, cloning,
/// public constructor or conversion into the general deployment capability is
/// supplied. Obtaining this value grants no start, issuer or credential powers.
pub struct TeardownDeploymentTarget {
    target: DeploymentTarget,
    config_path: PathBuf,
    descriptor_sha256: String,
}
impl std::fmt::Debug for TeardownDeploymentTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TeardownDeploymentTarget")
            .field("descriptor_sha256", &self.descriptor_sha256)
            .finish_non_exhaustive()
    }
}
fn require_root(uid: u32) -> EnclaveResult<()> {
    if uid != 0 {
        fail!(EACCES, "DEPLOYMENT_TEARDOWN_ROOT_REQUIRED");
    }
    Ok(())
}
fn require_native_root() -> EnclaveResult<()> {
    #[cfg(target_os = "macos")]
    {
        require_root(unsafe { libc::geteuid() })
    }
    #[cfg(not(target_os = "macos"))]
    {
        fail!(ENOSYS, "DEPLOYMENT_TEARDOWN_NATIVE_REQUIRED");
    }
}
fn load_using(
    path: &Path,
    read: &mut impl FnMut(&Path, usize) -> EnclaveResult<Vec<u8>>,
) -> EnclaveResult<TeardownDeploymentTarget> {
    normal_path(path)?;
    let raw = read(path, MAX_DESCRIPTOR_BYTES)?;
    let target = DeploymentTarget::parse(&raw)?;
    // Preserve the general loader's lexical config isolation, including fixed
    // Darwin aliases and case-insensitive comparisons. No output is inspected.
    for root in target
        .output_roots()
        .into_iter()
        .filter(|root| root.as_os_str() != target.layout.support_root.as_os_str())
    {
        if overlap(path, root)? {
            fail!(EACCES, "DEPLOYMENT_CONFIG_OUTPUT_OVERLAP");
        }
    }
    Ok(TeardownDeploymentTarget {
        target,
        config_path: path.to_owned(),
        descriptor_sha256: hex::encode(Sha256::digest(raw)),
    })
}

/// Read only an explicit root-protected descriptor for a native root caller.
/// Dedicated/upgrade schema and namespace isolation remain mandatory; current
/// compiled signing mode and referenced admission inputs are irrelevant here.
pub fn load(path: &Path) -> EnclaveResult<TeardownDeploymentTarget> {
    require_native_root()?;
    load_using(path, &mut read_protected_public)
}
impl TeardownDeploymentTarget {
    /// Validated inert routing schema, usable only within teardown consumers.
    pub fn target(&self) -> &DeploymentTarget {
        &self.target
    }
    /// Exact caller-authorized protected descriptor route, never a reference.
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }
    /// SHA-256 of the exact raw descriptor bytes accepted at initial load.
    pub fn descriptor_sha256(&self) -> &str {
        &self.descriptor_sha256
    }
    /// Recheck the same bounded protected path and exact raw bytes as native
    /// root. No referenced file, general load or process context is consulted.
    pub fn recheck(&self) -> EnclaveResult<()> {
        require_native_root()?;
        self.recheck_using(&mut read_protected_public)
    }
    fn recheck_using(
        &self,
        read: &mut impl FnMut(&Path, usize) -> EnclaveResult<Vec<u8>>,
    ) -> EnclaveResult<()> {
        let raw = read(&self.config_path, MAX_DESCRIPTOR_BYTES)?;
        if hex::encode(Sha256::digest(raw)) != self.descriptor_sha256 {
            fail!(ESTALE, "DEPLOYMENT_CHANGED");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        deployment::{DeploymentBroker, DeploymentLayout, DeploymentRole, DeploymentSigningMode},
        profile::Profile,
    };
    use std::{
        cell::RefCell,
        os::unix::fs::{symlink, PermissionsExt},
    };
    fn target(
        root: &Path,
        role: DeploymentRole,
        l3: bool,
        mode: DeploymentSigningMode,
    ) -> DeploymentTarget {
        let support = root.join("support");
        DeploymentTarget {
            version: 1,
            target_id: "teardown-fixture".into(),
            role,
            profile: if l3 { Profile::L3 } else { Profile::L2 },
            authority_config: support.join("authority.json"),
            expected_artifacts_manifest: support.join("inventory.json"),
            codesign_pins_file: support.join("pins.json"),
            signing_identity_mode: mode,
            layout: DeploymentLayout {
                binary_dir: root.join("bin"),
                custody_bundle: support.join("Custody.app"),
                sandbox_dir: root.join("sandbox"),
                socket_root: root.join("run"),
                state_root: root.join("state"),
                audit_root: root.join("audit"),
                cas_store_root: root.join("cas"),
                staging_root: root.join("stage"),
                support_root: support.clone(),
                launchd_namespace: "com.mcpmac.teardown-fixture".into(),
                mach_service: "com.mcpmac.teardown-fixture.exception".into(),
            },
            broker: l3.then(|| DeploymentBroker {
                base_dir: root.join("state/apfs-broker"),
                tuf_root_file: support.join("root.json"),
            }),
            shared_read_only_inputs: vec![],
        }
    }
    fn bytes(target: &DeploymentTarget) -> Vec<u8> {
        serde_json::to_vec(target).unwrap()
    }
    fn pure_target() -> DeploymentTarget {
        target(
            Path::new("/teardown-fixture/target"),
            DeploymentRole::DedicatedTest,
            false,
            DeploymentSigningMode::LocalPins,
        )
    }
    const CONFIG: &str = "/teardown-fixture/deployment.json";
    #[test]
    fn native_constructor_and_recheck_have_no_unsupported_platform_fallback_or_nonroot_grant() {
        require_root(0).unwrap();
        assert!(require_root(501)
            .unwrap_err()
            .is("DEPLOYMENT_TEARDOWN_ROOT_REQUIRED"));
        #[cfg(not(target_os = "macos"))]
        {
            assert!(load(Path::new(CONFIG))
                .unwrap_err()
                .is("DEPLOYMENT_TEARDOWN_NATIVE_REQUIRED"));
            let bound =
                load_using(Path::new(CONFIG), &mut |_, _| Ok(bytes(&pure_target()))).unwrap();
            assert!(bound
                .recheck()
                .unwrap_err()
                .is("DEPLOYMENT_TEARDOWN_NATIVE_REQUIRED"));
        }
    }
    #[test]
    fn both_signing_modes_roles_and_profiles_read_only_the_descriptor_not_unavailable_references() {
        for role in [
            DeploymentRole::DedicatedTest,
            DeploymentRole::ExistingUpgrade,
        ] {
            for l3 in [false, true] {
                for mode in [
                    DeploymentSigningMode::LocalPins,
                    DeploymentSigningMode::TeamId,
                ] {
                    let target = target(Path::new("/teardown-fixture/target"), role, l3, mode);
                    let raw = bytes(&target);
                    let mut reads = Vec::new();
                    let mut reader = |path: &Path, maximum: usize| {
                        assert_eq!(path, Path::new(CONFIG));
                        assert_eq!(maximum, MAX_DESCRIPTOR_BYTES);
                        reads.push(path.to_owned());
                        Ok(raw.clone())
                    };
                    let capability = load_using(Path::new(CONFIG), &mut reader).unwrap();
                    capability.recheck_using(&mut reader).unwrap();
                    assert_eq!(capability.target(), &target);
                    assert_eq!(capability.config_path(), Path::new(CONFIG));
                    assert_eq!(
                        capability.descriptor_sha256(),
                        hex::encode(Sha256::digest(&raw))
                    );
                    assert_eq!(reads.len(), 2);
                }
            }
        }
    }
    #[test]
    fn exact_raw_drift_refuses_even_if_parsed_target_is_identical() {
        let original = bytes(&pure_target());
        let raw = RefCell::new(original.clone());
        let mut reader = |_: &Path, _: usize| Ok(raw.borrow().clone());
        let capability = load_using(Path::new(CONFIG), &mut reader).unwrap();
        raw.borrow_mut().push(b'\n');
        assert_eq!(
            DeploymentTarget::parse(&raw.borrow()).unwrap(),
            *capability.target()
        );
        assert!(capability
            .recheck_using(&mut reader)
            .unwrap_err()
            .is("DEPLOYMENT_CHANGED"));
        *raw.borrow_mut() = original;
        capability.recheck_using(&mut reader).unwrap();
    }
    #[test]
    fn syntax_size_schema_and_dedicated_namespace_isolation_are_not_bypassed_for_stop() {
        for raw in [
            vec![],
            vec![b'x'; MAX_DESCRIPTOR_BYTES + 1],
            b"{}".to_vec(),
            b"not-json".to_vec(),
        ] {
            assert!(load_using(Path::new(CONFIG), &mut |_, _| Ok(raw.clone())).is_err());
        }
        let mut wrong = pure_target();
        wrong.layout.launchd_namespace = "com.enterprise.enclave".into();
        assert!(load_using(Path::new(CONFIG), &mut |_, _| Ok(bytes(&wrong))).is_err());
        wrong = pure_target();
        wrong.profile = Profile::L3;
        assert!(load_using(Path::new(CONFIG), &mut |_, _| Ok(bytes(&wrong))).is_err());
        let mut value = serde_json::to_value(pure_target()).unwrap();
        value["authority_override"] = serde_json::json!(true);
        assert!(
            load_using(Path::new(CONFIG), &mut |_, _| Ok(serde_json::to_vec(
                &value
            )
            .unwrap()))
            .is_err()
        );
        for bad in [
            "relative",
            "/",
            "/teardown-fixture/../deployment.json",
            "/teardown-fixture//deployment.json",
            "/VAR/run/x",
        ] {
            assert!(load_using(Path::new(bad), &mut |_, _| panic!(
                "reject path before read"
            ))
            .is_err());
        }
    }
    #[test]
    fn mutable_staging_case_and_fixed_darwin_alias_descriptor_collisions_are_refused() {
        let mut target = pure_target();
        target.layout.socket_root = "/var/run/teardown-fixture".into();
        for root in target
            .output_roots()
            .into_iter()
            .filter(|p| p.as_os_str() != target.layout.support_root.as_os_str())
        {
            for path in [
                root.join("descriptor.json"),
                PathBuf::from(root.to_str().unwrap().to_ascii_uppercase()).join("descriptor.json"),
            ] {
                // Reserved OS-alias case variants may fail lexical admission
                // sooner; either way they cannot acquire a teardown binding.
                assert!(load_using(&path, &mut |_, _| Ok(bytes(&target))).is_err());
            }
        }
        assert!(load_using(
            Path::new("/private/var/run/teardown-fixture/descriptor.json"),
            &mut |_, _| Ok(bytes(&target))
        )
        .unwrap_err()
        .is("DEPLOYMENT_CONFIG_OUTPUT_OVERLAP"));
    }

    struct Root {
        base: PathBuf,
        config: PathBuf,
        target: DeploymentTarget,
    }
    impl Root {
        fn new() -> Self {
            assert_eq!(
                unsafe { libc::geteuid() },
                0,
                "actual protected private root required"
            );
            let parent = std::env::var_os("ENCLAVE_TEST_STATE_ROOT")
                .map(PathBuf::from)
                .expect("explicit coordinated private-root fixture location required");
            let base = parent.join(format!("teardown-{:x}", crate::rng::u64()));
            std::fs::create_dir(&base).unwrap();
            std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
            let base = base.canonicalize().unwrap();
            let config = base.join("deployment.json");
            let target = target(
                &base.join("target"),
                DeploymentRole::DedicatedTest,
                false,
                DeploymentSigningMode::LocalPins,
            );
            std::fs::write(&config, bytes(&target)).unwrap();
            std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
            // Prove fixture protection before the tested descriptor-only load.
            read_protected_public(&config, MAX_DESCRIPTOR_BYTES).unwrap();
            Self {
                base,
                config,
                target,
            }
        }
        fn load(&self) -> EnclaveResult<TeardownDeploymentTarget> {
            load_using(&self.config, &mut read_protected_public)
        }
    }
    impl Drop for Root {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.base);
        }
    }
    #[test]
    #[ignore = "requires coordinated actual protected private-root filesystem"]
    fn protected_descriptor_succeeds_with_missing_then_malformed_references_and_opposite_signing_mode(
    ) {
        let selected_before = crate::deployment::selected().map(|value| value as *const _);
        let mut root = Root::new();
        root.target.signing_identity_mode = match crate::codesign::signing_mode() {
            crate::codesign::SigningMode::LocalPins => DeploymentSigningMode::TeamId,
            crate::codesign::SigningMode::TeamId => DeploymentSigningMode::LocalPins,
        };
        std::fs::write(&root.config, bytes(&root.target)).unwrap();
        let capability = root.load().unwrap();
        capability
            .recheck_using(&mut read_protected_public)
            .unwrap();
        std::fs::create_dir_all(&root.target.layout.support_root).unwrap();
        for path in [
            &root.target.authority_config,
            &root.target.expected_artifacts_manifest,
            &root.target.codesign_pins_file,
        ] {
            std::fs::write(path, b"not-json, expired and unusable").unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).unwrap();
        }
        root.load()
            .unwrap()
            .recheck_using(&mut read_protected_public)
            .unwrap();
        assert!(super::super::load(&root.config).is_err());
        assert_eq!(
            crate::deployment::selected().map(|value| value as *const _),
            selected_before,
            "teardown load never selects or freezes a general context"
        );
    }
    #[test]
    #[ignore = "requires coordinated actual protected private-root filesystem"]
    fn unsafe_descriptor_links_and_ancestry_refuse_without_repair() {
        let root = Root::new();
        let original = std::fs::read(&root.config).unwrap();
        let hard = root.base.join("hardlink");
        std::fs::hard_link(&root.config, &hard).unwrap();
        assert!(root.load().is_err());
        std::fs::remove_file(hard).unwrap();
        std::fs::set_permissions(&root.config, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(root.load().is_err());
        assert_eq!(std::fs::read(&root.config).unwrap(), original);
        std::fs::set_permissions(&root.config, std::fs::Permissions::from_mode(0o600)).unwrap();
        let saved = root.base.join("saved");
        std::fs::rename(&root.config, &saved).unwrap();
        symlink(&saved, &root.config).unwrap();
        assert!(root.load().is_err());
        std::fs::remove_file(&root.config).unwrap();
        std::fs::rename(saved, &root.config).unwrap();
        let capability = root.load().unwrap();
        std::fs::set_permissions(&root.base, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(capability
            .recheck_using(&mut read_protected_public)
            .is_err());
    }
    #[test]
    #[ignore = "requires coordinated actual protected private-root filesystem"]
    fn protected_raw_drift_recheck_refuses_and_never_reads_reference_paths() {
        let root = Root::new();
        let capability = root.load().unwrap();
        let mut raw = std::fs::read(&root.config).unwrap();
        raw.push(b' ');
        std::fs::write(&root.config, raw).unwrap();
        assert!(capability
            .recheck_using(&mut read_protected_public)
            .unwrap_err()
            .is("DEPLOYMENT_CHANGED"));
        assert!(!root.target.layout.support_root.exists());
        assert!(!root.target.layout.socket_root.exists());
    }
}
