//! Daemon entry point (UID 702 `_enclavecas`): argument handling, peer wiring and the
//! service loop, shared by the dedicated binary and `depot-enclave __daemon`.

use crate::service::{CasConfig, CasRequest, CasResponse, CasService};
use enclave_core::daemon::DaemonId;
use enclave_core::error::EnclaveResult;
use enclave_core::runtime::{resolve, run_service_with_startup, DaemonArgs};
use enclave_crypto::ohttp::KeyConfig;

/// Run the daemon until SIGTERM / SIGINT.
pub fn run(args: DaemonArgs) -> EnclaveResult<()> {
    args.bind_deployment_for_daemon(DaemonId::SwarmSync)?;
    run_service_with_startup::<CasRequest, CasResponse, _, _, _>(
        DaemonId::SwarmSync,
        &args,
        || with_snapshot_broker_ready(
            args.profile,
            args.dev_same_uid,
            || crate::snapshot_broker::BrokerClient.require_ready(),
            || {
                let store = args
                    .get("store-dir")
                    .map(|s| resolve(&args.socket_dir, s))
                    .unwrap_or_else(|| "/opt/enterprise/enclave/cas".into());
                let ohttp_gateway = args
                    .get("ohttp-key-config")
                    .map(KeyConfig::parse)
                    .transpose()?;
                let tuf_root = args
                    .get("tuf-root")
                    .map(|p| {
                        std::fs::read(resolve(&args.socket_dir, p))
                            .map_err(|e| enclave_core::err!(EIO, "TUF_ROOT_READ", "{e}"))
                    })
                    .transpose()?;
                let svc = CasService::start(CasConfig {dev_same_uid: args.dev_same_uid,
                    profile: args.profile,
                    store_dir: store,
                    audit_path: args.audit_path(DaemonId::SwarmSync),
                    ohttp_gateway,
                    tuf_root,
                    state_dir: args.state_dir.clone(),
                    // GAP-21: the root supervisor terminates holders of revoked
                    // artifacts; in the single-UID development mesh this process can.
                    revocation: match args.get("supervisor-socket") {
                        Some(p) => crate::revocation::Enforcement::Supervisor {
                            socket: resolve(&args.socket_dir, p),
                            dev: args.dev_same_uid,
                        },
                        None if args.dev_same_uid => crate::revocation::Enforcement::InProcess,
                        None => crate::revocation::Enforcement::Supervisor {
                            socket: enclave_core::supervisor::socket_path(&args.socket_dir),
                            dev: false,
                        },
                    },
                })?;
                // The provisioned repository is transport only: the pinned/restored TUF
                // client verifies signatures, hashes, freshness and rollback state. Loading
                // it before binding avoids a fresh install/reboot bootstrap deadlock.
                if let Some(repo) = args.get("tuf-repo") {
                    let repo = resolve(&args.socket_dir, repo);
                    let refresh = (|| {
                        let request = CasRequest::TufRefresh {
                            roots: read_root_chain(&repo, svc.initial_tuf_root_version()?)?,
                            timestamp: read_metadata(&repo.join("timestamp.json"))?.into(),
                            snapshot: read_metadata(&repo.join("snapshot.json"))?.into(),
                            targets: read_metadata(&repo.join("targets.json"))?.into(),
                        };
                        svc.validate_initial_tuf_refresh(&request)?;
                        Ok::<_, enclave_core::EnclaveError>(request)
                    })();
                    match refresh {
                        Ok(request) => {
                            // These errors may follow trust-state mutation. Do not serve
                            // with undurable trust or partially enforced revocations.
                            svc.handle(
                                &enclave_core::ipc::PeerCredentials::local(
                                    enclave_core::ipc::geteuid(),
                                    0,
                                ),
                                request,
                            )?;
                        }
                        Err(error) => {
                            // Only transport/pre-adoption verification errors recover into
                            // existing verified trust or configuration-only management.
                            eprintln!("TUF_REPO_REFRESH_DEFERRED: {error}");
                        }
                    }
                }
                svc.set_namespace_custody(std::sync::Arc::new(
                    crate::transport::custody::IpcNamespaceCustody::new(args.clone(),svc.namespace_release_serial())?,
                ))?;
                svc.enable_host_profile_floor(args.profile)?;
                // GAP-16: power / sleep / lock / yank wipe hook
                register_cas_wipe(enclave_core::power::registry(), &svc);
                let _power_mon = enclave_core::power::start_for_profile(
                    args.profile,
                    enclave_core::power::darwin::PowerMonitor::start,
                )?;
                // All required wipe registration precedes the first real QUIC
                // listener, not only the later CAS IPC serving socket.
                let _l2_seed = crate::transport::quic_seed::SeedListener::start(svc.clone())?;
                let h = svc.clone();
                Ok((
                    move |p: &enclave_core::ipc::PeerCredentials, r: CasRequest| h.handle(p, r),
                    (_l2_seed, _power_mon),
                ))
            },
        ),
        || {},
    )
}

/// The shared runtime calls this only after identity, hardening and confinement,
/// and binds CAS IPC only after it returns. A missing/stale/untrusted production
/// L3 helper therefore cannot leave an apparently ready CAS daemon. The probe is
/// authenticated and bounded; it neither publishes nor grants native acceptance.
fn with_snapshot_broker_ready<T>(
    profile: enclave_core::profile::Profile,
    dev_same_uid: bool,
    ready: impl FnOnce() -> EnclaveResult<()>,
    initialize: impl FnOnce() -> EnclaveResult<T>,
) -> EnclaveResult<T> {
    if profile == enclave_core::profile::Profile::L3 && !dev_same_uid {
        ready()?;
    }
    initialize()
}

#[cfg(test)]
mod broker_startup_tests {
    use super::*;
    use enclave_core::profile::Profile;
    use std::cell::RefCell;

    #[test]
    fn f38_broker_readiness_gates_only_production_l3_and_precedes_initialization() {
        for profile in Profile::ALL {
            for dev in [false, true] {
                let order = RefCell::new(Vec::new());
                let value = with_snapshot_broker_ready(
                    profile,
                    dev,
                    || { order.borrow_mut().push("ready"); Ok(()) },
                    || { order.borrow_mut().push("initialize"); Ok(42) },
                ).unwrap();
                assert_eq!(value, 42);
                let expected = if profile == Profile::L3 && !dev {
                    vec!["ready", "initialize"]
                } else {
                    vec!["initialize"]
                };
                assert_eq!(*order.borrow(), expected, "{profile}, dev={dev}");
            }
        }
        for reason in ["BROKER_CONNECT", "CODE_REQUIREMENT", "TUF_EXPIRED", "BROKER_GENERATION"] {
            let initialized = std::cell::Cell::new(false);
            let error = with_snapshot_broker_ready(
                Profile::L3,
                false,
                || Err(enclave_core::err!(EACCES, reason)),
                || { initialized.set(true); Ok(()) },
            ).unwrap_err();
            assert!(error.is(reason));
            assert!(!initialized.get(), "failed readiness must precede service effects");
        }
    }

    #[test]
    fn f38_missing_broker_aborts_shared_startup_before_service_effects_or_ipc_bind() {
        let Some(root) = std::env::var_os("depot_BROKER_GATE_CHILD") else {
            let root = std::env::temp_dir().join(format!("cas-broker-gate-{:x}", enclave_core::rng::u64()));
            std::fs::create_dir(&root).unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "entry::broker_startup_tests::f38_missing_broker_aborts_shared_startup_before_service_effects_or_ipc_bind", "--nocapture"])
                .env("depot_BROKER_GATE_CHILD", &root).output().unwrap();
            std::fs::remove_dir_all(root).unwrap();
            assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            return;
        };
        let root = std::path::PathBuf::from(root);
        // Only the policy selector uses production L3. Runtime execution remains
        // same-UID in an owned child and never contacts an installed/root helper.
        let mut args = DaemonArgs::parse(["daemon", "--dev-same-uid", "--profile", "L3"].map(String::from)).unwrap();
        args.socket_dir = root.join("sockets");
        let initialized = std::cell::Cell::new(false);
        let result = run_service_with_startup::<serde_json::Value, serde_json::Value, _, _, _>(
            DaemonId::SwarmSync,
            &args,
            || with_snapshot_broker_ready(
                Profile::L3,
                false,
                || {
                    std::os::unix::net::UnixStream::connect(root.join("absent-helper.sock"))
                        .map_err(|e| enclave_core::err!(EIO, "BROKER_CONNECT", "{e}"))?;
                    Ok(())
                },
                || {
                    initialized.set(true);
                    std::fs::write(root.join("service-effect"), b"unexpected")
                        .map_err(|e| enclave_core::err!(EIO, "FIXTURE_WRITE", "{e}"))?;
                    Ok((|_: &enclave_core::ipc::PeerCredentials, value: serde_json::Value| Ok(value), ()))
                },
            ),
            || {},
        );
        assert!(result.unwrap_err().is("BROKER_CONNECT"));
        assert!(!initialized.get());
        assert!(!root.join("service-effect").exists());
        assert!(!args.socket_path(DaemonId::SwarmSync).exists());
        assert!(!args.socket_dir.exists(), "IPC binding must not create its parent");
    }
}

// The process-wide registry outlives this daemon invocation. It must not keep
// service/key state alive after failed IPC binding or after serving ends.
fn register_cas_wipe(
    registry: &enclave_core::power::WipeRegistry,
    service: &std::sync::Arc<CasService>,
) {
    let service = std::sync::Arc::downgrade(service);
    registry.register("702_cas_wipe", move |_trigger| {
        let Some(service) = service.upgrade() else { return Ok(()); };
        let op = enclave_core::ipc::PeerCredentials::local(0, 0);
        service.handle(&op, CasRequest::Wipe)?;
        Ok(())
    });
}

#[cfg(test)]
mod power_hook_tests {
    use super::*;
    use enclave_core::power::{WipeRegistry, WipeTrigger};
    use enclave_core::power::start_for_profile as start_profile_power_monitor;
    use std::sync::Arc;

    #[test]
    fn f38_power_monitor_policy_requires_l2_l3_registration_and_retains_l1_optional() {
        use enclave_core::profile::Profile;
        for profile in Profile::ALL {
            assert_eq!(start_profile_power_monitor(profile, || Ok(42)).unwrap(), Some(42));
            let result = start_profile_power_monitor::<()>(profile, || Err(enclave_core::err!(EIO, "FIXTURE_POWER_REGISTRATION")));
            if profile == Profile::L1 { assert_eq!(result.unwrap(), None); }
            else { assert!(result.unwrap_err().is("FIXTURE_POWER_REGISTRATION")); }
        }
    }

    #[test]
    fn f38_required_monitor_failure_prevents_bind_and_success_guard_drops_on_bind_failure() {
        use enclave_core::profile::Profile;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let Some(root) = std::env::var_os("depot_REQUIRED_POWER_CHILD") else {
            let root = std::env::temp_dir().join(format!("cas-required-power-{:x}", enclave_core::rng::u64()));
            std::fs::create_dir(&root).unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "entry::power_hook_tests::f38_required_monitor_failure_prevents_bind_and_success_guard_drops_on_bind_failure", "--nocapture"])
                .env("depot_REQUIRED_POWER_CHILD", &root).output().unwrap();
            std::fs::remove_dir_all(root).unwrap();
            assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            return;
        };
        let root = std::path::PathBuf::from(root);
        struct Monitor(Arc<AtomicUsize>);
        impl Drop for Monitor { fn drop(&mut self) { self.0.fetch_add(1, Ordering::SeqCst); } }
        for profile in [Profile::L2, Profile::L3] {
            let mut args = DaemonArgs::parse(["daemon", "--dev-same-uid", "--profile", &profile.to_string()].map(String::from)).unwrap();
            args.socket_dir = root.join(format!("{profile}-missing"));
            let initialized = std::cell::Cell::new(false);
            let error = run_service_with_startup::<serde_json::Value, serde_json::Value, _, _, _>(
                DaemonId::SwarmSync, &args,
                || {
                    let guard = start_profile_power_monitor::<Monitor>(profile, || Err(enclave_core::err!(EIO, "FIXTURE_POWER_REGISTRATION")))?;
                    initialized.set(true);
                    Ok((|_: &enclave_core::ipc::PeerCredentials, value: serde_json::Value| Ok(value), guard))
                }, || {},
            ).unwrap_err();
            assert!(error.is("FIXTURE_POWER_REGISTRATION"));
            assert!(!initialized.get());
            assert!(!args.socket_path(DaemonId::SwarmSync).exists());
            assert!(!args.socket_dir.exists());

            let invalid_parent = root.join(format!("{profile}-not-directory"));
            std::fs::write(&invalid_parent, b"ordinary fixture file").unwrap();
            args.socket_dir = invalid_parent;
            let dropped = Arc::new(AtomicUsize::new(0));
            let error = run_service_with_startup::<serde_json::Value, serde_json::Value, _, _, _>(
                DaemonId::SwarmSync, &args,
                || {
                    let guard = start_profile_power_monitor(profile, || Ok(Monitor(dropped.clone())))?;
                    Ok((|_: &enclave_core::ipc::PeerCredentials, value: serde_json::Value| Ok(value), guard))
                }, || {},
            ).unwrap_err();
            assert!(!error.is("FIXTURE_POWER_REGISTRATION"));
            assert_eq!(dropped.load(Ordering::SeqCst), 1, "successful monitor guard must be released after failed IPC binding");
            assert!(!args.socket_path(DaemonId::SwarmSync).exists());
        }
    }

    #[test]
    fn f38_failed_ipc_bind_releases_service_despite_registered_power_hook() {
        let Some(root) = std::env::var_os("depot_CAS_WIPE_OWNER_CHILD") else {
            let root = std::env::temp_dir().join(format!("cas-wipe-owner-{:x}", enclave_core::rng::u64()));
            std::fs::create_dir(&root).unwrap();
            // Runtime hardening affects only the owned child, never sibling
            // tests in this harness process.
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "entry::power_hook_tests::f38_failed_ipc_bind_releases_service_despite_registered_power_hook", "--nocapture"])
                .env("depot_CAS_WIPE_OWNER_CHILD", &root).output().unwrap();
            std::fs::remove_dir_all(root).unwrap();
            assert!(output.status.success(), "{}\n{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
            return;
        };
        let root = std::path::PathBuf::from(root);
        let invalid_directory = root.join("not-directory");
        std::fs::write(&invalid_directory, b"not a directory").unwrap();
        let mut args = DaemonArgs::parse(["daemon", "--dev-same-uid", "--profile", "L1"].map(String::from)).unwrap();
        args.socket_dir = invalid_directory;
        let registry = WipeRegistry::default();
        let observed = std::cell::RefCell::new(None);
        let result = run_service_with_startup::<CasRequest, CasResponse, _, _, _>(
            DaemonId::SwarmSync,
            &args,
            || {
                let service = CasService::start(CasConfig {dev_same_uid: args.dev_same_uid,
                    profile: args.profile,
                    store_dir: root.join("store"),
                    audit_path: None,
                    tuf_root: None,
                    ohttp_gateway: None,
                    state_dir: None,
                    revocation: crate::revocation::Enforcement::Unavailable,
                })?;
                *observed.borrow_mut() = Some(Arc::downgrade(&service));
                register_cas_wipe(&registry, &service);
                assert!(registry.execute(WipeTrigger::SessionLocked).success);
                Ok((move |p: &enclave_core::ipc::PeerCredentials, r| service.handle(p, r), ()))
            },
            || {},
        );
        assert!(result.is_err(), "invalid IPC parent must reject startup");
        assert!(observed.borrow().as_ref().expect("initializer ran").upgrade().is_none(), "registry must not retain failed-start service or key state");
        assert!(registry.execute(WipeTrigger::SessionLocked).success, "expired weak callback is harmless");
    }
}

/// Local metadata has the same authority as received metadata: none until TUF
/// verification. Bound reads, reject links/special files and never block on FIFOs.
fn read_metadata(path: &std::path::Path) -> EnclaveResult<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    const MAX: u64 = 4 * 1024 * 1024;
    let mut file = std::fs::OpenOptions::new().read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path).map_err(|e| enclave_core::err!(EIO, "TUF_REPO_READ", "{e}"))?;
    let metadata = file.metadata().map_err(|e| enclave_core::err!(EIO, "TUF_REPO_READ", "{e}"))?;
    if !metadata.is_file() || metadata.len() > MAX {
        enclave_core::fail!(E2BIG, "TUF_REPO_FILE");
    }
    let mut bytes = Vec::new();
    (&mut file).take(MAX + 1).read_to_end(&mut bytes)
        .map_err(|e| enclave_core::err!(EIO, "TUF_REPO_READ", "{e}"))?;
    if bytes.len() as u64 > MAX { enclave_core::fail!(E2BIG, "TUF_REPO_FILE"); }
    Ok(bytes)
}

/// Read a bounded numeric rotation chain; filenames do not grant authority.
/// Every selected document is still cryptographically checked by TufClient.
fn read_root_chain(repo:&std::path::Path,current:u64)->EnclaveResult<Vec<serde_bytes::ByteBuf>> {
    use enclave_core::{err,fail};
    let mut documents=std::collections::BTreeMap::new();let mut total=0usize;
    for entry in std::fs::read_dir(repo).map_err(|e|err!(EIO,"TUF_REPO_READ","{e}"))? {
        let entry=entry.map_err(|e|err!(EIO,"TUF_REPO_READ","{e}"))?;
        let name=entry.file_name();let name=name.to_str().ok_or_else(||err!(EINVAL,"TUF_ROOT_CHAIN_NAME"))?;
        let Some(number)=name.strip_suffix(".root.json") else {continue;};
        if number.is_empty() || !number.bytes().all(|b|b.is_ascii_digit()) {fail!(EINVAL,"TUF_ROOT_CHAIN_NAME");}
        let version=number.parse::<u64>().map_err(|_|err!(EINVAL,"TUF_ROOT_CHAIN_NAME"))?;
        if version==0 || number!=version.to_string() {fail!(EINVAL,"TUF_ROOT_CHAIN_NAME");}
        if version<=current {continue;}
        if documents.len()>=64 {fail!(E2BIG,"TUF_ROOT_CHAIN_LIMIT");}
        let bytes=read_metadata(&entry.path())?;total=total.checked_add(bytes.len()).ok_or_else(||err!(E2BIG,"TUF_ROOT_CHAIN_LIMIT"))?;
        if total>16*1024*1024 {fail!(E2BIG,"TUF_ROOT_CHAIN_LIMIT");}
        let value:serde_json::Value=serde_json::from_slice(&bytes).map_err(|_|err!(EINVAL,"TUF_ROOT_CHAIN_DOCUMENT"))?;
        if value.get("signed").and_then(|v|v.get("version")).and_then(|v|v.as_u64())!=Some(version) {fail!(EINVAL,"TUF_ROOT_CHAIN_VERSION");}
        documents.insert(version,bytes.into());
    }
    let mut expected=current.checked_add(1).ok_or_else(||err!(EINVAL,"TUF_ROOT_CHAIN_VERSION"))?;
    for version in documents.keys() {if *version!=expected {fail!(EINVAL,"TUF_ROOT_CHAIN_GAP");}expected=expected.checked_add(1).ok_or_else(||err!(EINVAL,"TUF_ROOT_CHAIN_VERSION"))?;}
    Ok(documents.into_values().collect())
}

#[cfg(test)]
mod root_chain_tests {
    use super::*;
    use enclave_crypto::tuf::{RepoBuilder,TufClient};
    struct Fixture(std::path::PathBuf);
    impl Fixture {fn new()->Self {let path=std::env::temp_dir().join(format!("mc-f38-roots-{:x}",enclave_core::rng::u64()));std::fs::create_dir(&path).unwrap();Self(path)}}
    impl Drop for Fixture {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.0);}}
    #[test]
    fn f38_numbered_root_chain_is_ordered_and_still_cryptographically_verified() {
        let fixture=Fixture::new();let mut repo=RepoBuilder::new(3,2);let mut client=TufClient::bootstrap(&repo.root("2030-01-01T00:00:00Z").unwrap()).unwrap();
        for version in [3,2] {repo.root_version=version;std::fs::write(fixture.0.join(format!("{version}.root.json")),repo.root("2030-01-01T00:00:00Z").unwrap()).unwrap();}
        let roots=read_root_chain(&fixture.0,1).unwrap();assert_eq!(roots.len(),2);for root in roots {client.update_root(&root).unwrap();}assert_eq!(client.root().version,3);assert!(read_root_chain(&fixture.0,3).unwrap().is_empty());
        let mut bad=std::fs::read(fixture.0.join("3.root.json")).unwrap();let mut value:serde_json::Value=serde_json::from_slice(&bad).unwrap();value["signed"]["expires"]=serde_json::json!("2031-01-01T00:00:00Z");bad=serde_json::to_vec(&value).unwrap();std::fs::write(fixture.0.join("3.root.json"),bad).unwrap();let roots=read_root_chain(&fixture.0,2).unwrap();repo.root_version=2;let mut previous=TufClient::bootstrap(&repo.root("2030-01-01T00:00:00Z").unwrap()).unwrap();assert!(previous.update_root(&roots[0]).is_err());
    }
    #[test]
    fn f38_numbered_root_chain_rejects_gaps_names_version_confusion_and_excess() {
        for (name,version) in [("3.root.json",3),("02.root.json",2),("2.root.json",4),("0.root.json",0)] {
            let fixture=Fixture::new();std::fs::write(fixture.0.join(name),serde_json::to_vec(&serde_json::json!({"signed":{"version":version}})).unwrap()).unwrap();assert!(read_root_chain(&fixture.0,1).is_err(),"{name}");
        }
        let fixture=Fixture::new();for version in 2..=66 {std::fs::write(fixture.0.join(format!("{version}.root.json")),serde_json::to_vec(&serde_json::json!({"signed":{"version":version}})).unwrap()).unwrap();}assert!(read_root_chain(&fixture.0,1).unwrap_err().is("TUF_ROOT_CHAIN_LIMIT"));
    }
    #[test]
    fn f38_bootstrap_metadata_rejects_symlinks_fifos_and_oversize_without_blocking() {
        use std::os::unix::ffi::OsStrExt;
        let fixture=Fixture::new();let path=fixture.0.join("2.root.json");let source=fixture.0.join("ordinary");std::fs::write(&source,b"{}").unwrap();std::os::unix::fs::symlink(&source,&path).unwrap();assert!(read_root_chain(&fixture.0,1).is_err());std::fs::remove_file(&path).unwrap();
        let c=std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();assert_eq!(unsafe{libc::mkfifo(c.as_ptr(),0o600)},0);let start=std::time::Instant::now();assert!(read_metadata(&path).is_err());assert!(start.elapsed()<std::time::Duration::from_secs(1));std::fs::remove_file(&path).unwrap();
        let file=std::fs::File::create(&path).unwrap();file.set_len(4*1024*1024+1).unwrap();assert!(read_metadata(&path).unwrap_err().is("TUF_REPO_FILE"));
    }
}
