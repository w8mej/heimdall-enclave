//! Bounded ingress service; production uses a separate UID and Darwin code pins.
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::sync::{Arc, atomic::AtomicBool};
use enclave_core::{daemon, err, fail};
use enclave_core::error::EnclaveResult;
use enclave_core::ipc::{self, PeerCredentials};
use enclave_core::runtime::DaemonArgs;
use crate::{ClientGateway, SensitiveGatewayRequest, ClientGatewayResponse,
    DEFAULT_MAX_TURNS_PER_WINDOW, DEFAULT_WINDOW_DURATION};

// Keep the public wire enum movable for clients while the serving process owns
// a scrubbing response through serialization, queued release and every error.
#[derive(serde::Serialize)]
#[serde(transparent)]
struct ServingResponse(ClientGatewayResponse);
impl Drop for ServingResponse {
    fn drop(&mut self) {crate::wipe_gateway_reply(&mut self.0);}
}

/// Start the gateway. Never provisions directories/accounts or accepts identity
/// overrides. Development uses private same-UID sockets and makes no deployment claim.
pub fn run(args: DaemonArgs) -> EnclaveResult<()> {
    // Direct library callers must satisfy the same selected startup boundary
    // as argv-based main before any hardening, socket or thread effect.
    args.bind_deployment_context()?;
    if !args.socket_dir.is_absolute() { fail!(EINVAL,"GATEWAY_ABSOLUTE_SOCKET_DIRECTORY"); }
    if !args.extra.is_empty() || args.inherit_listener_fd.is_some() || args.simulated_hardware {
        fail!(EINVAL,"GATEWAY_UNSUPPORTED_OPTION");
    }
    if args.dev_same_uid && (ipc::geteuid()==daemon::GATEWAY_UID
        || args.socket_dir==std::path::Path::new(enclave_core::runtime::DEFAULT_SOCKET_DIR)) {
        fail!(EPERM,"GATEWAY_DEV_PRODUCTION_IDENTITY");
    }
    if !args.dev_same_uid {
        if !cfg!(target_os="macos") { fail!(EPERM,"GATEWAY_DARWIN_REQUIRED"); }
        if ipc::geteuid()!=daemon::GATEWAY_UID { fail!(EPERM,"WRONG_GATEWAY_UID"); }
        if args.sandbox_profile.is_none() { fail!(EPERM,"GATEWAY_SANDBOX_REQUIRED"); }
        if enclave_core::codesign::signing_mode()==enclave_core::codesign::SigningMode::LocalPins {
            enclave_core::codesign::pins::require(daemon::GATEWAY_IDENTIFIER)?;
        }
    }
    if !enclave_core::resource::harden_process() && !args.dev_same_uid {
        fail!(EPERM,"HARDENING_FAILED");
    }
    if let Some(path)=&args.sandbox_profile {
        enclave_core::runtime::sandbox::init_sandbox_in_process(path)?;
    }
    let path=args.socket_dir.join(daemon::GATEWAY_SOCKET_DIR).join("gateway.sock");
    if !args.dev_same_uid {
        let parent=std::fs::symlink_metadata(&args.socket_dir).map_err(|e|err!(EIO,"GATEWAY_LAYOUT","{e}"))?;
        let dir=std::fs::symlink_metadata(path.parent().unwrap()).map_err(|e|err!(EIO,"GATEWAY_LAYOUT","{e}"))?;
        if !parent.is_dir() || parent.uid()!=0 || parent.mode()&0o022!=0
            || !dir.is_dir() || dir.uid()!=daemon::GATEWAY_UID || dir.mode()&0o7777!=0o755 {
            fail!(EACCES,"GATEWAY_LAYOUT");
        }
    }
    let listener=ipc::bind(&path,ipc::SocketAccess::OwnerOnly)?;
    if !args.dev_same_uid {
        // Connect permission is public; only this service can replace its socket.
        // Kernel UID + code identity are checked before allocating request frames.
        std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o666))
            .map_err(|e|err!(EIO,"GATEWAY_SOCKET_MODE","{e}"))?;
    }
    let gateway=Arc::new(ClientGateway::new(path.clone(),
        args.socket_dir.join(daemon::DaemonId::AgentRuntime.socket_name()),
        DEFAULT_MAX_TURNS_PER_WINDOW,DEFAULT_WINDOW_DURATION,args.dev_same_uid));
    let authenticate=gateway.clone();
    let handler=gateway.clone();
    let stop=Arc::new(AtomicBool::new(false));
    enclave_core::runtime::install_signal_flag(stop.clone());
    let weak=Arc::downgrade(&gateway);
    enclave_core::power::registry().register("client-gateway-release",move |_| {
        if let Some(gateway)=weak.upgrade() {gateway.revoke()} else {Ok(())}
    });
    let _monitor=if args.dev_same_uid && !cfg!(target_os="macos") {None} else {
        enclave_core::power::start_for_profile(args.profile,enclave_core::power::darwin::PowerMonitor::start)?
    };
    let weak=Arc::downgrade(&gateway);let maintenance_stop=stop.clone();
    let maintenance=std::thread::Builder::new().name("gateway-recovery".into()).stack_size(256*1024).spawn(move|| {
        while !maintenance_stop.load(std::sync::atomic::Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(250));
            if maintenance_stop.load(std::sync::atomic::Ordering::SeqCst) {break;}
            let Some(gateway)=weak.upgrade() else {break;};
            let _=gateway.maintain_turns();
        }
    }).map_err(|e|err!(EIO,"TURN_RECOVERY_THREAD","{e}"))?;
    println!("gateway ready; dev_same_uid={}",args.dev_same_uid);
    let result=ipc::serve_with_authenticator::<SensitiveGatewayRequest,ServingResponse,_,_>(
        listener,Arc::new(move|peer:&PeerCredentials|authenticate.authenticate_connection(peer)),
        ipc::ServeLimits {max_per_uid:8,..Default::default()},Arc::new(ipc::ServeStats::default()),
        Arc::new(move|peer:&PeerCredentials,request|handler.handle_sensitive_request(peer,request).map(ServingResponse)),stop.clone());
    stop.store(true,std::sync::atomic::Ordering::SeqCst);
    let revoke=gateway.revoke();
    let joined=maintenance.join().map_err(|_|err!(EIO,"TURN_RECOVERY_THREAD_PANICKED"));
    let _=std::fs::remove_file(path);
    result.and(revoke).and(joined)
}
