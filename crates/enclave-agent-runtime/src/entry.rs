//! Daemon entry point (UID 704 `_enclaveifc`): argument handling, peer wiring and the
//! service loop, shared by the dedicated binary and `depot-enclave __daemon`.

use std::sync::Mutex;

use crate::registry::ToolRegistry;
use crate::service::{
    CustodyPort, Declassifier, IfcConfig, IfcRequest, IfcResponse, IfcService, StepUp,
};
use ed25519_dalek::SigningKey;
use enclave_core::daemon::DaemonId;
use enclave_core::error::EnclaveResult;
use enclave_core::intent_draft::IntentDraftV1;
use enclave_core::runtime::{run_service, DaemonArgs};
use enclave_crypto::pop_biscuit::spec_limits;

/// `declassify_enum` is executed by the Class 1/2 engines inside UID 701.
/// Largest tool output UID 704 sends to UID 703 for scrubbing (UID 703's
/// 256 KiB request frame minus CBOR framing headroom).
const MAX_SCRUB_BYTES: usize = 250 * 1024;

#[derive(Debug)]
struct RemoteModelRunner {
    args: DaemonArgs,
    conn: Mutex<Option<enclave_core::ipc::Client>>,
}

/// Wire-compatible subset of the UID 701 API (externally tagged CBOR).
#[derive(serde::Serialize)]
enum RunnerRequest<'a> {
    Declassify {
        payload: &'a serde_bytes::Bytes,
        cardinality: u64,
        schema: &'a str,
        slot: Option<&'a enclave_core::seq::GovernedSlot>,
    },
}

#[derive(serde::Deserialize)]
enum RunnerResponse {
    Declassified(u64),
}

impl Declassifier for RemoteModelRunner {
    fn classify(
        &self,
        payload: &[u8],
        cardinality: u64,
        schema: &str,
        slot: &enclave_core::seq::GovernedSlot,
    ) -> EnclaveResult<u64> {
        let mut g = self
            .conn
            .lock()
            .map_err(|_| enclave_core::err!(EIO, "LOCK"))?;
        if g.is_none() {
            *g = Some(self.args.connect(DaemonId::ModelRunner)?);
        }
        let c = g
            .as_mut()
            .ok_or_else(|| enclave_core::err!(EIO, "NO_CONN"))?;
        let r: EnclaveResult<u64> = c
            .call(&RunnerRequest::Declassify {
                payload: serde_bytes::Bytes::new(payload),
                cardinality,
                schema,
                slot: Some(slot),
            })
            .map(|RunnerResponse::Declassified(i)| i);
        if r.is_err() {
            *g = None;
        }
        r
    }
}

fn load_policy_key(args: &DaemonArgs) -> EnclaveResult<SigningKey> {
    match args.get("policy-key-file") {
        Some(path) => crate::execution_host::load_policy_key(std::path::Path::new(path)),
        None => Ok(SigningKey::generate(&mut rand_core::OsRng)),
    }
}

/// UID 703 (`_piivault`) over a mutually authenticated socket: the server's
/// UID (and, on macOS, its signing identity) is verified before any byte is
/// sent, so a step-up result arriving here is UID 703's own (GAP-04).
#[derive(Debug)]
struct RemoteCustody {
    args: DaemonArgs,
    /// GAP-27: UID 703's epoch is verified against the pinned SEP epoch key
    /// before any slot of it is used.
    epochs: enclave_crypto::epoch::EpochVerifier,
    current: Mutex<Option<enclave_core::seq::BootEpoch>>,
}

impl RemoteCustody {
    fn verified_epoch(&self, want: Option<&str>) -> EnclaveResult<enclave_core::seq::BootEpoch> {
        let mut cur = self
            .current
            .lock()
            .map_err(|_| enclave_core::err!(EIO, "LOCK"))?;
        if let Some(be) = cur
            .as_ref()
            .filter(|b| want.is_none_or(|w| w == b.boot_epoch_id))
        {
            return Ok(be.clone());
        }
        let VaultResponse::Epoch(be) = self
            .args
            .connect(DaemonId::CustodyVault)?
            .call(&VaultRequest::BootEpoch)?
        else {
            return Err(enclave_core::err!(EIO, "CUSTODY_PROTOCOL"));
        };
        self.epochs.check(&be)?;
        if let Some(w) = want {
            if w != be.boot_epoch_id {
                return Err(enclave_core::err!(
                    EACCES,
                    "EPOCH_MISMATCH",
                    "slot epoch {w} != signed epoch {}",
                    be.boot_epoch_id
                ));
            }
        }
        *cur = Some(be.clone());
        Ok(be)
    }
}

/// Wire-compatible subset of the UID 703 API (externally tagged CBOR).
#[derive(serde::Serialize)]
enum VaultRequest<'a> {
    ScrubText {
        text: &'a str,
        bulk_set: bool,
        grant: Option<()>,
    },
    AuthorizeIntent(&'a IntentDraftV1),
    AllocateSlot,
    BootEpoch,
    /// Track C `A3` reveal: the record goes to custody, which binds it into
    /// the intent and shows it only on the trusted display.
    RevealRecord {
        #[serde(with = "serde_bytes")]
        value: &'a [u8],
        draft: &'a IntentDraftV1,
    },
}

#[derive(serde::Deserialize)]
enum VaultResponse {
    Text(String),
    // Distinct variant: a legacy boundless response cannot silently pass.
    IntentAuthorizedV2(StepUp),
    Slot {
        boot_epoch_id: String,
        rpc_seq_u64: u64,
    },
    Epoch(enclave_core::seq::BootEpoch),
    Delivered {
        rows: usize,
        d_jcs: String,
    },
}

impl CustodyPort for RemoteCustody {
    fn scrub_text(&self, text: &str, bulk_set: bool) -> EnclaveResult<String> {
        // GAP-39: UID 703 accepts request frames of at most 256 KiB; refuse
        // larger tool outputs here with a clear reason (fail closed).
        if text.len() > MAX_SCRUB_BYTES {
            enclave_core::fail!(
                E2BIG,
                "TOOL_OUTPUT_TOO_LARGE",
                "{} bytes > {MAX_SCRUB_BYTES}",
                text.len()
            );
        }
        // A fresh connection per call: a ceremony on another connection never
        // blocks scrubbing, and no connection state is shared across threads.
        match self
            .args
            .connect(DaemonId::CustodyVault)?
            .call(&VaultRequest::ScrubText {
                text,
                bulk_set,
                grant: None,
            })? {
            VaultResponse::Text(t) => Ok(t),
            _ => Err(enclave_core::err!(EIO, "CUSTODY_PROTOCOL")),
        }
    }
    fn authorize_intent(&self, draft: &IntentDraftV1) -> EnclaveResult<StepUp> {
        match self
            .args
            .connect(DaemonId::CustodyVault)?
            .call(&VaultRequest::AuthorizeIntent(draft))?
        {
            VaultResponse::IntentAuthorizedV2(stepup) => {
                stepup.lifetime.dispatch_expiry()?;
                Ok(stepup)
            },
            _ => Err(enclave_core::err!(EIO, "CUSTODY_PROTOCOL")),
        }
    }
    fn boot_epoch(&self) -> EnclaveResult<enclave_core::seq::BootEpoch> {
        self.verified_epoch(None)
    }
    fn reveal(&self, value: &[u8], draft: &IntentDraftV1) -> EnclaveResult<String> {
        // A fresh connection, as for step-up: the ceremony may take 10 s.
        match self.args.connect(DaemonId::CustodyVault)?.call(&VaultRequest::RevealRecord { value, draft })? {
            VaultResponse::Delivered { rows: 1, d_jcs } => Ok(d_jcs),
            _ => Err(enclave_core::err!(EIO, "CUSTODY_PROTOCOL")),
        }
    }
    fn allocate_slot(&self) -> EnclaveResult<(String, u64)> {
        match self
            .args
            .connect(DaemonId::CustodyVault)?
            .call(&VaultRequest::AllocateSlot)?
        {
            VaultResponse::Slot {
                boot_epoch_id,
                rpc_seq_u64,
            } => {
                enclave_core::seq::validate_epoch_id(&boot_epoch_id)?;
                self.verified_epoch(Some(&boot_epoch_id))?;
                Ok((boot_epoch_id, rpc_seq_u64))
            }
            _ => Err(enclave_core::err!(EIO, "CUSTODY_PROTOCOL")),
        }
    }
}

fn load_registry(args: &DaemonArgs) -> EnclaveResult<ToolRegistry> {
    match args
        .get("depot-lock-file")
        .filter(|p| std::path::Path::new(p).exists())
    {
        Some(p) => ToolRegistry::load(
            &std::fs::read(p).map_err(|e| enclave_core::err!(EIO, "depot_LOCK_READ", "{e}"))?,
        ),
        // No lock: every tool is default-conservative and no server is pinned,
        // so tool outputs are refused (fail closed) until one is installed.
        None => Ok(ToolRegistry::empty()),
    }
}

/// Run the daemon until SIGTERM / SIGINT.
pub fn run(args: DaemonArgs) -> EnclaveResult<()> {
    args.bind_deployment_for_daemon(DaemonId::AgentRuntime)?;
    if !args.dev_same_uid && args.state_dir.is_none() {
        enclave_core::fail!(EPERM, "LITERAL_EXPOSURE_STATE_REQUIRED",
            "production literal provenance requires --state-dir");
    }
    enclave_core::host_config::require_profile_floor(
        &args.socket_dir, args.profile, args.dev_same_uid,
    )?;
    let cfg = IfcConfig {
        profile: args.profile,
        audit_path: args.audit_path(DaemonId::AgentRuntime),
        policy_key: load_policy_key(&args)?,
        limits: spec_limits(),
        registry: load_registry(&args)?,
        cedar: None,
        state_dir: args.state_dir.clone(),
        socket_dir: Some(args.socket_dir.clone()),
        dev_same_uid: args.dev_same_uid,
    };
    let decl = Box::new(RemoteModelRunner {
        args: args.clone(),
        conn: Mutex::new(None),
    });
    let dispatch = crate::execution_host::NativeToolDispatch::from_args(&args, &cfg.registry, &cfg.policy_key)?;
    let svc = IfcService::start_with_dispatch(
        cfg,
        decl,
        Box::new(RemoteCustody {
            args: args.clone(),
            epochs: enclave_crypto::epoch::EpochVerifier::open(args.state_dir.as_deref())?,
            current: Mutex::new(None),
        }),
        Box::new(crate::ssm::RemoteSsmRunner::new(args.clone())),
        dispatch,
    )?;
    // GAP-16: power / sleep / lock / yank wipe hook
    let svc_wipe = std::sync::Arc::downgrade(&svc);
    enclave_core::power::registry().register("704_ifc_wipe", move |_trigger| {
        let Some(svc_wipe) = svc_wipe.upgrade() else { return Ok(()); };
        let op = enclave_core::ipc::PeerCredentials::local(0, 0);
        svc_wipe.handle(&op, IfcRequest::Wipe).map(|_| ())
    });
    let _power_mon = enclave_core::power::start_for_profile(
        args.profile, enclave_core::power::darwin::PowerMonitor::start,
    )?;
    svc.start_gateway_maintenance()?;
    let h = svc.clone();
    let admission = args.clone();
    run_service::<IfcRequest, IfcResponse, _>(
        DaemonId::AgentRuntime,
        &args,
        move |p, r| {
            // Safety cleanup remains available even when trust/config expires.
            if !matches!(&r, IfcRequest::Wipe | IfcRequest::FinishTurn { .. } | IfcRequest::ReleaseHandles { .. }
                | IfcRequest::CancelGatewaySubmission {..} | IfcRequest::RecoverGatewayTurns) {
                enclave_core::host_config::require_profile_floor(
                    &admission.socket_dir, admission.profile, admission.dev_same_uid,
                )?;
            }
            h.handle(p, r)
        },
        || {},
    )
}


#[cfg(test)]
mod intent_lifetime_wire_tests {
    use super::*;
    use serde_json::{json,Value};
    use ciborium::value::Value as CborValue;
    use enclave_custody_vaultd::service::{IntentAuthorizationV2,
        IntentLifetimeV1 as SenderLifetime,VaultResponse as SenderResponse};
    fn wire(lifetime:Value)->Value {
        json!({"IntentAuthorizedV2":{"d_jcs":"ab".repeat(32),
            "factors":["TouchIdCoreauthui","YubikeyUp"],"lifetime":lifetime}})
    }
    fn sender(lifetime:SenderLifetime)->SenderResponse {
        SenderResponse::IntentAuthorizedV2(IntentAuthorizationV2 {d_jcs:"ab".repeat(32),
            factors:vec!["TouchIdCoreauthui".into(),"YubikeyUp".into()],lifetime})
    }
    fn encode(value:&impl serde::Serialize)->Vec<u8> {
        let mut bytes=Vec::new();ciborium::ser::into_writer(value,&mut bytes).unwrap();bytes
    }
    fn map(value:&mut CborValue)->&mut Vec<(CborValue,CborValue)> {
        let CborValue::Map(values)=value else {panic!("expected encoded map")};values
    }
    fn member<'a>(value:&'a mut CborValue,name:&str)->&'a mut CborValue {
        &mut map(value).iter_mut().find(|(key,_)|key==&CborValue::Text(name.into())).unwrap().1
    }
    #[test]
    fn exact_v2_wire_retains_original_endpoints_and_refuses_legacy_or_missing_fields() {
        let boot=enclave_core::clock::boot_clock_ns()+5_000_000_000;
        let valid=wire(json!({"v":1,"valid_until_unix":null,"deadline_boot_ns":boot}));
        // Serialize the ACTUAL UID703 response, then decode with the ACTUAL
        // UID704 private response type. Never send serde_json::Value numbers
        // through a nonJSON serializer (its private number map can differ).
        let cbor=encode(&sender(SenderLifetime {v:1,valid_until_unix:None,deadline_boot_ns:Some(boot)}));
        let decoded:VaultResponse=ciborium::de::from_reader(cbor.as_slice()).unwrap();
        let VaultResponse::IntentAuthorizedV2(stepup)=decoded else {panic!("wrong response")};
        assert_eq!(stepup.lifetime.dispatch_expiry().unwrap().boot_deadline_ns(),boot);
        let wall=enclave_crypto::time::now_unix()+4;
        let bounded=encode(&sender(SenderLifetime {v:1,valid_until_unix:Some(wall),deadline_boot_ns:Some(boot)}));
        let decoded:VaultResponse=ciborium::de::from_reader(bounded.as_slice()).unwrap();
        let VaultResponse::IntentAuthorizedV2(stepup)=decoded else {panic!("wrong bounded response")};
        assert_eq!(stepup.lifetime.valid_until_unix,Some(wall));
        assert_eq!(stepup.lifetime.dispatch_expiry().unwrap().wall_deadline_ns(),Some(wall as u64*1_000_000_000));
        let original:CborValue=ciborium::de::from_reader(cbor.as_slice()).unwrap();
        for field in ["v","valid_until_unix","deadline_boot_ns"] {
            let mut missing=original.clone();
            let lifetime=member(member(&mut missing,"IntentAuthorizedV2"),"lifetime");
            map(lifetime).retain(|(key,_)|key!=&CborValue::Text(field.into()));
            assert!(ciborium::de::from_reader::<VaultResponse,_>(encode(&missing).as_slice()).is_err(),"{field}");
            let mut missing=valid.clone();
            missing["IntentAuthorizedV2"]["lifetime"].as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<VaultResponse>(missing).is_err(),"{field}");
        }
        for lifetime_member in [true,false] {
            let mut unknown=original.clone();let payload=member(&mut unknown,"IntentAuthorizedV2");
            let object=if lifetime_member {member(payload,"lifetime")} else {payload};
            map(object).push((CborValue::Text("unexpected_authority".into()),CborValue::Bool(true)));
            assert!(ciborium::de::from_reader::<VaultResponse,_>(encode(&unknown).as_slice()).is_err());
        }
        let mut legacy=original.clone();map(&mut legacy)[0].0=CborValue::Text("IntentAuthorized".into());
        map(&mut map(&mut legacy)[0].1).retain(|(key,_)|key!=&CborValue::Text("lifetime".into()));
        assert!(ciborium::de::from_reader::<VaultResponse,_>(encode(&legacy).as_slice()).is_err());
        for malformed in [CborValue::Integer((-1i64).into()),CborValue::Text("later".into()),CborValue::Float(1.25)] {
            let mut changed=original.clone();
            *member(member(member(&mut changed,"IntentAuthorizedV2"),"lifetime"),"deadline_boot_ns")=malformed;
            assert!(ciborium::de::from_reader::<VaultResponse,_>(encode(&changed).as_slice()).is_err());
        }
    }
    #[test]
    fn matching_v2_reply_refuses_null_expired_excessive_overflow_and_unknown_version_bounds() {
        let boot=enclave_core::clock::boot_clock_ns();
        for (lifetime,code) in [
            (SenderLifetime {v:2,valid_until_unix:None,deadline_boot_ns:Some(boot+1_000_000_000)},"TOOL_AUTHORITY_LIFETIME_VERSION"),
            (SenderLifetime {v:1,valid_until_unix:None,deadline_boot_ns:None},"TOOL_AUTHORITY_LIFETIME_REQUIRED"),
            (SenderLifetime {v:1,valid_until_unix:None,deadline_boot_ns:Some(boot)},"TOOL_AUTHORITY_EXPIRED"),
            (SenderLifetime {v:1,valid_until_unix:None,deadline_boot_ns:Some(u64::MAX)},"TOOL_AUTHORITY_LIFETIME_BOUND"),
            (SenderLifetime {v:1,valid_until_unix:Some(0),deadline_boot_ns:Some(boot+5_000_000_000)},"TOOL_AUTHORITY_EXPIRED"),
            (SenderLifetime {v:1,valid_until_unix:Some(-1),deadline_boot_ns:Some(boot+5_000_000_000)},"TOOL_AUTHORITY_TIME"),
            (SenderLifetime {v:1,valid_until_unix:Some(i64::MAX),deadline_boot_ns:Some(boot+5_000_000_000)},"TOOL_AUTHORITY_TIME"),
        ] {
            let parsed:VaultResponse=ciborium::de::from_reader(encode(&sender(lifetime)).as_slice()).unwrap();
            let VaultResponse::IntentAuthorizedV2(stepup)=parsed else {panic!("wrong response")};
            assert!(stepup.lifetime.dispatch_expiry().unwrap_err().is(code),"{code}");
        }
    }
}
