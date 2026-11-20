//! Authenticated local namespace-key custody, separate from transport routing.
use enclave_core::{err,error::EnclaveResult,secret::SecretKey32,runtime::DaemonArgs,daemon::DaemonId};
use enclave_crypto::namespace::{WrappedNamespaceKey,CasKeyLease};
use enclave_custody_vaultd::service::{VaultRequest,VaultResponse};
/// A key release and its short-lived revocation lease.
#[derive(Debug)]
pub struct NamespaceRelease {
    /// Released namespace DEK, zeroized when its last local owner drops.
    pub key:SecretKey32,
    /// Issued custody lease required throughout streaming and publication.
    pub lease:CasKeyLease,
}
/// The production provider is the independently authenticated UID703 service.
/// Software fixture providers must be explicitly injected by the test harness.
pub trait NamespaceCustody:std::fmt::Debug+Send+Sync {
    /// Authenticate custody and release this exact signed namespace envelope.
    fn unwrap(&self,key:&WrappedNamespaceKey)->EnclaveResult<NamespaceRelease>;
    /// Refuse expired, restarted, wiped or otherwise unissued leases.
    fn revalidate(&self,lease:&CasKeyLease)->EnclaveResult<()>;
    /// Last remote observation before the local serialized release permit.
    /// Production uses a one-second socket deadline, outside the release lock.
    fn revalidate_for_release(&self,lease:&CasKeyLease)->EnclaveResult<()> {self.revalidate(lease)}
    /// Local cached membership check under CAS's final release fence. No RPC,
    /// file read or persistence belongs here. Explicit fixture providers opt out.
    fn validate_local_release(&self,_lease:&CasKeyLease)->EnclaveResult<()> {Ok(())}
}
/// Uses the ordinary kernel/code/pin-verified daemon connection; no same-UID
/// exception is introduced here. Development behavior remains DaemonArgs policy.
#[derive(Debug,Clone)]
pub struct IpcNamespaceCustody {
    /// Runtime socket routing and independent server authentication policy.
    pub args:DaemonArgs,
    authority:Option<std::sync::Arc<enclave_core::enterprise_authority::EnterpriseAuthority>>,
}
impl IpcNamespaceCustody {
    /// Bind independently configured membership to CAS's final FD-release fence.
    pub fn new(args:DaemonArgs,serial:std::sync::Arc<std::sync::Mutex<()>>)->EnclaveResult<Self> {
        use enclave_core::enterprise_authority::{AuthorityConfig,EnterpriseAuthority,read_public_file};
        let authority=match (args.get("enterprise-issuer-key-file"),args.get("enterprise-policy-file")) {
            (Some(issuer),Some(policy))=>{
                let pin=read_public_file(std::path::Path::new(issuer),128)?;
                let pin=std::str::from_utf8(&pin).map_err(|_|err!(EACCES,"ENTERPRISE_KEY"))?.trim().to_owned();
                let state=args.state_dir.as_deref().ok_or_else(||err!(EACCES,"ENTERPRISE_STATE_REQUIRED"))?;
                Some(EnterpriseAuthority::open_with_release_serial(AuthorityConfig{issuer_public_key_hex:pin,policy_path:policy.into()},&state.join("enterprise"),serial)?)
            },(None,None)=>None,_=>return Err(err!(EACCES,"ENTERPRISE_AUTHORITY_CONFIG")),
        };Ok(Self{args,authority})
    }
    fn local_membership(&self,lease:&CasKeyLease,refresh:bool)->EnclaveResult<()> {
        match (&self.authority,&lease.enterprise) {
            (Some(authority),Some(membership))=>{let now=enclave_crypto::time::now_unix();if refresh {authority.revalidate(membership,now)}else{authority.check_current(membership,now)}},
            (None,None) if self.args.dev_same_uid&&self.args.simulated_hardware=>Ok(()),
            _=>Err(err!(EACCES,"ENTERPRISE_AUTHORITY_REQUIRED")),
        }
    }
}
impl NamespaceCustody for IpcNamespaceCustody {
    fn unwrap(&self,key:&WrappedNamespaceKey)->EnclaveResult<NamespaceRelease> {
        let mut client=self.args.connect(DaemonId::CustodyVault)?;
        let mut expected_membership=None;
        let request=match (self.args.get("enterprise-principal"),self.args.get("enterprise-key-seed-file")) {
            (Some(principal),Some(path))=>{
                let seed=super::quic::credential(path,true)?;
                let seed=zeroize::Zeroizing::new(<[u8;32]>::try_from(seed.expose()).map_err(|_|err!(EACCES,"ENTERPRISE_HOLDER_KEY"))?);
                let holder=ed25519_dalek::SigningKey::from_bytes(&seed);
                let membership=self.authority.as_ref().ok_or_else(||err!(EACCES,"ENTERPRISE_AUTHORITY_REQUIRED"))?.authorize(&holder.verifying_key().to_bytes(),&key.namespace,enclave_crypto::time::now_unix())?;
                if membership.principal!=principal {return Err(err!(EACCES,"ENTERPRISE_PRINCIPAL_MISMATCH"));}
                expected_membership=Some(membership);
                let (challenge,boot_epoch,expires_unix)=match client.call(&VaultRequest::NamespaceKeyChallenge{wrapped:key.clone()})? {
                    VaultResponse::NamespaceKeyChallenge{challenge,boot_epoch,expires_unix}=>(challenge,boot_epoch,expires_unix),
                    _=>return Err(err!(EACCES,"ENTERPRISE_CHALLENGE_RESPONSE")),
                };
                let mut proof=enclave_core::enterprise_authority::NamespaceProof{principal:principal.into(),holder_public_key:String::new(),challenge,boot_epoch,envelope_blake3:hex::encode(blake3::hash(&enclave_core::jcs::to_jcs_bytes(key)?).as_bytes()),expires_unix,signature_hex:String::new()};
                proof.sign(&holder)?;VaultRequest::UnwrapCasKeyAuthorized{wrapped:key.clone(),proof}
            },
            (None,None) if self.args.dev_same_uid && self.args.simulated_hardware=>VaultRequest::UnwrapCasKey{wrapped:key.clone()},
            _=>return Err(err!(EACCES,"ENTERPRISE_PRINCIPAL_CONFIG_REQUIRED")),
        };
        match client.call(&request)? {
            VaultResponse::CasKey {key:material,lease}=> {
                if lease.namespace!=key.namespace||lease.key_epoch!=key.epoch||lease.enterprise!=expected_membership {return Err(err!(EACCES,"NAMESPACE_CUSTODY_BINDING"));}
                self.local_membership(&lease,true)?;let raw:[u8;32]=material.0.as_slice().try_into().map_err(|_|err!(EACCES,"NAMESPACE_KEY_LENGTH"))?;Ok(NamespaceRelease {key:SecretKey32::new(raw),lease})
            },
            _=>Err(err!(EACCES,"NAMESPACE_CUSTODY_RESPONSE")),
        }
    }
    fn revalidate_for_release(&self,lease:&CasKeyLease)->EnclaveResult<()> {
        let requirement=(!self.args.dev_same_uid).then(||enclave_core::codesign::CodeRequirement::daemon(DaemonId::CustodyVault));
        let mut client=enclave_core::ipc::Client::connect_verified_deadline(&self.args.socket_path(DaemonId::CustodyVault),self.args.expected_uid(DaemonId::CustodyVault),requirement.as_ref(),std::time::Duration::from_secs(1))?;
        client.set_timeout(Some(std::time::Duration::from_secs(1)))?;
        match client.call(&VaultRequest::CheckCasKeyLease(lease.clone()))? {VaultResponse::CasKeyLeaseValid=>self.local_membership(lease,true),_=>Err(err!(EACCES,"NAMESPACE_CUSTODY_RESPONSE"))}
    }

    fn revalidate(&self,lease:&CasKeyLease)->EnclaveResult<()> {
        let mut client=self.args.connect(DaemonId::CustodyVault)?;
        match client.call(&VaultRequest::CheckCasKeyLease(lease.clone()))? {VaultResponse::CasKeyLeaseValid=>self.local_membership(lease,true),_=>Err(err!(EACCES,"NAMESPACE_CUSTODY_RESPONSE"))}
    }
    fn validate_local_release(&self,lease:&CasKeyLease)->EnclaveResult<()> {self.local_membership(lease,false)}
}
