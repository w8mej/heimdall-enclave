//! Independently pinned enterprise namespace membership. No issuer is generated
//! or learned from a peer. Accepted signed updates fence local final releases.
use crate::{err, fail, error::EnclaveResult, sealed::{Loaded, SealedStore}};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{collections::{BTreeMap,BTreeSet}, path::{Path, PathBuf}, sync::{Arc, Mutex, MutexGuard, TryLockError}};

/// Maximum supported membership-policy lifetime; offline use never extends it.
pub const MAX_POLICY_TTL_S: i64 = 24 * 3600;
/// Bounded signed-policy document, including signature and membership inventory.
pub const MAX_POLICY_BYTES: usize = 256 * 1024;

/// Trusted administrator/TUF configuration, never selected by a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityConfig {
    /// Independently provisioned Ed25519 issuer public key (canonical hex).
    pub issuer_public_key_hex: String,
    /// Administrator-owned, nonwritable signed policy file.
    pub policy_path: PathBuf,
}
impl AuthorityConfig {
    /// Check fixed public pins and a canonical absolute administrator path.
    pub fn validate(&self)->EnclaveResult<()> {
        key32(&self.issuer_public_key_hex)?;
        if !self.policy_path.is_absolute() || self.policy_path.components().any(|c|matches!(c,std::path::Component::ParentDir))
            || self.policy_path.as_os_str().len()>4096 {fail!(EACCES,"ENTERPRISE_POLICY_PATH");}Ok(())
    }
}
/// Exact enterprise policy signed by the configured issuer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterprisePolicy {
    /// This implementation supports version 1 only.
    pub version: u32,
    /// Strictly monotonic policy revision, including issuer-key migrations.
    pub revision: u64,
    /// Corporate SPIFFE trust domain.
    pub trust_domain: String,
    /// Inclusive policy not-before time.
    pub issued_unix: i64,
    /// Exclusive policy expiry, at most MAX_POLICY_TTL_S after issuance.
    pub expires_unix: i64,
    /// Current members. Removing one or advancing its generation offboards it.
    pub members: Vec<EnterpriseMember>,
}
/// One independently authorized engineer and its current certificate holders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseMember {
    /// Exact spiffe://<trust-domain>/engineer/<stable-id> identity.
    pub principal: String,
    /// Monotonic principal incarnation; change on revocation/re-enrollment.
    pub generation: u64,
    /// Current Ed25519 certificate/proof public keys. Rekey preserves principal.
    pub holder_public_keys: Vec<String>,
    /// Exact namespace authorizations (no wildcards).
    pub namespaces: Vec<String>,
}
/// Detached signature over a domain-separated canonical policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnterprisePolicy {
    /// Enterprise-authorized policy.
    pub policy: EnterprisePolicy,
    /// Ed25519 signature, canonical lowercase hex.
    pub signature_hex: String,
}
/// Captured current membership, scoped to one namespace and holder incarnation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnterpriseLease {
    /// Stable independently signed principal.
    pub principal: String,
    /// Principal revocation generation.
    pub generation: u64,
    /// Authenticated current holder key.
    pub holder_public_key: String,
    /// Authorized namespace.
    pub namespace: String,
    /// A refresh never extends the already-issued lease's policy lifetime.
    pub policy_expires_unix: i64,
}
/// Challenge-bound proof delivered over authenticated CAS-to-vault IPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceProof {
    /// Requested stable engineer principal, checked against independent policy.
    pub principal: String,
    /// Holder key whose possession is proven.
    pub holder_public_key: String,
    /// Single-use, vault-issued random challenge.
    pub challenge: String,
    /// Custody boot identifier, not reusable after restart.
    pub boot_epoch: String,
    /// Exact envelope digest, including namespace and key/wrapping epochs.
    pub envelope_blake3: String,
    /// Exclusive proof expiration, at most 30 seconds after issue.
    pub expires_unix: i64,
    /// Holder signature over all preceding fields under a distinct domain.
    pub signature_hex: String,
}
fn domain_message(domain: &[u8], value: &impl Serialize) -> EnclaveResult<Vec<u8>> {
    let mut out=domain.to_vec(); out.extend(crate::jcs::to_jcs_bytes(value)?); Ok(out)
}
impl SignedEnterprisePolicy {
    /// Offline issuer helper. This never creates or configures an authority.
    pub fn sign(policy: EnterprisePolicy, issuer: &SigningKey) -> EnclaveResult<Self> {
        let message=domain_message(b"MCPMac-EnterpriseMembership-v1\0", &policy)?;
        Ok(Self {policy, signature_hex:hex::encode(issuer.sign(&message).to_bytes())})
    }
    fn verify(&self, issuer: &[u8;32], now:i64) -> EnclaveResult<()> {
        let p=&self.policy;
        if p.version!=1 || p.revision==0 || p.issued_unix<0 || p.issued_unix>now
            || p.expires_unix<=now || p.expires_unix.checked_sub(p.issued_unix).is_none_or(|n|n<=0||n>MAX_POLICY_TTL_S)
            || p.members.len()>1024 || !valid_domain(&p.trust_domain) {fail!(EACCES,"ENTERPRISE_POLICY_BOUNDS");}
        let mut principals=BTreeSet::new();let mut holders=BTreeSet::new();
        for member in &p.members {
            let prefix=format!("spiffe://{}/engineer/",p.trust_domain);
            if member.principal.len()>256 || !member.principal.strip_prefix(&prefix).is_some_and(valid_component)
                || !principals.insert(&member.principal) || member.generation==0
                || member.holder_public_keys.is_empty() || member.holder_public_keys.len()>16
                || member.namespaces.is_empty() || member.namespaces.len()>128 {fail!(EACCES,"ENTERPRISE_MEMBER_BOUNDS");}
            let mut namespaces=BTreeSet::new();
            for ns in &member.namespaces {if !valid_component(ns)||!namespaces.insert(ns) {fail!(EACCES,"ENTERPRISE_NAMESPACE");}}
            for holder in &member.holder_public_keys {key32(holder)?;if !holders.insert(holder) {fail!(EACCES,"ENTERPRISE_DUPLICATE_HOLDER");}}
        }
        let message=domain_message(b"MCPMac-EnterpriseMembership-v1\0",p)?;
        if message.len()>MAX_POLICY_BYTES {fail!(E2BIG,"ENTERPRISE_POLICY_SIZE");}
        verify_signature(issuer,&message,&self.signature_hex)
    }
}
impl NamespaceProof {
    fn message(&self)->EnclaveResult<Vec<u8>> {
        let mut unsigned=self.clone();unsigned.signature_hex.clear();
        domain_message(b"MCPMac-NamespaceHolderProof-v1\0",&unsigned)
    }
    /// Sign an already-issued exact challenge with the current holder key.
    pub fn sign(&mut self, holder:&SigningKey)->EnclaveResult<()> {
        self.holder_public_key=hex::encode(holder.verifying_key().as_bytes());
        self.signature_hex=hex::encode(holder.sign(&self.message()?).to_bytes());Ok(())
    }
    /// Verify shape, exclusive expiry and possession. Challenge consumption and
    /// envelope/boot comparisons remain mandatory in the custody service.
    pub fn verify(&self,now:i64)->EnclaveResult<()> {
        if self.principal.len()>256 || self.boot_epoch.is_empty() || self.boot_epoch.len()>128
            || self.expires_unix<=now || self.expires_unix>now.saturating_add(30) {fail!(EACCES,"ENTERPRISE_PROOF_BOUNDS");}
        canonical_hex(&self.challenge,32)?;canonical_hex(&self.envelope_blake3,32)?;
        verify_signature(&key32(&self.holder_public_key)?,&self.message()?,&self.signature_hex)
    }
}
/// Decode a canonical Ed25519 public key, refusing weak/invalid points.
pub fn key32(value:&str)->EnclaveResult<[u8;32]> {
    let bytes=canonical_hex(value,32)?;
    let key:[u8;32]=bytes.try_into().map_err(|_|err!(EACCES,"ENTERPRISE_KEY"))?;
    let verified=VerifyingKey::from_bytes(&key).map_err(|_|err!(EACCES,"ENTERPRISE_KEY"))?;
    if verified.is_weak(){fail!(EACCES,"ENTERPRISE_KEY");}Ok(key)
}
fn canonical_hex(value:&str,length:usize)->EnclaveResult<Vec<u8>> {
    if value.len()!=length*2||!value.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){fail!(EACCES,"ENTERPRISE_HEX");}
    hex::decode(value).map_err(|_|err!(EACCES,"ENTERPRISE_HEX"))
}
fn verify_signature(key:&[u8;32],message:&[u8],signature:&str)->EnclaveResult<()> {
    let signature=Signature::from_slice(&canonical_hex(signature,64)?).map_err(|_|err!(EACCES,"ENTERPRISE_SIGNATURE"))?;
    let verifier=VerifyingKey::from_bytes(key).map_err(|_|err!(EACCES,"ENTERPRISE_KEY"))?;
    verifier.verify_strict(message,&signature).map_err(|_|err!(EACCES,"ENTERPRISE_SIGNATURE"))
}
fn valid_component(value:&str)->bool { !value.is_empty()&&value.len()<=128&&value.bytes().all(|b|b.is_ascii_alphanumeric()||b"._-".contains(&b)) }
fn valid_domain(value:&str)->bool {value.len()<=253&&value.split('.').all(|part|!part.is_empty()&&part.len()<=63&&part.as_bytes()[0].is_ascii_alphanumeric()&&part.as_bytes()[part.len()-1].is_ascii_alphanumeric()&&part.bytes().all(|b|b.is_ascii_lowercase()||b.is_ascii_digit()||b==b'-'))}

#[derive(Debug,Clone,Default,Serialize,Deserialize)]
struct Watermark {
    revision:u64,digest:String,last_wall:i64,
    #[serde(default)] issuer_public_key_hex:String,
    #[serde(default)] member_generations:BTreeMap<String,u64>,
    #[serde(default)] active_members:Vec<EnterpriseMember>,
}
#[derive(Debug)]
struct Current {watermark:Watermark,persisted_wall:i64,policy:Option<EnterprisePolicy>,poisoned:bool,available:bool}
/// Allocation-free fixed refusal used while final-action guards are retained.
/// Convert to the ordinary owned error only after dropping those guards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FinalReleaseRefusal {
    /// Existing public errno category.
    pub errno: crate::error::Errno,
    /// Static stable reason, never peer-supplied text.
    pub reason: &'static str,
}
impl FinalReleaseRefusal {
    /// Construct a fixed refusal without allocation.
    pub const fn new(errno: crate::error::Errno, reason: &'static str) -> Self {
        Self {
            errno,
            reason
        }
    }
    /// Convert after releasing every protected-action guard.
    pub fn into_enclave(self) -> crate::error::EnclaveError {
        crate::error::EnclaveError::new(self.errno, self.reason)
    }
    /// Match the existing stable reason.
    pub fn is(self, reason: &str) -> bool {
        self.reason == reason
    }
}
/// Opaque retained view of accepted membership for one nonblocking handoff.
/// The accepted state remains locked until this guard is dropped. Acquisition
/// performs no I/O; final validation uses the caller's fresh post-lease clock.
#[derive(Debug)]
pub struct EnterpriseCurrentGuard<'a> {
    state: MutexGuard<'a, Current>
}
impl EnterpriseCurrentGuard<'_> {
    /// Recheck every existing accepted-membership predicate without I/O or a
    /// second lock. The caller retains this guard through its one enqueue.
    pub fn validate(&self, lease: &EnterpriseLease, now: i64) -> Result<(), FinalReleaseRefusal> {
        validate_current_fixed(&self.state, lease, now)
    }
}
fn validate_current(state: &Current, lease: &EnterpriseLease, now: i64) -> EnclaveResult<()> {
    validate_current_fixed(state, lease, now).map_err(FinalReleaseRefusal::into_enclave)
}
fn validate_current_fixed(state: &Current, lease: &EnterpriseLease, now: i64) -> Result<(), FinalReleaseRefusal> {
    use crate::error::Errno::EACCES;
    let policy = state.policy.as_ref().ok_or(FinalReleaseRefusal::new(EACCES, "ENTERPRISE_POLICY_REQUIRED"))?;
    if state.poisoned || !state.available || now<state.watermark.last_wall || now >= policy.expires_unix || now >= lease.policy_expires_unix || !policy.members.iter().any(|m|m.principal == lease.principal && m.generation == lease.generation && m.holder_public_keys.contains(&lease.holder_public_key) && m.namespaces.contains(&lease.namespace)) {
        return Err(FinalReleaseRefusal::new(EACCES, "ENTERPRISE_MEMBERSHIP_REVOKED"));
    }
    Ok(())
}
#[derive(Debug)]
enum Source {File(AuthorityConfig),Ephemeral(Mutex<SignedEnterprisePolicy>)}
/// Shared accepted enterprise authority. Persistence precedes admission, while
/// fsync/file reads/signature work stay outside the final-release mutex.
#[derive(Debug)]
pub struct EnterpriseAuthority {
    issuer:[u8;32], source:Source, refresh:Mutex<()>,
    store:Mutex<Option<SealedStore>>,current:Mutex<Current>,serial:Arc<Mutex<()>>,
}
impl EnterpriseAuthority {
    /// Open authenticated persistent high-water state and fixed public policy.
    /// This authority must own its absolute private state directory and be the
    /// only named store using that directory's sealing seed. Missing required
    /// persistence after a seed survives is refused, including interrupted first
    /// initialization; recovery must explicitly restore/reprovision authority.
    pub fn open(config:AuthorityConfig,state_dir:&Path)->EnclaveResult<Arc<Self>> {
        Self::open_with_release_serial(config,state_dir,Arc::new(Mutex::new(())))
    }
    /// Use the service's existing final-release/cancellation fence as the
    /// accepted-policy fence, so protected FDs and membership share one order.
    pub fn open_with_release_serial(config:AuthorityConfig,state_dir:&Path,serial:Arc<Mutex<()>>)->EnclaveResult<Arc<Self>> {
        config.validate()?;
        let issuer=key32(&config.issuer_public_key_hex)?;
        if !config.policy_path.is_absolute(){fail!(EACCES,"ENTERPRISE_POLICY_PATH");}
        let (mut store,loaded)=SealedStore::open_bounded_required(state_dir,"enterprise-authority",1024*1024)?;
        let watermark=match loaded {
            Loaded::Fresh=>{
                // Complete genuine first initialization before returning, even
                // if no policy refresh/request occurs before ordinary restart.
                // A surviving seed with missing state cannot enter this branch.
                let watermark=Watermark::default();
                store.save_json(&watermark)?;
                watermark
            },
            Loaded::State(bytes)=>crate::sealed::decode(&bytes)?,
        };
        let persisted_wall=watermark.last_wall;
        Ok(Arc::new(Self {issuer,source:Source::File(config),refresh:Mutex::new(()),store:Mutex::new(Some(store)),current:Mutex::new(Current{watermark,persisted_wall,policy:None,poisoned:false,available:false}),serial}))
    }
    /// Explicit portable-fixture/offline-issuer authority without persistence.
    /// Production entry points require `open` with administrator/TUF pins.
    pub fn ephemeral(issuer:[u8;32],policy:SignedEnterprisePolicy)->Arc<Self> {
        Self::ephemeral_with_release_serial(issuer,policy,Arc::new(Mutex::new(())))
    }
    /// Explicit fixture authority sharing a service's existing release fence.
    pub fn ephemeral_with_release_serial(issuer:[u8;32],policy:SignedEnterprisePolicy,serial:Arc<Mutex<()>>)->Arc<Self> {
        Arc::new(Self {issuer,source:Source::Ephemeral(Mutex::new(policy)),refresh:Mutex::new(()),store:Mutex::new(None),current:Mutex::new(Current{watermark:Watermark::default(),persisted_wall:0,policy:None,poisoned:false,available:false}),serial})
    }
    /// Replace a fixture policy; it receives the same signature/rollback checks
    /// on refresh. File-backed production policies cannot be replaced here.
    pub fn replace_ephemeral(&self,policy:SignedEnterprisePolicy)->EnclaveResult<()> {
        match &self.source{Source::Ephemeral(source)=>{*source.lock().map_err(|_|err!(EIO,"ENTERPRISE_LOCK"))?=policy;Ok(())},_=>Err(err!(EACCES,"ENTERPRISE_POLICY_SOURCE"))}
    }
    /// Serializes accepted offboarding with local final key/data handoff.
    pub fn release_serial(&self)->Arc<Mutex<()>> {self.serial.clone()}
    /// Authenticate and durably accept the current policy. Invalid/unavailable
    /// policy fails closed; no cached-policy fallback extends offline access.
    pub fn refresh(&self,now:i64)->EnclaveResult<()> {
        let _refresh=self.refresh.lock().map_err(|_|err!(EIO,"ENTERPRISE_LOCK"))?;
        let result=self.refresh_locked(now);
        if result.is_err(){let _serial=self.serial.lock().map_err(|_|err!(EIO,"ENTERPRISE_LOCK"))?;self.current.lock().map_err(|_|err!(EIO,"ENTERPRISE_LOCK"))?.available=false;}
        result
    }
    fn refresh_locked(&self,now:i64)->EnclaveResult<()> {
        let signed=match &self.source {
            Source::File(config)=>serde_json::from_slice(&read_public_file(&config.policy_path,MAX_POLICY_BYTES)?).map_err(|_|err!(EACCES,"ENTERPRISE_POLICY_JSON"))?,
            Source::Ephemeral(source)=>source.lock().map_err(|_|err!(EIO,"ENTERPRISE_LOCK"))?.clone(),
        };
        signed.verify(&self.issuer,now)?;
        let digest=hex::encode(blake3::hash(&crate::jcs::to_jcs_bytes(&signed.policy)?).as_bytes());
        let (previous,persisted_wall)={let state=self.current.lock().map_err(|_|err!(EIO,"ENTERPRISE_LOCK"))?;
            if state.poisoned || now<state.watermark.last_wall || signed.policy.revision<state.watermark.revision
                || (signed.policy.revision==state.watermark.revision&&(digest!=state.watermark.digest
                    || (state.watermark.revision>0&&state.watermark.issuer_public_key_hex!=hex::encode(self.issuer)))){fail!(EACCES,"ENTERPRISE_POLICY_ROLLBACK");}(state.watermark.clone(),state.persisted_wall)};
        let mut generations=previous.member_generations.clone();
        for member in &signed.policy.members {
            if let Some(seen)=generations.get(&member.principal) {
                let old=previous.active_members.iter().find(|old|old.principal==member.principal);
                if member.generation<*seen || (old.is_none()&&member.generation<=*seen)
                    || old.is_some_and(|old|old.generation==member.generation &&
                        (old.holder_public_keys.iter().any(|key|!member.holder_public_keys.contains(key))
                        ||old.namespaces.iter().any(|ns|!member.namespaces.contains(ns)))) {fail!(EACCES,"ENTERPRISE_GENERATION_ROLLBACK");}
            }
            generations.insert(member.principal.clone(),member.generation);
        }
        if generations.len()>4096 {fail!(E2BIG,"ENTERPRISE_PRINCIPAL_HISTORY_CAPACITY");}
        let next=Watermark{revision:signed.policy.revision,digest,last_wall:now,issuer_public_key_hex:hex::encode(self.issuer),member_generations:generations,active_members:signed.policy.members.clone()};
        let persist=next.revision!=previous.revision || now.saturating_sub(persisted_wall)>=300;
        if persist {
            let result=if let Some(store)=self.store.lock().map_err(|_|err!(EIO,"ENTERPRISE_LOCK"))?.as_mut(){store.save_json(&next)} else{Ok(())};
            if let Err(error)=result {self.current.lock().map_err(|_|err!(EIO,"ENTERPRISE_LOCK"))?.poisoned=true;return Err(error);}
        }
        let _serial=self.serial.lock().map_err(|_|err!(EIO,"ENTERPRISE_LOCK"))?;
        let mut state=self.current.lock().map_err(|_|err!(EIO,"ENTERPRISE_LOCK"))?;
        state.watermark=next;if persist {state.persisted_wall=now;}state.policy=Some(signed.policy);state.available=true;Ok(())
    }
    /// Get a signed stable principal for the authenticated holder and namespace.
    pub fn authorize(&self,holder:&[u8;32],namespace:&str,now:i64)->EnclaveResult<EnterpriseLease> {
        self.refresh(now)?;
        let state=self.current.lock().map_err(|_|err!(EIO,"ENTERPRISE_LOCK"))?;
        let policy=state.policy.as_ref().ok_or_else(||err!(EACCES,"ENTERPRISE_POLICY_REQUIRED"))?;
        if state.poisoned || !state.available || now<state.watermark.last_wall || now>=policy.expires_unix {fail!(EACCES,"ENTERPRISE_MEMBERSHIP_REVOKED");}
        let holder=hex::encode(holder);
        let member=policy.members.iter().find(|m|m.holder_public_keys.contains(&holder)&&m.namespaces.iter().any(|n|n==namespace)).ok_or_else(||err!(EACCES,"ENTERPRISE_MEMBERSHIP_DENIED"))?;
        Ok(EnterpriseLease{principal:member.principal.clone(),generation:member.generation,holder_public_key:holder,namespace:namespace.into(),policy_expires_unix:policy.expires_unix})
    }
    /// Check current accepted state without I/O; call under release_serial for
    /// final handoff, after `refresh` preflight outside that mutex.
    pub fn check_current(&self,lease:&EnterpriseLease,now:i64)->EnclaveResult<()> {
        let state=self.current.lock().map_err(|_|err!(EIO,"ENTERPRISE_LOCK"))?;
        validate_current(&state,lease,now)
    }
    /// Acquire accepted state without waiting or recovering poisoned data.
    /// Take the enterprise release serial first, then retain this guard through
    /// exactly one actual nonblocking protected action. Refresh stays outside.
    pub fn try_current_guard(&self)->Result<EnterpriseCurrentGuard<'_>,FinalReleaseRefusal> {
        let state=self.current.try_lock().map_err(|error|match error {
            TryLockError::WouldBlock=>FinalReleaseRefusal::new(crate::error::Errno::EAGAIN,"ENTERPRISE_CURRENT_BUSY"),
            TryLockError::Poisoned(_)=>FinalReleaseRefusal::new(crate::error::Errno::EIO,"ENTERPRISE_CURRENT_POISONED"),
        })?;
        Ok(EnterpriseCurrentGuard{state})
    }
    /// Re-read independent signed authority before revalidating an issued lease.
    pub fn revalidate(&self,lease:&EnterpriseLease,now:i64)->EnclaveResult<()> {self.refresh(now)?;self.check_current(lease,now)}
}
/// Bounded public authority file access, refusing links, FIFOs and writable data.
pub fn read_public_file(path:&Path,maximum:usize)->EnclaveResult<Vec<u8>> {
    use std::{io::Read,os::unix::fs::{OpenOptionsExt,MetadataExt}};
    let mut file=std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK|libc::O_CLOEXEC).open(path).map_err(|_|err!(EACCES,"ENTERPRISE_POLICY_OPEN"))?;
    let metadata=file.metadata().map_err(|_|err!(EACCES,"ENTERPRISE_POLICY_METADATA"))?;
    if !metadata.is_file() || (metadata.uid()!=0&&metadata.uid()!=crate::ipc::geteuid()) || metadata.mode()&0o022!=0 || metadata.len()==0 || metadata.len()>maximum as u64 {fail!(EACCES,"ENTERPRISE_POLICY_FILE");}
    let mut bytes=Vec::new();(&mut file).take(maximum as u64+1).read_to_end(&mut bytes).map_err(|_|err!(EIO,"ENTERPRISE_POLICY_READ"))?;
    if bytes.len() as u64!=metadata.len(){fail!(EACCES,"ENTERPRISE_POLICY_CHANGED");}Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    const NOW:i64=1_800_000_000;
    fn key(byte:u8)->SigningKey {SigningKey::from_bytes(&[byte;32])}
    fn policy()->EnterprisePolicy {EnterprisePolicy {version:1,revision:1,trust_domain:"corp.example".into(),issued_unix:NOW-1,expires_unix:NOW+3600,members:vec![
        EnterpriseMember{principal:"spiffe://corp.example/engineer/alice".into(),generation:1,holder_public_keys:vec![hex::encode(key(2).verifying_key().as_bytes())],namespaces:vec!["models".into()]},
        EnterpriseMember{principal:"spiffe://corp.example/engineer/bob".into(),generation:1,holder_public_keys:vec![hex::encode(key(3).verifying_key().as_bytes())],namespaces:vec!["models".into()]},
    ]}}
    fn signed(p:EnterprisePolicy)->SignedEnterprisePolicy {SignedEnterprisePolicy::sign(p,&key(1)).unwrap()}
    fn authority()->Arc<EnterpriseAuthority> {EnterpriseAuthority::ephemeral(key(1).verifying_key().to_bytes(),signed(policy()))}
    struct Directory(PathBuf);
    impl Directory {fn new()->Self {use std::os::unix::fs::PermissionsExt;let path=Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target").join(format!("enterprise-{:x}",crate::rng::u64()));std::fs::create_dir_all(&path).unwrap();std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o700)).unwrap();Self(path.canonicalize().unwrap())}}
    impl Drop for Directory {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.0);}}
    #[test]
    fn enterprise_independent_issuer_scope_and_expiry_refuse_hostile_authority() {
        let a=authority();let holder=key(2).verifying_key().to_bytes();
        assert!(a.authorize(&holder,"models",NOW).is_ok());
        assert!(a.authorize(&holder,"other",NOW).is_err());
        assert!(a.authorize(&key(4).verifying_key().to_bytes(),"models",NOW).is_err());
        for signed in [SignedEnterprisePolicy::sign(policy(),&key(2)).unwrap(),{let mut s=signed(policy());s.policy.members[0].namespaces.push("other".into());s},signed({let mut p=policy();p.expires_unix=NOW;p}),signed({let mut p=policy();p.issued_unix=NOW+1;p}),signed({let mut p=policy();p.expires_unix=p.issued_unix+MAX_POLICY_TTL_S+1;p})] {
            a.replace_ephemeral(signed).unwrap();assert!(a.authorize(&holder,"models",NOW).is_err());
        }
    }
    #[test]
    fn enterprise_offboarding_revokes_old_leases_while_other_engineer_continues() {
        let a=authority();let alice=a.authorize(&key(2).verifying_key().to_bytes(),"models",NOW).unwrap();
        let bob=a.authorize(&key(3).verifying_key().to_bytes(),"models",NOW).unwrap();
        let mut p=policy();p.revision=2;p.members.remove(0);a.replace_ephemeral(signed(p)).unwrap();
        assert!(a.revalidate(&alice,NOW).is_err());assert!(a.revalidate(&bob,NOW).is_ok());
        assert!(a.authorize(&key(2).verifying_key().to_bytes(),"models",NOW).is_err());
        assert!(a.authorize(&key(3).verifying_key().to_bytes(),"models",NOW).is_ok());
    }
    #[test]
    fn enterprise_rekey_keeps_stable_principal_and_generation_revokes_previous_incarnation() {
        let a=authority();let old=a.authorize(&key(2).verifying_key().to_bytes(),"models",NOW).unwrap();
        let mut p=policy();p.revision=2;p.members[0].holder_public_keys.push(hex::encode(key(4).verifying_key().as_bytes()));a.replace_ephemeral(signed(p.clone())).unwrap();
        let new=a.authorize(&key(4).verifying_key().to_bytes(),"models",NOW).unwrap();assert_eq!(old.principal,new.principal);assert!(a.revalidate(&old,NOW).is_ok());
        p.revision=3;p.members[0].generation=2;p.members[0].holder_public_keys.remove(0);a.replace_ephemeral(signed(p)).unwrap();
        assert!(a.revalidate(&old,NOW).is_err());assert!(a.revalidate(&new,NOW).is_err());assert!(a.authorize(&key(4).verifying_key().to_bytes(),"models",NOW).is_ok());
    }
    #[test]
    fn enterprise_retired_incarnation_cannot_revive_old_leases() {
        let a=authority();let holder=key(2).verifying_key().to_bytes();let old=a.authorize(&holder,"models",NOW).unwrap();
        let mut removed=policy();removed.revision=2;removed.members.remove(0);a.replace_ephemeral(signed(removed)).unwrap();a.refresh(NOW).unwrap();
        let mut restored=policy();restored.revision=3;a.replace_ephemeral(signed(restored.clone())).unwrap();assert!(a.authorize(&holder,"models",NOW).is_err());
        restored.members[0].generation=2;a.replace_ephemeral(signed(restored)).unwrap();a.authorize(&holder,"models",NOW).unwrap();assert!(a.revalidate(&old,NOW).is_err());
    }
    #[test]
    fn enterprise_duplicate_ambiguous_and_unbounded_memberships_are_denied() {
        let holder=key(2).verifying_key().to_bytes();
        for field in 0..7 {let mut p=policy();match field {
            0=>p.members.push(p.members[0].clone()),1=>p.members[1].holder_public_keys=p.members[0].holder_public_keys.clone(),
            2=>p.members[0].namespaces.push("models".into()),3=>p.members[0].principal="spiffe://foreign.example/engineer/alice".into(),
            4=>p.members[0].holder_public_keys[0]="00".repeat(32),5=>p.version=2,_=>p.members[0].generation=0,
        }let a=EnterpriseAuthority::ephemeral(key(1).verifying_key().to_bytes(),signed(p));assert!(a.authorize(&holder,"models",NOW).is_err(),"field {field}");}
    }
    #[test]
    fn enterprise_monotonic_revision_equivocation_and_clock_rollback_are_denied() {
        let a=authority();let holder=key(2).verifying_key().to_bytes();a.authorize(&holder,"models",NOW).unwrap();
        let mut p=policy();p.revision=2;a.replace_ephemeral(signed(p)).unwrap();a.authorize(&holder,"models",NOW+1).unwrap();
        a.replace_ephemeral(signed(policy())).unwrap();assert!(a.authorize(&holder,"models",NOW+1).is_err());
        let mut p=policy();p.revision=2;p.expires_unix+=1;a.replace_ephemeral(signed(p)).unwrap();assert!(a.authorize(&holder,"models",NOW+1).is_err());
        let mut p=policy();p.revision=3;a.replace_ephemeral(signed(p)).unwrap();assert!(a.authorize(&holder,"models",NOW).is_err());
    }
    #[test]
    fn enterprise_persistent_revision_survives_restart_and_cannot_reset_to_old_policy() {
        use std::os::unix::fs::PermissionsExt;
        // Inject an ordinary sealed store: repository ancestors on this Linux
        // host are writable and deliberately fail production's strict walker.
        // This checks persistence semantics, not installed path acceptance.
        fn open_fixture(cfg:AuthorityConfig,path:&Path)->Arc<EnterpriseAuthority> {
            let (store,loaded)=SealedStore::open(path,"enterprise-authority").unwrap();
            let watermark=match loaded{Loaded::Fresh=>Watermark::default(),Loaded::State(bytes)=>crate::sealed::decode(&bytes).unwrap()};
            let persisted_wall=watermark.last_wall;
            Arc::new(EnterpriseAuthority{issuer:key32(&cfg.issuer_public_key_hex).unwrap(),source:Source::File(cfg),refresh:Mutex::new(()),store:Mutex::new(Some(store)),current:Mutex::new(Current{watermark,persisted_wall,policy:None,poisoned:false,available:false}),serial:Arc::new(Mutex::new(()))})
        }
        let d=Directory::new();let path=d.0.join("policy.json");let mut p=policy();p.revision=2;std::fs::write(&path,serde_json::to_vec(&signed(p)).unwrap()).unwrap();
        std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600)).unwrap();
        let cfg=AuthorityConfig{issuer_public_key_hex:hex::encode(key(1).verifying_key().as_bytes()),policy_path:path.clone()};
        let a=open_fixture(cfg.clone(),&d.0.join("state"));a.authorize(&key(2).verifying_key().to_bytes(),"models",NOW).unwrap();
        // Frequent reads must not keep resetting the durable-save threshold.
        for elapsed in [100,200,300,400,500] {a.authorize(&key(2).verifying_key().to_bytes(),"models",NOW+elapsed).unwrap();}drop(a);
        let a=open_fixture(cfg.clone(),&d.0.join("state"));assert!(a.authorize(&key(2).verifying_key().to_bytes(),"models",NOW+299).is_err());drop(a);
        std::fs::write(&path,serde_json::to_vec(&signed(policy())).unwrap()).unwrap();
        let a=open_fixture(cfg.clone(),&d.0.join("state"));assert!(a.authorize(&key(2).verifying_key().to_bytes(),"models",NOW).is_err());drop(a);
        // Updating the administrator pin cannot equivocate at the same revision.
        let rotated=AuthorityConfig{issuer_public_key_hex:hex::encode(key(9).verifying_key().as_bytes()),policy_path:path.clone()};
        let mut p=policy();p.revision=2;std::fs::write(&path,serde_json::to_vec(&SignedEnterprisePolicy::sign(p.clone(),&key(9)).unwrap()).unwrap()).unwrap();
        let a=open_fixture(rotated.clone(),&d.0.join("state"));assert!(a.authorize(&key(2).verifying_key().to_bytes(),"models",NOW+501).is_err());drop(a);
        p.revision=3;std::fs::write(&path,serde_json::to_vec(&SignedEnterprisePolicy::sign(p,&key(9)).unwrap()).unwrap()).unwrap();
        let a=open_fixture(rotated,&d.0.join("state"));a.authorize(&key(2).verifying_key().to_bytes(),"models",NOW+501).unwrap();drop(a);
        let mut old=policy();old.revision=2;std::fs::write(&path,serde_json::to_vec(&signed(old)).unwrap()).unwrap();
        let a=open_fixture(cfg,&d.0.join("state"));assert!(a.authorize(&key(2).verifying_key().to_bytes(),"models",NOW+502).is_err());
    }
    #[test]
    fn enterprise_holder_proof_signature_covers_exact_envelope_boot_challenge_and_expiry() {
        let mut proof=NamespaceProof{principal:"spiffe://corp.example/engineer/alice".into(),holder_public_key:String::new(),challenge:"11".repeat(32),boot_epoch:"boot".into(),envelope_blake3:"22".repeat(32),expires_unix:NOW+30,signature_hex:String::new()};proof.sign(&key(2)).unwrap();proof.verify(NOW).unwrap();
        for field in 0..6 {let mut bad=proof.clone();match field {0=>bad.principal.push('x'),1=>bad.challenge="12".repeat(32),2=>bad.boot_epoch.push('x'),3=>bad.envelope_blake3="23".repeat(32),4=>bad.expires_unix+=1,_=>bad.holder_public_key=hex::encode(key(3).verifying_key().as_bytes())}assert!(bad.verify(NOW).is_err(),"field {field}");}
        assert!(proof.verify(NOW+30).is_err());
    }
    #[test]
    fn enterprise_file_reader_rejects_symlink_fifo_writable_and_oversized_policy() {
        use std::os::unix::{fs::PermissionsExt,ffi::OsStrExt};
        let d=Directory::new();let path=d.0.join("policy");std::fs::write(&path,b"data").unwrap();std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600)).unwrap();assert!(read_public_file(&path,4).is_ok());assert!(read_public_file(&path,3).is_err());
        std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o666)).unwrap();assert!(read_public_file(&path,4).is_err());
        let link=d.0.join("link");std::os::unix::fs::symlink(&path,&link).unwrap();assert!(read_public_file(&link,4).is_err());
        let fifo=d.0.join("fifo");let name=std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();assert_eq!(unsafe{libc::mkfifo(name.as_ptr(),0o600)},0);assert!(read_public_file(&fifo,4).is_err());
    }
    fn capacity_holders()->Vec<String> {
        (0u32..1025).map(|index|{
            let seed=blake3::derive_key("MCPMac enterprise capacity fixture v1",&index.to_be_bytes());
            hex::encode(SigningKey::from_bytes(&seed).verifying_key().as_bytes())
        }).collect()
    }
    fn capacity_policy(first:usize,count:usize,revision:u64,holders:&[String])->EnterprisePolicy {
        EnterprisePolicy {version:1,revision,trust_domain:"capacity.example".into(),issued_unix:NOW,
            expires_unix:NOW+MAX_POLICY_TTL_S,members:(0..count).map(|index|EnterpriseMember {
                principal:format!("spiffe://capacity.example/engineer/p{}",first+index),generation:1,
                holder_public_keys:vec![holders[index].clone()],namespaces:vec!["m".into()],
            }).collect()}
    }
    #[test]
    fn enterprise_active_capacity_accepts_1024_refuses_1025_and_preserves_accepted_history() {
        let holders=capacity_holders();let full=capacity_policy(0,1024,1,&holders);
        let a=EnterpriseAuthority::ephemeral(key(1).verifying_key().to_bytes(),signed(full.clone()));
        let holder=key32(&holders[1023]).unwrap();let lease=a.authorize(&holder,"m",NOW).unwrap();
        assert_eq!(lease.principal,"spiffe://capacity.example/engineer/p1023");
        let mut over=capacity_policy(0,1025,2,&holders);
        a.replace_ephemeral(signed(over.clone())).unwrap();
        assert!(a.authorize(&holder,"m",NOW).unwrap_err().is("ENTERPRISE_POLICY_BOUNDS"));
        {
            let state=a.current.lock().unwrap();assert_eq!(state.watermark.revision,1);
            assert_eq!(state.watermark.member_generations.len(),1024);
            assert_eq!(state.watermark.active_members,full.members);
            assert!(!state.available,"invalid current source must fail closed, not use stale cached authority");
        }
        assert!(a.check_current(&lease,NOW).is_err());
        a.replace_ephemeral(signed(full)).unwrap();a.authorize(&holder,"m",NOW).unwrap();
        over.members.pop();a.replace_ephemeral(signed(over)).unwrap();
        a.authorize(&holder,"m",NOW).unwrap();
        assert_eq!(a.current.lock().unwrap().watermark.revision,2);
    }
    #[test]
    fn enterprise_history_capacity_retains_4096_refuses_4097_and_preserves_generation_floors() {
        let holders=capacity_holders();let holder=key32(&holders[0]).unwrap();
        let a=EnterpriseAuthority::ephemeral(key(1).verifying_key().to_bytes(),signed(capacity_policy(0,1024,1,&holders)));
        let retired=a.authorize(&holder,"m",NOW).unwrap();
        // Fill history through four actual independently signed accepted
        // revisions; never prefill or directly mutate the authority map.
        for batch in 1..4 {
            a.replace_ephemeral(signed(capacity_policy(batch*1024,1024,batch as u64+1,&holders))).unwrap();
            a.authorize(&holder,"m",NOW).unwrap();
        }
        let current=capacity_policy(3072,1024,4,&holders);
        assert_eq!(a.current.lock().unwrap().watermark.member_generations.len(),4096);
        let mut revived=capacity_policy(0,1,5,&holders);
        a.replace_ephemeral(signed(revived.clone())).unwrap();
        assert!(a.authorize(&holder,"m",NOW).unwrap_err().is("ENTERPRISE_GENERATION_ROLLBACK"));
        a.replace_ephemeral(signed(current.clone())).unwrap();a.authorize(&holder,"m",NOW).unwrap();
        a.replace_ephemeral(signed(capacity_policy(4096,1,5,&holders))).unwrap();
        assert!(a.authorize(&holder,"m",NOW).unwrap_err().is("ENTERPRISE_PRINCIPAL_HISTORY_CAPACITY"));
        {
            let state=a.current.lock().unwrap();assert_eq!(state.watermark.revision,4);
            assert_eq!(state.watermark.member_generations.len(),4096);
            assert_eq!(state.watermark.active_members,current.members);assert!(!state.available);
            assert_eq!(state.watermark.member_generations[&retired.principal],1);
            assert!(!state.watermark.member_generations.contains_key("spiffe://capacity.example/engineer/p4096"));
        }
        assert!(a.check_current(&retired,NOW).is_err());
        a.replace_ephemeral(signed(current)).unwrap();a.authorize(&holder,"m",NOW).unwrap();
        // Full history may update a known principal at a strictly newer
        // generation; refusing all future authority is not the capacity policy.
        revived.members[0].generation=2;a.replace_ephemeral(signed(revived)).unwrap();
        assert_eq!(a.authorize(&holder,"m",NOW).unwrap().generation,2);
        assert!(a.check_current(&retired,NOW).is_err());
        assert_eq!(a.current.lock().unwrap().watermark.member_generations.len(),4096);
    }
    #[test]
    fn enterprise_policy_ttl_accepts_24h_and_excludes_expiry_without_extending_old_lease() {
        let holder=key(2).verifying_key().to_bytes();let mut p=policy();
        p.issued_unix=NOW;p.expires_unix=NOW+MAX_POLICY_TTL_S;
        let a=EnterpriseAuthority::ephemeral(key(1).verifying_key().to_bytes(),signed(p.clone()));
        let lease=a.authorize(&holder,"models",NOW).unwrap();
        a.authorize(&holder,"models",p.expires_unix-1).unwrap();
        a.check_current(&lease,p.expires_unix-1).unwrap();
        assert!(a.authorize(&holder,"models",p.expires_unix).unwrap_err().is("ENTERPRISE_POLICY_BOUNDS"));
        assert!(a.check_current(&lease,p.expires_unix).is_err());
        let mut over=p.clone();over.revision=2;over.expires_unix+=1;
        a.replace_ephemeral(signed(over)).unwrap();
        assert!(a.authorize(&holder,"models",p.expires_unix-1).unwrap_err().is("ENTERPRISE_POLICY_BOUNDS"));
        let mut renewed=policy();renewed.revision=2;renewed.issued_unix=p.expires_unix;
        renewed.expires_unix=renewed.issued_unix+MAX_POLICY_TTL_S;
        a.replace_ephemeral(signed(renewed)).unwrap();
        a.authorize(&holder,"models",p.expires_unix).unwrap();
        assert!(a.check_current(&lease,p.expires_unix).is_err(),"new policy cannot extend an old lease");
    }
    #[test]
    fn enterprise_policy_actual_file_accepts_exact_byte_cap_refuses_plus_one_and_recovers() {
        use std::os::unix::fs::PermissionsExt;
        let holders=capacity_holders();let mut p=capacity_policy(0,1024,1,&holders);
        let base=serde_json::to_vec(&signed(p.clone())).unwrap().len();
        let mut remaining=MAX_POLICY_BYTES.checked_sub(base).expect("valid full inventory fits policy file");
        assert!(remaining>0&&remaining<=1023*127);
        // Canonical safe ASCII changes serialized length by exactly one byte
        // per character. Preserve the final member's namespace for a positive
        // authorization at the exact public-file limit.
        for member in &mut p.members[..1023] {
            let extra=remaining.min(127);member.namespaces[0].push_str(&"x".repeat(extra));remaining-=extra;
        }
        assert_eq!(remaining,0);
        let bytes=serde_json::to_vec(&signed(p)).unwrap();assert_eq!(bytes.len(),MAX_POLICY_BYTES);
        let d=Directory::new();let path=d.0.join("exact-policy.json");
        std::fs::write(&path,&bytes).unwrap();std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut file_authority=Arc::try_unwrap(authority()).unwrap();
        file_authority.source=Source::File(AuthorityConfig {issuer_public_key_hex:hex::encode(key(1).verifying_key().as_bytes()),policy_path:path.clone()});
        // This fixture deliberately has no persistent store. The production
        // file reader, signature verification and admission remain actual.
        let a=Arc::new(file_authority);let holder=key32(&holders[1023]).unwrap();
        let lease=a.authorize(&holder,"m",NOW).unwrap();
        let mut over=bytes.clone();over.push(b' ');std::fs::write(&path,&over).unwrap();
        assert_eq!(over.len(),MAX_POLICY_BYTES+1);
        assert!(a.authorize(&holder,"m",NOW).unwrap_err().is("ENTERPRISE_POLICY_FILE"));
        assert!(a.check_current(&lease,NOW).is_err());
        {
            let state=a.current.lock().unwrap();assert_eq!(state.watermark.revision,1);
            assert_eq!(state.watermark.member_generations.len(),1024);assert!(!state.available);
        }
        std::fs::write(&path,&bytes).unwrap();a.authorize(&holder,"m",NOW).unwrap();
    }
    struct CoreFenceReceipt {
        directory: std::path::PathBuf,
        completed: Vec<&'static str>,
        finished: bool,
        stop: Option<std::sync::mpsc::Sender<()>>,
        watchdog: Option<std::thread::JoinHandle<()>>,
    }
    impl CoreFenceReceipt {
        const CASES: &'static [&'static str] = &["retention_and_busy", "principal_generation_holder_namespace", "rollback_policy_and_lease_expiry", "unavailable_poisoned_missing_policy", "mutex_poison_refusal"];
        fn new() -> Self {
            use std::os::unix::fs::{
                MetadataExt,
                PermissionsExt
            };
            let root = std::path::PathBuf::from(std::env::var_os("MCPMAC_QUARANTINE_FENCE_EVIDENCE_DIR").expect("explicit fence evidence directory"));
            let metadata = std::fs::symlink_metadata(&root).unwrap();
            assert!(root.is_absolute() && metadata.is_dir() && !metadata.file_type().is_symlink() && metadata.mode()&0o7777 == 0o700 && metadata.uid() == crate::ipc::geteuid());
            assert_eq!(root.canonicalize().unwrap(), root);
            let repository = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap().canonicalize().unwrap();
            assert!(root.parent() == Some(repository.join("target").as_path()));
            let name = root.file_name().unwrap().to_str().unwrap();
            assert!(name.starts_with("qf-evidence-") && name.len() <= 128 && name.bytes().all(|b|b.is_ascii_alphanumeric() || b == b'-'));
            let directory = root.join(format!("enterprise-final-guard-{:016x}", crate::rng::u64()));
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let (stop, receiver) = std::sync::mpsc::channel();
            let watchdog = std::thread::spawn(move || {
                if matches!(receiver.recv_timeout(std::time::Duration::from_secs(30)), Err(std::sync::mpsc::RecvTimeoutError::Timeout)) {
                    eprintln!("QF_CORE_OUTER_DEADLINE");
                    std::process::exit(124);
                }
            });
            Self {
                directory,
                completed: Vec::new(),
                finished: false,
                stop: Some(stop),
                watchdog: Some(watchdog),
            }
        }
        fn complete(&mut self, id: &'static str) {
            assert!(Self::CASES.contains(&id) && !self.completed.contains(&id));
            self.completed.push(id);
        }
        fn emit(&self, status: &str) {
            use std::{
                io::Write,
                os::unix::fs::OpenOptionsExt
            };
            let value = serde_json::json!( {
                "schema": 1,
                "outer_test": "enterprise_authority::tests::enterprise_quarantine_final_guard_preserves_predicates_and_is_nonblocking",
                "status": status,
                "expected_subcases": Self::CASES,
                "completed_subcases": self.completed,
                "children": []
            });
            let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(self.directory.join("outer-receipt.json")).unwrap();
            file.write_all(&serde_json::to_vec_pretty(&value).unwrap()).unwrap();
            file.sync_all().unwrap();
        }
        fn finish(&mut self) {
            assert_eq!(self.completed.len(), Self::CASES.len());
            self.emit("PASS");
            self.finished = true;
        }
    }
    impl Drop for CoreFenceReceipt {
        fn drop(&mut self) {
            if !self.finished {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.emit("FAIL")));
            }
            if let Some(stop) = self.stop.take() {
                let _ = stop.send(());
            }
            if let Some(watchdog) = self.watchdog.take() {
                let _ = watchdog.join();
            }
        }
    }

    #[test]
    fn enterprise_quarantine_final_guard_preserves_predicates_and_is_nonblocking() {
        let mut receipt = CoreFenceReceipt::new();
        let a = authority();
        let lease = a.authorize(&key(2).verifying_key().to_bytes(), "models", NOW).unwrap();
        let guard = a.try_current_guard().unwrap();
        guard.validate(&lease, NOW).unwrap();
        assert!(a.try_current_guard().unwrap_err().is("ENTERPRISE_CURRENT_BUSY"));
        let other = a.clone();
        let blocked = std::thread::spawn(move || matches!(other.current.try_lock(), Err(TryLockError::WouldBlock))).join().unwrap();
        assert!(blocked, "opaque guard retains the actual accepted-state mutex");
        receipt.complete("retention_and_busy");
        for field in 0..4 {
            let mut bad = lease.clone();
            match field {
                0 => bad.principal.push('x'),
                1 => bad.generation+=1,
                2 => bad.holder_public_key = hex::encode(key(3).verifying_key().as_bytes()),
                _ => bad.namespace = "other".into()
            }
            assert!(guard.validate(&bad, NOW).unwrap_err().is("ENTERPRISE_MEMBERSHIP_REVOKED"));
        }
        receipt.complete("principal_generation_holder_namespace");
        assert!(guard.validate(&lease, NOW-1).unwrap_err().is("ENTERPRISE_MEMBERSHIP_REVOKED"));
        guard.validate(&lease, NOW+3599).unwrap();
        assert!(guard.validate(&lease, NOW+3600).is_err());
        let mut short = lease.clone();
        short.policy_expires_unix = NOW+1;
        guard.validate(&short, NOW).unwrap();
        assert!(guard.validate(&short, NOW+1).is_err());
        drop(guard);
        assert!(a.current.try_lock().is_ok());
        receipt.complete("rollback_policy_and_lease_expiry");
        for state in 0..3 {
            let a = authority();
            let lease = a.authorize(&key(2).verifying_key().to_bytes(), "models", NOW).unwrap();
            {
                let mut current = a.current.lock().unwrap();
                match state {
                    0 => current.available = false,
                    1 => current.poisoned = true,
                    _ => current.policy = None
                }
            }
            let guard = a.try_current_guard().unwrap();
            let error = guard.validate(&lease, NOW).unwrap_err();
            assert!(error.is(if state == 2 {
                "ENTERPRISE_POLICY_REQUIRED"
            } else {
                "ENTERPRISE_MEMBERSHIP_REVOKED"
            }));
        }
        receipt.complete("unavailable_poisoned_missing_policy");
        let poisoned = authority();
        poisoned.authorize(&key(2).verifying_key().to_bytes(), "models", NOW).unwrap();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe( || {
            let _guard = poisoned.try_current_guard().unwrap();
            panic!("owned final-current poison control");
        }));
        assert!(caught.is_err());
        assert!(poisoned.try_current_guard().unwrap_err().is("ENTERPRISE_CURRENT_POISONED"));
        receipt.complete("mutex_poison_refusal");
        receipt.finish();
    }

}

#[cfg(test)]
#[path="enterprise_required_state_tests.rs"]
mod required_state_tests;
