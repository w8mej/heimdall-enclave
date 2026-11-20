//! Live FIDO metadata from the authenticated CAS service; no file-mtime trust.
use std::path::PathBuf;
use enclave_core::{daemon::DaemonId, error::EnclaveResult, ipc::Client, profile::Profile};
use enclave_core::custody_metadata::{CustodyMetadataReceipt,CustodyTarget,CustodyTargetReceipt};
use serde::{Deserialize, Serialize};
use crate::ctap::mds::MdsState;
use enclave_crypto::hpke_envelope::{SignedEnvelopePolicy, VerifiedEnvelopeContext};

/// Fixed public policy target; callers cannot select a policy by request.
pub use enclave_crypto::hpke_envelope::ENVELOPE_POLICY_TARGET;
/// Independently provisioned policy scope and issuer, never learned from CAS.
#[derive(Debug, Clone)]
pub struct EnvelopeAuthorityConfig {
    /// Ed25519 authority key configured by the operator.
    pub issuer: ed25519_dalek::VerifyingKey,
    /// Exact local custodian or host identity.
    pub subject: String,
    /// Exact namespace whose ciphertexts this vault stores.
    pub namespace: String,
}

#[derive(Serialize)]
enum Request { FetchCustodyMetadata }
#[derive(Deserialize)]
enum Response { CustodyMetadata(CustodyMetadataReceipt) }

/// Stable authority revision; diagnostic observation time does not change it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataRevision {
    digest: String,
    versions: (u64,u64,u64),
    refreshed_at: i64,
    expires_at: i64,
}

/// Caller-configured local CAS channel. Production pins both kernel UID and
/// code-signing identity; same-UID fixtures require the explicit dev flag.
#[derive(Debug, Clone)]
pub struct CustodyMetadataSource {
    socket_dir: PathBuf,
    dev_same_uid: bool,
    revision: Option<MetadataRevision>,
    deadline_ns: Option<u64>,
}

impl CustodyMetadataSource {
    /// Configure the already provisioned local service; never starts a runner.
    pub fn new(socket_dir: PathBuf, dev_same_uid: bool) -> Self {
        Self { socket_dir, dev_same_uid, revision: None, deadline_ns:None }
    }

    /// Fetch and validate current verified target bytes and all independent
    /// expiry limits immediately before a custody operation.
    pub fn fetch(&mut self, profile: Profile, now: i64) -> EnclaveResult<MdsState> {
        let anchor=enclave_core::custody_lifetime::ReceiptClockAnchor::capture()?;
        let Response::CustodyMetadata(receipt) = self.connect()?.prepare_call(&Request::FetchCustodyMetadata)?.handoff()?.receive()?;
        receipt.validate(now, profile)?;
        let expires_at=receipt.valid_until_unix(profile)?;
        let lifetime=anchor.capture_lifetime(expires_at,receipt.verified_now)?;
        let state = MdsState::from_verified_target_with_expiry(&receipt.bytes, receipt.refreshed_at, lifetime.valid_until_unix)?;
        self.revision = Some(MetadataRevision { digest: receipt.blake3, versions: receipt.versions,
            refreshed_at: receipt.refreshed_at, expires_at });
        self.deadline_ns=Some(lifetime.deadline_ns);
        Ok(state)
    }

    /// Last successfully authenticated revision, for in-flight policy fencing.
    pub fn revision(&self) -> Option<MetadataRevision> { self.revision.clone() }
    /// Latest successfully admitted MDS receipt's captured boot deadline.
    /// Keep this independently from raw source revision identity.
    pub fn deadline_ns(&self)->Option<u64> {self.deadline_ns}

    fn connect(&self) -> EnclaveResult<Client> {
        let socket = self.socket_dir.join(DaemonId::SwarmSync.socket_name());
        let requirement = enclave_core::codesign::CodeRequirement::daemon(DaemonId::SwarmSync);
        Client::connect_verified_deadline(&socket,
            if self.dev_same_uid { enclave_core::ipc::geteuid() } else { DaemonId::SwarmSync.uid() },
            (!self.dev_same_uid).then_some(&requirement), std::time::Duration::from_secs(2))
    }

    /// Current TUF-admitted fixed target plus an independent issuer signature,
    /// exact local scope and strict review/expiry. Metadata authentication alone
    /// never grants authority to a publisher-selected policy.
    pub fn envelope_context(&self, authority: &EnvelopeAuthorityConfig, profile:Profile, now: i64) -> EnclaveResult<VerifiedEnvelopeContext> {
        let anchor=enclave_core::custody_lifetime::ReceiptClockAnchor::capture()?;
        #[derive(Serialize)]
        enum PolicyRequest { FetchCustodyTarget { target: CustodyTarget } }
        #[derive(Deserialize)]
        enum PolicyResponse { CustodyTarget(CustodyTargetReceipt) }
        let PolicyResponse::CustodyTarget(receipt) = self.connect()?.prepare_call(&PolicyRequest::FetchCustodyTarget { target: CustodyTarget::EnvelopePolicy })?.handoff()?.receive()?;
        receipt.validate(now,profile,CustodyTarget::EnvelopePolicy)?;
        let valid_until=receipt.valid_until_unix(profile)?;
        let verified_at=now.max(receipt.verified_now);let bytes=receipt.bytes;
        if bytes.is_empty() || bytes.len() > 16 * 1024 { enclave_core::fail!(E2BIG, "ENVELOPE_POLICY_SIZE"); }
        let signed: SignedEnvelopePolicy = serde_json::from_slice(&bytes)
            .map_err(|_| enclave_core::err!(EACCES, "ENVELOPE_POLICY_DECODE"))?;
        let context=signed.verify(&authority.issuer, &authority.subject, &authority.namespace, now)?;
        signed.verify(&authority.issuer, &authority.subject, &authority.namespace, verified_at)?;
        let upper=anchor.trusted_upper_unix(verified_at,enclave_core::clock::boot_clock_ns())?;
        signed.verify(&authority.issuer, &authority.subject, &authority.namespace, upper)?;
        let lifetime=anchor.capture_lifetime(valid_until.min(context.policy_expires_unix()),receipt.verified_now)?;
        context.with_transport_lifetime(lifetime,enclave_crypto::time::now_unix())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::net::UnixListener, sync::atomic::{AtomicU64, Ordering}};
    use enclave_core::ipc::{self, Reply};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Root(PathBuf);
    impl Drop for Root { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
    fn root() -> Root {
        let root = Root(std::env::temp_dir().join(format!("yk-source-{}-{}", std::process::id(), NEXT.fetch_add(1,Ordering::SeqCst))));
        std::fs::create_dir(&root.0).unwrap(); root
    }
    fn receipt() -> CustodyMetadataReceipt {
        let bytes = b"{\"entries\":[]}".to_vec();
        CustodyMetadataReceipt {v:1,effective_profile:Profile::L3,target:enclave_core::custody_metadata::FIDO_MDS_TARGET.into(),
            blake3:blake3::hash(&bytes).to_hex().to_string(),bytes:bytes.into(),refreshed_at:enclave_crypto::time::now_unix()-10,
            expires_at:enclave_crypto::time::now_unix()+1_000_000,verified_now:enclave_crypto::time::now_unix(),versions:(1,2,3)}
    }
    #[derive(Serialize)] enum WireResponse { CustodyMetadata(CustodyMetadataReceipt) }
    fn serve(root:&Root, replies:Vec<CustodyMetadataReceipt>) -> std::thread::JoinHandle<()> {
        let path=root.0.join(DaemonId::SwarmSync.socket_name());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listener=UnixListener::bind(path).unwrap();
        std::thread::spawn(move|| for reply in replies {
            let (mut stream,_)=listener.accept().unwrap();
            stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
            let request=ipc::read_frame(&mut stream).unwrap();
            assert_eq!(ipc::from_cbor::<String>(&request).unwrap(),"FetchCustodyMetadata");
            ipc::write_frame(&mut stream,&ipc::to_cbor(&Reply::Ok(WireResponse::CustodyMetadata(reply))).unwrap()).unwrap();
        })
    }
    #[test]
    fn yk_metadata_actual_wire_positive_revision_and_strict_stale_or_substituted_receipt() {
        let root=root();let now=enclave_crypto::time::now_unix();
        let first=receipt();let mut later=first.clone();later.verified_now+=1;
        let mut substituted=first.clone();substituted.bytes=vec![0].into();
        let worker=serve(&root,vec![first.clone(),later,first.clone(),substituted]);
        let mut source=CustodyMetadataSource::new(root.0.clone(),true);
        let lower=source.fetch(Profile::L1,now).unwrap();assert_eq!(lower.refreshed_at,first.refreshed_at);
        let raw_expiry=first.refreshed_at+24*3600;
        assert!(lower.expires_at<=raw_expiry,"producer floor is never extended");
        assert!(lower.expires_at>now,"positive admission has usable remaining authority");
        let old_deadline=source.deadline_ns().unwrap();
        assert!(old_deadline>enclave_core::clock::boot_clock_ns());
        let revision=source.revision(); source.fetch(Profile::L3,now+1).unwrap();
        assert_eq!(source.revision(),revision,"observation clock cannot invent a new policy revision");
        assert!(source.fetch(Profile::L3,raw_expiry).unwrap_err().is("CUSTODY_METADATA_STALE"));
        assert_eq!(source.revision(),revision,"failed fetch never adopts substitute authority");
        assert!(source.fetch(Profile::L3,now+1).unwrap_err().is("CUSTODY_METADATA_RECEIPT"));
        assert_eq!(source.revision(),revision);worker.join().unwrap();
    }

    #[test]
    fn envelope_policy_wire_retains_chain_and_profile_age_without_changing_signed_digest() {
        use ed25519_dalek::{Signer,SigningKey};
        let root=root();let issuer=SigningKey::from_bytes(&[71;32]);let now=enclave_crypto::time::now_unix();
        let policy=enclave_crypto::hpke_envelope::EnvelopePolicy {version:1,revision:2,subject:"host".into(),namespace:"data".into(),
            issued_unix:now-50,expires_unix:now+1_000_000,review_unix:now+900_000,owner:"fixture".into(),profiles:vec![Profile::L2,Profile::L3],
            data_classes:vec!["C3".into(),"C4".into()],purpose:"fixture".into(),migration:"none".into(),disclosure:None,classical_exception:false};
        let signature=issuer.sign(&policy.signing_message().unwrap()).to_bytes().to_vec();
        let signed=SignedEnvelopePolicy {policy,signature};let bytes=serde_json::to_vec(&signed).unwrap();
        let authority=EnvelopeAuthorityConfig {issuer:issuer.verifying_key(),subject:"host".into(),namespace:"data".into()};
        let original=signed.verify(&authority.issuer,"host","data",now).unwrap();
        let make=|expiry|CustodyTargetReceipt {v:1,effective_profile:Profile::L2,target:CustodyTarget::EnvelopePolicy.target_name().into(),bytes:bytes.clone().into(),
            refreshed_at:now-10,expires_at:expiry,verified_now:now,versions:(1,1,1),blake3:blake3::hash(&bytes).to_hex().to_string()};
        let short=make(now+100);let fresh=make(now+200);let age=make(now+1_000_000);
        let mut wrong=make(now+100);wrong.target=CustodyTarget::OidcAuthority.target_name().into();
        let mut changed=make(now+100);changed.bytes=vec![0].into();
        let mut expired=make(now+100);expired.verified_now=now+100;
        let path=root.0.join(DaemonId::SwarmSync.socket_name());std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listener=UnixListener::bind(path).unwrap();
        let worker=std::thread::spawn(move||for receipt in [short,fresh,age,wrong,changed,expired] {
            let (mut stream,_)=listener.accept().unwrap();stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
            #[derive(Deserialize)] enum Request {FetchCustodyTarget {target:CustodyTarget}}
            let Request::FetchCustodyTarget {target}=ipc::from_cbor(&ipc::read_frame(&mut stream).unwrap()).unwrap();assert_eq!(target,CustodyTarget::EnvelopePolicy);
            #[derive(Serialize)] enum Response {CustodyTarget(CustodyTargetReceipt)}
            ipc::write_frame(&mut stream,&ipc::to_cbor(&Reply::Ok(Response::CustodyTarget(receipt))).unwrap()).unwrap();
        });
        let source=CustodyMetadataSource::new(root.0.clone(),true);
        let old=source.envelope_context(&authority,Profile::L3,now).unwrap();assert_eq!(old.digest(),original.digest());
        let old_expiry=old.expires_unix();let old_deadline=old.deadline_ns().unwrap();
        assert!(old_expiry<=now+100&&old_expiry>now);
        assert!(old.admit(Profile::L3,"C3",now+100,false).is_err());
        let new=source.envelope_context(&authority,Profile::L3,now).unwrap();assert_eq!(new.digest(),old.digest());
        assert!(new.expires_unix()>old_expiry&&new.expires_unix()<=now+200);
        assert_eq!(old.expires_unix(),old_expiry,"new receipt never extends captured wall authority");
        assert_eq!(old.deadline_ns(),Some(old_deadline),"new receipt never extends captured boot authority");
        let age=source.envelope_context(&authority,Profile::L3,now).unwrap();assert!(age.expires_unix()<=now-10+24*3600);
        assert!(age.admit(Profile::L3,"C4",now-10+24*3600,false).is_err());
        for _ in 0..3 {assert!(source.envelope_context(&authority,Profile::L3,now).is_err());}
        worker.join().unwrap();
    }

    #[test]
    fn yk_metadata_wrong_kernel_uid_is_rejected_before_request_bytes() {
        assert_ne!(ipc::geteuid(),DaemonId::SwarmSync.uid(),"fixture requires a genuinely different kernel UID");
        let root=root();let path=root.0.join(DaemonId::SwarmSync.socket_name());
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();let listener=UnixListener::bind(path).unwrap();
        let worker=std::thread::spawn(move|| {
            let (mut stream,_)=listener.accept().unwrap();
            stream.set_read_timeout(Some(std::time::Duration::from_secs(2))).unwrap();
            assert!(ipc::read_frame(&mut stream).is_err(),"untrusted server must receive no request frame");
        });
        let mut source=CustodyMetadataSource::new(root.0.clone(),false);
        assert!(source.fetch(Profile::L3,101).unwrap_err().is("SERVER_UID_MISMATCH"));
        assert!(source.revision().is_none());worker.join().unwrap();
    }
}
