//! Receiver-owned rollup authority. Never derive these inputs from a received frame.
use enclave_core::{err,fail,error::EnclaveResult};
use enclave_crypto::pqc::HybridVerifyingKey;
use serde::Deserialize;
use crate::rollup::{ComplianceRollupProofV1 as Frame,RollupTrust};

/// Versioned TUF target fetched through the authenticated CAS production path.
pub const TRUST_TARGET: &str="enclave-rollup-trust-v1.json";
/// Bounded configuration size, including a 1984-byte composite public key.
pub const MAX_TRUST_BYTES: usize=16*1024;

#[derive(Debug,Clone)]
enum Authority {L2(HybridVerifyingKey),L3 {root:[u8;32],size:u32}}
/// Validated immutable receiver authority; key/cohort input is operator-owned.
/// A pinned L3 root/count still does not prove distinct-host membership (F78).
#[derive(Debug,Clone)]
pub struct ReceiverTrust(Authority);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {v:u8,authority:AuthorityDocument}
#[derive(Deserialize)]
#[serde(tag="kind",rename_all="snake_case",deny_unknown_fields)]
enum AuthorityDocument {L2HybridAnchor {public_key_hex:String},L3Cohort {root_hex:String,size:u32}}
impl ReceiverTrust {
    /// Pin an independently obtained composite issuer public key.
    pub fn l2_anchor(key:HybridVerifyingKey)->EnclaveResult<Self> {
        Ok(Self(Authority::L2(HybridVerifyingKey::from_bytes(&key.to_bytes())?)))
    }
    /// Pin independently obtained enrollment root and unique-leaf count.
    pub fn l3_cohort(root:[u8;32],size:u32)->EnclaveResult<Self> {
        if !(crate::cohort::MIN_COHORT as u32..=crate::cohort::MAX_COHORT as u32).contains(&size) {
            fail!(EINVAL,"ROLLUP_TRUST_COHORT_SIZE");
        }
        Ok(Self(Authority::L3 {root,size}))
    }
    /// Parse a bounded version-1 authority document. Authenticating its source
    /// remains the caller's responsibility (TUF or protected operator file).
    pub fn from_json(bytes:&[u8])->EnclaveResult<Self> {
        if bytes.len()>MAX_TRUST_BYTES {fail!(E2BIG,"ROLLUP_TRUST_BOUNDS");}
        let doc:Document=serde_json::from_slice(bytes).map_err(|e|err!(EINVAL,"ROLLUP_TRUST_JSON","{e}"))?;
        if doc.v!=1 {fail!(EINVAL,"ROLLUP_TRUST_VERSION");}
        match doc.authority {
            AuthorityDocument::L2HybridAnchor {public_key_hex}=>{
                let bytes=hex::decode(public_key_hex).map_err(|_|err!(EINVAL,"ROLLUP_TRUST_KEY_HEX"))?;
                Self::l2_anchor(HybridVerifyingKey::from_bytes(&bytes)?)
            }
            AuthorityDocument::L3Cohort {root_hex,size}=>{
                let bytes:[u8;32]=hex::decode(root_hex).map_err(|_|err!(EINVAL,"ROLLUP_TRUST_ROOT_HEX"))?
                    .try_into().map_err(|_|err!(EINVAL,"ROLLUP_TRUST_ROOT_LENGTH"))?;
                Self::l3_cohort(bytes,size)
            }
        }
    }
    fn borrowed(&self)->RollupTrust<'_> {
        match &self.0 {Authority::L2(key)=>RollupTrust::L2Anchor(key),Authority::L3 {root,size}=>RollupTrust::L3Cohort {root,size:*size}}
    }
    /// Verify accounting plus the configured issuer/cohort authority.
    pub fn verify(&self,bytes:&[u8],pins:&[[u8;32]])->EnclaveResult<Frame> {
        Frame::verify_with_trust(bytes,pins,self.borrowed())
    }
    /// Verify every member with this authority and preserve all chain checks.
    pub fn verify_series(&self,frames:&[impl AsRef<[u8]>],pins:&[[u8;32]])->EnclaveResult<Vec<Frame>> {
        Frame::verify_series_with_trust(frames,pins,self.borrowed())
    }
    /// Load a protected operator-selected file, never a request-supplied path.
    /// Refuses links, special files, mutable parents and oversized reads. The
    /// operator must protect the directory ancestry against replacement.
    pub fn from_operator_file(path:&std::path::Path)->EnclaveResult<Self> {
        use std::os::unix::fs::{OpenOptionsExt,MetadataExt};use std::io::Read;
        if !path.is_absolute() {fail!(EINVAL,"ROLLUP_TRUST_ABSOLUTE_PATH");}
        let parent=path.parent().ok_or_else(||err!(EINVAL,"ROLLUP_TRUST_PARENT"))?;
        let directory=std::fs::symlink_metadata(parent).map_err(|e|err!(EIO,"ROLLUP_TRUST_PARENT","{e}"))?;
        let owner=|uid|uid==0 || uid==enclave_core::ipc::geteuid();
        if !directory.is_dir() || !owner(directory.uid()) || directory.mode()&0o022!=0 {fail!(EACCES,"ROLLUP_TRUST_PARENT_UNTRUSTED");}
        for ancestor in parent.ancestors() {
            let meta=std::fs::symlink_metadata(ancestor).map_err(|e|err!(EIO,"ROLLUP_TRUST_ANCESTOR","{e}"))?;
            // Root-owned sticky temporary roots cannot be replaced by another
            // user; the immediate private parent was checked strictly above.
            let sticky_root=meta.uid()==0 && meta.mode()&0o1000!=0;
            if !meta.is_dir() || !owner(meta.uid()) || (meta.mode()&0o022!=0 && !sticky_root) {
                fail!(EACCES,"ROLLUP_TRUST_ANCESTOR_UNTRUSTED");
            }
        }
        let file=std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK).open(path)
            .map_err(|e|err!(EACCES,"ROLLUP_TRUST_FILE","{e}"))?;
        let meta=file.metadata().map_err(|e|err!(EIO,"ROLLUP_TRUST_FILE","{e}"))?;
        if !meta.is_file() || !owner(meta.uid()) || meta.mode()&0o022!=0 || meta.len()>MAX_TRUST_BYTES as u64 {fail!(EACCES,"ROLLUP_TRUST_FILE_UNTRUSTED");}
        let mut bytes=Vec::new();file.take((MAX_TRUST_BYTES+1) as u64).read_to_end(&mut bytes).map_err(|e|err!(EIO,"ROLLUP_TRUST_FILE","{e}"))?;
        Self::from_json(&bytes)
    }
}
