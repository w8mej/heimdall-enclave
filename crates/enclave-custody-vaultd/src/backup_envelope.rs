//! Staged alternate hybrid wrappers for an independently admitted backup key.
//!
//! This crate-private library is deliberately disconnected from activation.
//! A credential fingerprint is public identity, not proof of inventory admission.
//! Service adoption still requires an independently signed receipt, fresh factors,
//! a versioned durable membership ledger and its original complete ceremony cap.
use enclave_core::{fail,error::EnclaveResult,profile::Profile,secret::ct_eq};
use enclave_crypto::hpke_envelope::{rewrap_tier,verify_tier_wrapping,A3,A4,A3Checkpoint,EnvelopeA3,EnvelopeA4,KekShares,VerifiedEnvelopeContext,WrappedTierKey};
use serde::{Serialize,Deserialize};
use sha2::{Digest,Sha256};
use crate::{ctap::assertion::{CredentialKey,EnrolledCredential},vault::{VaultEnvelopeCheckpoint,A3_EPOCHS_PER_ENROLLMENT}};

/// Validated immutable source wrappers. Contains no raw factor or private key.
#[derive(Debug)]
pub(crate) struct BackupSource {
    pub(crate) profile:Profile,
    pub(crate) policy_revision:u64,
    pub(crate) policy_digest:[u8;32],
    pub(crate) pool_digest:[u8;32],
    pub(crate) a3:Vec<WrappedTierKey>,
    pub(crate) a4:WrappedTierKey,
}

/// Complete candidate only. Persisting or deserializing this value grants no
/// membership or recovery authority and cannot replace the active primary.
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StagedBackupEnvelopes {
    version:u32,
    profile:Profile,
    policy_revision:u64,
    policy_digest:[u8;32],
    pool_digest:[u8;32],
    primary_credential_sha256:[u8;32],
    backup_credential_sha256:[u8;32],
    a3:Vec<WrappedTierKey>,
    a4:WrappedTierKey,
}

/// Runtime-only encrypted wrappers. Public scope validation constructs this
/// value; only the vault's typed admitted-member selector can install it.
/// It retains no factor/private key and never replaces durable primary state.
#[derive(Debug)]
pub(crate) struct BackupProjection { a3:Vec<WrappedTierKey>, a4:WrappedTierKey }

/// Encrypted source selector for staging only. Neither arm establishes current
/// membership, retirement, fresh factors or recovery authority. The original
/// primary always retains its immutable enrollment/checkpoint meaning.
#[derive(Debug,Clone,Copy)]
pub(crate) enum SelectedMemberWrappers<'a> {
    OriginalPrimary,
    Alternate(&'a StagedBackupEnvelopes),
}
impl BackupProjection {
    pub(crate) fn a3(&self,epoch:u32)->EnclaveResult<&WrappedTierKey> {
        self.a3.get(epoch as usize).filter(|wrapped|wrapped.epoch==epoch)
            .ok_or_else(||enclave_core::err!(ESTALE,"A3_EPOCH_RETIRED"))
    }
    pub(crate) fn a4(&self)->&WrappedTierKey {&self.a4}
}

fn credential_id(credential:&EnrolledCredential)->EnclaveResult<[u8;32]> {
    if credential.credential_id.is_empty()||credential.credential_id.len()>1023 {fail!(EACCES,"BACKUP_CREDENTIAL_ID");}
    let mut message=b"MCPMac-BackupCredential-v1\0".to_vec();
    message.extend(enclave_core::jcs::to_jcs_bytes(credential)?);
    Ok(Sha256::digest(message).into())
}
fn normalized_key(credential:&EnrolledCredential)->Vec<u8> {
    let mut key=(credential.key.alg() as i32).to_be_bytes().to_vec();
    key.extend(match &credential.key {
        CredentialKey::Ed25519(key)=>key.to_edwards().compress().to_bytes().to_vec(),
        CredentialKey::Es256(_)=>credential.key.to_raw(),
    });key
}
fn distinct(primary:&EnrolledCredential,backup:&EnrolledCredential)->EnclaveResult<([u8;32],[u8;32])> {
    let ids=(credential_id(primary)?,credential_id(backup)?);
    if primary.credential_id==backup.credential_id||normalized_key(primary)==normalized_key(backup) {fail!(EACCES,"BACKUP_DISTINCT_CREDENTIAL_REQUIRED");}
    Ok(ids)
}
fn same_key(source:&WrappedTierKey,target:&WrappedTierKey)->bool {
    source.version==target.version&&source.suite==target.suite&&source.context==target.context
        &&source.tier==target.tier&&source.epoch==target.epoch&&source.public_key==target.public_key
}

impl StagedBackupEnvelopes {
    /// Stage all independent tiers under the backup shares or return no result.
    /// The caller separately authenticates both credential identities and factor
    /// ceremonies; caller-owned source/checkpoint bytes are never mutated.
    pub(crate) fn stage(checkpoint:&VaultEnvelopeCheckpoint,primary:&EnrolledCredential,
        backup:&EnrolledCredential,source_a3:&KekShares<'_>,source_a4:&KekShares<'_>,
        backup_a3:&KekShares<'_>,backup_a4:&KekShares<'_>,context:&VerifiedEnvelopeContext,now:i64)
        ->EnclaveResult<Self> {
        Self::stage_from_selected_member(checkpoint,primary,primary,backup,
            SelectedMemberWrappers::OriginalPrimary,source_a3,source_a4,backup_a3,backup_a4,context,now)
    }

    /// Rewrap the actual selected survivor's complete set, including an
    /// alternate whose PRFs cannot open the original primary wrappers. Return
    /// only a complete encrypted ORIGINAL-primary-to-replacement overlay after
    /// all17 hybrid possessions succeed. All inputs remain unchanged.
    ///
    /// Parent adoption must independently authenticate current membership,
    /// permanent tombstones, receipts and exact-code/release authority, burn
    /// one-use preparation before both fresh factor chains, and publish through
    /// the SAME workflow/fence/readback within its original complete10s. This
    /// pure helper has no store, grant, activation or raw-key export API.
    pub(crate) fn stage_from_selected_member(checkpoint:&VaultEnvelopeCheckpoint,
        original_primary:&EnrolledCredential,selected:&EnrolledCredential,replacement:&EnrolledCredential,
        selected_wrappers:SelectedMemberWrappers<'_>,source_a3:&KekShares<'_>,source_a4:&KekShares<'_>,
        backup_a3:&KekShares<'_>,backup_a4:&KekShares<'_>,context:&VerifiedEnvelopeContext,now:i64)
        ->EnclaveResult<Self> {
        let (primary_credential_sha256,backup_credential_sha256)=distinct(original_primary,replacement)?;
        distinct(selected,replacement)?;
        if ct_eq(source_a3.yubikey_prf,backup_a3.yubikey_prf)||ct_eq(source_a4.yubikey_prf,backup_a4.yubikey_prf)
            ||ct_eq(backup_a3.yubikey_prf,backup_a4.yubikey_prf) {fail!(EACCES,"BACKUP_INDEPENDENT_PRF_REQUIRED");}
        let source=checkpoint.backup_source(context,now)?;
        let (selected_a3,selected_a4)=match selected_wrappers {
            SelectedMemberWrappers::OriginalPrimary=>{
                if credential_id(selected)?!=primary_credential_sha256 {fail!(EACCES,"BACKUP_SELECTED_SOURCE");}
                (&source.a3,&source.a4)
            },
            SelectedMemberWrappers::Alternate(wrappers)=>{
                wrappers.validate_scope(checkpoint,original_primary,selected,context,now)?;
                (&wrappers.a3,&wrappers.a4)
            },
        };
        let a3=selected_a3.iter().map(|key|rewrap_tier::<A3>(key,source_a3,backup_a3,context,source.profile,now))
            .collect::<EnclaveResult<Vec<_>>>()?;
        let a4=rewrap_tier::<A4>(selected_a4,source_a4,backup_a4,context,source.profile,now)?;
        let staged=Self {version:1,profile:source.profile,policy_revision:source.policy_revision,
            policy_digest:source.policy_digest,pool_digest:source.pool_digest,primary_credential_sha256,
            backup_credential_sha256,a3,a4};
        staged.verify(checkpoint,original_primary,replacement,backup_a3,backup_a4,context,now)?;Ok(staged)
    }

    /// Validate a stored candidate against the still-current content-key pool
    /// and fresh backup shares. This never selects or activates the credential.
    pub(crate) fn verify(&self,checkpoint:&VaultEnvelopeCheckpoint,primary:&EnrolledCredential,
        backup:&EnrolledCredential,backup_a3:&KekShares<'_>,backup_a4:&KekShares<'_>,
        context:&VerifiedEnvelopeContext,now:i64)->EnclaveResult<()> {
        if ct_eq(backup_a3.yubikey_prf,backup_a4.yubikey_prf) {fail!(EACCES,"BACKUP_INDEPENDENT_PRF_REQUIRED");}
        self.validate_scope(checkpoint,primary,backup,context,now)?;
        for backup in &self.a3 {verify_tier_wrapping::<A3>(backup,backup_a3)?;}
        verify_tier_wrapping::<A4>(&self.a4,backup_a4)?;Ok(())
    }

    /// Public shape, exact identities and current signed-pool scope only.
    /// This is not membership admission or private-key possession. Live add
    /// still uses verify() for all17 actual hybrid challenges; normal actions
    /// prove the selected tier using that action's fresh authorized factors.
    pub(crate) fn validate_scope(&self,checkpoint:&VaultEnvelopeCheckpoint,primary:&EnrolledCredential,
        backup:&EnrolledCredential,context:&VerifiedEnvelopeContext,now:i64)->EnclaveResult<()> {
        let ids=distinct(primary,backup)?;let source=checkpoint.backup_source(context,now)?;
        if self.version!=1||self.profile!=source.profile||self.policy_revision!=source.policy_revision
            ||self.policy_digest!=source.policy_digest||self.pool_digest!=source.pool_digest
            ||self.primary_credential_sha256!=ids.0||self.backup_credential_sha256!=ids.1
            ||self.a3.len()!=A3_EPOCHS_PER_ENROLLMENT as usize||!same_key(&source.a4,&self.a4) {
            fail!(EACCES,"BACKUP_ENVELOPE_SCOPE");
        }
        for (source,backup) in source.a3.iter().zip(&self.a3) {
            if !same_key(source,backup) {fail!(EACCES,"BACKUP_ENVELOPE_SCOPE");}
            EnvelopeA3::restore(A3Checkpoint {wrapped:backup.clone(),sealed_this_epoch:0})?;
        }
        EnvelopeA4::restore(self.a4.clone())?;Ok(())
    }

    pub(crate) fn public_projection(&self,checkpoint:&VaultEnvelopeCheckpoint,primary:&EnrolledCredential,
        backup:&EnrolledCredential,context:&VerifiedEnvelopeContext,now:i64)->EnclaveResult<BackupProjection> {
        self.validate_scope(checkpoint,primary,backup,context,now)?;
        Ok(BackupProjection {a3:self.a3.clone(),a4:self.a4.clone()})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use enclave_core::secret::SecretKey32;
    use enclave_crypto::hpke_envelope::{EnvelopePolicy,SignedEnvelopePolicy,SealedValue,open,unwrap_tier};
    use ed25519_dalek::{Signer,SigningKey};
    use crate::vault::CustodyVault;
    const SEP3:[u8;32]=[11;32];const SEP4:[u8;32]=[21;32];
    const OLD3:[u8;32]=[12;32];const OLD4:[u8;32]=[22;32];
    const NEW3:[u8;32]=[13;32];const NEW4:[u8;32]=[23;32];
    fn shares<'a>(sep:&'a [u8],prf:&'a [u8])->KekShares<'a> {KekShares {sep_ecdh_share:sep,yubikey_prf:prf}}
    fn context()->VerifiedEnvelopeContext {
        let issuer=SigningKey::from_bytes(&[39;32]);
        let policy=EnvelopePolicy {version:1,revision:2,subject:"fixture-host".into(),namespace:"fixture-data".into(),
            issued_unix:10,expires_unix:100,review_unix:90,owner:"fixture-inventory".into(),profiles:vec![Profile::L2,Profile::L3],
            data_classes:vec!["C3".into(),"C4".into()],purpose:"independent backup fixture".into(),migration:"hybrid-v2 backup wrapping".into(),
            disclosure:None,classical_exception:false};
        let signature=issuer.sign(&policy.signing_message().unwrap()).to_bytes().to_vec();
        SignedEnvelopePolicy {policy,signature}.verify(&issuer.verifying_key(),"fixture-host","fixture-data",20).unwrap()
    }
    fn credential(seed:u8)->EnrolledCredential {
        EnrolledCredential {credential_id:vec![seed;32],key:CredentialKey::Ed25519(SigningKey::from_bytes(&[seed;32]).verifying_key()),
            aaguid:[8;16],firmware_version:crate::ctap::mds::MIN_FW_ED25519}
    }
    fn vault(context:&VerifiedEnvelopeContext)->CustodyVault {
        CustodyVault::enroll_authorized(Profile::L2,&shares(&SEP3,&OLD3),&shares(&SEP4,&OLD4),None,context,SecretKey32::new([31;32]),20).unwrap()
    }
    fn stage(checkpoint:&VaultEnvelopeCheckpoint,context:&VerifiedEnvelopeContext)->EnclaveResult<StagedBackupEnvelopes> {
        StagedBackupEnvelopes::stage(checkpoint,&credential(41),&credential(42),
            &shares(&SEP3,&OLD3),&shares(&SEP4,&OLD4),&shares(&SEP3,&NEW3),&shares(&SEP4,&NEW4),context,20)
    }
    fn verify(staged:&StagedBackupEnvelopes,checkpoint:&VaultEnvelopeCheckpoint,context:&VerifiedEnvelopeContext)->EnclaveResult<()> {
        staged.verify(checkpoint,&credential(41),&credential(42),&shares(&SEP3,&NEW3),&shares(&SEP4,&NEW4),context,20)
    }
    #[test]
    fn complete_backup_opens_existing_ciphertext_and_preserves_primary_and_live_pool() {
        let context=context();let mut vault=vault(&context);
        vault.tokenize("first@example.invalid",None,false,None,20).unwrap();
        let checkpoint=vault.checkpoint().unwrap();let before=serde_json::to_vec(&checkpoint).unwrap();
        let staged=stage(&checkpoint,&context).unwrap();verify(&staged,&checkpoint,&context).unwrap();
        assert_eq!(staged.a3.len(),16);
        let encoded=serde_json::to_value(&checkpoint).unwrap();
        let entry=encoded["store"].as_object().unwrap().values().next().unwrap();
        let sealed:SealedValue=serde_json::from_value(entry["sealed"].clone()).unwrap();
        let aad:Vec<u8>=serde_json::from_value(entry["aad"].clone()).unwrap();
        let key=unwrap_tier::<A3>(&staged.a3[sealed.epoch as usize],&shares(&SEP3,&NEW3)).unwrap();
        assert_eq!(open(&key,&sealed,&aad).unwrap().expose(),b"first@example.invalid");
        assert!(unwrap_tier::<A3>(&staged.a3[0],&shares(&SEP3,&OLD3)).is_err());
        checkpoint.verify_factor_shares(&shares(&SEP3,&OLD3),&shares(&SEP4,&OLD4)).unwrap();
        assert_eq!(serde_json::to_vec(&checkpoint).unwrap(),before,"staging does not change any wrapper/count/session/ciphertext/surrogate");
        vault.tokenize("second@example.invalid",None,false,None,20).unwrap();
        let later=vault.checkpoint().unwrap();assert_ne!(serde_json::to_vec(&later).unwrap(),before);
        verify(&staged,&later,&context).unwrap();
        assert_eq!(later.backup_source(&context,20).unwrap().pool_digest,staged.pool_digest,"ordinary ciphertext/count growth does not change content-key identity");
    }
    #[test]
    fn backup_refuses_duplicate_alias_wrong_identity_mixed_pool_and_partial_epoch_sets() {
        let context=context();let checkpoint=vault(&context).checkpoint().unwrap();let primary=credential(41);
        for mut duplicate in [credential(42),primary.clone()] {
            if duplicate.credential_id!=primary.credential_id {duplicate.credential_id=primary.credential_id.clone();}
            else {duplicate.credential_id=vec![45;32];}
            assert!(StagedBackupEnvelopes::stage(&checkpoint,&primary,&duplicate,
                &shares(&SEP3,&OLD3),&shares(&SEP4,&OLD4),&shares(&SEP3,&NEW3),&shares(&SEP4,&NEW4),&context,20)
                .unwrap_err().is("BACKUP_DISTINCT_CREDENTIAL_REQUIRED"));
        }
        let staged=stage(&checkpoint,&context).unwrap();
        assert!(staged.verify(&checkpoint,&primary,&credential(43),&shares(&SEP3,&NEW3),&shares(&SEP4,&NEW4),&context,20).is_err());
        let mut changed=staged.clone();changed.a3.pop();assert!(verify(&changed,&checkpoint,&context).is_err());
        changed=staged.clone();changed.a3.swap(0,1);assert!(verify(&changed,&checkpoint,&context).is_err());
        changed=staged.clone();changed.a3[1]=changed.a3[0].clone();assert!(verify(&changed,&checkpoint,&context).is_err());
        let other=vault(&context).checkpoint().unwrap();assert!(verify(&staged,&other,&context).is_err());
    }
    #[test]
    fn late_source_failure_wrong_shares_expiry_and_reused_prf_return_no_partial_backup() {
        let context=context();let checkpoint=vault(&context).checkpoint().unwrap();
        let mut value=serde_json::to_value(&checkpoint).unwrap();let byte=value["a4"]["ct"][0].as_u64().unwrap();value["a4"]["ct"][0]=serde_json::json!(byte^1);
        let damaged:VaultEnvelopeCheckpoint=serde_json::from_value(value).unwrap();let before=serde_json::to_vec(&damaged).unwrap();
        assert!(stage(&damaged,&context).is_err(),"a failure after all16A3 wrappers yields no complete candidate");
        assert_eq!(serde_json::to_vec(&damaged).unwrap(),before);
        let staged=stage(&checkpoint,&context).unwrap();
        assert!(staged.verify(&checkpoint,&credential(41),&credential(42),&shares(&SEP3,&OLD3),&shares(&SEP4,&NEW4),&context,20).is_err());
        assert!(staged.verify(&checkpoint,&credential(41),&credential(42),&shares(&SEP3,&NEW3),&shares(&SEP4,&NEW4),&context,90).is_err());
        assert!(StagedBackupEnvelopes::stage(&checkpoint,&credential(41),&credential(42),
            &shares(&SEP3,&OLD3),&shares(&SEP4,&OLD4),&shares(&SEP3,&OLD3),&shares(&SEP4,&NEW4),&context,20)
            .unwrap_err().is("BACKUP_INDEPENDENT_PRF_REQUIRED"));
    }
    #[test]
    fn public_scope_checks_complete_wire_shape_but_never_claims_private_possession() {
        let context=context();let checkpoint=vault(&context).checkpoint().unwrap();let staged=stage(&checkpoint,&context).unwrap();
        staged.validate_scope(&checkpoint,&credential(41),&credential(42),&context,20).unwrap();
        for malformed in 0..4 {
            let mut changed=staged.clone();
            match malformed {0=>{changed.a3[15].ct.pop();},1=>{changed.a4.nonce.pop();},
                2=>{changed.a3.swap(0,1);},_=>{changed.a4.public_key[0]^=1;}}
            assert!(changed.validate_scope(&checkpoint,&credential(41),&credential(42),&context,20).is_err());
        }
        let mut encrypted_corruption=staged.clone();encrypted_corruption.a4.ct[0]^=1;
        encrypted_corruption.validate_scope(&checkpoint,&credential(41),&credential(42),&context,20).unwrap();
        assert!(verify(&encrypted_corruption,&checkpoint,&context).is_err(),
            "public shape at boot cannot substitute for existing all17 private possession challenges");
        assert!(staged.public_projection(&checkpoint,&credential(41),&credential(43),&context,20).is_err());
    }

    const REPLACEMENT3:[u8;32]=[14;32];const REPLACEMENT4:[u8;32]=[24;32];
    fn from_alternate(checkpoint:&VaultEnvelopeCheckpoint,selected:u8,replacement:u8,
        wrappers:&StagedBackupEnvelopes,source:(&[u8],&[u8]),target:(&[u8],&[u8]),
        context:&VerifiedEnvelopeContext)->EnclaveResult<StagedBackupEnvelopes> {
        StagedBackupEnvelopes::stage_from_selected_member(checkpoint,&credential(41),&credential(selected),
            &credential(replacement),SelectedMemberWrappers::Alternate(wrappers),
            &shares(&SEP3,source.0),&shares(&SEP4,source.1),
            &shares(&SEP3,target.0),&shares(&SEP4,target.1),context,20)
    }

    #[test]
    fn backup_survivor_rewraps_all17_without_original_prfs_or_changing_origin_or_content() {
        let context=context();let mut vault=vault(&context);
        vault.tokenize("survivor@example.invalid",None,false,None,20).unwrap();
        let checkpoint=vault.checkpoint().unwrap();let before=serde_json::to_vec(&checkpoint).unwrap();
        let survivor=stage(&checkpoint,&context).unwrap();let survivor_before=serde_json::to_vec(&survivor).unwrap();
        assert!(StagedBackupEnvelopes::stage(&checkpoint,&credential(41),&credential(43),
            &shares(&SEP3,&NEW3),&shares(&SEP4,&NEW4),&shares(&SEP3,&REPLACEMENT3),
            &shares(&SEP4,&REPLACEMENT4),&context,20).is_err(),"backup factors cannot open original wrappers");
        let replacement=from_alternate(&checkpoint,42,43,&survivor,(&NEW3,&NEW4),
            (&REPLACEMENT3,&REPLACEMENT4),&context).unwrap();
        replacement.verify(&checkpoint,&credential(41),&credential(43),
            &shares(&SEP3,&REPLACEMENT3),&shares(&SEP4,&REPLACEMENT4),&context,20).unwrap();
        assert_eq!(replacement.a3.len(),16);
        assert_eq!(replacement.primary_credential_sha256,survivor.primary_credential_sha256);
        assert_eq!(replacement.pool_digest,survivor.pool_digest);
        let encoded=serde_json::to_value(&checkpoint).unwrap();
        let entry=encoded["store"].as_object().unwrap().values().next().unwrap();
        let sealed:SealedValue=serde_json::from_value(entry["sealed"].clone()).unwrap();
        let aad:Vec<u8>=serde_json::from_value(entry["aad"].clone()).unwrap();
        let key=unwrap_tier::<A3>(&replacement.a3[sealed.epoch as usize],&shares(&SEP3,&REPLACEMENT3)).unwrap();
        assert_eq!(open(&key,&sealed,&aad).unwrap().expose(),b"survivor@example.invalid");
        assert!(unwrap_tier::<A4>(&replacement.a4,&shares(&SEP4,&NEW4)).is_err());
        assert_eq!(serde_json::to_vec(&checkpoint).unwrap(),before);
        assert_eq!(serde_json::to_vec(&survivor).unwrap(),survivor_before);
        checkpoint.verify_factor_shares(&shares(&SEP3,&OLD3),&shares(&SEP4,&OLD4)).unwrap();
        verify(&survivor,&checkpoint,&context).unwrap();
    }

    #[test]
    fn selected_source_never_relabels_an_alternate_or_accepts_wrong_spare_or_origin() {
        let context=context();let checkpoint=vault(&context).checkpoint().unwrap();let survivor=stage(&checkpoint,&context).unwrap();
        let attempt=|selected:&EnrolledCredential,selector|StagedBackupEnvelopes::stage_from_selected_member(
            &checkpoint,&credential(41),selected,&credential(43),selector,
            &shares(&SEP3,&OLD3),&shares(&SEP4,&OLD4),&shares(&SEP3,&REPLACEMENT3),
            &shares(&SEP4,&REPLACEMENT4),&context,20);
        assert!(attempt(&credential(42),SelectedMemberWrappers::OriginalPrimary).unwrap_err().is("BACKUP_SELECTED_SOURCE"));
        let mut metadata_alias=credential(41);metadata_alias.firmware_version+=1;
        assert!(attempt(&metadata_alias,SelectedMemberWrappers::OriginalPrimary).unwrap_err().is("BACKUP_SELECTED_SOURCE"));
        assert!(attempt(&credential(44),SelectedMemberWrappers::Alternate(&survivor)).is_err());
        assert!(attempt(&credential(41),SelectedMemberWrappers::Alternate(&survivor)).is_err());
        let other=vault(&context).checkpoint().unwrap();
        assert!(from_alternate(&other,42,43,&survivor,(&NEW3,&NEW4),(&REPLACEMENT3,&REPLACEMENT4),&context).is_err());
        let replacement=attempt(&credential(41),SelectedMemberWrappers::OriginalPrimary).unwrap();
        replacement.verify(&checkpoint,&credential(41),&credential(43),
            &shares(&SEP3,&REPLACEMENT3),&shares(&SEP4,&REPLACEMENT4),&context,20).unwrap();
    }

    #[test]
    fn selected_survivor_late_a4_failure_wrong_factors_and_partial_sets_return_no_candidate() {
        let context=context();let checkpoint=vault(&context).checkpoint().unwrap();let survivor=stage(&checkpoint,&context).unwrap();
        for failure in 0..5 {
            let mut damaged=survivor.clone();
            match failure {0=>damaged.a4.ct[0]^=1,1=>damaged.a3[15].ct[0]^=1,
                2=>{damaged.a3.pop();},3=>damaged.a3.swap(0,1),_=>{damaged.a4.nonce.pop();}}
            let before=serde_json::to_vec(&damaged).unwrap();
            assert!(from_alternate(&checkpoint,42,43,&damaged,(&NEW3,&NEW4),
                (&REPLACEMENT3,&REPLACEMENT4),&context).is_err());
            assert_eq!(serde_json::to_vec(&damaged).unwrap(),before);
        }
        assert!(from_alternate(&checkpoint,42,43,&survivor,(&OLD3,&NEW4),
            (&REPLACEMENT3,&REPLACEMENT4),&context).is_err());
        assert!(from_alternate(&checkpoint,42,43,&survivor,(&NEW3,&OLD4),
            (&REPLACEMENT3,&REPLACEMENT4),&context).is_err());
        assert!(from_alternate(&checkpoint,42,43,&survivor,(&NEW3,&NEW4),
            (&NEW3,&REPLACEMENT4),&context).unwrap_err().is("BACKUP_INDEPENDENT_PRF_REQUIRED"));
    }

    #[test]
    fn selected_survivor_rejects_replacement_credential_and_key_aliases_and_expiry() {
        let context=context();let checkpoint=vault(&context).checkpoint().unwrap();let survivor=stage(&checkpoint,&context).unwrap();
        for member in [credential(41),credential(42)] {
            for same_id in [true,false] {
                let mut replacement=credential(43);
                if same_id {replacement.credential_id=member.credential_id.clone();}else{replacement.key=member.key.clone();}
                assert!(StagedBackupEnvelopes::stage_from_selected_member(&checkpoint,&credential(41),&credential(42),
                    &replacement,SelectedMemberWrappers::Alternate(&survivor),&shares(&SEP3,&NEW3),&shares(&SEP4,&NEW4),
                    &shares(&SEP3,&REPLACEMENT3),&shares(&SEP4,&REPLACEMENT4),&context,20)
                    .unwrap_err().is("BACKUP_DISTINCT_CREDENTIAL_REQUIRED"));
            }
        }
        assert!(StagedBackupEnvelopes::stage_from_selected_member(&checkpoint,&credential(41),&credential(42),
            &credential(43),SelectedMemberWrappers::Alternate(&survivor),&shares(&SEP3,&NEW3),&shares(&SEP4,&NEW4),
            &shares(&SEP3,&REPLACEMENT3),&shares(&SEP4,&REPLACEMENT4),&context,90).is_err());
    }

    #[test]
    fn repeated_encrypted_overlays_keep_original_primary_and_stable_pool_scope() {
        let context=context();let mut vault=vault(&context);let checkpoint=vault.checkpoint().unwrap();
        let survivor=stage(&checkpoint,&context).unwrap();
        let replacement=from_alternate(&checkpoint,42,43,&survivor,(&NEW3,&NEW4),
            (&REPLACEMENT3,&REPLACEMENT4),&context).unwrap();
        vault.tokenize("later@example.invalid",None,false,None,20).unwrap();let later=vault.checkpoint().unwrap();
        let next3=[15;32];let next4=[25;32];
        let next=from_alternate(&later,43,44,&replacement,(&REPLACEMENT3,&REPLACEMENT4),(&next3,&next4),&context).unwrap();
        next.verify(&later,&credential(41),&credential(44),&shares(&SEP3,&next3),&shares(&SEP4,&next4),&context,20).unwrap();
        assert_eq!(next.primary_credential_sha256,survivor.primary_credential_sha256);
        assert_eq!(next.pool_digest,survivor.pool_digest);
        assert!(next.validate_scope(&later,&credential(43),&credential(44),&context,20).is_err(),
            "current survivor never becomes immutable original primary");
        // These encrypted facts alone cannot deny the lost key; parent
        // retirement/current admission remains mandatory for every use.
        checkpoint.verify_factor_shares(&shares(&SEP3,&OLD3),&shares(&SEP4,&OLD4)).unwrap();
    }
}
