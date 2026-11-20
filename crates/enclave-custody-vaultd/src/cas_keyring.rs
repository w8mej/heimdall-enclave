//! Durable operator-controlled namespace keyring. Only opaque envelopes persist.
use std::{collections::BTreeMap,path::Path};
use enclave_core::{err,fail,error::EnclaveResult,sealed::{SealedStore,Loaded}};
use enclave_crypto::namespace::WrappedNamespaceKey;
use serde::{Serialize,Deserialize};
use crate::namespace_capsule::NamespaceKekCapsule;
const MAXIMUM:usize=8*1024*1024;
// SealedStore persists an escaped JSON body plus its fixed v/domain/generation/
// MAC fields. Reserve more than that metadata's maximum encoded length; do not
// admit a raw body that becomes unreadable after outer-envelope escaping.
const SEALED_METADATA_RESERVE:usize=1024;
#[derive(Clone,Copy,Default,PartialEq,Eq,Serialize,Deserialize)]
enum CapsuleMode {#[default] LegacyDirect,Required}
fn legacy_mode(mode:&CapsuleMode)->bool {*mode==CapsuleMode::LegacyDirect}
#[derive(Clone,Default,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct RingState {namespaces:BTreeMap<String,Ring>}
#[derive(Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
struct Ring {
    minimum_wrapping_epoch:u64,keys:BTreeMap<u64,WrappedNamespaceKey>,
    #[serde(default,skip_serializing_if="legacy_mode")]
    capsule_mode:CapsuleMode,
    #[serde(default,skip_serializing_if="BTreeMap::is_empty")]
    capsules:BTreeMap<u64,NamespaceKekCapsule>,
}

/// This is a storage mode, never admission. A committed membership must refuse
/// LegacyDirect and require explicit original-primary migration instead.
#[derive(Debug)]
pub(crate) enum NamespaceCapsuleAccess<'a> {LegacyDirect,Required(&'a NamespaceKekCapsule)}
pub(crate) struct CasKeyring {store:Option<SealedStore>,state:RingState,poisoned:bool}
impl CasKeyring {
    pub(crate) fn open(directory:Option<&Path>)->EnclaveResult<Self> {
        let (store,state)=match directory {
            None=>(None,RingState::default()),
            Some(directory)=>{let (store,state)=Self::open_persistent(directory)?;(Some(store),state)},
        };
        Self::validate(&state)?;Ok(Self{store,state,poisoned:false})
    }
    fn present(path:&Path)->EnclaveResult<bool> {
        match std::fs::symlink_metadata(path){Ok(_)=>Ok(true),Err(error) if error.kind()==std::io::ErrorKind::NotFound=>Ok(false),Err(error)=>Err(err!(EIO,"CAS_KEYRING_PATH","{error}"))}
    }
    fn open_persistent(directory:&Path)->EnclaveResult<(SealedStore,RingState)> {
        const NAME:&str="cas-namespace-keyring";
        let child=directory.join(NAME);
        let child_existed=Self::present(&child)?;
        // Never fall back to an older shared-directory ring once the child
        // exists. Even an empty preexisting child is incomplete authority.
        let initial=if child_existed{None}else{
            let marker="cas-namespace-keyring-migration";
            if Self::present(&directory.join(format!("{marker}.sealed")))?||Self::present(&directory.join(format!("{marker}.gen")))?{fail!(EACCES,"CAS_KEYRING_MIGRATION_INCOMPLETE");}
            if Self::present(&directory.join(format!("{NAME}.sealed")))?||Self::present(&directory.join(format!("{NAME}.gen")))?{
                let (_,loaded)=SealedStore::open_bounded(directory,NAME,MAXIMUM)?;
                let Loaded::State(bytes)=loaded else{fail!(EACCES,"CAS_KEYRING_MIGRATION_STATE");};
                let state=enclave_core::sealed::decode::<RingState>(&bytes)?;Self::validate(&state)?;
                // Persist intent before creating the new ring. A lost child
                // must not replay stale legacy envelopes after a later floor
                // increase. Partial migration refuses for operator recovery.
                let (mut guard,loaded)=SealedStore::open_bounded(directory,marker,4096)?;
                if !matches!(loaded,Loaded::Fresh){fail!(EACCES,"CAS_KEYRING_MIGRATION_INCOMPLETE");}
                guard.save_json(&serde_json::json!({"v":1,"destination":NAME}))?;
                Some(state)
            }else{None}
        };
        let (mut store,loaded)=SealedStore::open_bounded_required(&child,NAME,MAXIMUM)?;
        let state=match loaded{
            Loaded::Fresh=>{
                if child_existed{fail!(EACCES,"STATE_MISSING");}
                let state=initial.unwrap_or_default();store.save_json(&state)?;state
            },
            Loaded::State(bytes)=>enclave_core::sealed::decode::<RingState>(&bytes)?,
        };
        Self::validate(&state)?;Ok((store,state))
    }
    fn validate(state:&RingState)->EnclaveResult<()> {
        if state.namespaces.len()>64 {fail!(E2BIG,"CAS_KEYRING_LIMIT");}
        for (namespace,ring) in &state.namespaces {
            if ring.minimum_wrapping_epoch==0||ring.keys.is_empty()||ring.keys.len()>64 {fail!(EACCES,"CAS_KEYRING_STATE");}
            match ring.capsule_mode {
                CapsuleMode::LegacyDirect=>if !ring.capsules.is_empty(){fail!(EACCES,"CAS_KEYRING_CAPSULE_STATE");},
                CapsuleMode::Required=>if ring.capsules.len()!=ring.keys.len(){fail!(EACCES,"CAS_KEYRING_CAPSULE_STATE");},
            }
            for (epoch,key) in &ring.keys {
                key.validate()?;if key.namespace!=*namespace||key.epoch!=*epoch||key.wrapping_epoch<ring.minimum_wrapping_epoch{fail!(EACCES,"CAS_KEYRING_STATE");}
                if ring.capsule_mode==CapsuleMode::Required {
                    ring.capsules.get(epoch).ok_or_else(||err!(EACCES,"CAS_KEYRING_CAPSULE_STATE"))?.validate_canonical(key)?;
                }
            }
        }
        // Bound the exact escaped body plus conservative fixed sealed metadata
        // against the SAME reader limit, before any sealed-store write.
        let body=serde_json::to_string(state).map_err(|_|err!(EIO,"CAS_KEYRING_ENCODE"))?;
        if serde_json::to_vec(&body).map_err(|_|err!(EIO,"CAS_KEYRING_ENCODE"))?.len()>MAXIMUM-SEALED_METADATA_RESERVE {fail!(E2BIG,"CAS_KEYRING_SIZE");}
        Ok(())
    }
    fn save(&mut self,state:RingState)->EnclaveResult<()> {
        self.healthy()?;Self::validate(&state)?;
        if let Some(store)=&mut self.store{if let Err(error)=store.save_json(&state){self.poisoned=true;return Err(error);}}
        self.state=state;Ok(())
    }
    fn healthy(&self)->EnclaveResult<()> {if self.poisoned{fail!(EACCES,"CAS_KEYRING_POISONED");}Ok(())}
    pub(crate) fn poisoned(&self)->bool {self.poisoned}
    pub(crate) fn verify(&self,key:&WrappedNamespaceKey)->EnclaveResult<()> {
        self.healthy()?;key.validate()?;let ring=self.state.namespaces.get(&key.namespace).ok_or_else(||err!(EACCES,"CAS_KEY_NOT_REGISTERED"))?;
        if key.wrapping_epoch<ring.minimum_wrapping_epoch||ring.keys.get(&key.epoch)!=Some(key){fail!(EACCES,"CAS_KEY_AUTHORITY_RETIRED");}Ok(())
    }
    /// Exact sorted full history for one trusted intent/migration candidate.
    /// The commit rechecks the entire vector, including every canonical byte.
    pub(crate) fn namespace_snapshot(&self,namespace:&str)->EnclaveResult<Vec<WrappedNamespaceKey>> {
        self.healthy()?;
        let ring=self.state.namespaces.get(namespace).ok_or_else(||err!(EACCES,"CAS_KEY_NOT_REGISTERED"))?;
        Ok(ring.keys.values().cloned().collect())
    }
    pub(crate) fn capsule_access(&self,key:&WrappedNamespaceKey)->EnclaveResult<NamespaceCapsuleAccess<'_>> {
        self.verify(key)?;
        let ring=&self.state.namespaces[&key.namespace];
        match ring.capsule_mode {
            CapsuleMode::LegacyDirect=>Ok(NamespaceCapsuleAccess::LegacyDirect),
            CapsuleMode::Required=>{
                let capsule=ring.capsules.get(&key.epoch).ok_or_else(||err!(EACCES,"CAS_KEYRING_CAPSULE_REQUIRED"))?;
                capsule.validate_canonical(key)?;Ok(NamespaceCapsuleAccess::Required(capsule))
            }
        }
    }
    fn insert_key(ring:&mut Ring,key:WrappedNamespaceKey,replace:bool)->EnclaveResult<()> {
        if key.wrapping_epoch<ring.minimum_wrapping_epoch{fail!(EACCES,"CAS_KEY_AUTHORITY_RETIRED");}
        if let Some(previous)=ring.keys.get(&key.epoch){if !replace{fail!(EALREADY,"CAS_KEY_EPOCH_EXISTS");}if key.wrapping_epoch<=previous.wrapping_epoch{fail!(EACCES,"CAS_KEY_ROTATION_ROLLBACK");}}
        else if replace{fail!(EACCES,"CAS_KEY_NOT_REGISTERED");}
        ring.keys.insert(key.epoch,key);Ok(())
    }
    pub(crate) fn register(&mut self,key:WrappedNamespaceKey,replace:bool)->EnclaveResult<()> {
        self.healthy()?;key.validate()?;let mut state=self.state.clone();let ring=state.namespaces.entry(key.namespace.clone())
            .or_insert_with(||Ring{minimum_wrapping_epoch:key.wrapping_epoch,keys:BTreeMap::new(),capsule_mode:CapsuleMode::LegacyDirect,capsules:BTreeMap::new()});
        if ring.capsule_mode==CapsuleMode::Required {fail!(EACCES,"CAS_KEYRING_CAPSULE_REQUIRED");}
        Self::insert_key(ring,key,replace)?;self.save(state)
    }
    /// ONE save contains canonical envelope and its encrypted KEK capsule.
    /// Existing direct-only history must first migrate in full. A new namespace
    /// starts Required immediately and can never use register() to downgrade.
    pub(crate) fn register_with_capsule(&mut self,key:WrappedNamespaceKey,capsule:NamespaceKekCapsule,replace:bool)->EnclaveResult<()> {
        self.healthy()?;key.validate()?;capsule.validate_canonical(&key)?;
        let mut state=self.state.clone();let ring=state.namespaces.entry(key.namespace.clone())
            .or_insert_with(||Ring{minimum_wrapping_epoch:key.wrapping_epoch,keys:BTreeMap::new(),capsule_mode:CapsuleMode::Required,capsules:BTreeMap::new()});
        if ring.capsule_mode!=CapsuleMode::Required {fail!(EACCES,"NAMESPACE_BACKUP_MIGRATION_REQUIRED");}
        let epoch=key.epoch;Self::insert_key(ring,key,replace)?;ring.capsules.insert(epoch,capsule);self.save(state)
    }
    /// All exact registered historical envelopes participate or nothing is
    /// published. Parent has already validated each capsule's CURRENT vault
    /// scope and fresh original-primary factors/window/fence, and must recheck
    /// those after this save. This method checks storage coverage, not factors.
    pub(crate) fn migrate_namespace(&mut self,namespace:&str,expected_sorted:&[WrappedNamespaceKey],capsules:Vec<NamespaceKekCapsule>)->EnclaveResult<()> {
        self.healthy()?;
        if expected_sorted.is_empty()||expected_sorted.len()>64||capsules.len()!=expected_sorted.len() {fail!(EACCES,"CAS_KEYRING_MIGRATION_COVERAGE");}
        let mut state=self.state.clone();let ring=state.namespaces.get_mut(namespace).ok_or_else(||err!(EACCES,"CAS_KEY_NOT_REGISTERED"))?;
        if !ring.keys.values().eq(expected_sorted.iter()) {fail!(ESTALE,"CAS_KEYRING_REFERENCE_CHANGED");}
        if ring.capsule_mode!=CapsuleMode::LegacyDirect {fail!(EALREADY,"CAS_KEYRING_ALREADY_MIGRATED");}
        let mut next=BTreeMap::new();
        for (key,capsule) in expected_sorted.iter().zip(capsules) {capsule.validate_canonical(key)?;next.insert(key.epoch,capsule);}
        ring.capsule_mode=CapsuleMode::Required;ring.capsules=next;self.save(state)
    }
    pub(crate) fn advance_floor(&mut self,namespace:&str,minimum:u64)->EnclaveResult<()> {
        self.healthy()?;let mut state=self.state.clone();let ring=state.namespaces.get_mut(namespace).ok_or_else(||err!(EACCES,"CAS_KEY_NOT_REGISTERED"))?;
        if minimum<ring.minimum_wrapping_epoch||minimum==0{fail!(EACCES,"CAS_KEY_ROTATION_ROLLBACK");}
        if ring.keys.values().any(|key|key.wrapping_epoch<minimum){fail!(EACCES,"CAS_KEYRING_REWRAP_REQUIRED");}
        ring.minimum_wrapping_epoch=minimum;self.save(state)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn wrapped(epoch:u64,wrapping:u64)->WrappedNamespaceKey {WrappedNamespaceKey{namespace:"models".into(),epoch,wrapping_epoch:wrapping,envelope_hex:"00".repeat(72)}}
    #[test]
    fn f38_keyring_offboarding_requires_all_historical_envelopes_and_survives_restart() {
        let directory=std::env::temp_dir().canonicalize().unwrap().join(format!("mc-keyring-{:x}",enclave_core::rng::u64()));std::os::unix::fs::DirBuilderExt::mode(&mut std::fs::DirBuilder::new(),0o700).create(&directory).unwrap();
        {let mut ring=CasKeyring::open(Some(&directory)).unwrap();ring.register(wrapped(1,1),false).unwrap();ring.register(wrapped(2,1),false).unwrap();assert!(ring.advance_floor("models",2).unwrap_err().is("CAS_KEYRING_REWRAP_REQUIRED"));ring.register(wrapped(1,2),true).unwrap();assert!(ring.verify(&wrapped(1,1)).is_err());assert!(ring.advance_floor("models",2).is_err());ring.register(wrapped(2,2),true).unwrap();ring.advance_floor("models",2).unwrap();}
        {let mut ring=CasKeyring::open(Some(&directory)).unwrap();ring.verify(&wrapped(1,2)).unwrap();ring.verify(&wrapped(2,2)).unwrap();assert!(ring.verify(&wrapped(1,1)).is_err());assert!(ring.advance_floor("models",1).is_err());assert!(ring.register(wrapped(3,1),false).is_err());}
        std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn f38_keyring_partial_persistence_poison_denies_previous_authority_until_restart() {
        use std::os::unix::fs::DirBuilderExt;
        let directory=std::env::temp_dir().canonicalize().unwrap().join(format!("mc-keyring-{:x}",enclave_core::rng::u64()));std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let mut ring=CasKeyring::open(Some(&directory)).unwrap();ring.register(wrapped(1,1),false).unwrap();
        // Private fixture: prevent only the second rename. No host service,
        // filesystem fault injection, or mount is involved.
        let checkpoint=directory.join("cas-namespace-keyring/cas-namespace-keyring.gen");std::fs::remove_file(&checkpoint).unwrap();std::fs::create_dir(&checkpoint).unwrap();
        assert!(ring.register(wrapped(1,2),true).is_err());assert!(ring.poisoned());
        assert!(ring.verify(&wrapped(1,1)).unwrap_err().is("CAS_KEYRING_POISONED"));assert!(ring.register(wrapped(2,1),false).unwrap_err().is("CAS_KEYRING_POISONED"));
        assert!(CasKeyring::open(Some(&directory)).is_err());std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn f38_keyring_deleted_or_tampered_state_never_becomes_an_empty_keyring() {
        for damage in ["deleted","tampered","both-deleted"]{let directory=std::env::temp_dir().canonicalize().unwrap().join(format!("mc-keyring-{:x}",enclave_core::rng::u64()));std::os::unix::fs::DirBuilderExt::mode(&mut std::fs::DirBuilder::new(),0o700).create(&directory).unwrap();{let mut ring=CasKeyring::open(Some(&directory)).unwrap();ring.register(wrapped(1,1),false).unwrap();}let state=directory.join("cas-namespace-keyring/cas-namespace-keyring.sealed");if damage=="tampered"{std::fs::write(state,b"invalid").unwrap();}else{std::fs::remove_file(state).unwrap();if damage=="both-deleted"{std::fs::remove_file(directory.join("cas-namespace-keyring/cas-namespace-keyring.gen")).unwrap();}}assert!(CasKeyring::open(Some(&directory)).is_err(),"{damage}");std::fs::remove_dir_all(directory).unwrap();}
    }
    #[test]
    fn f38_keyring_legacy_migration_preserves_history_and_never_replays_stale_legacy() {
        use std::os::unix::fs::DirBuilderExt;
        let directory=std::env::temp_dir().canonicalize().unwrap().join(format!("mc-keyring-{:x}",enclave_core::rng::u64()));std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let state=RingState{namespaces:BTreeMap::from([("models".into(),Ring{minimum_wrapping_epoch:2,keys:BTreeMap::from([(1,wrapped(1,2)),(2,wrapped(2,2))]),capsule_mode:CapsuleMode::LegacyDirect,capsules:BTreeMap::new()})])};
        let (mut legacy,_)=SealedStore::open_bounded(&directory,"cas-namespace-keyring",8*1024*1024).unwrap();legacy.save_json(&state).unwrap();drop(legacy);
        let original=std::fs::read(directory.join("cas-namespace-keyring.sealed")).unwrap();let seed=std::fs::read(directory.join("sealing.key")).unwrap();
        {let mut ring=CasKeyring::open(Some(&directory)).unwrap();ring.verify(&wrapped(1,2)).unwrap();ring.verify(&wrapped(2,2)).unwrap();assert!(ring.register(wrapped(3,1),false).is_err());assert!(ring.advance_floor("models",1).is_err());ring.register(wrapped(1,3),true).unwrap();ring.register(wrapped(2,3),true).unwrap();ring.advance_floor("models",3).unwrap();}
        {let ring=CasKeyring::open(Some(&directory)).unwrap();ring.verify(&wrapped(1,3)).unwrap();ring.verify(&wrapped(2,3)).unwrap();assert!(ring.verify(&wrapped(1,2)).is_err());}
        assert_eq!(original,std::fs::read(directory.join("cas-namespace-keyring.sealed")).unwrap());assert_eq!(seed,std::fs::read(directory.join("sealing.key")).unwrap());
        std::fs::remove_dir_all(directory.join("cas-namespace-keyring")).unwrap();assert!(matches!(CasKeyring::open(Some(&directory)),Err(error) if error.is("CAS_KEYRING_MIGRATION_INCOMPLETE")));std::fs::remove_dir_all(directory).unwrap();
    }
    #[test]
    fn f38_keyring_legacy_damage_or_incomplete_child_refuses_migration() {
        use std::os::unix::fs::DirBuilderExt;
        for damage in ["state","checkpoint","seed","child"]{
            let directory=std::env::temp_dir().canonicalize().unwrap().join(format!("mc-keyring-{:x}",enclave_core::rng::u64()));std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
            let (mut legacy,_)=SealedStore::open_bounded(&directory,"cas-namespace-keyring",8*1024*1024).unwrap();legacy.save_json(&RingState::default()).unwrap();drop(legacy);
            match damage{"state"=>std::fs::write(directory.join("cas-namespace-keyring.sealed"),b"invalid").unwrap(),"checkpoint"=>std::fs::remove_file(directory.join("cas-namespace-keyring.gen")).unwrap(),"seed"=>std::fs::remove_file(directory.join("sealing.key")).unwrap(),"child"=>std::fs::DirBuilder::new().mode(0o700).create(directory.join("cas-namespace-keyring")).unwrap(),_=>unreachable!()}
            assert!(CasKeyring::open(Some(&directory)).is_err(),"{damage}");std::fs::remove_dir_all(directory).unwrap();
        }
    }
}

#[cfg(test)]
mod capsule_tests {
    use super::*;
    use crate::namespace_capsule::NamespaceCapsuleScope;
    use ed25519_dalek::{Signer,SigningKey};
    use enclave_core::{profile::Profile,secret::SecretKey32};
    use enclave_crypto::{namespace,hpke_envelope::{A4,EnvelopeA4,EnvelopePolicy,
        SignedEnvelopePolicy,VerifiedEnvelopeContext,KekShares,rewrap_tier,unwrap_tier}};
    use sha2::{Digest,Sha256};
    const SEP:[u8;32]=[11;32];
    const PRIMARY:[u8;32]=[12;32];
    const BACKUP:[u8;32]=[13;32];
    fn shares(prf:&[u8;32])->KekShares<'_> {KekShares{sep_ecdh_share:&SEP,yubikey_prf:prf}}
    struct Fixture {context:VerifiedEnvelopeContext,public:EnvelopeA4,scope:NamespaceCapsuleScope}
    impl Fixture {
        fn new()->Self {
            let signer=SigningKey::from_bytes(&[39;32]);
            let policy=EnvelopePolicy{version:1,revision:2,subject:"fixture-host".into(),namespace:"fixture-data".into(),
                issued_unix:1,expires_unix:100,review_unix:90,owner:"fixture-owner".into(),profiles:vec![Profile::L2],
                data_classes:vec!["C3".into(),"C4".into()],purpose:"synthetic namespace keyring fixture".into(),
                migration:"reviewed successor".into(),disclosure:None,classical_exception:false};
            let signature=signer.sign(&policy.signing_message().unwrap()).to_bytes().to_vec();
            let context=SignedEnvelopePolicy{policy,signature}.verify(&signer.verifying_key(),"fixture-host","fixture-data",20).unwrap();
            let public=EnvelopeA4::new_bound(0,&shares(&PRIMARY),&context).unwrap();
            let scope=NamespaceCapsuleScope{profile:Profile::L2,policy_revision:context.revision(),policy_digest:context.digest(),
                source_binding:[255;32],pool_digest:[254;32],a4_public_sha256:Sha256::digest(&public.wrapped().public_key).into()};
            Self{context,public,scope}
        }
        fn pair(&self,namespace:&str,epoch:u64,wrapping:u64,prf:&[u8;32])->(WrappedNamespaceKey,NamespaceKekCapsule) {
            let kek=namespace::custody_kek(&SEP,prf,namespace,wrapping).unwrap();
            let key=namespace::wrap(namespace,epoch,wrapping,&[epoch as u8;32],&kek).unwrap();
            let capsule=NamespaceKekCapsule::seal_checked(&self.public,&self.scope,&key,&kek,&self.context,20).unwrap();
            (key,capsule)
        }
        fn read(&self,ring:&CasKeyring,key:&WrappedNamespaceKey,prf:&[u8;32])->SecretKey32 {
            let selected=rewrap_tier::<A4>(self.public.wrapped(),&shares(&PRIMARY),&shares(prf),&self.context,Profile::L2,20).unwrap();
            let private=unwrap_tier::<A4>(&selected,&shares(prf)).unwrap();
            let NamespaceCapsuleAccess::Required(capsule)=ring.capsule_access(key).unwrap() else {panic!("capsule required")};
            capsule.open_checked(&private,&self.scope,key,&self.context,20).unwrap()
        }
    }
    struct Directory(std::path::PathBuf);
    impl Directory {
        fn new()->Self {
            use std::os::unix::fs::DirBuilderExt;
            let path=std::env::temp_dir().canonicalize().unwrap().join(format!("mc-capsule-keyring-{:x}",enclave_core::rng::u64()));
            std::fs::DirBuilder::new().mode(0o700).create(&path).unwrap();Self(path)
        }
        fn file(&self,suffix:&str)->std::path::PathBuf {self.0.join(format!("cas-namespace-keyring/cas-namespace-keyring.{suffix}"))}
        fn bytes(&self)->(Vec<u8>,Vec<u8>) {(std::fs::read(self.file("sealed")).unwrap(),std::fs::read(self.file("gen")).unwrap())}
    }
    impl Drop for Directory {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.0);}}

    #[test]
    fn namespace_capsules_atomic_registration_and_restart_allow_actual_either_member() {
        let fixture=Fixture::new();let directory=Directory::new();let mut ring=CasKeyring::open(Some(&directory.0)).unwrap();
        let (primary,primary_capsule)=fixture.pair("models",1,1,&PRIMARY);
        let (backup,backup_capsule)=fixture.pair("models",2,1,&BACKUP);
        let original=serde_json::to_vec(&primary).unwrap();let generation=ring.store.as_ref().unwrap().generation();
        ring.register_with_capsule(primary.clone(),primary_capsule,false).unwrap();
        assert_eq!(ring.store.as_ref().unwrap().generation(),generation+1,"one publication for the pair");
        ring.register_with_capsule(backup.clone(),backup_capsule,false).unwrap();
        let before=directory.bytes();
        assert!(ring.register(primary.clone(),false).unwrap_err().is("CAS_KEYRING_CAPSULE_REQUIRED"));
        assert_eq!(directory.bytes(),before);drop(ring);
        let ring=CasKeyring::open(Some(&directory.0)).unwrap();
        for (key,selected) in [(&primary,&BACKUP),(&backup,&PRIMARY)] {
            let kek=fixture.read(&ring,key,selected);
            assert_eq!(namespace::unwrap(key,&kek).unwrap().expose(),&[key.epoch as u8;32]);
            let direct=namespace::custody_kek(&SEP,selected,"models",1).unwrap();
            assert!(namespace::unwrap(key,&direct).is_err(),"different selected PRF cannot open the original direct envelope");
        }
        assert_eq!(serde_json::to_vec(&ring.namespace_snapshot("models").unwrap()[0]).unwrap(),original);
    }

    #[test]
    fn namespace_capsules_migration_demands_unchanged_whole_sorted_history_before_one_save() {
        let fixture=Fixture::new();let directory=Directory::new();let mut ring=CasKeyring::open(Some(&directory.0)).unwrap();
        let pairs:Vec<_>=(1..=3).map(|epoch|fixture.pair("models",epoch,2,&PRIMARY)).collect();
        for (key,_) in &pairs {ring.register(key.clone(),false).unwrap();}
        let keys=ring.namespace_snapshot("models").unwrap();let original=serde_json::to_vec(&keys).unwrap();
        let capsules=NamespaceKekCapsule::stage_primary_migration(&fixture.public,&fixture.scope,&keys,&SEP,&PRIMARY,&fixture.context,20,||Ok(())).unwrap();
        let before=directory.bytes();let generation=ring.store.as_ref().unwrap().generation();
        let mut reversed=keys.clone();reversed.reverse();
        let mut stale=keys.clone();stale[2]=fixture.pair("models",3,3,&PRIMARY).0;
        let mut extra=keys.clone();extra.push(fixture.pair("models",4,2,&PRIMARY).0);
        let mut swapped=capsules.clone();swapped.swap(0,1);
        let mut substituted=capsules.clone();substituted[2]=fixture.pair("other",3,2,&PRIMARY).1;
        for (snapshot,candidates) in [
            (keys[..2].to_vec(),capsules[..2].to_vec()),(keys.clone(),capsules[..2].to_vec()),
            (extra,capsules.clone()),(reversed,capsules.clone()),(stale,capsules.clone()),
            (keys.clone(),swapped),(keys.clone(),substituted),
        ] {
            assert!(ring.migrate_namespace("models",&snapshot,candidates).is_err());
            assert!(!ring.poisoned());assert_eq!(directory.bytes(),before);
            assert_eq!(ring.store.as_ref().unwrap().generation(),generation);
            assert!(matches!(ring.capsule_access(&keys[0]).unwrap(),NamespaceCapsuleAccess::LegacyDirect));
        }
        let (next,capsule)=fixture.pair("models",4,2,&PRIMARY);
        assert!(ring.register_with_capsule(next,capsule,false).unwrap_err().is("NAMESPACE_BACKUP_MIGRATION_REQUIRED"));
        assert_eq!(directory.bytes(),before);
        ring.migrate_namespace("models",&keys,capsules.clone()).unwrap();
        assert_eq!(ring.store.as_ref().unwrap().generation(),generation+1);
        assert_eq!(ring.state.namespaces["models"].minimum_wrapping_epoch,2);
        assert_eq!(serde_json::to_vec(&ring.namespace_snapshot("models").unwrap()).unwrap(),original);
        assert!(ring.migrate_namespace("models",&keys,capsules).unwrap_err().is("CAS_KEYRING_ALREADY_MIGRATED"));
        drop(ring);let ring=CasKeyring::open(Some(&directory.0)).unwrap();
        for key in keys {assert_eq!(namespace::unwrap(&key,&fixture.read(&ring,&key,&BACKUP)).unwrap().expose(),&[key.epoch as u8;32]);}
    }

    #[test]
    fn namespace_capsules_rotation_preserves_all_history_and_floor_without_downgrade() {
        let fixture=Fixture::new();let directory=Directory::new();let mut ring=CasKeyring::open(Some(&directory.0)).unwrap();
        let mut old=Vec::new();
        for epoch in 1..=2 {let (key,capsule)=fixture.pair("models",epoch,1,&PRIMARY);old.push(key.clone());ring.register_with_capsule(key,capsule,false).unwrap();}
        let (first,capsule)=fixture.pair("models",1,2,&BACKUP);ring.register_with_capsule(first.clone(),capsule,true).unwrap();
        let before=directory.bytes();
        assert!(ring.advance_floor("models",2).unwrap_err().is("CAS_KEYRING_REWRAP_REQUIRED"));
        assert!(ring.verify(&old[0]).is_err());ring.verify(&old[1]).unwrap();assert_eq!(directory.bytes(),before);
        let (second,capsule)=fixture.pair("models",2,2,&BACKUP);ring.register_with_capsule(second.clone(),capsule,true).unwrap();
        ring.advance_floor("models",2).unwrap();let before=directory.bytes();
        let (third,capsule)=fixture.pair("models",3,1,&PRIMARY);assert!(ring.register_with_capsule(third,capsule,false).is_err());
        assert!(ring.advance_floor("models",1).is_err());assert_eq!(directory.bytes(),before);
        drop(ring);let ring=CasKeyring::open(Some(&directory.0)).unwrap();
        assert_eq!(ring.namespace_snapshot("models").unwrap(),vec![first.clone(),second.clone()]);
        for key in [&first,&second] {assert_eq!(namespace::unwrap(key,&fixture.read(&ring,key,&PRIMARY)).unwrap().expose(),&[key.epoch as u8;32]);}
        for key in old {assert!(ring.verify(&key).is_err());}
    }

    #[test]
    fn namespace_capsules_uncertain_real_save_poison_and_restart_never_publish_half_state() {
        let fixture=Fixture::new();
        for migration in [false,true] {
            let directory=Directory::new();let mut ring=CasKeyring::open(Some(&directory.0)).unwrap();
            let (first,first_capsule)=fixture.pair("models",1,1,&PRIMARY);
            if migration {ring.register(first.clone(),false).unwrap();}else{ring.register_with_capsule(first.clone(),first_capsule.clone(),false).unwrap();}
            let before=directory.bytes();std::fs::remove_file(directory.file("gen")).unwrap();std::fs::create_dir(directory.file("gen")).unwrap();
            let (next,next_capsule)=fixture.pair("models",2,1,&BACKUP);
            let result=if migration {ring.migrate_namespace("models",&[first.clone()],vec![first_capsule])}
                else{ring.register_with_capsule(next.clone(),next_capsule,false)};
            assert!(result.is_err());assert!(ring.poisoned());
            assert_ne!(std::fs::read(directory.file("sealed")).unwrap(),before.0,"actual state write precedes obstructed checkpoint rename");
            assert!(ring.capsule_access(&first).unwrap_err().is("CAS_KEYRING_POISONED"));
            assert!(ring.namespace_snapshot("models").is_err());assert!(CasKeyring::open(Some(&directory.0)).is_err());drop(ring);
            // Test-only recovery of the exact old checkpoint: the real store
            // admits a complete ahead-of-checkpoint candidate, never half a pair.
            std::fs::remove_dir(directory.file("gen")).unwrap();std::fs::write(directory.file("gen"),before.1).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(directory.file("gen"),std::fs::Permissions::from_mode(0o600)).unwrap();
            let ring=CasKeyring::open(Some(&directory.0)).unwrap();
            assert_eq!(ring.namespace_snapshot("models").unwrap().len(),if migration{1}else{2});
            fixture.read(&ring,&first,&BACKUP);
            if !migration {fixture.read(&ring,&next,&PRIMARY);}
        }
    }

    #[test]
    fn namespace_capsules_missing_mismatched_and_legacy_sidecars_refuse_restart() {
        let fixture=Fixture::new();
        for damage in ["missing","mismatched","legacy"] {
            let directory=Directory::new();let mut ring=CasKeyring::open(Some(&directory.0)).unwrap();
            let (key,capsule)=fixture.pair("models",1,1,&PRIMARY);ring.register_with_capsule(key,capsule,false).unwrap();
            let mut malformed=ring.state.clone();let history=malformed.namespaces.get_mut("models").unwrap();
            match damage {
                "missing"=>history.capsules.clear(),
                "mismatched"=>{history.capsules.insert(1,fixture.pair("models",2,1,&PRIMARY).1);},
                "legacy"=>history.capsule_mode=CapsuleMode::LegacyDirect,
                _=>unreachable!(),
            }
            // Authenticate malformed bytes through the actual sealed store;
            // startup must enforce capsule coverage beyond envelope integrity.
            ring.store.as_mut().unwrap().save_json(&malformed).unwrap();drop(ring);
            assert!(CasKeyring::open(Some(&directory.0)).is_err(),"{damage}");
        }
    }

    #[test]
    fn namespace_capsules_history_and_aggregate_bound_refuse_before_any_write() {
        let fixture=Fixture::new();let directory=Directory::new();let mut ring=CasKeyring::open(Some(&directory.0)).unwrap();
        let mut candidate=RingState::default();let mut last_valid=None;let mut oversized=None;
        for index in 0..64 {
            let namespace=format!("aggregate-{index:03}-{}","n".repeat(114));assert_eq!(namespace.len(),128);
            let mut history=Ring{minimum_wrapping_epoch:1,keys:BTreeMap::new(),capsule_mode:CapsuleMode::Required,capsules:BTreeMap::new()};
            for epoch in 1..=64 {let (key,capsule)=fixture.pair(&namespace,epoch,1,&PRIMARY);history.keys.insert(epoch,key);history.capsules.insert(epoch,capsule);}
            candidate.namespaces.insert(namespace,history);
            match CasKeyring::validate(&candidate) {
                Ok(())=>last_valid=Some(candidate.clone()),
                Err(error)=>{assert!(error.is("CAS_KEYRING_SIZE"));oversized=Some(candidate);break;},
            }
        }
        let valid=last_valid.expect("at least one full history fits");let oversized=oversized.expect("aggregate limit binds before shape count limits");
        ring.save(valid).unwrap();let before=directory.bytes();let generation=ring.store.as_ref().unwrap().generation();
        assert!(before.0.len()<=MAXIMUM,"actual persisted outer envelope fits the bounded reader");
        assert!(ring.save(oversized).unwrap_err().is("CAS_KEYRING_SIZE"));
        assert!(!ring.poisoned());assert_eq!(ring.store.as_ref().unwrap().generation(),generation);assert_eq!(directory.bytes(),before);
        let namespace=ring.state.namespaces.keys().next().unwrap().clone();
        let (key,capsule)=fixture.pair(&namespace,65,1,&PRIMARY);
        assert!(ring.register_with_capsule(key,capsule,false).is_err());assert_eq!(directory.bytes(),before);assert!(!ring.poisoned());
        let key=ring.namespace_snapshot(&namespace).unwrap()[63].clone();drop(ring);
        let ring=CasKeyring::open(Some(&directory.0)).unwrap();fixture.read(&ring,&key,&BACKUP);
    }
}
