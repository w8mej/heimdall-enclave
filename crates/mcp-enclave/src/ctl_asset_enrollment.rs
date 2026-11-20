//! Operator transport for durable independent asset enrollment. This client
//! supplies no issuer, policy scope, PIN, biometric proof or admission bypass.
use super::*;
use enclave_custody_vaultd::{ctap::asset_enrollment::AssetEnrollmentReceipt,
    service::{VaultRequest,VaultResponse}};
use std::{fs::{File,OpenOptions},io::{Read,Write},os::unix::fs::{MetadataExt,OpenOptionsExt}};

fn operator(env:&Env)->EnclaveResult<()> {
    if !env.dev&&enclave_core::ipc::geteuid()!=0 {fail!(EPERM,"ENROLL_ADMIN_ONLY");}
    if env.profile==Profile::L1 {fail!(EPERM,"ENROLL_NOT_APPLICABLE_L1");}Ok(())
}
fn trusted_path(path:&Path)->EnclaveResult<PathBuf> {
    #[cfg(target_os="macos")]
    let platform=path.strip_prefix("/var").ok().map(|suffix|Path::new("/private/var").join(suffix));
    #[cfg(target_os="macos")]
    let path=platform.as_deref().unwrap_or(path);
    if !path.is_absolute()||!path.components().all(|part|matches!(part,std::path::Component::RootDir|std::path::Component::Normal(_))) {
        fail!(EACCES,"ASSET_OPERATOR_FILE_PATH");
    }
    for parent in path.parent().ok_or_else(||err!(EACCES,"ASSET_OPERATOR_FILE_PATH"))?.ancestors() {
        let metadata=std::fs::symlink_metadata(parent).map_err(|_|err!(EACCES,"ASSET_OPERATOR_FILE_PATH"))?;
        let sticky_root=metadata.uid()==0&&metadata.mode()&0o1000!=0;
        if !metadata.is_dir()||(metadata.uid()!=0&&metadata.uid()!=enclave_core::ipc::geteuid())
            ||(metadata.mode()&0o022!=0&&!sticky_root) {fail!(EACCES,"ASSET_OPERATOR_FILE_PATH");}
    }
    Ok(path.to_owned())
}
fn private_file(file:&File)->EnclaveResult<()> {
    let metadata=file.metadata().map_err(|_|err!(EACCES,"ASSET_OPERATOR_FILE"))?;
    if !metadata.is_file()||(metadata.uid()!=0&&metadata.uid()!=enclave_core::ipc::geteuid())||metadata.mode()&0o077!=0 {
        fail!(EACCES,"ASSET_OPERATOR_FILE");
    }Ok(())
}
fn create_pending(path:&Path)->EnclaveResult<(File,PathBuf)> {
    let path=trusted_path(path)?;
    let file=OpenOptions::new().write(true).create_new(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK).open(&path)
        .map_err(|_|err!(EACCES,"ASSET_PENDING_OUTPUT_CREATE_NEW"))?;
    private_file(&file)?;Ok((file,path))
}
fn read_receipt(path:&Path)->EnclaveResult<AssetEnrollmentReceipt> {
    let path=trusted_path(path)?;
    let file=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK)
        .open(path).map_err(|_|err!(EACCES,"ASSET_RECEIPT_FILE"))?;
    private_file(&file)?;
    let mut bytes=Vec::new();file.take(16*1024+1).read_to_end(&mut bytes).map_err(|_|err!(EIO,"ASSET_RECEIPT_FILE"))?;
    if bytes.len()>16*1024 {fail!(E2BIG,"ASSET_RECEIPT_FILE");}
    serde_json::from_slice(&bytes).map_err(|_|err!(EINVAL,"ASSET_RECEIPT_DECODE"))
}

/// Begin the daemon's independent asset transaction. The destination is created
/// before sending an effectful request and is never overwritten. On uncertain
/// RPC/output failure retain this file; Begin can retrieve durable pending again
/// into another new private file without repeating a completed makeCredential.
pub fn vault_enrollment_begin(env:&Env,pending_output:&Path)->EnclaveResult<serde_json::Value> {
    begin_enrollment(env,pending_output,VaultRequest::BeginAssetEnrollment)
}

/// Create public backup enrollment evidence on the daemon's second selected
/// authenticator. Its encrypted biometric blob stays in daemon-owned state.
/// A lost reply is recovered into a new output file, never by replaying an
/// already completed credential creation.
pub fn vault_enrollment_begin_backup(env:&Env,pending_output:&Path)->EnclaveResult<serde_json::Value> {
    begin_enrollment(env,pending_output,VaultRequest::BeginAssetBackupEnrollment)
}

fn begin_enrollment(env:&Env,pending_output:&Path,request:VaultRequest)->EnclaveResult<serde_json::Value> {
    operator(env)?;
    let client=env.connect(DaemonId::CustodyVault)?;
    let (mut output,path)=create_pending(pending_output)?;
    crate::custody_notice::show_for_profile(&env.profile.to_string());
    match client.prepare_call(&request)?.handoff()?.receive_with_timeout::<VaultResponse>(Duration::from_secs(30))? {
        VaultResponse::AssetEnrollmentPending {pending}=>{
            let bytes=serde_json::to_vec_pretty(&pending).map_err(|_|err!(EIO,"ASSET_PENDING_ENCODE"))?;
            if bytes.len()>2*1024*1024 {fail!(E2BIG,"ASSET_PENDING_OUTPUT");}
            output.write_all(&bytes).and_then(|()|output.write_all(b"\n")).and_then(|()|output.sync_all())
                .map_err(|_|err!(EIO,"ASSET_PENDING_OUTPUT"))?;
            File::open(path.parent().ok_or_else(||err!(EACCES,"ASSET_OPERATOR_FILE_PATH"))?)
                .and_then(|directory|directory.sync_all()).map_err(|_|err!(EIO,"ASSET_PENDING_OUTPUT"))?;
            Ok(json!({"status":"pending_saved","pending_sha256":hex::encode(pending.digest()?)}))
        },_=>fail!(EIO,"UNEXPECTED_RESPONSE"),
    }
}

/// Submit a host-local independent signed receipt. The daemon verifies the
/// issuer, exact pending digest, floors and expiry and performs fresh factors.
/// No private input or full evidence is emitted to stdout.
pub fn vault_enrollment_activate(env:&Env,receipt_file:&Path)->EnclaveResult<serde_json::Value> {
    submit_receipt(env,receipt_file,false)
}
/// Renew an exact existing identity with a newer independent signed receipt.
/// Ciphertexts and tier keys remain intact; all old leases are fenced first.
pub fn vault_enrollment_renew(env:&Env,receipt_file:&Path)->EnclaveResult<serde_json::Value> {
    submit_receipt(env,receipt_file,true)
}

/// Submit only the independent receipt for the daemon's exact pending backup.
/// Both fresh factor chains and durable member adoption run in the daemon; the
/// client supplies no pending replacement, private material or success claim.
pub fn vault_enrollment_add_backup(env:&Env,receipt_file:&Path)->EnclaveResult<serde_json::Value> {
    operator(env)?;let receipt=read_receipt(receipt_file)?;
    crate::custody_notice::show_for_profile(&env.profile.to_string());
    match env.connect(DaemonId::CustodyVault)?.prepare_call(&VaultRequest::AddAssetBackup {receipt})?
        .handoff()?.receive_with_timeout::<VaultResponse>(Duration::from_secs(30))? {
        VaultResponse::AssetBackupAdded {membership_id,generation}=>
            Ok(json!({"status":"backup_added","membership_id":membership_id,"generation":generation})),
        _=>fail!(EIO,"UNEXPECTED_RESPONSE"),
    }
}

/// Renew the daemon's exact admitted pair with two new inventory receipts.
/// Receipt files are only transport; the daemon checks identity, generation,
/// expiry and both fresh factor chains before adopting a new generation.
pub fn vault_enrollment_renew_membership(env:&Env,primary_file:&Path,backup_file:&Path)->EnclaveResult<serde_json::Value> {
    operator(env)?;
    let primary_receipt=read_receipt(primary_file)?;
    let backup_receipt=read_receipt(backup_file)?;
    crate::custody_notice::show_for_profile(&env.profile.to_string());
    match env.connect(DaemonId::CustodyVault)?
        .prepare_call(&VaultRequest::RenewAssetMembership {primary_receipt,backup_receipt})?
        .handoff()?.receive_with_timeout::<VaultResponse>(Duration::from_secs(30))? {
        VaultResponse::AssetMembershipRenewed {membership_id,generation}=>
            Ok(json!({"status":"membership_renewed","membership_id":membership_id,"generation":generation})),
        _=>fail!(EIO,"UNEXPECTED_RESPONSE"),
    }
}
/// Migrate all server-registered historical envelopes for one namespace. Only
/// the namespace is supplied; the server selects canonical envelopes and
/// verifies the original primary's fresh full A4 proof before publication.
pub fn vault_namespace_backup_migrate(env:&Env,namespace:&str)->EnclaveResult<serde_json::Value> {
    operator(env)?;
    crate::custody_notice::show_for_profile(&env.profile.to_string());
    match env.connect(DaemonId::CustodyVault)?
        .prepare_call(&VaultRequest::MigrateNamespaceBackup {namespace:namespace.to_owned()})?
        .handoff()?.receive_with_timeout::<VaultResponse>(Duration::from_secs(30))? {
        VaultResponse::NamespaceBackupMigrated {namespace,envelopes}=>
            Ok(json!({"status":"namespace_backup_migrated","namespace":namespace,"envelopes":envelopes})),
        _=>fail!(EIO,"UNEXPECTED_RESPONSE"),
    }
}

/// Submit a bounded signed travel token. Trust pins, quorum and rollback
/// authority come only from the daemon's independently installed configuration.
pub fn vault_travel_recovery_activate(env:&Env,token_file:&Path)->EnclaveResult<serde_json::Value> {
    operator(env)?;
    if env.profile!=Profile::L3 {fail!(EPERM,"TRAVEL_REQUIRES_L3");}
    let path=trusted_path(token_file)?;
    let file=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK)
        .open(path).map_err(|_|err!(EACCES,"TRAVEL_TOKEN_FILE"))?;
    private_file(&file)?;
    let mut token=Vec::new();file.take(128*1024+1).read_to_end(&mut token)
        .map_err(|_|err!(EIO,"TRAVEL_TOKEN_FILE"))?;
    if token.is_empty()||token.len()>128*1024 {fail!(E2BIG,"TRAVEL_TOKEN_FILE");}
    match env.connect(DaemonId::CustodyVault)?
        .prepare_call(&VaultRequest::ActivateTravelRecovery {token})?
        .handoff()?.receive_with_timeout::<VaultResponse>(Duration::from_secs(30))? {
        VaultResponse::TravelRecoveryActive {token_sha256,valid_until_utc_ms,effective_profile}=>
            Ok(json!({"status":"travel_recovery_active","token_sha256":hex::encode(token_sha256),
                "valid_until_utc_ms":valid_until_utc_ms,"effective_profile":effective_profile})),
        _=>fail!(EIO,"UNEXPECTED_RESPONSE"),
    }
}

/// Submit a denial-only inventory statement. Independent time/head authority
/// must already be installed in the service; the client supplies no trust,
/// replacement factors, recovery grant or wrapper selection.
pub fn vault_member_loss_record(env:&Env,statement_file:&Path)->EnclaveResult<serde_json::Value> {
    operator(env)?;
    let path=trusted_path(statement_file)?;
    let file=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK)
        .open(path).map_err(|_|err!(EACCES,"MEMBER_LOSS_STATEMENT_FILE"))?;
    private_file(&file)?;
    let mut statement=Vec::new();
    file.take(64*1024+1).read_to_end(&mut statement).map_err(|_|err!(EIO,"MEMBER_LOSS_STATEMENT_FILE"))?;
    if statement.is_empty()||statement.len()>64*1024 {fail!(E2BIG,"MEMBER_LOSS_STATEMENT_FILE");}
    match env.connect(DaemonId::CustodyVault)?.prepare_call(&VaultRequest::RecordMemberLoss {statement})?
        .handoff()?.receive_with_timeout::<VaultResponse>(Duration::from_secs(30))? {
        VaultResponse::MemberLossRecorded {statement_sha256,loss_generation,survivor_enrolled_sha256}=>
            Ok(json!({"status":"member_loss_recorded","statement_sha256":hex::encode(statement_sha256),
                "loss_generation":loss_generation,"survivor_enrolled_sha256":hex::encode(survivor_enrolled_sha256)})),
        _=>fail!(EIO,"UNEXPECTED_RESPONSE"),
    }
}
/// Transport a signed candidate and public receipts for inert preparation.
/// The opaque ID refers only to server-validated enrollment; the client cannot
/// supply pending enrollment, encrypted biometric material or release authority.
pub fn vault_member_replacement_prepare(env:&Env,candidate_file:&Path,evidence_id:&str,
    replacement_file:&Path,survivor_file:Option<&Path>)->EnclaveResult<serde_json::Value> {
    operator(env)?;
    let mut enrollment_evidence_id=[0u8;32];
    hex::decode_to_slice(evidence_id,&mut enrollment_evidence_id)
        .map_err(|_|err!(EINVAL,"REPLACEMENT_ENROLLMENT_EVIDENCE_ID"))?;
    if enrollment_evidence_id==[0;32] {fail!(EINVAL,"REPLACEMENT_ENROLLMENT_EVIDENCE_ID");}
    let path=trusted_path(candidate_file)?;
    let file=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK)
        .open(path).map_err(|_|err!(EACCES,"REPLACEMENT_CANDIDATE_FILE"))?;
    private_file(&file)?;
    let mut candidate=Vec::new();
    file.take(64*1024+1).read_to_end(&mut candidate).map_err(|_|err!(EIO,"REPLACEMENT_CANDIDATE_FILE"))?;
    if candidate.is_empty()||candidate.len()>64*1024 {fail!(E2BIG,"REPLACEMENT_CANDIDATE_FILE");}
    let replacement_receipt=read_receipt(replacement_file)?;
    let survivor_receipt=survivor_file.map(read_receipt).transpose()?;
    match env.connect(DaemonId::CustodyVault)?.prepare_call(&VaultRequest::PrepareMemberReplacement {
        candidate,enrollment_evidence_id,replacement_receipt,survivor_receipt})?
        .handoff()?.receive_with_timeout::<VaultResponse>(Duration::from_secs(30))? {
        VaultResponse::MemberReplacementPrepared {candidate_sha256,attempt,receipt_floor}=>
            Ok(json!({"status":"member_replacement_prepared","candidate_sha256":hex::encode(candidate_sha256),
                "attempt":attempt,"receipt_floor":receipt_floor})),
        _=>fail!(EIO,"UNEXPECTED_RESPONSE"),
    }
}
fn submit_receipt(env:&Env,receipt_file:&Path,renewal:bool)->EnclaveResult<serde_json::Value> {
    operator(env)?;let receipt=read_receipt(receipt_file)?;
    crate::custody_notice::show_for_profile(&env.profile.to_string());
    let request=if renewal {VaultRequest::RenewAssetEnrollment {receipt}} else {VaultRequest::ActivateAssetEnrollment {receipt}};
    match env.connect(DaemonId::CustodyVault)?.prepare_call(&request)?.handoff()?.receive_with_timeout::<VaultResponse>(Duration::from_secs(30))? {
        VaultResponse::Enrolled {sas,..}=>Ok(json!({"status":"active","sas":sas})),
        _=>fail!(EIO,"UNEXPECTED_RESPONSE"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt,PermissionsExt,symlink};
    struct Root(PathBuf);
    impl Root {fn new()->Self {
        let path=Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target").join(format!("enrollment-cli-{:x}",enclave_core::rng::u64()));
        std::fs::DirBuilder::new().recursive(true).mode(0o755).create(&path).unwrap();
        std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o700)).unwrap();Self(path.canonicalize().unwrap())
    }}
    impl Drop for Root {fn drop(&mut self){let _=std::fs::remove_dir_all(&self.0);}}
    #[test]
    fn pending_output_never_truncates_or_follows_links_and_requires_trusted_parent() {
        let root=Root::new();let path=root.0.join("pending.json");
        let (mut file,_)=create_pending(&path).unwrap();file.write_all(b"preserve").unwrap();drop(file);
        assert!(create_pending(&path).is_err());assert_eq!(std::fs::read(&path).unwrap(),b"preserve");
        let link=root.0.join("link.json");symlink(&path,&link).unwrap();assert!(create_pending(&link).is_err());
        let shared=root.0.join("shared");std::fs::create_dir(&shared).unwrap();std::fs::set_permissions(&shared,std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(create_pending(&shared.join("pending.json")).is_err());
        assert!(create_pending(Path::new("relative.json")).is_err());
    }
    #[test]
    fn receipt_input_is_private_bounded_regular_and_never_issuer_authority() {
        let root=Root::new();let path=root.0.join("receipt.json");
        let receipt=AssetEnrollmentReceipt {version:1,pending_sha256:[7;32],generation:3,issued_unix:1,expires_unix:2,signature:vec![0;64]};
        let (mut file,_)=create_pending(&path).unwrap();file.write_all(&serde_json::to_vec(&receipt).unwrap()).unwrap();drop(file);
        // The client only transports shape; the daemon must reject this unsigned fixture.
        assert_eq!(read_receipt(&path).unwrap().generation,3);
        std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o644)).unwrap();assert!(read_receipt(&path).unwrap_err().is("ASSET_OPERATOR_FILE"));
        std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600)).unwrap();std::fs::write(&path,vec![b' ';16*1024+1]).unwrap();
        assert!(read_receipt(&path).unwrap_err().is("ASSET_RECEIPT_FILE"));
        assert!(read_receipt(&root.0).is_err());
    }
}
