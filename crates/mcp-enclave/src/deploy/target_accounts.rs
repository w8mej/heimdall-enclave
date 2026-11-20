//! Read-only admission of the fixed existing macOS service accounts/groups.
//!
//! This does not create, repair, adopt or authorize provisioning of accounts.
//! Exact name and numeric-ID lookups must each yield one identical record;
//! first-match libc lookups are insufficient for collision admission. Official
//! names remain fixed. Complete bounded alias sets are observed and
//! compared, because one directory record may legitimately have several names.
//! Required client memberships must be affirmed by the native directory service. This
//! is not a complete audit of every other member or host directory record.
//! Results cover the system authentication search policy. The cooperative host
//! guard does not lock a remote directory administrator or make queries atomic;
//! concurrent administrative directory changes are outside this boundary.
//! The opaque observation is bound to the protected descriptor/inventory and
//! must be rechecked before use under the same host maintenance exclusion.
//! Native calls are synchronous; result/byte bounds are not a hard timeout.

use std::collections::{BTreeMap,BTreeSet};
use enclave_core::{deployment::CheckedDeploymentTarget,error::EnclaveResult,err,fail};
use sha2::{Digest,Sha256};
use super::{target_activity::MaintenanceExclusion,target_maintenance::HostMaintenanceGuard,target_plan};

const USERS:[(&str,u32,u32);8]=[
    ("root",0,0),("_llmagent",701,8701),("_enclavecas",702,8702),("_piivault",703,8703),
    ("_enclaveifc",704,8704),("_enclavezk",705,8705),("_cdpbrowser",707,8707),("_enclaveingress",708,8708),
];
const GROUPS:[(&str,u32);17]=[
    ("wheel",0),("_llmagent",8701),("_enclavecas",8702),("_piivault",8703),
    ("_enclaveifc",8704),("_enclavezk",8705),("_cdpbrowser",8707),("_enclaveingress",8708),
    ("_enclave_adapter_c",8711),("_enclave_cas_c",8712),("_enclave_custody_c",8713),
    ("_enclave_ifc_c",8714),("_enclave_zk_c",8715),("_enclave_sup_c",8716),
    ("_enclave_browser_c",8718),("_enclave_witness_c",8719),("_enclave_journal_r",8720),
];
const MEMBERSHIPS:[(&str,&str);20]=[
    ("_enclave_adapter_c","_enclaveifc"),
    ("_enclave_cas_c","_llmagent"),("_enclave_cas_c","_piivault"),
    ("_enclave_cas_c","_enclaveifc"),("_enclave_cas_c","_enclavezk"),
    ("_enclave_custody_c","_enclavecas"),("_enclave_custody_c","_enclaveifc"),("_enclave_custody_c","_enclavezk"),
    ("_enclave_ifc_c","_llmagent"),("_enclave_ifc_c","_piivault"),
    ("_enclave_ifc_c","_enclavezk"),("_enclave_ifc_c","_enclaveingress"),
    ("_enclave_zk_c","_llmagent"),("_enclave_zk_c","_enclavecas"),
    ("_enclave_zk_c","_piivault"),("_enclave_zk_c","_enclaveifc"),
    ("_enclave_sup_c","_enclavecas"),("_enclave_browser_c","_llmagent"),
    ("_enclave_witness_c","_piivault"),("_enclave_journal_r","_enclavezk"),
];
const MAX_ALIASES:usize=8;
const MAX_ALIAS_BYTES:usize=4096;

#[derive(Clone,Debug,PartialEq,Eq)]
struct User {name:String,aliases:BTreeSet<String>,uid:u32,primary_gid:u32,record_id:String,node:String}
#[derive(Clone,Debug,PartialEq,Eq)]
struct Group {name:String,aliases:BTreeSet<String>,gid:u32,record_id:String,node:String}
#[derive(Clone,Debug,PartialEq,Eq)]
struct Snapshot {users:BTreeMap<String,User>,groups:BTreeMap<String,Group>,memberships:BTreeSet<(String,String)>}
#[derive(Clone,Copy)]
enum Lookup {Name(&'static str),Id(u32)}
trait DirectoryBackend {
    fn users(&mut self,lookup:Lookup)->EnclaveResult<Vec<User>>;
    fn groups(&mut self,lookup:Lookup)->EnclaveResult<Vec<Group>>;
    fn contains(&mut self,group:&Group,user:&User)->EnclaveResult<bool>;
}

/// In-process observation only: no public fields, deserialization or arbitrary
/// constructor. It grants neither account adoption nor installation authority.
pub(crate) struct FixedAccountAdmission {
    target_id:String,descriptor_sha256:String,inventory_sha256:String,snapshot:Snapshot,
}
impl std::fmt::Debug for FixedAccountAdmission {
    fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result {
        f.debug_struct("FixedAccountAdmission").finish_non_exhaustive()
    }
}
fn require_root(uid:u32)->EnclaveResult<()> {
    if uid!=0 {fail!(EACCES,"ACCOUNTS_ROOT_REQUIRED");}Ok(())
}
fn public_identity(record_id:&str,node:&str)->EnclaveResult<()> {
    if record_id.len()!=36 || !record_id.bytes().enumerate().all(|(i,c)|
        if [8,13,18,23].contains(&i) {c==b'-'}else{c.is_ascii_hexdigit()})
        || node.is_empty() || node.len()>1024 || !node.starts_with('/')
        || node.chars().any(char::is_control) {
        fail!(EACCES,"ACCOUNTS_RECORD_IDENTITY");
    }Ok(())
}
fn checked_aliases(official:&str,values:Vec<String>)->EnclaveResult<BTreeSet<String>> {
    if values.is_empty() || values.len()>MAX_ALIASES {fail!(EACCES,"ACCOUNTS_NATIVE_ALIASES");}
    let mut aliases=BTreeSet::new();let mut folded=BTreeSet::new();let mut bytes=0usize;
    for value in values {
        bytes=bytes.checked_add(value.len()).ok_or_else(||err!(E2BIG,"ACCOUNTS_NATIVE_ALIASES"))?;
        // Attribute schemas define native case matching. Conservatively reject
        // ASCII case collisions here; no Unicode equivalence rule is claimed.
        if value.is_empty() || value.len()>1024 || value.chars().any(char::is_control)
            || bytes>MAX_ALIAS_BYTES || !folded.insert(value.to_ascii_lowercase()) || !aliases.insert(value) {
            fail!(EACCES,"ACCOUNTS_NATIVE_ALIASES");
        }
    }
    if !aliases.contains(official) {fail!(EACCES,"ACCOUNTS_NATIVE_ALIASES");}Ok(aliases)
}
fn validate_aliases(official:&str,aliases:&BTreeSet<String>)->EnclaveResult<()> {
    // The portable admission model enforces these invariants too. A backend
    // returning already-collected values cannot bypass count/length controls.
    if aliases.is_empty() || aliases.len()>MAX_ALIASES {fail!(EACCES,"ACCOUNTS_NATIVE_ALIASES");}
    checked_aliases(official,aliases.iter().cloned().collect())?;Ok(())
}
fn one<T>(mut records:Vec<T>)->EnclaveResult<T> {
    if records.len()!=1 {fail!(EACCES,"ACCOUNTS_MISSING_OR_AMBIGUOUS");}
    Ok(records.remove(0))
}
fn observe(backend:&mut dyn DirectoryBackend)->EnclaveResult<Snapshot> {
    let mut users=BTreeMap::new();let mut groups=BTreeMap::new();let mut identities=BTreeSet::new();
    for (name,uid,gid) in USERS {
        let named=one(backend.users(Lookup::Name(name))?)?;
        let numeric=one(backend.users(Lookup::Id(uid))?)?;
        public_identity(&named.record_id,&named.node)?;
        validate_aliases(&named.name,&named.aliases)?;
        if named!=numeric || named.name!=name || named.uid!=uid || named.primary_gid!=gid
            || !identities.insert((named.node.clone(),named.record_id.to_ascii_lowercase())) {
            fail!(EACCES,"ACCOUNTS_USER_COLLISION");
        }
        users.insert(name.to_owned(),named);
    }
    for (name,gid) in GROUPS {
        let named=one(backend.groups(Lookup::Name(name))?)?;
        let numeric=one(backend.groups(Lookup::Id(gid))?)?;
        public_identity(&named.record_id,&named.node)?;
        validate_aliases(&named.name,&named.aliases)?;
        if named!=numeric || named.name!=name || named.gid!=gid
            || !identities.insert((named.node.clone(),named.record_id.to_ascii_lowercase())) {
            fail!(EACCES,"ACCOUNTS_GROUP_COLLISION");
        }
        groups.insert(name.to_owned(),named);
    }
    let mut memberships=BTreeSet::new();
    for (group,user) in MEMBERSHIPS {
        if !backend.contains(groups.get(group).expect("fixed group"),users.get(user).expect("fixed user"))? {
            fail!(EACCES,"ACCOUNTS_REQUIRED_MEMBERSHIP");
        }
        memberships.insert((group.to_owned(),user.to_owned()));
    }
    Ok(Snapshot {users,groups,memberships})
}
fn stable_observation(backend:&mut dyn DirectoryBackend)->EnclaveResult<Snapshot> {
    let first=observe(backend)?;
    if observe(backend)?!=first {fail!(ESTALE,"ACCOUNTS_CHANGED");}Ok(first)
}
fn native_observation()->EnclaveResult<Snapshot> {
    #[cfg(target_os="macos")]
    {stable_observation(&mut darwin::Directory::new()?)}
    #[cfg(not(target_os="macos"))]
    {fail!(ENOSYS,"ACCOUNTS_NATIVE_REQUIRED");}
}
fn context(checked:&CheckedDeploymentTarget,inventory:&str)->EnclaveResult<()> {
    if hex::encode(Sha256::digest(checked.read_artifact_inventory()?))!=inventory {
        fail!(ESTALE,"ACCOUNTS_CONTEXT_CHANGED");
    }Ok(())
}

pub(crate) fn admit_fixed_accounts(checked:&CheckedDeploymentTarget,guard:&mut HostMaintenanceGuard)
    ->EnclaveResult<FixedAccountAdmission> {
    #[cfg(not(target_os="macos"))]
    {let _=(checked,guard);fail!(ENOSYS,"ACCOUNTS_NATIVE_REQUIRED");}
    #[cfg(target_os="macos")]
    {
        require_root(unsafe {libc::geteuid()})?;guard.assert_held()?;
        let plan=target_plan::prepare(checked)?;
        let snapshot=native_observation()?;
        context(checked,&plan.artifact_inventory_sha256)?;guard.assert_held()?;
        Ok(FixedAccountAdmission {target_id:plan.target_id,descriptor_sha256:plan.deployment_config_sha256,
            inventory_sha256:plan.artifact_inventory_sha256,snapshot})
    }
}
impl FixedAccountAdmission {
    pub(crate) fn assert_current(&self,checked:&CheckedDeploymentTarget,guard:&mut HostMaintenanceGuard)->EnclaveResult<()> {
        #[cfg(not(target_os="macos"))]
        {let _=(checked,guard);fail!(ENOSYS,"ACCOUNTS_NATIVE_REQUIRED");}
        #[cfg(target_os="macos")]
        {
            require_root(unsafe {libc::geteuid()})?;guard.assert_held()?;
            if checked.target().target_id!=self.target_id || checked.descriptor_sha256()!=self.descriptor_sha256 {
                fail!(ESTALE,"ACCOUNTS_CONTEXT_CHANGED");
            }
            context(checked,&self.inventory_sha256)?;
            if native_observation()?!=self.snapshot {fail!(ESTALE,"ACCOUNTS_CHANGED");}
            context(checked,&self.inventory_sha256)?;guard.assert_held()
        }
    }
}

#[cfg(target_os="macos")]
mod darwin {
    use super::*;
    use std::{ffi::{c_void,CStr},os::raw::c_char};
    type CfRef=*const c_void;
    // Confirmed public CFOpenDirectoryConstants.h: ODNodeType/ODMatchType u32.
    const AUTHENTICATION:u32=0x2201;
    const EQUAL:u32=0x2001;
    const UTF8:u32=0x0800_0100;
    #[link(name="CoreFoundation",kind="framework")]
    extern "C" {
        fn CFRelease(value:CfRef);
        fn CFRetain(value:CfRef)->CfRef;
        fn CFGetTypeID(value:CfRef)->usize;
        fn CFEqual(left:CfRef,right:CfRef)->u8;
        fn CFStringGetTypeID()->usize;
        fn CFArrayGetTypeID()->usize;
        fn CFStringCreateWithBytes(allocator:CfRef,bytes:*const u8,length:isize,encoding:u32,external:u8)->CfRef;
        fn CFStringGetLength(value:CfRef)->isize;
        fn CFStringGetCString(value:CfRef,buffer:*mut c_char,size:isize,encoding:u32)->u8;
        fn CFArrayCreate(allocator:CfRef,values:*const CfRef,count:isize,callbacks:CfRef)->CfRef;
        fn CFArrayGetCount(value:CfRef)->isize;
        fn CFArrayGetValueAtIndex(value:CfRef,index:isize)->CfRef;
    }
    #[link(name="OpenDirectory",kind="framework")]
    extern "C" {
        static kODSessionDefault:CfRef;
        static kODRecordTypeUsers:CfRef;
        static kODRecordTypeGroups:CfRef;
        static kODAttributeTypeRecordName:CfRef;
        static kODAttributeTypeUniqueID:CfRef;
        static kODAttributeTypePrimaryGroupID:CfRef;
        static kODAttributeTypeGUID:CfRef;
        static kODAttributeTypeMetaNodeLocation:CfRef;
        fn ODNodeGetTypeID()->usize;
        fn ODQueryGetTypeID()->usize;
        fn ODRecordGetTypeID()->usize;
        fn ODNodeCreateWithNodeType(allocator:CfRef,session:CfRef,kind:u32,error:*mut CfRef)->CfRef;
        fn ODQueryCreateWithNode(allocator:CfRef,node:CfRef,record_type:CfRef,attribute:CfRef,match_type:u32,
            query_value:CfRef,return_attributes:CfRef,max_results:isize,error:*mut CfRef)->CfRef;
        fn ODQueryCopyResults(query:CfRef,allow_partial:bool,error:*mut CfRef)->CfRef;
        fn ODRecordGetRecordName(record:CfRef)->CfRef;
        fn ODRecordGetRecordType(record:CfRef)->CfRef;
        fn ODRecordCopyValues(record:CfRef,attribute:CfRef,error:*mut CfRef)->CfRef;
        fn ODRecordContainsMember(group:CfRef,member:CfRef,error:*mut CfRef)->bool;
    }
    struct Cf(CfRef);
    impl Drop for Cf {fn drop(&mut self) {if !self.0.is_null() {unsafe {CFRelease(self.0)};}}}
    fn typed(value:CfRef,kind:usize)->EnclaveResult<CfRef> {
        if value.is_null() || unsafe {CFGetTypeID(value)}!=kind {fail!(EACCES,"ACCOUNTS_NATIVE_METADATA");}Ok(value)
    }
    fn returned(value:CfRef,error:CfRef,kind:usize)->EnclaveResult<Cf> {
        let value=Cf(value);let error=Cf(error);
        if !error.0.is_null() {fail!(EIO,"ACCOUNTS_DIRECTORY_UNAVAILABLE");}
        typed(value.0,kind)?;Ok(value)
    }
    fn text(value:CfRef)->EnclaveResult<String> {
        typed(value,unsafe {CFStringGetTypeID()})?;let mut buffer=[0i8;4096];
        let length=unsafe {CFStringGetLength(value)};
        if !(1..=1024).contains(&length)
            || unsafe {CFStringGetCString(value,buffer.as_mut_ptr(),buffer.len() as isize,UTF8)}==0 {
            fail!(EACCES,"ACCOUNTS_NATIVE_METADATA");
        }
        let result=unsafe {CStr::from_ptr(buffer.as_ptr())}.to_str().map_err(|_|err!(EACCES,"ACCOUNTS_NATIVE_METADATA"))?;
        if result.len()>1024 || result.encode_utf16().count() as isize!=length || result.chars().any(char::is_control) {
            fail!(EACCES,"ACCOUNTS_NATIVE_METADATA");
        }Ok(result.to_owned())
    }
    fn cf_text(value:&str)->EnclaveResult<Cf> {
        let result=Cf(unsafe {CFStringCreateWithBytes(std::ptr::null(),value.as_ptr(),value.len() as isize,UTF8,0)});
        typed(result.0,unsafe {CFStringGetTypeID()})?;Ok(result)
    }
    fn one_value(record:CfRef,attribute:CfRef)->EnclaveResult<String> {
        let mut error=std::ptr::null();let result=unsafe {ODRecordCopyValues(record,attribute,&mut error)};
        let result=returned(result,error,unsafe {CFArrayGetTypeID()})?;
        if unsafe {CFArrayGetCount(result.0)}!=1 {fail!(EACCES,"ACCOUNTS_NATIVE_METADATA");}
        text(unsafe {CFArrayGetValueAtIndex(result.0,0)})
    }
    fn alias_values(official:&str,values:CfRef)->EnclaveResult<BTreeSet<String>> {
        typed(values,unsafe {CFArrayGetTypeID()})?;let count=unsafe {CFArrayGetCount(values)};
        // Bound the native array before indexing or allocating a result vector.
        if !(1..=MAX_ALIASES as isize).contains(&count) {fail!(EACCES,"ACCOUNTS_NATIVE_ALIASES");}
        let mut names=Vec::with_capacity(count as usize);let mut bytes=0usize;
        for index in 0..count {
            let name=text(unsafe {CFArrayGetValueAtIndex(values,index)})?;
            bytes+=name.len();if bytes>MAX_ALIAS_BYTES {fail!(EACCES,"ACCOUNTS_NATIVE_ALIASES");}
            names.push(name);
        }
        checked_aliases(official,names)
    }
    fn record_aliases(record:CfRef,official:&str)->EnclaveResult<BTreeSet<String>> {
        let mut error=std::ptr::null();
        let values=unsafe {ODRecordCopyValues(record,kODAttributeTypeRecordName,&mut error)};
        let values=returned(values,error,unsafe {CFArrayGetTypeID()})?;
        alias_values(official,values.0)
    }
    fn number(value:String)->EnclaveResult<u32> {
        let result=value.parse::<u32>().map_err(|_|err!(EACCES,"ACCOUNTS_NATIVE_METADATA"))?;
        if result.to_string()!=value {fail!(EACCES,"ACCOUNTS_NATIVE_METADATA");}Ok(result)
    }
    fn identity(record:CfRef,record_type:CfRef)->EnclaveResult<(String,BTreeSet<String>,String,String)> {
        typed(record,unsafe {ODRecordGetTypeID()})?;
        let actual_type=unsafe {ODRecordGetRecordType(record)};typed(actual_type,unsafe {CFStringGetTypeID()})?;
        if unsafe {CFEqual(actual_type,record_type)}==0 {fail!(EACCES,"ACCOUNTS_NATIVE_METADATA");}
        let name=text(unsafe {ODRecordGetRecordName(record)})?;
        let aliases=record_aliases(record,&name)?;
        Ok((name,aliases,one_value(record,unsafe {kODAttributeTypeGUID})?,one_value(record,unsafe {kODAttributeTypeMetaNodeLocation})?))
    }
    fn user(record:CfRef)->EnclaveResult<User> {
        let (name,aliases,record_id,node)=identity(record,unsafe {kODRecordTypeUsers})?;
        Ok(User {name,aliases,record_id,node,uid:number(one_value(record,unsafe {kODAttributeTypeUniqueID})?)?,
            primary_gid:number(one_value(record,unsafe {kODAttributeTypePrimaryGroupID})?)?})
    }
    fn group(record:CfRef)->EnclaveResult<Group> {
        let (name,aliases,record_id,node)=identity(record,unsafe {kODRecordTypeGroups})?;
        Ok(Group {name,aliases,record_id,node,gid:number(one_value(record,unsafe {kODAttributeTypePrimaryGroupID})?)?})
    }
    pub(super) struct Directory {node:Cf,users:BTreeMap<String,Cf>,groups:BTreeMap<String,Cf>}
    impl Directory {
        pub(super) fn new()->EnclaveResult<Self> {
            let mut error=std::ptr::null();
            let node=unsafe {ODNodeCreateWithNodeType(std::ptr::null(),kODSessionDefault,AUTHENTICATION,&mut error)};
            Ok(Self {node:returned(node,error,unsafe {ODNodeGetTypeID()})?,users:BTreeMap::new(),groups:BTreeMap::new()})
        }
        fn query(&self,record_type:CfRef,numeric_attribute:CfRef,lookup:Lookup)->EnclaveResult<Vec<Cf>> {
            let (attribute,value)=match lookup {
                Lookup::Name(name)=>(unsafe {kODAttributeTypeRecordName},name.to_owned()),Lookup::Id(id)=>(numeric_attribute,id.to_string()),
            };
            let value=cf_text(&value)?;
            // Only these public identity attributes are fetched. Passwords,
            // authentication authorities and password hashes are never asked for.
            let attributes=unsafe {[kODAttributeTypeRecordName,kODAttributeTypeUniqueID,kODAttributeTypePrimaryGroupID,
                kODAttributeTypeGUID,kODAttributeTypeMetaNodeLocation]};
            // Globals remain alive throughout this borrowed no-callback array.
            let attributes=Cf(unsafe {CFArrayCreate(std::ptr::null(),attributes.as_ptr(),attributes.len() as isize,std::ptr::null())});
            typed(attributes.0,unsafe {CFArrayGetTypeID()})?;
            let mut error=std::ptr::null();
            let query=unsafe {ODQueryCreateWithNode(std::ptr::null(),self.node.0,record_type,attribute,EQUAL,
                value.0,attributes.0,2,&mut error)};
            let query=returned(query,error,unsafe {ODQueryGetTypeID()})?;
            let mut error=std::ptr::null();
            // false requires completion or error; partial results never admit.
            let records=unsafe {ODQueryCopyResults(query.0,false,&mut error)};
            let records=returned(records,error,unsafe {CFArrayGetTypeID()})?;
            let count=unsafe {CFArrayGetCount(records.0)};
            if !(0..=2).contains(&count) {fail!(E2BIG,"ACCOUNTS_NATIVE_RESULT_LIMIT");}
            let mut result=Vec::new();
            for index in 0..count {
                let record=unsafe {CFArrayGetValueAtIndex(records.0,index)};typed(record,unsafe {ODRecordGetTypeID()})?;
                result.push(Cf(unsafe {CFRetain(record)}));
            }Ok(result)
        }
    }
    impl DirectoryBackend for Directory {
        fn users(&mut self,lookup:Lookup)->EnclaveResult<Vec<User>> {
            let records=self.query(unsafe {kODRecordTypeUsers},unsafe {kODAttributeTypeUniqueID},lookup)?;
            let mut result=Vec::new();
            for record in records {let observed=user(record.0)?;self.users.insert(observed.name.clone(),record);result.push(observed);}
            if self.users.len()>USERS.len() {fail!(E2BIG,"ACCOUNTS_NATIVE_RESULT_LIMIT");}Ok(result)
        }
        fn groups(&mut self,lookup:Lookup)->EnclaveResult<Vec<Group>> {
            let records=self.query(unsafe {kODRecordTypeGroups},unsafe {kODAttributeTypePrimaryGroupID},lookup)?;
            let mut result=Vec::new();
            for record in records {let observed=group(record.0)?;self.groups.insert(observed.name.clone(),record);result.push(observed);}
            if self.groups.len()>GROUPS.len() {fail!(E2BIG,"ACCOUNTS_NATIVE_RESULT_LIMIT");}Ok(result)
        }
        fn contains(&mut self,expected_group:&Group,expected_user:&User)->EnclaveResult<bool> {
            let native_group=self.groups.get(&expected_group.name).ok_or_else(||err!(EACCES,"ACCOUNTS_NATIVE_METADATA"))?;
            let native_user=self.users.get(&expected_user.name).ok_or_else(||err!(EACCES,"ACCOUNTS_NATIVE_METADATA"))?;
            if group(native_group.0)?!=*expected_group || user(native_user.0)?!=*expected_user {
                fail!(ESTALE,"ACCOUNTS_CHANGED");
            }
            let mut error=std::ptr::null();
            let contains=unsafe {ODRecordContainsMember(native_group.0,native_user.0,&mut error)};let error=Cf(error);
            if !error.0.is_null() {fail!(EIO,"ACCOUNTS_DIRECTORY_UNAVAILABLE");}Ok(contains)
        }
    }
    #[cfg(test)]
    pub(super) fn test_cf_boundaries() {
        let good=cf_text("/Local/Default").unwrap();assert_eq!(text(good.0).unwrap(),"/Local/Default");
        let nul=cf_text("root\0suffix").unwrap();assert!(text(nul.0).is_err());assert!(text(std::ptr::null()).is_err());
        let entries=[good.0];let array=Cf(unsafe {CFArrayCreate(std::ptr::null(),entries.as_ptr(),1,std::ptr::null())});
        assert!(text(array.0).is_err());assert!(typed(good.0,unsafe {ODRecordGetTypeID()}).is_err());
        assert_eq!(number("0".into()).unwrap(),0);
        for value in ["", "-1", "+1", "01", "1\0suffix", "4294967296"] {assert!(number(value.into()).is_err());}
    }
    #[cfg(test)]
    pub(super) fn test_alias_boundaries() {
        fn array(values:&[CfRef])->Cf {
            Cf(unsafe {CFArrayCreate(std::ptr::null(),values.as_ptr(),values.len() as isize,std::ptr::null())})
        }
        let root=cf_text("root").unwrap();let alias=cf_text("public synthetic alias").unwrap();
        let other_case=cf_text("ROOT").unwrap();let nul=cf_text("root\0suffix").unwrap();
        let empty=cf_text("").unwrap();let long=cf_text(&"a".repeat(1025)).unwrap();
        let good=array(&[root.0,alias.0]);
        let expected=BTreeSet::from(["root".to_owned(),"public synthetic alias".to_owned()]);
        assert_eq!(alias_values("root",good.0).unwrap(),expected);
        assert_eq!(alias_values("root",array(&[alias.0,root.0]).0).unwrap(),expected);
        assert!(alias_values("foreign-primary",good.0).is_err());
        assert!(alias_values("root",std::ptr::null()).is_err());assert!(alias_values("root",root.0).is_err());
        for entries in [vec![],vec![root.0,root.0],vec![root.0,other_case.0],vec![root.0,nul.0],
            vec![root.0,empty.0],vec![root.0,long.0],vec![root.0,good.0],vec![root.0;MAX_ALIASES+1]] {
            assert!(alias_values("root",array(&entries).0).is_err());
        }
        let large=(0..5).map(|index|cf_text(&format!("{index}{}","a".repeat(999))).unwrap()).collect::<Vec<_>>();
        let mut entries=vec![root.0];entries.extend(large.iter().map(|item|item.0));
        assert!(alias_values("root",array(&entries).0).is_err());
    }
}

#[cfg(test)]
#[path="target_accounts_tests.rs"]
mod tests;
