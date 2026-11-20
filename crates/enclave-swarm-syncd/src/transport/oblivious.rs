//! Model download protocol, distinct from compliance-proof uploads. Requests and
//! replies use fresh hybrid OHTTP contexts and fixed 64KiB/4MiB outer quanta.
//! The relay sees TLS endpoints and fixed frames; root/namespace/offset stay encrypted.
//! The signed ciphertext Bao root authenticates leaves before namespace decryption.
use std::{io::{self,Read,Write},net::TcpStream,time::{Duration,Instant}};
use enclave_core::{err,fail,error::EnclaveResult,secret::SecretKey32};
use enclave_crypto::{namespace::{self,WrappedNamespaceKey},ohttp,tuf::TargetFile};
use serde::{Serialize,Deserialize};
use super::registry::{RegistryConfig,DeadlineSocket};

/// Signed relay routing and independent gateway key. No direct-origin address.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObliviousConfig {
    /// TLS relay configuration; repository is an inert routing domain.
    pub relay: RegistryConfig,
    /// Independent TUF-provisioned gateway HPKE public key.
    pub gateway_config_hex: String,
    /// Exact required KEM: X25519 (0x20) or X-Wing (0x647a); no negotiation fallback.
    pub required_kem: u16,
    /// BHTTP origin authority, visible only inside HPKE.
    pub gateway_authority:String,
    /// Fixed outer framing quantum: 65536 (policy) or 4194304 (tensor).
    pub quantum:u32,
    /// Mandatory dedicated volume routing, authenticated by the distribution target.
    pub sealed:crate::snapshot_publication::SealedConfig,
}
impl ObliviousConfig {
    /// Reject unknown suites, unsafe routing and unsupported padding before I/O.
    pub fn validate(&self)->EnclaveResult<()> {
        self.relay.validate()?;
        self.sealed.validate()?;
        if ![65536,4194304].contains(&self.quantum) || self.gateway_authority.is_empty() || self.gateway_authority.len()>253
            || !self.gateway_authority.bytes().all(|b|b.is_ascii_alphanumeric() || b".-".contains(&b)) {fail!(EINVAL,"OHTTP_MODEL_CONFIG");}
        let encoded=hex::decode(&self.gateway_config_hex).map_err(|_|err!(EINVAL,"OHTTP_MODEL_KEY"))?;
        if ![0x20,0x647a].contains(&self.required_kem) || encoded.len()>4096 || encoded.len()<3 || u16::from_be_bytes([encoded[1],encoded[2]])!=self.required_kem {fail!(EPERM,"OHTTP_MODEL_KEM_PIN");}
        let public_len=if self.required_kem==0x20 {32}else{1216};
        // Pin a single HKDF-SHA256/ChaCha20Poly1305 suite. Untrusted config cannot
        // reorder suites to silently select a weaker cipher or add trailing bytes.
        if encoded.len()!=3+public_len+6 || encoded[3+public_len..]!=[0,4,0,1,0,3] {fail!(EINVAL,"OHTTP_MODEL_SUITE");}
        ohttp_rfc::ClientRequest::from_encoded_config(&encoded).map_err(|_|err!(EINVAL,"OHTTP_MODEL_KEY"))?;Ok(())
    }
}
/// Signed per-artifact transport binding. DEKs are opaque custody envelopes.
#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EncryptedTarget {
    /// Exactly one for namespace-keyed leaf framing.
    pub version:u32,
    /// Complete encoded stream's ciphertext Bao root.
    pub ciphertext_bao_root:String,
    /// Ciphertext size excluding Bao parent records.
    pub ciphertext_length:u64,
    /// Separate signed Bao stream of72B wrapped content-key records. This preserves
    /// the16,368B plaintext+16B tag ciphertext-leaf contract.
    pub key_index_bao_root:String,
    /// Exactly one wrapped key record per ciphertext leaf.
    pub key_index_length:u64,
    /// Namespace data key and wrapping epochs.
    pub key:WrappedNamespaceKey,
}
impl EncryptedTarget {
    /// Decode only authenticated metadata; caller must verify its TUF target first.
    pub fn from_target(tf:&TargetFile,namespace:&str)->EnclaveResult<Self> {
        let value=tf.custom.as_ref().and_then(|c|c.get("encrypted_transport")).ok_or_else(||err!(EACCES,"ENCRYPTED_TRANSPORT_REQUIRED"))?;
        let value:Self=serde_json::from_value(value.clone()).map_err(|_|err!(EINVAL,"ENCRYPTED_TRANSPORT_CONFIG"))?;
        value.key.validate()?;
        let leaves=tf.length.div_ceil(namespace::PLAINTEXT_SIZE as u64);
        let expected=tf.length.checked_add(leaves.checked_mul(namespace::CHUNK_OVERHEAD as u64).ok_or_else(||err!(E2BIG,"ENCRYPTED_TRANSPORT_SIZE"))?).ok_or_else(||err!(E2BIG,"ENCRYPTED_TRANSPORT_SIZE"))?;
        if tf.length==0 || value.version!=1 || value.key.namespace!=namespace || value.ciphertext_length!=expected
            || value.key_index_length!=leaves*namespace::KEY_RECORD_SIZE as u64 || value.key_index_bao_root.len()!=64 || !value.key_index_bao_root.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
            || value.ciphertext_bao_root.len()!=64 || !value.ciphertext_bao_root.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)) {fail!(EACCES,"ENCRYPTED_TRANSPORT_BINDING");}Ok(value)
    }
    /// Exact full-range Bao stream length; parent count follows 16KiB groups.
    pub fn encoded_length(size:u64)->EnclaveResult<u64> { let leaves=size.div_ceil(namespace::LEAF_SIZE as u64);
        size.checked_add(leaves.saturating_sub(1).checked_mul(64).ok_or_else(||err!(E2BIG,"ENCRYPTED_TRANSPORT_SIZE"))?).ok_or_else(||err!(E2BIG,"ENCRYPTED_TRANSPORT_SIZE")) }
}
/// Authenticated response payload magic; this framing is inside OHTTP AEAD.
pub const RESPONSE_MAGIC:&[u8;8]=b"CASOHP01";
/// Requested range is bounded by the padding quantum, never the artifact size.
#[derive(Debug,Clone,Serialize,Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RangeRequest {
    /// Exact protocol framing version, currently one.
    pub version:u32,
    /// Namespace protected inside the fresh OHTTP request context.
    pub namespace:String,
    /// Signed ciphertext or wrapped-key-index Bao stream root.
    pub ciphertext_root:String,
    /// Byte offset within the complete signed Bao-encoded stream.
    pub offset:u64,
    /// Exact bounded bytes requested, excluding fixed frame padding.
    pub length:u32,
}
/// Encode the gateway response within a fixed OHTTP plaintext allocation.
fn varint(out:&mut Vec<u8>,v:u64) {match v {0..=63=>out.push(v as u8),64..=16383=>out.extend_from_slice(&((v as u16)|0x4000).to_be_bytes()),_=>out.extend_from_slice(&((v as u32)|0x80000000).to_be_bytes())}}
fn read_varint(bytes:&[u8],at:&mut usize)->EnclaveResult<u64> {let f=*bytes.get(*at).ok_or_else(||err!(EINVAL,"OHTTP_MODEL_BHTTP"))?;let n=1usize<<(f>>6);let b=bytes.get(*at..*at+n).ok_or_else(||err!(EINVAL,"OHTTP_MODEL_BHTTP"))?;let mut v=(f&63) as u64;for x in &b[1..]{v=(v<<8)|*x as u64;}*at+=n;Ok(v)}
/// Encode RFC9292 known-length200 response with an empty field/trailer section.
pub fn response_plaintext(offset:u64,payload:&[u8],quantum:u32)->EnclaveResult<Vec<u8>> {
    if ![65536,4194304].contains(&quantum) || payload.len()>quantum as usize-80 {fail!(E2BIG,"OHTTP_MODEL_FRAME");}
    let mut b=Vec::with_capacity(quantum as usize-48);varint(&mut b,1);varint(&mut b,200);varint(&mut b,0);varint(&mut b,20+payload.len() as u64);
    b.extend_from_slice(RESPONSE_MAGIC);b.extend_from_slice(&offset.to_be_bytes());b.extend_from_slice(&(payload.len() as u32).to_be_bytes());b.extend_from_slice(payload);varint(&mut b,0);b.resize(quantum as usize-48,0);Ok(b)
}
fn request_plaintext(cfg:&ObliviousConfig,namespace:&str,root:&str,offset:u64,length:u32)->EnclaveResult<Vec<u8>> {
    let body=serde_json::to_vec(&RangeRequest {version:1,namespace:namespace.into(),ciphertext_root:root.into(),offset,length}).map_err(|_|err!(EINVAL,"OHTTP_MODEL_REQUEST"))?;
    let mut b=ohttp::bhttp_post(&cfg.gateway_authority,"/v1/cas/range","application/json",&body);
    // Hybrid request = 7B header + 1120B encapsulated key + 16B tag.
    let overhead=7+if cfg.required_kem==0x20 {32}else{1120}+16;
    let bound=(cfg.quantum as usize).checked_sub(overhead).ok_or_else(||err!(E2BIG,"OHTTP_MODEL_FRAME"))?;
    if b.len()>bound {fail!(E2BIG,"OHTTP_MODEL_FRAME");}b.resize(bound,0);Ok(b)
}
fn frame(cfg:&ObliviousConfig,namespace:&str,root:&str,offset:u64,length:u32,deadline:Instant)->EnclaveResult<Vec<u8>> {
    let request=request_plaintext(cfg,namespace,root,offset,length)?;
    let encoded=hex::decode(&cfg.gateway_config_hex).map_err(|_|err!(EINVAL,"OHTTP_MODEL_KEY"))?;
    let (encrypted,context)=ohttp_rfc::ClientRequest::from_encoded_config(&encoded).and_then(|c|c.encapsulate(&request)).map_err(|_|err!(EACCES,"OHTTP_MODEL_ENCAPSULATE"))?;
    if encrypted.len()!=cfg.quantum as usize {fail!(EIO,"OHTTP_MODEL_FRAME");}
    let (address,name,tls)=cfg.relay.validate()?;
    let left=deadline.saturating_duration_since(Instant::now());if left.is_zero(){fail!(ETIMEDOUT,"OHTTP_MODEL_DEADLINE");}
    let socket=TcpStream::connect_timeout(&address,left).map_err(|e|err!(EIO,"OHTTP_MODEL_CONNECT","{e}"))?;
    let transport=DeadlineSocket {socket,deadline};let conn=rustls::ClientConnection::new(tls,name).map_err(|_|err!(EIO,"OHTTP_MODEL_TLS"))?;
    let mut stream=rustls::StreamOwned::new(conn,transport);
    while stream.conn.is_handshaking(){stream.conn.complete_io(&mut stream.sock).map_err(|e|err!(EACCES,"OHTTP_MODEL_TLS","{e}"))?;}
    let head=format!("POST /relay HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: message/ohttp-req\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",cfg.relay.server_name,address.port(),encrypted.len());
    stream.write_all(head.as_bytes()).and_then(|()|stream.write_all(&encrypted)).and_then(|()|stream.flush()).map_err(|e|err!(EIO,"OHTTP_MODEL_WRITE","{e}"))?;
    let mut header=Vec::with_capacity(1024);
    while !header.ends_with(b"\r\n\r\n") {if header.len()>=16384 {fail!(E2BIG,"OHTTP_MODEL_HEADERS");}let mut byte=[0];stream.read_exact(&mut byte).map_err(|e|err!(EIO,"OHTTP_MODEL_HEADERS","{e}"))?;header.push(byte[0]);}
    let text=std::str::from_utf8(&header).map_err(|_|err!(EINVAL,"OHTTP_MODEL_HEADERS"))?;let mut lines=text[..text.len()-4].split("\r\n");
    if !matches!(lines.next(),Some("HTTP/1.1 200 OK"|"HTTP/1.0 200 OK")){fail!(EACCES,"OHTTP_MODEL_STATUS");}
    let mut headers=std::collections::BTreeMap::new();
    for (i,line) in lines.enumerate() {let (key,value)=line.split_once(':').ok_or_else(||err!(EINVAL,"OHTTP_MODEL_HEADERS"))?;
        if i>=128 || key.is_empty() || !key.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-') || value.bytes().any(|b|b.is_ascii_control()&&b!=b'\t')
            || headers.insert(key.to_ascii_lowercase(),value.trim()).is_some(){fail!(EINVAL,"OHTTP_MODEL_HEADERS");}}
    if headers.get("content-length").copied()!=Some(cfg.quantum.to_string().as_str()) || headers.get("content-type").copied()!=Some("message/ohttp-res") || headers.contains_key("transfer-encoding")
        || headers.get("content-encoding").is_some_and(|v|*v!="identity") {fail!(EACCES,"OHTTP_MODEL_FRAMING");}
    let mut response=vec![0u8;cfg.quantum as usize];stream.read_exact(&mut response).map_err(|e|err!(EIO,"OHTTP_MODEL_READ","{e}"))?;
    let mut extra=[0];if stream.read(&mut extra).map_err(|e|err!(EIO,"OHTTP_MODEL_READ","{e}"))?!=0 {fail!(EACCES,"OHTTP_MODEL_TRAILING");}
    let plain=context.decapsulate(&response).map_err(|_|err!(EACCES,"OHTTP_MODEL_RESPONSE_AUTH"))?;
    if plain.len()!=cfg.quantum as usize-48 {fail!(EACCES,"OHTTP_MODEL_CONTEXT");}
    let mut at=0;if read_varint(&plain,&mut at)?!=1 || read_varint(&plain,&mut at)?!=200 || read_varint(&plain,&mut at)?!=0 {fail!(EACCES,"OHTTP_MODEL_BHTTP");}
    if read_varint(&plain,&mut at)?!=20+length as u64 {fail!(EACCES,"OHTTP_MODEL_CONTEXT");}
    let body=plain.get(at..at+20+length as usize).ok_or_else(||err!(EACCES,"OHTTP_MODEL_CONTEXT"))?;at+=body.len();
    if read_varint(&plain,&mut at)?!=0 || plain[at..].iter().any(|b|*b!=0) || body.get(..8)!=Some(RESPONSE_MAGIC.as_slice())
        || u64::from_be_bytes(body[8..16].try_into().unwrap())!=offset || u32::from_be_bytes(body[16..20].try_into().unwrap())!=length {fail!(EACCES,"OHTTP_MODEL_CONTEXT");}
    Ok(body[20..].to_vec())
}
struct RelayReader<'a> {cfg:&'a ObliviousConfig,namespace:&'a str,root:&'a str,offset:u64,total:u64,buffer:io::Cursor<Vec<u8>>,deadline:Instant}
impl Read for RelayReader<'_> {
    fn read(&mut self,out:&mut [u8])->io::Result<usize> {
        if out.is_empty(){return Ok(0);}if self.buffer.position() as usize==self.buffer.get_ref().len() {
            if self.offset==self.total {return Ok(0);}let n=(self.total-self.offset).min(self.cfg.quantum as u64-80) as u32;
            let bytes=frame(self.cfg,self.namespace,self.root,self.offset,n,self.deadline).map_err(|e|io::Error::new(io::ErrorKind::PermissionDenied,e.to_string()))?;
            self.offset+=n as u64;self.buffer=io::Cursor::new(bytes);
        }self.buffer.read(out)
    }
}
/// Download, Bao-authenticate then decrypt each bounded leaf into an unpublished
/// stage callback. The caller must revalidate custody/metadata and commit atomically.
/// A software fixture key is not production hardware-custody acceptance evidence.
pub fn fetch(cfg:&ObliviousConfig,tf:&TargetFile,target:&EncryptedTarget,key:&SecretKey32,mut accept:impl FnMut(&[u8])->EnclaveResult<()>)->EnclaveResult<()> {
    cfg.validate()?;crate::streaming::validate_target(tf)?;super::ohttp_fetch::assert_l3_zero_listeners()?;
    let deadline=Instant::now()+Duration::from_millis(cfg.relay.timeout_ms);
    let ciphertext=RelayReader {cfg,namespace:&target.key.namespace,root:&target.ciphertext_bao_root,offset:0,total:EncryptedTarget::encoded_length(target.ciphertext_length)?,buffer:io::Cursor::new(vec![]),deadline};
    let keys=RelayReader {cfg,namespace:&target.key.namespace,root:&target.key_index_bao_root,offset:0,total:EncryptedTarget::encoded_length(target.key_index_length)?,buffer:io::Cursor::new(vec![]),deadline};
    verify_encrypted_streams(tf,target,key,ciphertext,keys,&mut accept)
}
/// Shared bounded verifier used after either authenticated QUIC or OHTTP I/O.
/// Both streams must include exact full-range Bao encodings, never unverified slices.
pub fn verify_encrypted_streams(tf:&TargetFile,target:&EncryptedTarget,key:&SecretKey32,mut ciphertext:impl Read,mut keys:impl Read,mut accept:impl FnMut(&[u8])->EnclaveResult<()>)->EnclaveResult<()> {
    use bao_tree::{io::{sync::DecodeResponseIter,BaoContentItem},BaoTree,ChunkRanges};
    crate::streaming::validate_target(tf)?;target.key.validate()?;
    let root:[u8;32]=hex::decode(&tf.hashes["blake3"]).map_err(|_|err!(EINVAL,"OHTTP_MODEL_ROOT"))?.try_into().map_err(|_|err!(EINVAL,"OHTTP_MODEL_ROOT"))?;
    let expected=bao_tree::blake3::Hash::from_hex(&target.ciphertext_bao_root).map_err(|_|err!(EINVAL,"OHTTP_MODEL_ROOT"))?;
    let key_root=bao_tree::blake3::Hash::from_hex(&target.key_index_bao_root).map_err(|_|err!(EINVAL,"OHTTP_MODEL_ROOT"))?;
    let all=ChunkRanges::all();let mut key_iter=DecodeResponseIter::new(key_root,BaoTree::new(target.key_index_length,crate::bao::block_size()),&mut keys,&all);
    let mut key_buffer=io::Cursor::new(Vec::new());let mut key_record=[0u8;namespace::KEY_RECORD_SIZE];
    let tree=BaoTree::new(target.ciphertext_length,crate::bao::block_size());let mut iter=DecodeResponseIter::new(expected,tree,&mut ciphertext,&all);let mut index=0;let mut total=0u64;
    let leaves=target.ciphertext_length.div_ceil(namespace::LEAF_SIZE as u64);
    for item in &mut iter {if let BaoContentItem::Leaf(leaf)=item.map_err(|e|err!(EACCES,"BAO_SLICE_CORRUPT","{e}"))? {
        let mut got=0;while got<key_record.len() {
            let n=key_buffer.read(&mut key_record[got..]).map_err(|_|err!(EIO,"KEY_INDEX_READ"))?;
            if n>0 {got+=n;continue;}loop {match key_iter.next() {
                Some(Ok(BaoContentItem::Leaf(leaf)))=>{key_buffer=io::Cursor::new(leaf.data.to_vec());break;},Some(Ok(BaoContentItem::Parent(_)))=>(),
                Some(Err(e))=>return Err(err!(EACCES,"BAO_KEY_INDEX_CORRUPT","{e}")),None=>return Err(err!(EACCES,"BAO_KEY_INDEX_TRUNCATED")),
            }}
        }
        let plain=namespace::decrypt_chunk(key,&root,index,index+1==leaves,&leaf.data,&key_record)?;total=total.checked_add(plain.len() as u64).ok_or_else(||err!(E2BIG,"OHTTP_MODEL_LENGTH"))?;
        if total>tf.length {fail!(EACCES,"OHTTP_MODEL_LENGTH");}accept(&plain)?;index+=1;
    }}
    if index!=leaves || total!=tf.length || key_buffer.position() as usize!=key_buffer.get_ref().len() {fail!(EACCES,"OHTTP_MODEL_LENGTH");}
    drop(iter);
    for item in &mut key_iter {match item {Ok(BaoContentItem::Parent(_))=>(),_=>fail!(EACCES,"BAO_KEY_INDEX_TRAILING")}}
    drop(key_iter);
    let mut trailing=[0u8;1];
    if ciphertext.read(&mut trailing).map_err(|_|err!(EIO,"BAO_STREAM_EOF"))?!=0 || keys.read(&mut trailing).map_err(|_|err!(EIO,"BAO_STREAM_EOF"))?!=0 {fail!(EACCES,"BAO_STREAM_TRAILING");}
    Ok(())
}
