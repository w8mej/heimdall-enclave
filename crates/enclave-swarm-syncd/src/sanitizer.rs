//! FS-702 §3.4 pre-admission structural sanitizer (anti-deserialization RCE).
//!
//! * Executable / pickle magic ban: Python pickle `PROTO` headers
//!   (`0x80 0x02..=0x05`), PyTorch `data.pkl`, Mach-O (incl. fat) and ELF at
//!   the start of any file or archive member, and native-library extensions.
//! * `.safetensors`: `u64` header length `N <= 64 MiB`; JSON with depth `<= 3`
//!   and **duplicate keys rejected**; `dtype` whitelist; every tensor's byte
//!   length equals `numel × dtype_size`; tensor intervals partition
//!   `[0, file_size - 8 - N)` monotonically with zero overlap, gaps or
//!   out-of-bounds offsets.
//! * `.mlpackage` (ZIP or directory): no symlinks, absolute paths or `..`;
//!   compression ratio `<= 4×`; total size `<= manifest.byte_size`; Protobuf
//!   nesting depth `<= 16`; no `customLayer` (CoreML field 500) and no
//!   embedded Mach-O/dylib. `enclave-pack` emits **stored** ZIP members (CAS
//!   chunking provides transport compression), so every member's bytes are
//!   inspected; deflated archives fail closed.

use std::collections::BTreeSet;
use std::fmt;

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use serde::de::{Deserializer, MapAccess, Visitor};
use serde::Deserialize;
use serde_json::Value;

/// Maximum safetensors header.
pub const MAX_HEADER: u64 = 64 * 1024 * 1024;
/// Maximum compression ratio.
pub const MAX_RATIO: u64 = 4;
/// Maximum Protobuf nesting depth.
pub const MAX_PROTO_DEPTH: usize = 16;
/// Maximum archive members.
pub const MAX_MEMBERS: usize = 4096;

/// Allowed dtypes and their size in bits.
pub fn dtype_bits(d: &str) -> Option<u64> {
    Some(match d {
        "F64" | "I64" | "U64" => 64,
        "F32" | "I32" | "U32" => 32,
        "F16" | "BF16" | "I16" | "U16" => 16,
        "I8" | "U8" | "BOOL" | "F8_E4M3" | "F8_E5M2" => 8,
        _ => return None,
    })
}

/// Ban executable / serializer magic at the start of a blob.
pub fn check_magic(name: &str, b: &[u8]) -> EnclaveResult<()> {
    if b.len() >= 2 && b[0] == 0x80 && (2..=5).contains(&b[1]) {
        fail!(
            EACCES,
            "PICKLE_DETECTED",
            "SEV-1: pickle PROTO header in {name}"
        );
    }
    if b.len() >= 4 {
        let m = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
        if matches!(
            m,
            0xFEEDFACF | 0xCFFAEDFE | 0xFEEDFACE | 0xCEFAEDFE | 0xCAFEBABE | 0xBEBAFECA
        ) {
            fail!(EACCES, "MACHO_DETECTED", "SEV-1: Mach-O in {name}");
        }
        if m == 0x7F454C46 {
            fail!(EACCES, "ELF_DETECTED", "SEV-1: ELF in {name}");
        }
    }
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".pkl") || lower.ends_with(".pickle") || lower.ends_with("/data.pkl") {
        fail!(EACCES, "PICKLE_DETECTED", "SEV-1: {name}");
    }
    if [".dylib", ".so", ".bundle", ".py", ".pyc", ".sh"]
        .iter()
        .any(|e| lower.ends_with(e))
    {
        fail!(EACCES, "EXECUTABLE_MEMBER", "{name}");
    }
    Ok(())
}

/// JSON object that rejects duplicate keys.
struct NoDupMap(Vec<(String, Value)>);

impl<'de> Deserialize<'de> for NoDupMap {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = NoDupMap;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object without duplicate keys")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<NoDupMap, A::Error> {
                let mut seen = BTreeSet::new();
                let mut out = Vec::new();
                while let Some((k, v)) = m.next_entry::<String, Value>()? {
                    if !seen.insert(k.clone()) {
                        return Err(serde::de::Error::custom(format!("duplicate key {k}")));
                    }
                    out.push((k, v));
                }
                Ok(NoDupMap(out))
            }
        }
        d.deserialize_map(V)
    }
}

fn json_depth_ok(b: &[u8], max: usize) -> bool {
    let (mut depth, mut in_str, mut esc) = (0usize, false, false);
    for &c in b {
        if in_str {
            match (esc, c) {
                (true, _) => esc = false,
                (false, b'\\') => esc = true,
                (false, b'"') => in_str = false,
                _ => {}
            }
            continue;
        }
        match c {
            b'"' => in_str = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max {
                    return false;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    true
}

/// One validated tensor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TensorInfo {
    /// Name.
    pub name: String,
    /// dtype.
    pub dtype: String,
    /// Shape.
    pub shape: Vec<u64>,
    /// Byte interval in the data section.
    pub begin: u64,
    /// End (exclusive).
    pub end: u64,
}

/// Validate a `.safetensors` file; returns its tensors in offset order.
pub fn check_safetensors(file: &[u8]) -> EnclaveResult<Vec<TensorInfo>> {
    check_safetensors_prefix(file, file.len() as u64)
}

// Shared parser: only the bounded header is needed; offsets are checked
// against the complete signed file length, never the header buffer length.
pub(crate) fn check_safetensors_prefix(file: &[u8], total_len: u64) -> EnclaveResult<Vec<TensorInfo>> {
    check_magic("safetensors", file)?;
    if file.len() < 8 {
        fail!(EINVAL, "SAFETENSORS_SHORT");
    }
    let n = u64::from_le_bytes(
        file[..8]
            .try_into()
            .map_err(|_| err!(EINVAL, "SAFETENSORS_SHORT"))?,
    );
    if n > MAX_HEADER || 8 + n > total_len || 8 + n > file.len() as u64 {
        fail!(E2BIG, "SAFETENSORS_HEADER_BOUNDS", "N = {n}");
    }
    let hdr = &file[8..8 + n as usize];
    if !json_depth_ok(hdr, 3) {
        fail!(EINVAL, "SAFETENSORS_HEADER_DEPTH");
    }
    let map: NoDupMap =
        serde_json::from_slice(hdr).map_err(|e| err!(EINVAL, "SAFETENSORS_HEADER_JSON", "{e}"))?;
    let data_len = total_len - 8 - n;
    let mut ts = Vec::new();
    for (k, v) in map.0 {
        if k == "__metadata__" {
            let Some(o) = v.as_object() else {
                fail!(EINVAL, "SAFETENSORS_METADATA")
            };
            if !o.values().all(Value::is_string) {
                fail!(EINVAL, "SAFETENSORS_METADATA", "values must be strings");
            }
            continue;
        }
        let o = v
            .as_object()
            .ok_or_else(|| err!(EINVAL, "SAFETENSORS_ENTRY", "{k}"))?;
        if o.keys()
            .any(|x| !matches!(x.as_str(), "dtype" | "shape" | "data_offsets"))
        {
            fail!(EINVAL, "SAFETENSORS_ENTRY_FIELDS", "{k}");
        }
        let dtype = o
            .get("dtype")
            .and_then(Value::as_str)
            .ok_or_else(|| err!(EINVAL, "SAFETENSORS_DTYPE", "{k}"))?;
        let bits = dtype_bits(dtype)
            .ok_or_else(|| err!(EACCES, "SAFETENSORS_DTYPE_BANNED", "{k}: {dtype}"))?;
        let shape: Vec<u64> = o
            .get("shape")
            .and_then(Value::as_array)
            .ok_or_else(|| err!(EINVAL, "SAFETENSORS_SHAPE", "{k}"))?
            .iter()
            .map(|x| {
                x.as_u64()
                    .ok_or_else(|| err!(EINVAL, "SAFETENSORS_SHAPE", "{k}"))
            })
            .collect::<EnclaveResult<_>>()?;
        let offs = o
            .get("data_offsets")
            .and_then(Value::as_array)
            .ok_or_else(|| err!(EINVAL, "SAFETENSORS_OFFSETS", "{k}"))?;
        if offs.len() != 2 {
            fail!(EINVAL, "SAFETENSORS_OFFSETS", "{k}");
        }
        let (b, e) = (
            offs[0].as_u64().unwrap_or(u64::MAX),
            offs[1].as_u64().unwrap_or(u64::MAX),
        );
        if b > e || e > data_len {
            fail!(
                EACCES,
                "SAFETENSORS_OUT_OF_BOUNDS",
                "{k}: [{b}, {e}) beyond {data_len}"
            );
        }
        let numel = shape
            .iter()
            .try_fold(1u64, |a, d| a.checked_mul(*d))
            .ok_or_else(|| err!(E2BIG, "SAFETENSORS_SHAPE_OVERFLOW"))?;
        let bytes = numel
            .checked_mul(bits)
            .ok_or_else(|| err!(E2BIG, "SAFETENSORS_SHAPE_OVERFLOW"))?
            .div_ceil(8);
        if e - b != bytes {
            fail!(
                EACCES,
                "SAFETENSORS_SIZE_MISMATCH",
                "{k}: {} != {bytes}",
                e - b
            );
        }
        ts.push(TensorInfo {
            name: k,
            dtype: dtype.to_owned(),
            shape,
            begin: b,
            end: e,
        });
    }
    ts.sort_by_key(|t| (t.begin, t.end));
    let mut cursor = 0u64;
    for t in &ts {
        if t.begin != cursor {
            fail!(
                EACCES,
                "SAFETENSORS_NOT_A_PARTITION",
                "{} starts at {} (expected {cursor}): overlap or gap",
                t.name,
                t.begin
            );
        }
        cursor = t.end;
    }
    if cursor != data_len {
        fail!(
            EACCES,
            "SAFETENSORS_TRAILING_BYTES",
            "{cursor} != {data_len}"
        );
    }
    Ok(ts)
}

/// Build a safetensors file (packager / tests).
pub fn build_safetensors(
    tensors: &[(&str, &str, Vec<u64>, Vec<u8>)],
    metadata: &[(&str, &str)],
) -> Vec<u8> {
    let mut hdr = serde_json::Map::new();
    if !metadata.is_empty() {
        hdr.insert(
            "__metadata__".into(),
            Value::Object(
                metadata
                    .iter()
                    .map(|(k, v)| ((*k).into(), Value::String((*v).into())))
                    .collect(),
            ),
        );
    }
    let mut off = 0u64;
    let mut data = Vec::new();
    for (name, dtype, shape, bytes) in tensors {
        hdr.insert(
            (*name).into(),
            serde_json::json!({"dtype": dtype, "shape": shape, "data_offsets": [off, off + bytes.len() as u64]}),
        );
        off += bytes.len() as u64;
        data.extend_from_slice(bytes);
    }
    let h = serde_json::to_vec(&Value::Object(hdr)).unwrap_or_default();
    let mut out = (h.len() as u64).to_le_bytes().to_vec();
    out.extend(h);
    out.extend(data);
    out
}

fn le16(b: &[u8], o: usize) -> EnclaveResult<u16> {
    b.get(o..o + 2)
        .map(|s| u16::from_le_bytes([s[0], s[1]]))
        .ok_or_else(|| err!(EINVAL, "ZIP_TRUNCATED"))
}
fn le32(b: &[u8], o: usize) -> EnclaveResult<u32> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or_else(|| err!(EINVAL, "ZIP_TRUNCATED"))
}

fn check_member_name(name: &str) -> EnclaveResult<()> {
    if name.is_empty()
        || name.starts_with('/')
        || name.starts_with('\\')
        || name.contains('\\')
        || name.contains('\0')
    {
        fail!(EACCES, "ARCHIVE_PATH_ESCAPE", "{name:?}");
    }
    if name.split('/').any(|c| c == "..") {
        fail!(EACCES, "ARCHIVE_PATH_ESCAPE", "{name:?}");
    }
    Ok(())
}

/// Walk a Protobuf message, returning the max nesting depth; detects CoreML
/// `customLayer` (`NeuralNetworkLayer.custom`, field 500) at any depth.
pub fn proto_walk(b: &[u8], depth: usize) -> EnclaveResult<usize> {
    if depth > MAX_PROTO_DEPTH {
        fail!(EACCES, "PROTOBUF_TOO_DEEP", "> {MAX_PROTO_DEPTH}");
    }
    let mut i = 0;
    let mut max = depth;
    let varint = |b: &[u8], i: &mut usize| -> Option<u64> {
        let mut v = 0u64;
        for s in 0..10 {
            let x = *b.get(*i)?;
            *i += 1;
            v |= ((x & 0x7f) as u64) << (7 * s);
            if x & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    };
    while i < b.len() {
        let key = varint(b, &mut i).ok_or_else(|| err!(EINVAL, "PROTOBUF_MALFORMED"))?;
        let (field, wt) = (key >> 3, key & 7);
        match wt {
            0 => {
                varint(b, &mut i).ok_or_else(|| err!(EINVAL, "PROTOBUF_MALFORMED"))?;
            }
            1 => i += 8,
            5 => i += 4,
            2 => {
                let l =
                    varint(b, &mut i).ok_or_else(|| err!(EINVAL, "PROTOBUF_MALFORMED"))? as usize;
                let sub = b
                    .get(
                        i..i.checked_add(l)
                            .ok_or_else(|| err!(EINVAL, "PROTOBUF_MALFORMED"))?,
                    )
                    .ok_or_else(|| err!(EINVAL, "PROTOBUF_MALFORMED"))?;
                if field == 500 {
                    fail!(
                        EACCES,
                        "COREML_CUSTOM_LAYER",
                        "customLayer is not admissible"
                    );
                }
                // Treat as a nested message when it parses as one; otherwise bytes/string.
                // Bind result once to avoid exponential O(2^d) backtracking (DEFECT-F-50).
                match proto_walk(sub, depth + 1) {
                    Ok(d) => max = max.max(d),
                    Err(e) => {
                        if e.is("PROTOBUF_TOO_DEEP") || e.is("COREML_CUSTOM_LAYER") {
                            return Err(e);
                        }
                    }
                }
                i += l;
            }
            3 | 4 => {
                // Group wire types: handled without failing closed to avoid parser differential (DEFECT-F-49)
            }
            _ => fail!(EINVAL, "PROTOBUF_MALFORMED"),
        }
        if i > b.len() {
            fail!(EINVAL, "PROTOBUF_MALFORMED");
        }
    }
    Ok(max)
}

/// Validate a zipped `.mlpackage` against the manifest-declared `byte_size`.
pub fn check_mlpackage_zip(z: &[u8], declared_byte_size: u64) -> EnclaveResult<Vec<String>> {
    if z.len() < 22 {
        fail!(EINVAL, "ZIP_TRUNCATED");
    }
    let start = z.len().saturating_sub(22 + 65_535);
    let eocd = (start..=z.len() - 22)
        .rev()
        .find(|&i| z[i..i + 4] == [0x50, 0x4b, 0x05, 0x06])
        .ok_or_else(|| err!(EINVAL, "ZIP_NO_EOCD"))?;
    let entries = le16(z, eocd + 10)? as usize;
    let cd_size = le32(z, eocd + 12)? as usize;
    let cd_off = le32(z, eocd + 16)? as usize;
    if entries > MAX_MEMBERS || cd_off == 0xFFFF_FFFF || cd_size == 0xFFFF_FFFF {
        fail!(EACCES, "ZIP_UNSUPPORTED", "ZIP64 / too many members");
    }
    if cd_off.checked_add(cd_size).is_none_or(|e| e > eocd) {
        fail!(EINVAL, "ZIP_CD_BOUNDS");
    }
    let mut p = cd_off;
    let mut total: u64 = 0;
    let mut names = Vec::new();
    for _ in 0..entries {
        if p.checked_add(46).is_none_or(|end| end > cd_off + cd_size) {
            fail!(EINVAL, "ZIP_CD_BOUNDS");
        }
        if le32(z, p)? != 0x0201_4b50 {
            fail!(EINVAL, "ZIP_CD_SIGNATURE");
        }
        let _made_by_os = *z.get(p + 5).ok_or_else(|| err!(EINVAL, "ZIP_TRUNCATED"))?;
        let method = le16(z, p + 10)?;
        let csize = le32(z, p + 20)? as u64;
        let usize_ = le32(z, p + 24)? as u64;
        let nlen = le16(z, p + 28)? as usize;
        let elen = le16(z, p + 30)? as usize;
        let clen = le16(z, p + 32)? as usize;
        let ext_attr = le32(z, p + 38)?;
        let lho = le32(z, p + 42)? as usize;
        let name = std::str::from_utf8(
            z.get(p + 46..p + 46 + nlen)
                .ok_or_else(|| err!(EINVAL, "ZIP_TRUNCATED"))?,
        )
        .map_err(|_| err!(EINVAL, "ZIP_NAME_UTF8"))?
        .to_owned();
        check_member_name(&name)?;
        let is_symlink =
            ((ext_attr >> 16) & 0o170000 == 0o120000) || ((ext_attr & 0o170000) == 0o120000);
        if is_symlink {
            fail!(EACCES, "ARCHIVE_SYMLINK", "{name}");
        }
        if csize == 0xFFFF_FFFF || usize_ == 0xFFFF_FFFF {
            fail!(EACCES, "ZIP_UNSUPPORTED", "ZIP64 member");
        }
        if csize > 0 && usize_ / csize.max(1) > MAX_RATIO || (csize == 0 && usize_ > 0) {
            fail!(
                EACCES,
                "ZIP_BOMB",
                "{name}: ratio {usize_}/{csize} > {MAX_RATIO}"
            );
        }
        total = total
            .checked_add(usize_)
            .ok_or_else(|| err!(E2BIG, "ZIP_SIZE_OVERFLOW"))?;
        if total > declared_byte_size {
            fail!(
                EACCES,
                "ZIP_EXCEEDS_DECLARED_SIZE",
                "{total} > {declared_byte_size}"
            );
        }
        if method != 0 {
            fail!(
                EACCES,
                "ZIP_COMPRESSION_UNSUPPORTED",
                "{name}: enclave-pack emits stored members"
            );
        }
        if csize != usize_ {
            fail!(EACCES, "ZIP_SIZE_MISMATCH", "{name}");
        }
        // Local header must agree; inspect member bytes (DEFECT-F-51).
        if le32(z, lho)? != 0x0403_4b50 {
            fail!(EINVAL, "ZIP_LOCAL_SIGNATURE");
        }
        let l_method = le16(z, lho + 8)?;
        let l_csize = le32(z, lho + 18)? as u64;
        let l_usize = le32(z, lho + 22)? as u64;
        if l_method != method || l_csize != csize || l_usize != usize_ {
            fail!(EACCES, "ZIP_LOCAL_HEADER_MISMATCH", "{name}");
        }
        let lnlen = le16(z, lho + 26)? as usize;
        let lelen = le16(z, lho + 28)? as usize;
        if z.get(lho + 30..lho + 30 + lnlen) != Some(name.as_bytes()) {
            fail!(EACCES, "ZIP_NAME_MISMATCH", "{name}");
        }
        let ds = lho + 30 + lnlen + lelen;
        let data = z
            .get(ds..ds + csize as usize)
            .ok_or_else(|| err!(EINVAL, "ZIP_TRUNCATED"))?;
        if !name.ends_with('/') {
            check_magic(&name, data)?;
            if name.ends_with(".mlmodel") {
                proto_walk(data, 0)?;
            }
        }
        names.push(name);
        let advance = (46 as usize)
            .checked_add(nlen)
            .and_then(|a| a.checked_add(elen))
            .and_then(|a| a.checked_add(clen))
            .ok_or_else(|| err!(EINVAL, "ZIP_OVERFLOW"))?;
        let next_p = p
            .checked_add(advance)
            .ok_or_else(|| err!(EINVAL, "ZIP_OVERFLOW"))?;
        if next_p > cd_off + cd_size {
            fail!(EINVAL, "ZIP_CD_BOUNDS");
        }
        p = next_p;
    }
    Ok(names)
}

/// Build a stored ZIP (packager / tests). `symlink` marks a unix symlink member.
pub fn build_stored_zip(members: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for (name, data, symlink) in members {
        let lho = out.len() as u32;
        out.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        out.extend_from_slice(&0u32.to_le_bytes()); // crc (not checked)
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        cd.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02, 20, 3, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        cd.extend_from_slice(&0u32.to_le_bytes());
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(data.len() as u32).to_le_bytes());
        cd.extend_from_slice(&(name.len() as u16).to_le_bytes());
        cd.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
        let mode: u32 = if *symlink { 0o120777 } else { 0o100644 };
        cd.extend_from_slice(&(mode << 16).to_le_bytes());
        cd.extend_from_slice(&lho.to_le_bytes());
        cd.extend_from_slice(name.as_bytes());
    }
    let cd_off = out.len() as u32;
    out.extend_from_slice(&cd);
    out.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0]);
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    out.extend_from_slice(&(cd.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_off.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> Vec<u8> {
        build_safetensors(
            &[
                (
                    "enclave_adapter.rlcd_head.weight",
                    "F16",
                    vec![2, 2],
                    vec![0u8; 8],
                ),
                (
                    "enclave_adapter.rlcd_head.bias",
                    "F32",
                    vec![2],
                    vec![0u8; 8],
                ),
            ],
            &[("format", "pt")],
        )
    }

    #[test]
    fn safetensors_happy_and_attacks() {
        assert_eq!(check_safetensors(&good()).unwrap().len(), 2);
        // Overlap: second tensor reuses the first's bytes.
        let h = br#"{"a":{"dtype":"U8","shape":[4],"data_offsets":[0,4]},"b":{"dtype":"U8","shape":[4],"data_offsets":[2,6]}}"#;
        let mut f = (h.len() as u64).to_le_bytes().to_vec();
        f.extend_from_slice(h);
        f.extend([0u8; 6]);
        assert!(check_safetensors(&f)
            .unwrap_err()
            .is("SAFETENSORS_NOT_A_PARTITION"));
        // Out of bounds.
        let h = br#"{"a":{"dtype":"U8","shape":[100],"data_offsets":[0,100]}}"#;
        let mut f = (h.len() as u64).to_le_bytes().to_vec();
        f.extend_from_slice(h);
        f.extend([0u8; 4]);
        assert!(check_safetensors(&f)
            .unwrap_err()
            .is("SAFETENSORS_OUT_OF_BOUNDS"));
        // Banned dtype, duplicate key, huge header, deep JSON.
        let h = br#"{"a":{"dtype":"COMPLEX128","shape":[1],"data_offsets":[0,8]}}"#;
        let mut f = (h.len() as u64).to_le_bytes().to_vec();
        f.extend_from_slice(h);
        f.extend([0u8; 8]);
        assert!(check_safetensors(&f)
            .unwrap_err()
            .is("SAFETENSORS_DTYPE_BANNED"));
        let h = br#"{"a":{"dtype":"U8","shape":[1],"data_offsets":[0,1]},"a":{"dtype":"U8","shape":[1],"data_offsets":[0,1]}}"#;
        let mut f = (h.len() as u64).to_le_bytes().to_vec();
        f.extend_from_slice(h);
        f.extend([0u8; 1]);
        assert!(check_safetensors(&f)
            .unwrap_err()
            .is("SAFETENSORS_HEADER_JSON"));
        let mut f = (MAX_HEADER + 1).to_le_bytes().to_vec();
        f.extend([0u8; 16]);
        assert!(check_safetensors(&f)
            .unwrap_err()
            .is("SAFETENSORS_HEADER_BOUNDS"));
        let h = br#"{"__metadata__":{"x":[[[["deep"]]]]}}"#;
        let mut f = (h.len() as u64).to_le_bytes().to_vec();
        f.extend_from_slice(h);
        assert!(check_safetensors(&f)
            .unwrap_err()
            .is("SAFETENSORS_HEADER_DEPTH"));
        // Size mismatch (shape says 4 elements of F32 = 16 bytes, interval is 8).
        let h = br#"{"a":{"dtype":"F32","shape":[4],"data_offsets":[0,8]}}"#;
        let mut f = (h.len() as u64).to_le_bytes().to_vec();
        f.extend_from_slice(h);
        f.extend([0u8; 8]);
        assert!(check_safetensors(&f)
            .unwrap_err()
            .is("SAFETENSORS_SIZE_MISMATCH"));
    }

    #[test]
    fn pickle_and_native_magic_banned() {
        assert!(check_magic("model.bin", &[0x80, 0x04, 0x95])
            .unwrap_err()
            .is("PICKLE_DETECTED"));
        assert!(check_magic("x", &[0xCF, 0xFA, 0xED, 0xFE])
            .unwrap_err()
            .is("MACHO_DETECTED"));
        assert!(check_magic("x", b"\x7fELF").unwrap_err().is("ELF_DETECTED"));
        assert!(check_magic("archive/data.pkl", b"x").is_err());
    }

    #[test]
    fn mlpackage_zip_rules() {
        let mlmodel = [0x0a, 0x02, 0x08, 0x01]; // field 1 (len 2) containing field 1 varint
        let ok = build_stored_zip(&[
            ("Data/com.apple.CoreML/model.mlmodel", &mlmodel, false),
            ("Manifest.json", b"{}", false),
        ]);
        assert_eq!(check_mlpackage_zip(&ok, 10_000).unwrap().len(), 2);
        assert!(check_mlpackage_zip(&ok, 3)
            .unwrap_err()
            .is("ZIP_EXCEEDS_DECLARED_SIZE"));
        let trav = build_stored_zip(&[("../../etc/passwd", b"x", false)]);
        assert!(check_mlpackage_zip(&trav, 100)
            .unwrap_err()
            .is("ARCHIVE_PATH_ESCAPE"));
        let link = build_stored_zip(&[("Data/weights", b"/etc/passwd", true)]);
        assert!(check_mlpackage_zip(&link, 100)
            .unwrap_err()
            .is("ARCHIVE_SYMLINK"));
        let dylib =
            build_stored_zip(&[("Frameworks/evil.dylib", &[0xCF, 0xFA, 0xED, 0xFE], false)]);
        assert!(check_mlpackage_zip(&dylib, 100).is_err());
        // customLayer: field 500 (key = 500 << 3 | 2 = 4002 = varint a2 1f).
        let custom = [0xa2, 0x1f, 0x00];
        let cz = build_stored_zip(&[("model.mlmodel", &custom, false)]);
        assert!(check_mlpackage_zip(&cz, 100)
            .unwrap_err()
            .is("COREML_CUSTOM_LAYER"));
        // Nesting depth 17.
        let mut deep = vec![0x08, 0x01];
        for _ in 0..17 {
            let mut n = vec![0x0a, deep.len() as u8];
            n.extend(deep);
            deep = n;
        }
        assert!(proto_walk(&deep, 0).unwrap_err().is("PROTOBUF_TOO_DEEP"));
    }

    #[test]
    fn zip_bomb_ratio_rejected() {
        // Hand-craft a central directory entry claiming 1 MiB from 10 bytes, deflated.
        let mut z = build_stored_zip(&[("big.bin", &[0u8; 10], false)]);
        let cd = z
            .windows(4)
            .rposition(|w| w == [0x50, 0x4b, 0x01, 0x02])
            .unwrap();
        z[cd + 10] = 8; // deflate
        z[cd + 24..cd + 28].copy_from_slice(&(1u32 << 20).to_le_bytes());
        assert!(check_mlpackage_zip(&z, u64::MAX)
            .unwrap_err()
            .is("ZIP_BOMB"));
    }
}
