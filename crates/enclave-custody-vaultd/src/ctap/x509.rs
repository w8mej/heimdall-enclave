//! Minimal, fail-closed ASN.1 DER and X.509 attestation certificate parser
//! (RFC 5280, FIDO CTAP 2.1 §6.2.1, FS-703 §3.3).
//!
//! Validates X.509 basic attestation chains (`x5c`):
//! 1. Parses DER TLV elements strictly (no indefinite lengths, no trailing bytes).
//! 2. Verifies the FIDO AAGUID extension (`1.3.6.1.4.1.45724.1.1.4`) matches the
//!    authenticator's AAGUID.
//! 3. Verifies certificate signatures along the chain up to an allowlisted root.
//! 4. Verifies the attestation signature over `authData ‖ clientDataHash`.

use enclave_core::error::EnclaveResult;
use enclave_core::{err, fail};
use p256::ecdsa::signature::Verifier as _;

/// ASN.1 OID for FIDO AAGUID extension: `1.3.6.1.4.1.45724.1.1.4`.
pub const OID_FIDO_AAGUID: &[u8] = &[
    0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xe5, 0x1c, 0x01, 0x01, 0x04,
];

/// ASN.1 OID for id-ecPublicKey: `1.2.840.10045.2.1`.
pub const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

/// ASN.1 OID for id-Ed25519: `1.3.101.112`.
pub const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];

/// A parsed ASN.1 DER Tag-Length-Value (TLV) slice.
#[derive(Debug, Clone, Copy)]
pub struct Der<'a> {
    /// ASN.1 tag identifier.
    pub tag: u8,
    /// Raw byte slice spanning the tag, length, and value.
    pub raw: &'a [u8],
    /// Value byte slice.
    pub value: &'a [u8],
}

impl<'a> Der<'a> {
    /// Parse the first DER element from `buf`. Fails if trailing bytes exist or if encoding is invalid.
    pub fn parse(buf: &'a [u8]) -> EnclaveResult<Self> {
        let (elem, rest) = Self::parse_prefix(buf)?;
        if !rest.is_empty() {
            fail!(EINVAL, "DER_TRAILING_BYTES");
        }
        Ok(elem)
    }

    /// Parse one DER element at the start of `buf`, returning `(element, remainder)`.
    pub fn parse_prefix(buf: &'a [u8]) -> EnclaveResult<(Self, &'a [u8])> {
        if buf.is_empty() {
            fail!(EINVAL, "DER_EMPTY");
        }
        let tag = buf[0];
        // This parser supports the single-octet tags used by the attestation
        // profile. Do not interpret high-tag-number continuation bytes as a length.
        if tag & 0x1f == 0x1f {
            fail!(EINVAL, "DER_UNSUPPORTED_TAG");
        }
        if buf.len() < 2 {
            fail!(EINVAL, "DER_TRUNCATED");
        }
        let (len, header_len) = if buf[1] < 0x80 {
            (buf[1] as usize, 2)
        } else {
            let num_octets = (buf[1] & 0x7f) as usize;
            if num_octets == 0 || num_octets > 4 || buf.len() < 2 + num_octets {
                fail!(EINVAL, "DER_INVALID_LENGTH");
            }
            if buf[2] == 0 {
                fail!(EINVAL, "DER_NONCANONICAL_LENGTH");
            }
            let mut l = 0usize;
            for i in 0..num_octets {
                l = (l << 8) | (buf[2 + i] as usize);
            }
            if l < 128 {
                fail!(EINVAL, "DER_NONCANONICAL_LENGTH");
            }
            (l, 2 + num_octets)
        };
        let total_len = header_len
            .checked_add(len)
            .ok_or_else(|| err!(EINVAL, "DER_OVERFLOW"))?;
        if buf.len() < total_len {
            fail!(EINVAL, "DER_TRUNCATED");
        }
        let (raw, rest) = buf.split_at(total_len);
        let value = &raw[header_len..];
        Ok((Self { tag, raw, value }, rest))
    }

    /// Iterate over child DER elements within a constructed TLV (like SEQUENCE `0x30`).
    pub fn children(&self) -> Children<'a> {
        Children { input: self.value }
    }

    /// Strip the leading unused-bits count from a BIT STRING (`0x03`).
    pub fn bit_string_bytes(&self) -> EnclaveResult<&'a [u8]> {
        if self.tag != 0x03 || self.value.is_empty() {
            fail!(EINVAL, "DER_NOT_BIT_STRING");
        }
        // First byte is the number of unused bits in the final byte. For public keys it must be 0.
        if self.value[0] != 0 {
            fail!(EINVAL, "DER_BIT_STRING_PADDING");
        }
        Ok(&self.value[1..])
    }
}

/// Iterator yielding parsed child DER elements.
#[derive(Debug, Clone)]
pub struct Children<'a> {
    input: &'a [u8],
}

impl<'a> Iterator for Children<'a> {
    type Item = EnclaveResult<Der<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.input.is_empty() {
            None
        } else {
            match Der::parse_prefix(self.input) {
                Ok((elem, rest)) => {
                    self.input = rest;
                    Some(Ok(elem))
                }
                Err(e) => {
                    self.input = &[];
                    Some(Err(e))
                }
            }
        }
    }
}

// Validate every constructed TLV, including Name/Validity fields the small
// signature extractor otherwise skips. This checks canonical lengths and bounds
// traversal before either parser handles device-controlled certificate bytes;
// x509-parser still supplies the semantic X.509/path checks below.
fn validate_certificate_der(bytes: &[u8]) -> EnclaveResult<()> {
    if bytes.len() > 16 * 1024 {
        fail!(EINVAL, "CERT_SIZE_LIMIT");
    }
    let mut pending = vec![(bytes, 0usize)];
    while let Some((mut input, depth)) = pending.pop() {
        if depth > 32 {
            fail!(EINVAL, "DER_DEPTH_LIMIT");
        }
        while !input.is_empty() {
            let (element, rest) = Der::parse_prefix(input)?;
            if element.tag & 0x20 != 0 {
                pending.push((element.value, depth + 1));
            }
            input = rest;
        }
    }
    Ok(())
}

/// A parsed X.509 certificate.
#[derive(Debug, Clone)]
pub struct X509Cert<'a> {
    /// Full DER encoding.
    pub raw: &'a [u8],
    /// `tbsCertificate` raw bytes (the signed message).
    pub tbs_raw: &'a [u8],
    /// Signature algorithm identifier.
    pub sig_alg: Der<'a>,
    /// Raw signature bytes (DER ECDSA signature or Ed25519 signature).
    pub signature: &'a [u8],
    /// Subject Public Key bytes (SEC1 uncompressed for P-256, or 32 B for Ed25519).
    pub public_key: &'a [u8],
    /// Public key algorithm OID.
    pub pubkey_alg_oid: &'a [u8],
    /// Extensions element if present.
    pub extensions: Option<Der<'a>>,
}

impl<'a> X509Cert<'a> {
    /// Parse an X.509 certificate from DER.
    pub fn parse(der_bytes: &'a [u8]) -> EnclaveResult<Self> {
        validate_certificate_der(der_bytes)?;
        let cert = Der::parse(der_bytes)?;
        if cert.tag != 0x30 {
            fail!(EINVAL, "X509_NOT_SEQUENCE");
        }
        let mut children = cert.children();
        let tbs = children
            .next()
            .ok_or_else(|| err!(EINVAL, "X509_NO_TBS"))??;
        let sig_alg = children
            .next()
            .ok_or_else(|| err!(EINVAL, "X509_NO_SIG_ALG"))??;
        let sig_val = children
            .next()
            .ok_or_else(|| err!(EINVAL, "X509_NO_SIG_VAL"))??;
        // AlgorithmIdentifier is a universal constructed SEQUENCE. Matching
        // only its child OID would also accept another ASN.1 tag class with
        // identical contents outside the signed TBSCertificate bytes.
        if sig_alg.tag != 0x30 {
            fail!(EINVAL, "X509_SIG_ALG_TAG");
        }
        if children.next().is_some() {
            fail!(EINVAL, "X509_TRAILING_ELEMENTS");
        }
        let signature = sig_val.bit_string_bytes()?;

        // Parse TBSCertificate
        if tbs.tag != 0x30 {
            fail!(EINVAL, "TBS_NOT_SEQUENCE");
        }
        let mut tbs_children = tbs.children();

        // Optional [0] EXPLICIT version
        let mut curr = tbs_children
            .next()
            .ok_or_else(|| err!(EINVAL, "TBS_EMPTY"))??;
        if curr.tag == 0xa0 {
            curr = tbs_children
                .next()
                .ok_or_else(|| err!(EINVAL, "TBS_NO_SERIAL"))??;
        }
        // serialNumber (INTEGER)
        if curr.tag != 0x02 {
            fail!(EINVAL, "TBS_INVALID_SERIAL");
        }
        // signature (AlgorithmIdentifier)
        let _tbs_sig = tbs_children
            .next()
            .ok_or_else(|| err!(EINVAL, "TBS_NO_SIG"))??;
        if _tbs_sig.tag != 0x30 {
            fail!(EINVAL, "TBS_SIG_ALG_TAG");
        }
        // issuer (Name)
        let _issuer = tbs_children
            .next()
            .ok_or_else(|| err!(EINVAL, "TBS_NO_ISSUER"))??;
        // validity (Validity)
        let _validity = tbs_children
            .next()
            .ok_or_else(|| err!(EINVAL, "TBS_NO_VALIDITY"))??;
        // subject (Name)
        let _subject = tbs_children
            .next()
            .ok_or_else(|| err!(EINVAL, "TBS_NO_SUBJECT"))??;
        // subjectPublicKeyInfo (SubjectPublicKeyInfo)
        let spki = tbs_children
            .next()
            .ok_or_else(|| err!(EINVAL, "TBS_NO_SPKI"))??;

        // Parse SPKI
        if spki.tag != 0x30 {
            fail!(EINVAL, "SPKI_NOT_SEQUENCE");
        }
        let mut spki_children = spki.children();
        let alg_id = spki_children
            .next()
            .ok_or_else(|| err!(EINVAL, "SPKI_NO_ALG"))??;
        if alg_id.tag != 0x30 {
            fail!(EINVAL, "SPKI_ALG_TAG");
        }
        let spk = spki_children
            .next()
            .ok_or_else(|| err!(EINVAL, "SPKI_NO_KEY"))??;
        let public_key = spk.bit_string_bytes()?;

        let mut alg_children = alg_id.children();
        let pubkey_alg_oid = alg_children
            .next()
            .ok_or_else(|| err!(EINVAL, "ALG_NO_OID"))??;
        if pubkey_alg_oid.tag != 0x06 {
            fail!(EINVAL, "SPKI_ALG_OID_TAG");
        }
        let pubkey_alg_oid = pubkey_alg_oid.value;

        // Scan remaining optional fields for [3] EXPLICIT Extensions
        let mut extensions = None;
        for item in tbs_children {
            let item = item?;
            if item.tag == 0xa3 {
                extensions = Some(item);
                break;
            }
        }

        Ok(Self {
            raw: der_bytes,
            tbs_raw: tbs.raw,
            sig_alg,
            signature,
            public_key,
            pubkey_alg_oid,
            extensions,
        })
    }

    /// Extract the FIDO AAGUID from certificate extensions.
    pub fn aaguid(&self) -> EnclaveResult<Option<[u8; 16]>> {
        let ext_container = match self.extensions {
            Some(e) => e,
            None => return Ok(None),
        };
        // Inside [3] EXPLICIT is a SEQUENCE of Extension
        let ext_seq = ext_container
            .children()
            .next()
            .ok_or_else(|| err!(EINVAL, "EXT_EMPTY"))??;
        for ext in ext_seq.children() {
            let ext = ext?;
            let mut ext_fields = ext.children();
            let oid = ext_fields
                .next()
                .ok_or_else(|| err!(EINVAL, "EXT_NO_OID"))??;
            if oid.value == OID_FIDO_AAGUID {
                let mut next = ext_fields
                    .next()
                    .ok_or_else(|| err!(EINVAL, "EXT_NO_VAL"))??;
                // Skip optional critical BOOLEAN
                if next.tag == 0x01 {
                    next = ext_fields
                        .next()
                        .ok_or_else(|| err!(EINVAL, "EXT_NO_VAL"))??;
                }
                if next.tag != 0x04 {
                    fail!(EINVAL, "EXT_NOT_OCTET_STRING");
                }
                // The value may be an inner OCTET STRING (0x04, 0x10, ...) or raw 16 bytes
                let val = next.value;
                if val.len() == 16 {
                    let mut b = [0u8; 16];
                    b.copy_from_slice(val);
                    return Ok(Some(b));
                } else if val.len() == 18 && val[0] == 0x04 && val[1] == 0x10 {
                    let mut b = [0u8; 16];
                    b.copy_from_slice(&val[2..18]);
                    return Ok(Some(b));
                } else {
                    fail!(EINVAL, "AAGUID_EXT_INVALID_LENGTH");
                }
            }
        }
        Ok(None)
    }

    /// Verify this certificate was signed by `issuer_pubkey`.
    pub fn verify_signature(&self, issuer_pubkey: &[u8]) -> EnclaveResult<()> {
        if self.sig_alg.tag != 0x30 {
            fail!(EINVAL, "X509_SIG_ALG_TAG");
        }
        let algorithm = self
            .sig_alg
            .children()
            .next()
            .ok_or_else(|| err!(EINVAL, "CERT_SIG_ALG"))??;
        if algorithm.tag != 0x06 {
            fail!(EINVAL, "CERT_SIG_ALG");
        }
        if algorithm.value == [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02] {
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(issuer_pubkey)
                .map_err(|e| err!(EINVAL, "ISSUER_PUBKEY_INVALID", "{e}"))?;
            let sig = p256::ecdsa::Signature::from_der(self.signature)
                .or_else(|_| p256::ecdsa::Signature::from_slice(self.signature))
                .map_err(|e| err!(EINVAL, "CERT_SIG_INVALID", "{e}"))?;
            vk.verify(self.tbs_raw, &sig)
                .map_err(|e| err!(EACCES, "CERT_SIG_VERIFY_FAILED", "{e}"))?;
            Ok(())
        } else if algorithm.value == OID_ED25519 {
            let b: [u8; 32] = issuer_pubkey
                .try_into()
                .map_err(|_| err!(EINVAL, "ISSUER_PUBKEY_LEN"))?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&b)
                .map_err(|e| err!(EINVAL, "ISSUER_PUBKEY_INVALID", "{e}"))?;
            let sig = ed25519_dalek::Signature::from_slice(self.signature)
                .map_err(|e| err!(EINVAL, "CERT_SIG_INVALID", "{e}"))?;
            vk.verify_strict(self.tbs_raw, &sig)
                .map_err(|e| err!(EACCES, "CERT_SIG_VERIFY_FAILED", "{e}"))?;
            Ok(())
        } else {
            fail!(EINVAL, "UNSUPPORTED_CERT_ALG");
        }
    }
}

fn validate_path(x5c: &[Vec<u8>], roots: &[Vec<u8>], now: i64) -> EnclaveResult<()> {
    use x509_parser::prelude::*;
    if x5c.is_empty() || x5c.len() > 8 || roots.is_empty() || roots.len() > 64 {
        fail!(EINVAL, "ATTESTATION_PATH_LIMIT");
    }
    let time = ASN1Time::from_timestamp(now).map_err(|e| err!(EINVAL, "CERT_TIME", "{e}"))?;
    let parse = |bytes: &[u8]| -> EnclaveResult<()> {
        validate_certificate_der(bytes)?;
        let (rest, cert) =
            parse_x509_certificate(bytes).map_err(|e| err!(EINVAL, "CERT_PARSE", "{e}"))?;
        if !rest.is_empty() || !cert.validity().is_valid_at(time) {
            fail!(EACCES, "CERT_VALIDITY_OR_TRAILING");
        }
        cert.extensions_map()
            .map_err(|e| err!(EINVAL, "CERT_EXTENSION_DUPLICATE", "{e}"))?;
        if cert.signature_algorithm != cert.tbs_certificate.signature {
            fail!(EACCES, "CERT_SIGNATURE_ALGORITHM_MISMATCH");
        }
        for ext in cert.extensions() {
            if ext.critical
                && !matches!(
                    ext.parsed_extension(),
                    x509_parser::extensions::ParsedExtension::BasicConstraints(_)
                        | x509_parser::extensions::ParsedExtension::KeyUsage(_)
                )
            {
                fail!(EACCES, "CERT_UNSUPPORTED_CRITICAL_EXTENSION");
            }
        }
        Ok(())
    };
    for bytes in x5c {
        parse(bytes)?;
    }
    let (_, leaf) =
        parse_x509_certificate(&x5c[0]).map_err(|e| err!(EINVAL, "CERT_PARSE", "{e}"))?;
    if leaf
        .basic_constraints()
        .map_err(|e| err!(EINVAL, "CERT_CONSTRAINTS", "{e}"))?
        .is_some_and(|b| b.value.ca)
    {
        fail!(EACCES, "ATTESTATION_LEAF_IS_CA");
    }
    if leaf
        .key_usage()
        .map_err(|e| err!(EINVAL, "CERT_KEY_USAGE", "{e}"))?
        .is_some_and(|k| !k.value.digital_signature())
    {
        fail!(EACCES, "ATTESTATION_LEAF_KEY_USAGE");
    }
    for root in roots {
        if parse(root).is_err() {
            continue;
        }
        let mut path: Vec<&[u8]> = x5c.iter().map(Vec::as_slice).collect();
        if path.last() != Some(&root.as_slice()) {
            path.push(root);
        }
        let valid = (|| -> EnclaveResult<()> {
            for i in 1..path.len() {
                let (_, child) = parse_x509_certificate(path[i - 1])
                    .map_err(|e| err!(EINVAL, "CERT_PARSE", "{e}"))?;
                let (_, parent) = parse_x509_certificate(path[i])
                    .map_err(|e| err!(EINVAL, "CERT_PARSE", "{e}"))?;
                if child.issuer() != parent.subject() {
                    fail!(EACCES, "CERT_ISSUER_NAME");
                }
                let basic = parent
                    .basic_constraints()
                    .map_err(|e| err!(EINVAL, "CERT_CONSTRAINTS", "{e}"))?
                    .ok_or_else(|| err!(EACCES, "CERT_ISSUER_NOT_CA"))?;
                if !basic.value.ca
                    || basic
                        .value
                        .path_len_constraint
                        .is_some_and(|max| (i - 1) > max as usize)
                {
                    fail!(EACCES, "CERT_CA_PATH_CONSTRAINT");
                }
                if parent
                    .key_usage()
                    .map_err(|e| err!(EINVAL, "CERT_KEY_USAGE", "{e}"))?
                    .is_some_and(|k| !k.value.key_cert_sign())
                {
                    fail!(EACCES, "CERT_ISSUER_KEY_USAGE");
                }
                X509Cert::parse(path[i - 1])?
                    .verify_signature(X509Cert::parse(path[i])?.public_key)?;
            }
            Ok(())
        })();
        if valid.is_ok() {
            return Ok(());
        }
    }
    fail!(EACCES, "ATTESTATION_PATH_INVALID");
}

/// Verify an `x5c` certificate chain against a trusted root and check AAGUID + attestation signature.
pub fn verify_packed_attestation(
    x5c_der: &[Vec<u8>],
    trusted_roots: &[Vec<u8>],
    expected_aaguid: &[u8; 16],
    auth_data_raw: &[u8],
    client_data_hash: &[u8; 32],
    att_sig: &[u8],
) -> EnclaveResult<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| err!(EINVAL, "CERT_CLOCK", "{e}"))?
        .as_secs();
    let now = i64::try_from(now).map_err(|_| err!(EINVAL, "CERT_CLOCK"))?;
    validate_path(x5c_der, trusted_roots, now)?;
    if x5c_der.is_empty() {
        fail!(EINVAL, "X5C_EMPTY");
    }
    let leaf = X509Cert::parse(&x5c_der[0])?;

    // 1. Check AAGUID extension in leaf
    let aaguid = leaf
        .aaguid()?
        .ok_or_else(|| err!(EACCES, "ATTESTATION_AAGUID_MISSING"))?;
    if &aaguid != expected_aaguid {
        fail!(
            EACCES,
            "ATTESTATION_AAGUID_MISMATCH",
            "cert aaguid {} != authenticator aaguid {}",
            hex::encode(aaguid),
            hex::encode(expected_aaguid)
        );
    }

    // 2. Validate chain up to one of trusted_roots
    let mut verified_to_root = false;

    // Check if leaf itself is signed directly by a trusted root
    for root in trusted_roots {
        if let Ok(root_cert) = X509Cert::parse(root) {
            if leaf.verify_signature(root_cert.public_key).is_ok() {
                verified_to_root = true;
                break;
            }
        }
    }

    // If intermediate certs exist in x5c, verify down the chain
    if !verified_to_root && x5c_der.len() > 1 {
        for (i, parent_der) in x5c_der[1..].iter().enumerate() {
            let parent = X509Cert::parse(parent_der)?;
            let child_cert = X509Cert::parse(&x5c_der[i])?;
            child_cert.verify_signature(parent.public_key)?;

            // Check if this parent matches a trusted root
            for root in trusted_roots {
                if parent.raw == root.as_slice() {
                    verified_to_root = true;
                    break;
                }
                if let Ok(root_cert) = X509Cert::parse(root) {
                    if parent.verify_signature(root_cert.public_key).is_ok() {
                        verified_to_root = true;
                        break;
                    }
                }
            }
            if verified_to_root {
                break;
            }
        }
    }

    if !verified_to_root {
        fail!(EACCES, "ATTESTATION_ROOT_UNTRUSTED");
    }

    // 3. Verify attestation signature over authData ‖ clientDataHash using leaf's public key
    let mut signed_data = auth_data_raw.to_vec();
    signed_data.extend_from_slice(client_data_hash);

    if leaf.pubkey_alg_oid == OID_EC_PUBLIC_KEY {
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(leaf.public_key)
            .map_err(|e| err!(EINVAL, "LEAF_PUBKEY_INVALID", "{e}"))?;
        let sig = p256::ecdsa::Signature::from_der(att_sig)
            .or_else(|_| p256::ecdsa::Signature::from_slice(att_sig))
            .map_err(|e| err!(EINVAL, "ATT_SIG_INVALID", "{e}"))?;
        vk.verify(&signed_data, &sig)
            .map_err(|e| err!(EACCES, "ATT_SIG_VERIFY_FAILED", "{e}"))?;
    } else if leaf.pubkey_alg_oid == OID_ED25519 {
        let b: [u8; 32] = leaf
            .public_key
            .try_into()
            .map_err(|_| err!(EINVAL, "LEAF_PUBKEY_LEN"))?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&b)
            .map_err(|e| err!(EINVAL, "LEAF_PUBKEY_INVALID", "{e}"))?;
        let sig = ed25519_dalek::Signature::from_slice(att_sig)
            .map_err(|e| err!(EINVAL, "ATT_SIG_INVALID", "{e}"))?;
        vk.verify_strict(&signed_data, &sig)
            .map_err(|e| err!(EACCES, "ATT_SIG_VERIFY_FAILED", "{e}"))?;
    } else {
        fail!(EINVAL, "UNSUPPORTED_ATTESTATION_KEY_TYPE");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer as _;

    fn der_elem(tag: u8, val: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if val.len() < 0x80 {
            out.push(val.len() as u8);
        } else if val.len() <= 0xff {
            out.push(0x81);
            out.push(val.len() as u8);
        } else {
            out.push(0x82);
            out.push((val.len() >> 8) as u8);
            out.push((val.len() & 0xff) as u8);
        }
        out.extend_from_slice(val);
        out
    }

    fn der_seq(children: &[Vec<u8>]) -> Vec<u8> {
        let val: Vec<u8> = children.iter().flatten().copied().collect();
        der_elem(0x30, &val)
    }

    #[test]
    fn der_tlv_strict_parsing_and_error_cases() {
        assert!(Der::parse(&[]).is_err());
        assert!(Der::parse(&[0x30]).is_err());
        assert!(Der::parse(&[0x30, 0x05, 1, 2]).is_err()); // truncated
        assert!(Der::parse(&[0x30, 0x01, 1, 0xFF]).is_err()); // trailing bytes

        let s = der_seq(&[der_elem(0x02, &[0x01]), der_elem(0x04, b"test")]);
        let d = Der::parse(&s).unwrap();
        assert_eq!(d.tag, 0x30);
        let items: Vec<_> = d.children().collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].tag, 0x02);
        assert_eq!(items[1].tag, 0x04);
        assert_eq!(items[1].value, b"test");
    }

    #[test]
    fn der_requires_shortest_length_encoding_at_every_boundary() {
        for len in [0usize, 1, 127, 128, 255, 256, 16_384, 65_535] {
            let value = vec![0x5a; len];
            let canonical = der_elem(0x04, &value);
            assert_eq!(Der::parse(&canonical).unwrap().value, value);
            // A redundant leading zero in any long-form length is BER, not DER.
            let width = if len < 256 { 1 } else { 2 };
            let mut redundant = vec![0x04, 0x80 | (width + 1), 0];
            if width == 2 {
                redundant.push((len >> 8) as u8);
            }
            redundant.push(len as u8);
            redundant.extend_from_slice(&value);
            assert!(
                Der::parse(&redundant).is_err(),
                "accepted redundant length for {len}"
            );
            if len < 128 {
                let mut long = vec![0x04, 0x81, len as u8];
                long.extend_from_slice(&value);
                assert!(
                    Der::parse(&long).is_err(),
                    "accepted long form for short length {len}"
                );
            }
        }
        for invalid in [
            vec![0x04, 0x80],                         // indefinite length
            vec![0x04, 0xff],                         // reserved length octet
            vec![0x04, 0x84, 0xff, 0xff, 0xff, 0xff], // bounded, truncated value
        ] {
            assert!(Der::parse(&invalid).is_err());
        }
    }

    #[test]
    fn bounded_der_prefix_mutation_campaign_makes_progress_without_panics() {
        // Exhaust all 65,536 tag/length prefixes, each followed by bounded data.
        // This is a reproducible mutation campaign, not coverage-guided fuzzing.
        for prefix in 0u32..=u16::MAX as u32 {
            let mut input = vec![(prefix >> 8) as u8, prefix as u8];
            input.extend_from_slice(&[0; 8]);
            if let Ok((element, rest)) = Der::parse_prefix(&input) {
                assert!(element.raw.len() >= 2);
                assert_eq!(element.raw.len() + rest.len(), input.len());
                assert!(element.value.len() < element.raw.len());
                // Both public entrypoints must return or reject every input.
                let _ = element.children().collect::<Result<Vec<_>, _>>();
                let _ = element.bit_string_bytes();
            }
            let _ = X509Cert::parse(&input);
        }
    }

    #[test]
    fn real_signed_attestation_mutations_are_rejected_without_panics() {
        use p256::pkcs8::DecodePrivateKey;
        use rcgen::{
            BasicConstraints, Certificate, CertificateParams, CustomExtension, IsCa,
            KeyUsagePurpose,
        };
        let mut root_params = CertificateParams::new(vec![]);
        root_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        root_params.not_after = rcgen::date_time_ymd(2040, 1, 1);
        root_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "mutation-campaign-root");
        root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let root = Certificate::from_params(root_params).unwrap();
        let root_der = root.serialize_der().unwrap();
        let aaguid = [0x55; 16];
        let mut leaf_params = CertificateParams::new(vec![]);
        leaf_params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        leaf_params.not_after = rcgen::date_time_ymd(2040, 1, 1);
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 45724, 1, 1, 4],
                der_elem(0x04, &aaguid),
            ));
        let leaf = Certificate::from_params(leaf_params).unwrap();
        let leaf_der = leaf.serialize_der_with_signer(&root).unwrap();
        let signing =
            p256::ecdsa::SigningKey::from_pkcs8_der(&leaf.serialize_private_key_der()).unwrap();
        let auth = [0x33; 37];
        let client_hash = [0x44; 32];
        let mut message = auth.to_vec();
        message.extend_from_slice(&client_hash);
        let signature: p256::ecdsa::Signature = signing.sign(&message);
        let signature = signature.to_der();
        let verify = |candidate: Vec<u8>| {
            verify_packed_attestation(
                &[candidate],
                &[root_der.clone()],
                &aaguid,
                &auth,
                &client_hash,
                signature.as_bytes(),
            )
        };
        verify(leaf_der.clone()).unwrap();
        // The outer AlgorithmIdentifier is unsigned. Keep its OID, signature
        // and the complete signed TBS identical while changing only tag class.
        let original = X509Cert::parse(&leaf_der).unwrap();
        let mut direct = original.clone();
        direct.sig_alg.tag = 0xb0;
        assert!(direct
            .verify_signature(X509Cert::parse(&root_der).unwrap().public_key)
            .unwrap_err()
            .is("X509_SIG_ALG_TAG"));
        let algorithm_offset = original.sig_alg.raw.as_ptr() as usize - leaf_der.as_ptr() as usize;
        let mut wrong_class = leaf_der.clone();
        wrong_class[algorithm_offset] = 0xb0;
        assert!(X509Cert::parse(&wrong_class)
            .unwrap_err()
            .is("X509_SIG_ALG_TAG"));
        assert!(verify(wrong_class).is_err());
        // Alter only the unsigned outer length; signed TBS, algorithms and
        // signature bytes remain identical. Signature verification alone cannot
        // detect this non-DER encoding.
        let cert = Der::parse(&leaf_der).unwrap();
        let len = cert.value.len();
        let mut noncanonical = vec![0x30, 0x83, 0, (len >> 8) as u8, len as u8];
        noncanonical.extend_from_slice(cert.value);
        assert!(verify(noncanonical).is_err());
        let mut cases = 0;
        // Every truncated prefix, two independent bit flips at every position,
        // and a suffix exercise the mature path and handwritten public parser.
        for end in 0..leaf_der.len() {
            assert!(
                verify(leaf_der[..end].to_vec()).is_err(),
                "accepted truncated certificate at {end}"
            );
            cases += 1;
        }
        for offset in 0..leaf_der.len() {
            for mask in [1u8, 0x80] {
                let mut changed = leaf_der.clone();
                changed[offset] ^= mask;
                let _ = X509Cert::parse(&changed).and_then(|c| c.aaguid());
                if verify(changed.clone()).is_ok() {
                    let original = X509Cert::parse(&leaf_der).unwrap();
                    let mutated = X509Cert::parse(&changed).unwrap();
                    panic!("accepted signed-certificate mutation at {offset} mask {mask}; original_byte={} changed_byte={}; tbs_unchanged={} signature_unchanged={} sig_alg_original={} sig_alg_mutated={}; original_cert={} changed_cert={}",
                        leaf_der[offset], changed[offset], original.tbs_raw == mutated.tbs_raw,
                        original.signature == mutated.signature, hex::encode(original.sig_alg.raw),
                        hex::encode(mutated.sig_alg.raw), hex::encode(&leaf_der), hex::encode(&changed));
                }
                cases += 1;
            }
        }
        let mut trailing = leaf_der.clone();
        trailing.push(0);
        assert!(verify(trailing).is_err());
        cases += 1;
        eprintln!("F85 signed-certificate mutation cases: {cases}; valid original accepted");
    }

    #[test]
    fn certificate_der_traversal_checks_skipped_fields_and_depth() {
        let noncanonical_inner = der_seq(&[vec![0x04, 0x81, 1, 0x55]]);
        assert!(validate_certificate_der(&noncanonical_inner)
            .unwrap_err()
            .is("DER_NONCANONICAL_LENGTH"));
        let mut nested = der_elem(0x04, b"bounded");
        for _ in 0..32 {
            nested = der_seq(&[nested]);
        }
        validate_certificate_der(&nested).unwrap();
        nested = der_seq(&[nested]);
        assert!(validate_certificate_der(&nested)
            .unwrap_err()
            .is("DER_DEPTH_LIMIT"));
        assert!(validate_certificate_der(&vec![0; 16 * 1024 + 1])
            .unwrap_err()
            .is("CERT_SIZE_LIMIT"));
        assert!(Der::parse(&[0x1f, 0x00])
            .unwrap_err()
            .is("DER_UNSUPPORTED_TAG"));
    }

    #[test]
    fn x509_cert_parse_aaguid_and_verify_signature() {
        let sk_ca = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let pk_ca = sk_ca
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        let sk_leaf = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let pk_leaf = sk_leaf
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        let aaguid_raw = [0x5au8; 16];
        // Build AAGUID extension: SEQUENCE { OID, OCTET STRING(OCTET STRING(aaguid)) }
        let ext_val_inner = der_elem(0x04, &aaguid_raw);
        let ext_val = der_elem(0x04, &ext_val_inner);
        let aaguid_ext = der_seq(&[der_elem(0x06, OID_FIDO_AAGUID), ext_val]);
        let extensions_seq = der_seq(&[aaguid_ext]);
        let extensions_tag = der_elem(0xa3, &extensions_seq);

        // Build SPKI
        let alg_id = der_seq(&[der_elem(0x06, OID_EC_PUBLIC_KEY)]);
        let mut spk_bytes = vec![0x00]; // 0 unused bits
        spk_bytes.extend_from_slice(&pk_leaf);
        let spk = der_elem(0x03, &spk_bytes);
        let spki = der_seq(&[alg_id.clone(), spk]);

        // Build TBSCertificate
        let serial = der_elem(0x02, &[0x01]);
        let dummy_name = der_seq(&[]);
        let validity = der_seq(&[]);
        let tbs = der_seq(&[
            serial,
            alg_id.clone(),
            dummy_name.clone(),
            validity,
            dummy_name,
            spki,
            extensions_tag,
        ]);

        // Sign TBS with CA key
        let sig: p256::ecdsa::Signature = sk_ca.sign(&tbs);
        let sig_der = sig.to_der();
        let mut sig_val_bytes = vec![0x00];
        sig_val_bytes.extend_from_slice(sig_der.as_bytes());
        let sig_val = der_elem(0x03, &sig_val_bytes);

        // Build Certificate
        let cert_der = der_seq(&[
            tbs,
            der_seq(&[der_elem(
                0x06,
                &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02],
            )]),
            sig_val,
        ]);
        let cert = X509Cert::parse(&cert_der).unwrap();

        assert_eq!(cert.aaguid().unwrap(), Some(aaguid_raw));
        assert!(cert.verify_signature(&pk_ca).is_ok());

        // Corrupted issuer key should fail
        let mut bad_pk = pk_ca.clone();
        bad_pk[10] ^= 0xff;
        assert!(cert.verify_signature(&bad_pk).is_err());
    }

    #[test]
    fn real_certificate_paths_enforce_validity_ca_and_names() {
        use p256::pkcs8::DecodePrivateKey;
        use rcgen::{
            BasicConstraints, Certificate, CertificateParams, CustomExtension, IsCa,
            KeyUsagePurpose,
        };
        fn root(ca: bool) -> Certificate {
            let mut p = CertificateParams::new(vec![]);
            p.not_before = rcgen::date_time_ymd(2020, 1, 1);
            p.not_after = rcgen::date_time_ymd(2040, 1, 1);
            p.distinguished_name.push(rcgen::DnType::CommonName, "root");
            if ca {
                p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
                p.key_usages = vec![KeyUsagePurpose::KeyCertSign];
            }
            Certificate::from_params(p).unwrap()
        }
        let root = root(true);
        let root_der = root.serialize_der().unwrap();
        let aaguid = [0x77; 16];
        let mut params = CertificateParams::new(vec![]);
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2040, 1, 1);
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 45724, 1, 1, 4],
                der_elem(0x04, &aaguid),
            ));
        let leaf = Certificate::from_params(params).unwrap();
        let leaf_der = leaf.serialize_der_with_signer(&root).unwrap();
        let signing =
            p256::ecdsa::SigningKey::from_pkcs8_der(&leaf.serialize_private_key_der()).unwrap();
        let auth = vec![0xaa; 37];
        let hash = [0xbb; 32];
        let mut message = auth.clone();
        message.extend_from_slice(&hash);
        let signature: p256::ecdsa::Signature = signing.sign(&message);
        assert!(verify_packed_attestation(
            &[leaf_der.clone()],
            &[root_der.clone()],
            &aaguid,
            &auth,
            &hash,
            signature.to_der().as_bytes()
        )
        .is_ok());
        let at_2030 = 1893456000;
        assert!(validate_path(&[leaf_der.clone()], &[root_der.clone()], at_2030).is_ok());
        assert!(validate_path(&[leaf_der.clone()], &[root_der.clone()], 0).is_err());
        assert!(validate_path(&[leaf_der.clone()], &[root_der.clone()], 2524608000).is_err());
        let notca = {
            let mut p = CertificateParams::new(vec![]);
            p.distinguished_name.push(rcgen::DnType::CommonName, "root");
            Certificate::from_params(p).unwrap()
        };
        let bad_leaf = leaf.serialize_der_with_signer(&notca).unwrap();
        assert!(validate_path(&[bad_leaf], &[notca.serialize_der().unwrap()], at_2030).is_err());
        let mut wrong = leaf_der.clone();
        wrong.push(0);
        assert!(validate_path(&[wrong], &[root_der.clone()], at_2030).is_err());
        let mut corrupted = leaf_der;
        let n = corrupted.len();
        corrupted[n - 1] ^= 1;
        assert!(validate_path(&[corrupted], &[root_der], at_2030).is_err());
    }
}
