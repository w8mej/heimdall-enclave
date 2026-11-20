//! Platform-side CTAP 2.1 client: channel allocation, `getInfo`, protocol-2
//! key agreement, `makeCredential` (enrollment) and `getAssertion` with the
//! encrypted `hmac-secret` PRF.

use ciborium::Value;
use enclave_core::error::EnclaveResult;
use enclave_core::secret::SecretBytes;
use enclave_core::{err, fail};

use super::assertion::{
    AssertionResponse, AuthenticatorData, CredentialKey, EnrolledCredential, FLAG_AT,
};
use super::cbor::{self, imap, tmap};
use super::hid::{transact, HidDevice, BROADCAST_CID, CMD_CBOR, CMD_INIT};
use super::mds::MdsState;
use super::pin::{cose_to_p256, p256_to_cose, platform_agree, SharedSecret};
use super::{alg, cmd, status, RP_ID};
use enclave_core::profile::{ActionClass, Profile};

/// Parsed `getInfo`.
#[derive(Debug, Clone)]
pub struct AuthenticatorInfo {
    /// Versions.
    pub versions: Vec<String>,
    /// Extensions.
    pub extensions: Vec<String>,
    /// AAGUID.
    pub aaguid: [u8; 16],
    /// PIN/UV protocols.
    pub pin_uv_protocols: Vec<i64>,
    /// Built-in UV capability advertised by getInfo (not proof that UV occurred).
    pub built_in_uv: bool,
    /// Enterprise attestation is enabled per GetInfo; not asset/attestation proof.
    pub enterprise_attestation_enabled: bool,
    /// Firmware.
    pub firmware_version: u32,
    /// Algorithms supported (COSE IDs, e.g. -8 for EdDSA, -7 for ES256).
    pub algorithms: Vec<i64>,
}

/// A CTAP client bound to one allocated channel.
#[derive(Debug)]
pub struct CtapClient<'a> {
    dev: &'a mut dyn HidDevice,
    cid: u32,
    restore_deadline: Option<Option<u64>>,
}

fn status_err(st: u8) -> enclave_core::EnclaveError {
    match st {
        status::USER_ACTION_TIMEOUT => err!(ETIMEDOUT, "YUBIKEY_TOUCH_TIMEOUT"),
        status::OPERATION_DENIED => err!(EACCES, "YUBIKEY_DENIED"),
        status::NO_CREDENTIALS => err!(EACCES, "YUBIKEY_NO_CREDENTIAL"),
        status::PIN_AUTH_INVALID => err!(EACCES, "PIN_UV_AUTH_INVALID"),
        0x31 => err!(EACCES, "FIDO_PIN_INVALID"),
        0x32 => err!(EACCES, "FIDO_PIN_BLOCKED"),
        0x34 => err!(EACCES, "FIDO_PIN_AUTH_BLOCKED"),
        0x35 => err!(EACCES, "FIDO_PIN_NOT_SET"),
        0x38 => err!(EACCES, "FIDO_PIN_TOKEN_EXPIRED"),
        status::CHANNEL_BUSY => err!(EAGAIN, "CTAP2_ERR_CHANNEL_BUSY"),
        s => err!(EIO, "CTAP2_ERROR", "status {s:#04x}"),
    }
}

// The same caller cancellation flag and ORIGINAL continuous-clock endpoint
// gate each later PIN-authorized command. This cannot retract a report already
// written or interrupt an in-flight synchronous native operation.
fn check_pin_ceremony(
    deadline_ns: u64,
    cancelled: &std::sync::atomic::AtomicBool,
) -> EnclaveResult<()> {
    if cancelled.load(std::sync::atomic::Ordering::Acquire) {
        fail!(EACCES, "FIDO_PIN_CEREMONY_CANCELLED");
    }
    let now = enclave_core::power::continuous_time_ns();
    if now >= deadline_ns || deadline_ns - now > 10_000_000_000 {
        fail!(ETIMEDOUT, "FIDO_PIN_CEREMONY_DEADLINE");
    }
    Ok(())
}

impl<'a> CtapClient<'a> {
    /// Allocate a channel with `CTAPHID_INIT`.
    pub fn open(dev: &'a mut dyn HidDevice) -> EnclaveResult<Self> {
        let cid = Self::allocate_channel(dev)?;
        Ok(Self {
            dev,
            cid,
            restore_deadline: None,
        })
    }

    /// Bound every report, including INIT/keepalives, to the ORIGINAL ceremony
    /// deadline. The previous transport deadline is restored when dropped.
    pub fn open_with_deadline(dev: &'a mut dyn HidDevice, deadline_ns: u64) -> EnclaveResult<Self> {
        let now = enclave_core::power::continuous_time_ns();
        if now >= deadline_ns || deadline_ns - now > 10_000_000_000 {
            fail!(ETIMEDOUT, "CTAPHID_DEADLINE_EXCEEDED");
        }
        let previous = dev.deadline_ns();
        let deadline = previous.map_or(deadline_ns, |old| old.min(deadline_ns));
        dev.set_deadline_ns(Some(deadline))?;
        match Self::allocate_channel(dev) {
            Ok(cid) => Ok(Self {
                dev,
                cid,
                restore_deadline: Some(previous),
            }),
            Err(error) => {
                let _ = dev.set_deadline_ns(previous);
                Err(error)
            }
        }
    }

    fn allocate_channel(dev: &mut dyn HidDevice) -> EnclaveResult<u32> {
        let mut nonce = [0u8; 8];
        enclave_core::rng::fill(&mut nonce);
        let (c, r) = transact(dev, BROADCAST_CID, CMD_INIT, &nonce)?;
        if c != CMD_INIT || r.len() != 17 || r[..8] != nonce {
            fail!(EACCES, "CTAPHID_INIT_NONCE_MISMATCH");
        }
        let cid = u32::from_be_bytes([r[8], r[9], r[10], r[11]]);
        if cid == BROADCAST_CID || cid == 0 {
            fail!(EINVAL, "CTAPHID_BAD_CID");
        }
        Ok(cid)
    }

    /// Topology depth of the underlying device.
    pub fn hub_depth(&self) -> u8 {
        self.dev.hub_depth()
    }

    fn call(&mut self, command: u8, params: Option<Value>) -> EnclaveResult<Option<Value>> {
        let mut msg = vec![command];
        if let Some(p) = params {
            msg.extend(cbor::encode(&p)?);
        }
        let (c, r) = transact(self.dev, self.cid, CMD_CBOR, &msg)?;
        if c != CMD_CBOR || r.is_empty() {
            fail!(EIO, "CTAPHID_UNEXPECTED");
        }
        if r[0] != status::OK {
            return Err(status_err(r[0]));
        }
        if r.len() == 1 {
            return Ok(None);
        }
        Ok(Some(cbor::decode(&r[1..])?))
    }

    /// `authenticatorGetInfo`.
    pub fn get_info(&mut self) -> EnclaveResult<AuthenticatorInfo> {
        let v = self
            .call(cmd::GET_INFO, None)?
            .ok_or_else(|| err!(EIO, "GET_INFO_EMPTY"))?;
        let texts = |k| match cbor::iget(&v, k) {
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|x| x.as_text().map(str::to_owned))
                .collect(),
            _ => vec![],
        };
        let aaguid: [u8; 16] = cbor::bytes(cbor::iget(&v, 3))?
            .try_into()
            .map_err(|_| err!(EINVAL, "AAGUID_LEN"))?;
        let protos = match cbor::iget(&v, 6) {
            Some(Value::Array(a)) => a.iter().filter_map(|x| cbor::int(Some(x)).ok()).collect(),
            _ => vec![],
        };
        let fw = cbor::int(cbor::iget(&v, 0x0e)).unwrap_or(0);
        let algs = match cbor::iget(&v, 0x0a) {
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|x| match x {
                    Value::Map(_) => cbor::int(cbor::tget(x, "alg"))
                        .ok()
                        .or_else(|| cbor::int(cbor::iget(x, 3)).ok()),
                    _ => None,
                })
                .collect(),
            _ => vec![],
        };
        Ok(AuthenticatorInfo {
            versions: texts(1),
            extensions: texts(2),
            aaguid,
            pin_uv_protocols: protos,
            built_in_uv: cbor::iget(&v, 4)
                .is_some_and(|opts| cbor::boolean(cbor::tget(opts, "uv"))),
            enterprise_attestation_enabled: cbor::iget(&v, 4)
                .is_some_and(|opts| cbor::boolean(cbor::tget(opts, "ep"))),
            firmware_version: u32::try_from(fw).map_err(|_| err!(EINVAL, "FIRMWARE_RANGE"))?,
            algorithms: algs,
        })
    }

    /// `clientPIN.getKeyAgreement` (protocol 2).
    pub fn key_agreement(&mut self) -> EnclaveResult<p256::PublicKey> {
        let v = self
            .call(
                cmd::CLIENT_PIN,
                Some(imap(vec![
                    (1, Value::Integer(2.into())),
                    (2, Value::Integer(2.into())),
                ])),
            )?
            .ok_or_else(|| err!(EIO, "KEY_AGREEMENT_EMPTY"))?;
        cose_to_p256(cbor::iget(&v, 1).ok_or_else(|| err!(EINVAL, "KEY_AGREEMENT_MISSING"))?)
    }

    /// Enroll a new non-resident credential (negotiating `algorithms`).
    pub fn make_credential(
        &mut self,
        client_data_hash: &[u8; 32],
        user_id: &[u8],
        algorithms: &[i64],
    ) -> EnclaveResult<(String, AuthenticatorData, Value)> {
        let (fmt, auth_data, attestation, _) = self.make_credential_enrollment(
            client_data_hash,
            user_id,
            algorithms,
            false,
            false,
            None,
        )?;
        Ok((fmt, auth_data, attestation))
    }

    fn make_credential_enrollment(
        &mut self,
        client_data_hash: &[u8; 32],
        user_id: &[u8],
        algorithms: &[i64],
        enterprise: bool,
        require_uv: bool,
        token: Option<&[u8]>,
    ) -> EnclaveResult<(String, AuthenticatorData, Value, bool)> {
        let cred_params: Vec<Value> = algorithms
            .iter()
            .map(|&a| {
                tmap(vec![
                    ("alg", Value::Integer(a.into())),
                    ("type", Value::Text("public-key".into())),
                ])
            })
            .collect();
        let mut fields = vec![
            (1, Value::Bytes(client_data_hash.to_vec())),
            (
                2,
                tmap(vec![
                    ("id", Value::Text(RP_ID.into())),
                    ("name", Value::Text("depot Enclave".into())),
                ]),
            ),
            (
                3,
                tmap(vec![
                    ("id", Value::Bytes(user_id.to_vec())),
                    ("name", Value::Text("custodian".into())),
                ]),
            ),
            (4, Value::Array(cred_params)),
            (6, tmap(vec![("hmac-secret", Value::Bool(true))])),
        ];
        if require_uv && token.is_none() {
            fields.push((7, tmap(vec![("uv", Value::Bool(true))])));
        }
        if let Some(token) = token {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(token)
                .map_err(|_| err!(EACCES, "PIN_TOKEN_LENGTH"))?;
            mac.update(client_data_hash);
            fields.push((8, Value::Bytes(mac.finalize().into_bytes().to_vec())));
            fields.push((9, Value::Integer(2.into())));
        }
        if enterprise {
            fields.push((10, Value::Integer(2.into())));
        }
        let v = self
            .call(cmd::MAKE_CREDENTIAL, Some(imap(fields)))?
            .ok_or_else(|| err!(EIO, "MAKE_CREDENTIAL_EMPTY"))?;
        let fmt = cbor::text(cbor::iget(&v, 1))?;
        let ad = AuthenticatorData::parse(&cbor::bytes(cbor::iget(&v, 2))?)?;
        let att = cbor::iget(&v, 3)
            .cloned()
            .ok_or_else(|| err!(EINVAL, "ATT_STMT_MISSING"))?;
        let ep_att = cbor::iget(&v, 4).is_some_and(|value| cbor::boolean(Some(value)));
        Ok((fmt, ad, att, ep_att))
    }

    /// `getAssertion`, optionally requesting `hmac-secret(salt)` over an
    /// encrypted protocol-2 channel. Returns the shared secret needed to decrypt
    /// the PRF output after the assertion has been verified.
    pub fn get_assertion(
        &mut self,
        credential_id: &[u8],
        client_data_hash: &[u8; 32],
        require_uv: bool,
        hmac_salt: Option<&[u8; 32]>,
    ) -> EnclaveResult<(AssertionResponse, Option<SharedSecret>)> {
        self.get_assertion_authorized(credential_id, client_data_hash, require_uv, hmac_salt, None)
    }

    /// Obtain a minimally scoped PIN token on this live CTAP channel and use it
    /// for one L3 assertion. No token or retained PIN escapes this call. The
    /// caller must authenticate the host-only UI provider and enforce its
    /// original ceremony deadline/cancellation; this API is not a UI trust proof.
    /// `deadline_ns` is the ORIGINAL ceremony deadline in mach-continuous ns,
    /// never a new ten-second allowance starting at PIN acquisition.
    pub fn get_assertion_with_pin_provider(
        &mut self,
        profile: Profile,
        credential_id: &[u8],
        client_data_hash: &[u8; 32],
        hmac_salt: Option<&[u8; 32]>,
        deadline_ns: u64,
        cancelled: &std::sync::atomic::AtomicBool,
        provider: impl FnOnce() -> EnclaveResult<SecretBytes>,
    ) -> EnclaveResult<(AssertionResponse, Option<SharedSecret>)> {
        let previous = self.dev.deadline_ns();
        let deadline = previous.map_or(deadline_ns, |old| old.min(deadline_ns));
        self.dev.set_deadline_ns(Some(deadline))?;
        let result = self.get_assertion_with_pin_provider_inner(
            profile,
            credential_id,
            client_data_hash,
            hmac_salt.map(|salt| salt.as_slice()),
            deadline,
            cancelled,
            provider,
        );
        let restored = self.dev.set_deadline_ns(previous);
        match (result, restored) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (_, Err(error)) => Err(error),
        }
    }

    /// One assertion derives the two distinct tier salts under one original
    /// approval/PIN budget. No PIN token is cached between ceremonies.
    pub fn get_assertion_dual_prf(
        &mut self,
        id: &[u8],
        challenge: &[u8; 32],
        require_uv: bool,
        salts: &[u8; 64],
    ) -> EnclaveResult<(AssertionResponse, Option<SharedSecret>)> {
        self.request_assertion(id, challenge, true, require_uv, Some(salts), None, None)
    }
    /// L3 PIN-only counterpart of the two-salt enrollment assertion.
    pub fn get_assertion_dual_prf_with_pin_provider(
        &mut self,
        id: &[u8],
        challenge: &[u8; 32],
        salts: &[u8; 64],
        deadline_ns: u64,
        cancelled: &std::sync::atomic::AtomicBool,
        provider: impl FnOnce() -> EnclaveResult<SecretBytes>,
    ) -> EnclaveResult<(AssertionResponse, Option<SharedSecret>)> {
        let previous = self.dev.deadline_ns();
        let deadline = previous.map_or(deadline_ns, |old| old.min(deadline_ns));
        self.dev.set_deadline_ns(Some(deadline))?;
        let result = self.get_assertion_with_pin_provider_inner(
            Profile::L3,
            id,
            challenge,
            Some(salts),
            deadline,
            cancelled,
            provider,
        );
        let restored = self.dev.set_deadline_ns(previous);
        match (result, restored) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (_, Err(error)) => Err(error),
        }
    }

    fn obtain_pin_token(
        &mut self,
        profile: Profile,
        permission: u8,
        deadline_ns: u64,
        cancelled: &std::sync::atomic::AtomicBool,
        provider: impl FnOnce() -> EnclaveResult<SecretBytes>,
    ) -> EnclaveResult<SecretBytes> {
        let check = || check_pin_ceremony(deadline_ns, cancelled);
        check()?;
        if permission != 1 && permission != 2 {
            fail!(EINVAL, "PIN_PERMISSION_SCOPE");
        }
        if profile != Profile::L3 {
            fail!(EPERM, "FIDO_TYPED_PIN_FORBIDDEN_FOR_PROFILE");
        }
        if !self.get_info()?.pin_uv_protocols.contains(&2) {
            fail!(EACCES, "PIN_PROTOCOL_2_REQUIRED");
        }
        check()?;
        let pin = provider()?;
        check()?;
        let text =
            std::str::from_utf8(pin.expose()).map_err(|_| err!(EINVAL, "FIDO_PIN_ENCODING"))?;
        if text.chars().count() < 4 || pin.len() > 63 || pin.expose().contains(&0) {
            fail!(EINVAL, "FIDO_PIN_LENGTH");
        }
        if !unicode_normalization::is_nfc(text) {
            fail!(EINVAL, "FIDO_PIN_NORMALIZATION_REQUIRED");
        }
        check()?;
        let peer = self.key_agreement()?;
        check()?;
        let (ours, shared) = platform_agree(&peer)?;
        use sha2::{Digest, Sha256};
        use zeroize::Zeroize;
        let mut pin_hash = Sha256::digest(pin.expose());
        let pin_hash_half = SecretBytes::new(pin_hash[..16].to_vec());
        pin_hash.as_mut_slice().zeroize();
        drop(pin);
        let encrypted_pin_hash = shared.encrypt(pin_hash_half.expose())?;
        drop(pin_hash_half);
        // Local crypto may outlive a cancellation; do not begin a new token
        // operation after observing it, even though prior I/O already completed.
        check()?;
        let response = self
            .call(
                cmd::CLIENT_PIN,
                Some(imap(vec![
                    (1, Value::Integer(2.into())),
                    (2, Value::Integer(9.into())), // getPinUvAuthTokenUsingPinWithPermissions
                    (3, p256_to_cose(&ours)),
                    (6, Value::Bytes(encrypted_pin_hash)),
                    (9, Value::Integer(permission.into())), // one specific operation only
                    (10, Value::Text(RP_ID.into())),
                ])),
            )?
            .ok_or_else(|| err!(EIO, "PIN_TOKEN_EMPTY"))?;
        check()?;
        let token = shared.decrypt(&cbor::bytes(cbor::iget(&response, 2))?)?;
        if token.len() != 32 {
            fail!(EACCES, "PIN_TOKEN_LENGTH");
        }
        check()?;
        Ok(token)
    }

    fn get_assertion_with_pin_provider_inner(
        &mut self,
        profile: Profile,
        credential_id: &[u8],
        client_data_hash: &[u8; 32],
        hmac_salt: Option<&[u8]>,
        deadline_ns: u64,
        cancelled: &std::sync::atomic::AtomicBool,
        provider: impl FnOnce() -> EnclaveResult<SecretBytes>,
    ) -> EnclaveResult<(AssertionResponse, Option<SharedSecret>)> {
        let token = self.obtain_pin_token(profile, 2, deadline_ns, cancelled, provider)?;
        let assertion = self.request_assertion(
            credential_id,
            client_data_hash,
            true,
            true,
            hmac_salt,
            Some(token.expose()),
            Some((deadline_ns, cancelled)),
        )?;
        check_pin_ceremony(deadline_ns, cancelled)?;
        Ok(assertion)
    }

    fn get_assertion_authorized(
        &mut self,
        credential_id: &[u8],
        client_data_hash: &[u8; 32],
        require_uv: bool,
        hmac_salt: Option<&[u8; 32]>,
        token: Option<&[u8]>,
    ) -> EnclaveResult<(AssertionResponse, Option<SharedSecret>)> {
        self.request_assertion(
            credential_id,
            client_data_hash,
            true,
            require_uv,
            hmac_salt.map(|salt| salt.as_slice()),
            token,
            None,
        )
    }

    /// Silent liveness observation only. No UP/UV requirement, PIN token or PRF
    /// request; its separately verified result cannot become a custody factor.
    pub fn get_presence(
        &mut self,
        credential_id: &[u8],
        challenge: &[u8; 32],
    ) -> EnclaveResult<AssertionResponse> {
        Ok(self
            .request_assertion(credential_id, challenge, false, false, None, None, None)?
            .0)
    }

    fn request_assertion(
        &mut self,
        credential_id: &[u8],
        client_data_hash: &[u8; 32],
        require_up: bool,
        require_uv: bool,
        hmac_salt: Option<&[u8]>,
        token: Option<&[u8]>,
        pin_ceremony: Option<(u64, &std::sync::atomic::AtomicBool)>,
    ) -> EnclaveResult<(AssertionResponse, Option<SharedSecret>)> {
        // Only the existing PIN-provider path supplies this same concrete flag
        // and endpoint. Unrelated assertion/presence APIs gain no new authority.
        let check = || match pin_ceremony {
            Some((deadline, cancelled)) => check_pin_ceremony(deadline, cancelled),
            None => Ok(()),
        };
        check()?;
        if token.is_none() && require_uv {
            let info = self.get_info()?;
            check()?;
            if !info.built_in_uv {
                fail!(EACCES,"YUBIKEY_PIN_PROVIDER_REQUIRED",
                    "UV is required; this authenticator needs a PIN token but no secure PIN provider is configured");
            }
        }
        let mut ext = None;
        let mut ss_out = None;
        if let Some(salt) = hmac_salt {
            if salt.len() != 32 && salt.len() != 64 {
                fail!(EINVAL, "PRF_INPUT_LENGTH");
            }
            check()?;
            let peer = self.key_agreement()?;
            // In particular, cancellation during this later PRF exchange must
            // stop before dispatch of a fresh authenticatorGetAssertion.
            check()?;
            let (ours, ss) = platform_agree(&peer)?;
            let salt_enc = ss.encrypt(salt)?;
            let salt_auth = ss.authenticate(&salt_enc);
            ext = Some(tmap(vec![(
                "hmac-secret",
                imap(vec![
                    (1, p256_to_cose(&ours)),
                    (2, Value::Bytes(salt_enc)),
                    (3, Value::Bytes(salt_auth.to_vec())),
                    (4, Value::Integer(2.into())),
                ]),
            )]));
            ss_out = Some(ss);
        }
        let mut entries = vec![
            (1, Value::Text(RP_ID.into())),
            (2, Value::Bytes(client_data_hash.to_vec())),
            (
                3,
                Value::Array(vec![tmap(vec![
                    ("type", Value::Text("public-key".into())),
                    ("id", Value::Bytes(credential_id.to_vec())),
                ])]),
            ),
        ];
        if let Some(e) = ext {
            entries.push((4, e));
        }
        entries.push((
            5,
            tmap(vec![
                ("up", Value::Bool(require_up)),
                ("uv", Value::Bool(require_uv && token.is_none())),
            ]),
        ));
        if let Some(token) = token {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(token)
                .map_err(|_| err!(EINVAL, "PIN_TOKEN_LENGTH"))?;
            mac.update(client_data_hash);
            entries.push((6, Value::Bytes(mac.finalize().into_bytes().to_vec())));
            entries.push((7, Value::Integer(2.into())));
        }
        check()?;
        let v = self
            .call(cmd::GET_ASSERTION, Some(imap(entries)))?
            .ok_or_else(|| err!(EIO, "GET_ASSERTION_EMPTY"))?;
        check()?;
        let cred_id = cbor::iget(&v, 1).and_then(|c| cbor::bytes(cbor::tget(c, "id")).ok());
        Ok((
            AssertionResponse {
                credential_id: cred_id,
                auth_data: cbor::bytes(cbor::iget(&v, 2))?,
                signature: cbor::bytes(cbor::iget(&v, 3))?,
            },
            ss_out,
        ))
    }
}

impl Drop for CtapClient<'_> {
    fn drop(&mut self) {
        if let Some(previous) = self.restore_deadline {
            let _ = self.dev.set_deadline_ns(previous);
        }
    }
}

/// Decrypt the `hmac-secret` output with the session secret.
pub fn decrypt_prf(ss: &SharedSecret, enc: &[u8]) -> EnclaveResult<SecretBytes> {
    let pt = ss.decrypt(enc)?;
    if pt.len() != 32 && pt.len() != 64 {
        fail!(EINVAL, "PRF_OUTPUT_LEN");
    }
    Ok(pt)
}

/// Enrollment: `getInfo` + MDS check + `makeCredential` + packed basic
/// attestation verified against the MDS attestation keys. `none`/self
/// attestation is rejected in `L2`/`L3`.
pub fn enroll(
    client: &mut CtapClient<'_>,
    mds: &MdsState,
    profile: Profile,
    now: i64,
) -> EnclaveResult<EnrolledCredential> {
    if profile == Profile::L3 {
        fail!(EACCES,"L3_INDEPENDENT_ASSET_ENROLLMENT_REQUIRED",
            "no authenticated independent asset admission or Enterprise policy provider is configured; no credential created");
    }
    enroll_inner(client, mds, profile, now)
}

/// Enrollment with a trusted live clock. Production callers must use this
/// entry so metadata is rechecked at the actual use after device waits.
pub fn enroll_with_clock(
    client: &mut CtapClient<'_>,
    mds: &MdsState,
    profile: Profile,
    clock: &dyn crate::clock::Clock,
) -> EnclaveResult<EnrolledCredential> {
    if profile == Profile::L3 {
        fail!(EACCES, "L3_INDEPENDENT_ASSET_ENROLLMENT_REQUIRED");
    }
    Ok(enroll_attested_inner(
        client,
        mds,
        profile,
        &|| clock.now_unix(),
        None,
        None,
        None,
        None,
    )?
    .0)
}

/// Begin an authorized two-phase L3 enrollment. This creates a credential only
/// after independent policy and fresh SEP-verified disclosure. The returned
/// pending object cannot authorize custody until an independent inventory issuer
/// signs its exact evidence. Any created nonresident handle must be retained on
/// downstream failure; this API never deletes/resets the authenticator.
#[cfg(any(test, feature = "simulation"))]
pub fn begin_asset_enrollment(
    client: &mut CtapClient<'_>,
    mds: &MdsState,
    policy: &super::asset_enrollment::VerifiedAssetEnrollmentPolicy,
    disclosure: super::asset_enrollment::VerifiedSetupDisclosure,
    now: i64,
) -> EnclaveResult<super::asset_enrollment::PendingAssetEnrollment> {
    // Compatibility for software fixtures with an explicit epoch. Production
    // service uses the trusted live-clock entry below.
    let clock = crate::clock::TestClock::at(now);
    begin_asset_enrollment_with_clock(client, mds, policy, disclosure, &clock)
}

/// Trusted-clock two-phase enrollment. Check independent expiry immediately
/// before credential creation and again after every interactive device wait.
pub fn begin_asset_enrollment_with_clock(
    client: &mut CtapClient<'_>,
    mds: &MdsState,
    policy: &super::asset_enrollment::VerifiedAssetEnrollmentPolicy,
    disclosure: super::asset_enrollment::VerifiedSetupDisclosure,
    clock: &dyn crate::clock::Clock,
) -> EnclaveResult<super::asset_enrollment::PendingAssetEnrollment> {
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    begin_asset_enrollment_capturing(
        client,
        mds,
        policy,
        disclosure,
        Profile::L3,
        clock,
        &cancelled,
        |_| Ok(()),
    )
}

/// Service enrollment preserves verified public evidence before post-response
/// time checks. A failed/expired attempt never activates the captured handle.
/// The sink must durably store evidence and return only after its commit.
pub fn begin_asset_enrollment_capturing(
    client: &mut CtapClient<'_>,
    mds: &MdsState,
    policy: &super::asset_enrollment::VerifiedAssetEnrollmentPolicy,
    disclosure: super::asset_enrollment::VerifiedSetupDisclosure,
    profile: Profile,
    clock: &dyn crate::clock::Clock,
    cancelled: &std::sync::atomic::AtomicBool,
    mut capture: impl FnMut(&super::asset_enrollment::PendingAssetEnrollment) -> EnclaveResult<()>,
) -> EnclaveResult<super::asset_enrollment::PendingAssetEnrollment> {
    begin_asset_enrollment_capturing_with_pin(
        client, mds, policy, disclosure, profile, clock, cancelled, None, capture,
    )
}

/// Native L3 makeCredential may require its own operation-scoped PIN token.
/// The provider must be bound to the same verified setup prompt and deadline;
/// L2 never invokes it. makeCredential permission1 cannot authorize assertions.
pub fn begin_asset_enrollment_capturing_with_pin(
    client: &mut CtapClient<'_>,
    mds: &MdsState,
    policy: &super::asset_enrollment::VerifiedAssetEnrollmentPolicy,
    disclosure: super::asset_enrollment::VerifiedSetupDisclosure,
    profile: Profile,
    clock: &dyn crate::clock::Clock,
    cancelled: &std::sync::atomic::AtomicBool,
    pin_provider: Option<&mut dyn FnMut() -> EnclaveResult<SecretBytes>>,
    mut capture: impl FnMut(&super::asset_enrollment::PendingAssetEnrollment) -> EnclaveResult<()>,
) -> EnclaveResult<super::asset_enrollment::PendingAssetEnrollment> {
    if profile < Profile::L2 {
        fail!(EACCES, "ASSET_ENROLLMENT_PROFILE");
    }
    let (sep_public_key, disclosure_evidence, deadline) = disclosure.consume(policy)?;
    let previous = client.dev.deadline_ns();
    client
        .dev
        .set_deadline_ns(Some(previous.map_or(deadline, |old| old.min(deadline))))?;
    let result = (|| {
        use sha2::Digest;
        let mut public = |credential: &EnrolledCredential, evidence: &[u8]| {
            capture(&super::asset_enrollment::PendingAssetEnrollment {
                credential: credential.clone(),
                policy_digest: policy.digest(),
                sep_public_key: sep_public_key.clone(),
                disclosure_evidence: disclosure_evidence.clone(),
                evidence_sha256: sha2::Sha256::digest(evidence).into(),
                attestation_evidence: evidence.to_vec(),
                mode: policy.mode(),
            })
        };
        let (credential, attestation_evidence) = enroll_attested_inner(
            client,
            mds,
            profile,
            &|| clock.now_unix(),
            Some(policy),
            Some(cancelled),
            pin_provider,
            Some(&mut public),
        )?;
        if cancelled.load(std::sync::atomic::Ordering::Acquire) {
            fail!(EACCES, "ASSET_SETUP_CANCELLED");
        }
        if enclave_core::power::continuous_time_ns() >= deadline {
            fail!(ETIMEDOUT, "ASSET_SETUP_DEADLINE");
        }
        Ok(super::asset_enrollment::PendingAssetEnrollment {
            credential,
            policy_digest: policy.digest(),
            sep_public_key,
            disclosure_evidence,
            evidence_sha256: sha2::Sha256::digest(&attestation_evidence).into(),
            attestation_evidence,
            mode: policy.mode(),
        })
    })();
    let restore = client.dev.set_deadline_ns(previous);
    result.and_then(|value| restore.map(|()| value))
}

/// Explicit software-only enrollment fixture. Requiring a concrete virtual
/// authenticator prevents simulation dev-dependencies from enabling physical
/// L3 enrollment without an independent asset authority.
#[cfg(any(test, feature = "simulation"))]
pub fn enroll_simulated(
    device: &mut super::virtual_device::VirtualAuthenticator,
    mds: &MdsState,
    profile: Profile,
    now: i64,
) -> EnclaveResult<EnrolledCredential> {
    enroll_inner(&mut CtapClient::open(device)?, mds, profile, now)
}

fn enroll_inner(
    client: &mut CtapClient<'_>,
    mds: &MdsState,
    profile: Profile,
    now: i64,
) -> EnclaveResult<EnrolledCredential> {
    let started = enclave_core::power::continuous_time_ns();
    let wall_started = enclave_crypto::time::now_unix();
    let current = || {
        now.saturating_add(
            enclave_crypto::time::now_unix()
                .saturating_sub(wall_started)
                .max(
                    (enclave_core::power::continuous_time_ns().saturating_sub(started)
                        / 1_000_000_000) as i64,
                ),
        )
    };
    Ok(enroll_attested_inner(client, mds, profile, &current, None, None, None, None)?.0)
}

fn enroll_attested_inner(
    client: &mut CtapClient<'_>,
    mds: &MdsState,
    profile: Profile,
    now: &dyn Fn() -> i64,
    policy: Option<&super::asset_enrollment::VerifiedAssetEnrollmentPolicy>,
    cancelled: Option<&std::sync::atomic::AtomicBool>,
    mut pin_provider: Option<&mut dyn FnMut() -> EnclaveResult<SecretBytes>>,
    mut capture: Option<&mut dyn FnMut(&EnrolledCredential, &[u8]) -> EnclaveResult<()>>,
) -> EnclaveResult<(EnrolledCredential, Vec<u8>)> {
    // Enrollment admits long-lived custody keys and therefore uses the same
    // freshness boundary as a critical custody action, before makeCredential.
    let metadata_action = if profile >= Profile::L2 {
        ActionClass::A3
    } else {
        ActionClass::A2
    };
    if profile == Profile::L3 && policy.is_some() && client.hub_depth() != 1 {
        fail!(EACCES, "USB_HUB_FORBIDDEN_L3");
    }
    let info = client.get_info()?;
    if cancelled.is_some_and(|c| c.load(std::sync::atomic::Ordering::Acquire)) {
        fail!(EACCES, "ASSET_SETUP_CANCELLED");
    }
    if !info
        .versions
        .iter()
        .any(|version| version == "FIDO_2_1" || version == "FIDO_2_1_PRE")
        || !info.extensions.iter().any(|e| e == "hmac-secret")
        || !info.pin_uv_protocols.contains(&2)
    {
        fail!(EACCES, "AUTHENTICATOR_LACKS_CTAP21_FEATURES");
    }
    let enterprise = policy
        .is_some_and(|p| p.mode() == super::asset_enrollment::AttestationMode::EnterpriseRequired);
    if let Some(policy) = policy {
        policy.check(&info.aaguid, now())?;
    }
    if enterprise && !info.enterprise_attestation_enabled {
        fail!(EACCES, "ENTERPRISE_ATTESTATION_NOT_ENABLED");
    }
    let supports_eddsa = info.algorithms.contains(&alg::EDDSA)
        && info.firmware_version >= crate::ctap::mds::MIN_FW_ED25519;
    let preferred_algs = if supports_eddsa {
        vec![alg::EDDSA, alg::ES256]
    } else {
        vec![alg::ES256]
    };
    let selected_alg = preferred_algs[0];

    mds.check(
        &info.aaguid,
        info.firmware_version,
        selected_alg,
        profile,
        metadata_action,
        now(),
    )?;
    let mut challenge = [0u8; 32];
    enclave_core::rng::fill(&mut challenge);
    // GetInfo and metadata validation may themselves block. Use a fresh
    // trusted time immediately before the irreversible credential operation.
    if let Some(policy) = policy {
        policy.check(&info.aaguid, now())?;
    }
    mds.check(
        &info.aaguid,
        info.firmware_version,
        selected_alg,
        profile,
        metadata_action,
        now(),
    )?;
    if cancelled.is_some_and(|c| c.load(std::sync::atomic::Ordering::Acquire)) {
        fail!(EACCES, "ASSET_SETUP_CANCELLED");
    }
    let require_uv = profile == Profile::L3 && policy.is_some();
    let never_cancelled = std::sync::atomic::AtomicBool::new(false);
    let token = if require_uv && !info.built_in_uv {
        let provider = pin_provider
            .as_mut()
            .ok_or_else(|| err!(EACCES, "YUBIKEY_PIN_PROVIDER_REQUIRED"))?;
        let deadline = client
            .dev
            .deadline_ns()
            .ok_or_else(|| err!(ETIMEDOUT, "ASSET_SETUP_DEADLINE"))?;
        Some(client.obtain_pin_token(
            Profile::L3,
            1,
            deadline,
            cancelled.unwrap_or(&never_cancelled),
            provider,
        )?)
    } else {
        None
    };
    // PIN acquisition is inside the same original setup budget and can cross
    // policy/metadata expiry: recheck before the credential write itself.
    if let Some(policy) = policy {
        policy.check(&info.aaguid, now())?;
    }
    mds.check(
        &info.aaguid,
        info.firmware_version,
        selected_alg,
        profile,
        metadata_action,
        now(),
    )?;
    if cancelled.is_some_and(|c| c.load(std::sync::atomic::Ordering::Acquire)) {
        fail!(EACCES, "ASSET_SETUP_CANCELLED");
    }
    let (fmt, ad, att, ep_att) = client.make_credential_enrollment(
        &challenge,
        b"depot-custodian",
        &preferred_algs,
        enterprise,
        require_uv,
        token.as_ref().map(|value| value.expose()),
    )?;
    drop(token);
    if require_uv && ad.flags & super::assertion::FLAG_UV == 0 {
        fail!(EACCES, "ENROLL_USER_VERIFICATION_MISSING");
    }
    if ad.rp_id_hash != super::rp_id_hash() {
        fail!(EACCES, "ENROLL_RP_ID_HASH_MISMATCH");
    }
    if ad.flags & super::assertion::FLAG_UP == 0 {
        fail!(EACCES, "ENROLL_USER_PRESENCE_MISSING");
    }
    if ad.flags & FLAG_AT == 0 {
        fail!(EINVAL, "ENROLL_NO_ATTESTED_DATA");
    }
    let acd = ad
        .attested
        .clone()
        .ok_or_else(|| err!(EINVAL, "ENROLL_NO_ATTESTED_DATA"))?;
    if acd.aaguid != info.aaguid {
        fail!(EACCES, "ENROLL_AAGUID_MISMATCH");
    }
    if !ad
        .extensions
        .as_ref()
        .is_some_and(|extension| cbor::boolean(cbor::tget(extension, "hmac-secret")))
    {
        fail!(EACCES, "ENROLL_PRF_NOT_ENABLED");
    }
    if profile >= Profile::L2 {
        if fmt != "packed" {
            fail!(
                EACCES,
                "ENROLL_ATTESTATION_REJECTED",
                "{fmt} attestation not acceptable in {profile}"
            );
        }
        let sig = cbor::bytes(cbor::tget(&att, "sig"))?;
        let trusted_roots = mds.attestation_roots(&info.aaguid)?;

        // If attStmt contains "x5c" and we have trusted roots, verify X.509 chain
        if let Some(Value::Array(x5c_arr)) = cbor::tget(&att, "x5c") {
            let mut x5c_der = Vec::new();
            for item in x5c_arr {
                x5c_der.push(cbor::bytes(Some(item))?);
            }
            crate::ctap::x509::verify_packed_attestation(
                &x5c_der,
                &trusted_roots,
                &info.aaguid,
                &ad.raw,
                &challenge,
                &sig,
            )?;
        } else {
            // Raw basic attestation key verification (used by the emulator)
            let a = cbor::int(cbor::tget(&att, "alg"))?;
            let mut msg = ad.raw.clone();
            msg.extend_from_slice(&challenge);
            let ok = mds
                .attestation_keys(&info.aaguid)?
                .into_iter()
                .any(|(ka, raw)| {
                    ka == a && CredentialKey::from_raw(ka, &raw).is_ok_and(|k| k.verify(&msg, &sig))
                });
            if !ok {
                fail!(EACCES, "ENROLL_ATTESTATION_INVALID");
            }
        }
    }
    if enterprise {
        use sha2::Digest;
        if !ep_att {
            fail!(EACCES, "ENTERPRISE_ATTESTATION_NOT_RETURNED");
        }
        let Some(Value::Array(chain))=cbor::tget(&att,"x5c") else {fail!(EACCES,"ENTERPRISE_ATTESTATION_IDENTITY_REQUIRED");};
        let leaf = cbor::bytes(chain.first())?;
        let digest: [u8; 32] = sha2::Sha256::digest(&leaf).into();
        if policy.and_then(|p| p.leaf()) != Some(digest) {
            fail!(EACCES, "ENTERPRISE_ATTESTATION_IDENTITY_MISMATCH");
        }
    }
    let key = CredentialKey::from_cose(&acd.cose_key)?;
    if !preferred_algs.contains(&key.alg()) {
        fail!(EACCES, "ENROLL_ALGORITHM_NOT_OFFERED");
    }
    let evidence = cbor::encode(&tmap(vec![
        ("challenge", Value::Bytes(challenge.to_vec())),
        ("fmt", Value::Text(fmt)),
        ("authData", Value::Bytes(ad.raw)),
        ("attStmt", att),
        ("enterpriseAttested", Value::Bool(ep_att)),
    ]))?;
    let credential = EnrolledCredential {
        credential_id: acd.credential_id,
        key,
        aaguid: info.aaguid,
        firmware_version: info.firmware_version,
    };
    if let Some(sink) = capture.as_mut() {
        sink(&credential, &evidence)?;
    }
    mds.check(
        &info.aaguid,
        info.firmware_version,
        credential.key.alg(),
        profile,
        metadata_action,
        now(),
    )?;
    if let Some(policy) = policy {
        policy.check(&info.aaguid, now())?;
    }
    Ok((credential, evidence))
}

#[cfg(test)]
mod capability_tests {
    use super::*;
    use crate::ctap::virtual_device::VirtualAuthenticator;
    #[test]
    fn no_builtin_uv_fails_explicitly_without_downgrading_required_factor() {
        let mut dev = VirtualAuthenticator::new([7; 16]);
        dev.uv_capable = false;
        let mut client = CtapClient::open(&mut dev).unwrap();
        assert!(!client.get_info().unwrap().built_in_uv);
        assert!(client
            .get_assertion(b"credential", &[2; 32], true, Some(&[3; 32]))
            .unwrap_err()
            .is("YUBIKEY_PIN_PROVIDER_REQUIRED"));
    }
    #[test]
    fn builtin_uv_capability_is_parsed_without_treating_it_as_verified_assertion() {
        let mut dev = VirtualAuthenticator::new([7; 16]);
        dev.uv_capable = true;
        let mut client = CtapClient::open(&mut dev).unwrap();
        assert!(client.get_info().unwrap().built_in_uv);
        assert!(client
            .get_assertion(b"missing", &[2; 32], true, None)
            .is_err());
    }
}

#[cfg(test)]
mod pin_provider_tests {
    use super::*;
    use crate::ctap::assertion::{verify_assertion, SignCountStore};
    use crate::ctap::mds::{MdsAllowlist, MdsEntry};
    use crate::ctap::virtual_device::VirtualAuthenticator;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn fixture() -> (VirtualAuthenticator, EnrolledCredential) {
        let mut dev = VirtualAuthenticator::new([9; 16]);
        let mds = MdsState {
            refreshed_at: 100,
            expires_at: i64::MAX,
            allowlist: MdsAllowlist {
                entries: vec![MdsEntry {
                    aaguid: hex::encode(dev.aaguid),
                    description: "synthetic".into(),
                    min_firmware_version: 0x05_07_00,
                    status_reports: vec![],
                    attestation_public_keys: vec![dev.attestation_key_mds()],
                    attestation_root_certificates: vec![],
                }],
            },
        };
        let cred = enroll(
            &mut CtapClient::open(&mut dev).unwrap(),
            &mds,
            Profile::L2,
            100,
        )
        .unwrap();
        dev.configure_synthetic_pin(b"synthetic-pin");
        (dev, cred)
    }
    fn deadline() -> u64 {
        enclave_core::power::continuous_time_ns() + 10_000_000_000
    }
    fn pin() -> EnclaveResult<SecretBytes> {
        Ok(SecretBytes::new(b"synthetic-pin".to_vec()))
    }

    #[test]
    fn cancellation_during_getinfo_never_invokes_pin_provider() {
        use crate::ctap::hid::{CMD_CBOR, REPORT};
        use std::sync::Arc;
        #[derive(Debug)]
        struct CancelOnInfo {
            inner: VirtualAuthenticator,
            cancelled: Arc<AtomicBool>,
            armed: bool,
        }
        impl HidDevice for CancelOnInfo {
            fn write_report(&mut self, report: &[u8; REPORT]) -> EnclaveResult<()> {
                if report[4] == (CMD_CBOR | 0x80) && report[7] == cmd::GET_INFO {
                    self.armed = true;
                }
                self.inner.write_report(report)
            }
            fn read_report(&mut self) -> EnclaveResult<[u8; REPORT]> {
                let report = self.inner.read_report()?;
                if self.armed {
                    self.cancelled.store(true, Ordering::Release);
                    self.armed = false;
                }
                Ok(report)
            }
            fn hub_depth(&self) -> u8 {
                self.inner.hub_depth()
            }
            fn deadline_ns(&self) -> Option<u64> {
                self.inner.deadline_ns()
            }
            fn set_deadline_ns(&mut self, deadline: Option<u64>) -> EnclaveResult<()> {
                self.inner.set_deadline_ns(deadline)
            }
        }
        let (inner, credential) = fixture();
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut device = CancelOnInfo {
            inner,
            cancelled: cancelled.clone(),
            armed: false,
        };
        let error = CtapClient::open(&mut device)
            .unwrap()
            .get_assertion_with_pin_provider(
                Profile::L3,
                &credential.credential_id,
                &[1; 32],
                None,
                deadline(),
                &cancelled,
                || panic!("cancelled GetInfo must not prompt"),
            )
            .unwrap_err();
        assert!(error.is("FIDO_PIN_CEREMONY_CANCELLED"));
    }

    // Synthetic command/response observation only. No native provider or raw
    // PIN/token/PRF capture: retain just command kinds and advertised endpoints.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum PinAction {
        Init,
        Info,
        KeyAgreement(usize),
        Token,
        Assertion,
        Other,
    }
    #[derive(Debug)]
    struct CancelAfterResponse {
        inner: VirtualAuthenticator,
        cancelled: std::sync::Arc<AtomicBool>,
        at: Option<PinAction>,
        outgoing: super::super::hid::Reassembler,
        incoming: super::super::hid::Reassembler,
        pending: Option<PinAction>,
        agreements: usize,
        sent: Vec<PinAction>,
        completed: Vec<PinAction>,
        endpoints: Vec<Option<u64>>,
    }
    impl CancelAfterResponse {
        fn new(
            inner: VirtualAuthenticator,
            cancelled: std::sync::Arc<AtomicBool>,
            at: Option<PinAction>,
        ) -> Self {
            Self {
                inner,
                cancelled,
                at,
                outgoing: Default::default(),
                incoming: Default::default(),
                pending: None,
                agreements: 0,
                sent: Vec::new(),
                completed: Vec::new(),
                endpoints: Vec::new(),
            }
        }
        fn action(&mut self, command: u8, payload: &[u8]) -> EnclaveResult<PinAction> {
            if command == CMD_INIT {
                return Ok(PinAction::Init);
            }
            if command != CMD_CBOR {
                return Ok(PinAction::Other);
            }
            Ok(match payload.first().copied() {
                Some(cmd::GET_INFO) => PinAction::Info,
                Some(cmd::GET_ASSERTION) => PinAction::Assertion,
                Some(cmd::CLIENT_PIN) => {
                    let params = cbor::decode(&payload[1..])?;
                    match cbor::int(cbor::iget(&params, 2))? {
                        2 => {
                            self.agreements += 1;
                            PinAction::KeyAgreement(self.agreements)
                        }
                        9 => PinAction::Token,
                        _ => PinAction::Other,
                    }
                }
                _ => PinAction::Other,
            })
        }
    }
    impl HidDevice for CancelAfterResponse {
        fn write_report(&mut self, report: &[u8; super::super::hid::REPORT]) -> EnclaveResult<()> {
            let cid = u32::from_be_bytes(report[..4].try_into().unwrap());
            if let Some((command, payload)) = self.outgoing.feed(cid, report)? {
                let action = self.action(command, &payload)?;
                assert!(
                    self.pending.replace(action).is_none(),
                    "fixture overlapping commands"
                );
                self.sent.push(action);
                self.endpoints.push(self.inner.deadline_ns());
            }
            self.inner.write_report(report)
        }
        fn read_report(&mut self) -> EnclaveResult<[u8; super::super::hid::REPORT]> {
            let report = self.inner.read_report()?;
            let cid = u32::from_be_bytes(report[..4].try_into().unwrap());
            if self.incoming.feed(cid, &report)?.is_some() {
                let action = self
                    .pending
                    .take()
                    .expect("fixture response follows request");
                self.completed.push(action);
                if self.at == Some(action) {
                    self.cancelled.store(true, Ordering::Release);
                }
            }
            Ok(report)
        }
        fn hub_depth(&self) -> u8 {
            self.inner.hub_depth()
        }
        fn deadline_ns(&self) -> Option<u64> {
            self.inner.deadline_ns()
        }
        fn set_deadline_ns(&mut self, end: Option<u64>) -> EnclaveResult<()> {
            self.inner.set_deadline_ns(end)
        }
    }

    #[test]
    fn cancellation_after_prf_key_agreement_prevents_single_and_dual_assertion_dispatch() {
        for dual in [false, true] {
            let (inner, credential) = fixture();
            let initial_count = inner.sign_count();
            let cancelled = std::sync::Arc::new(AtomicBool::new(false));
            let mut device = CancelAfterResponse::new(
                inner,
                cancelled.clone(),
                Some(PinAction::KeyAgreement(2)),
            );
            let original = enclave_core::power::continuous_time_ns() + 9_000_000_000;
            device.set_deadline_ns(Some(original)).unwrap();
            let mut prompts = 0;
            let mut client = CtapClient::open(&mut device).unwrap();
            let result = if dual {
                client.get_assertion_dual_prf_with_pin_provider(
                    &credential.credential_id,
                    &[41; 32],
                    &[7; 64],
                    deadline(),
                    &cancelled,
                    || {
                        prompts += 1;
                        pin()
                    },
                )
            } else {
                client.get_assertion_with_pin_provider(
                    Profile::L3,
                    &credential.credential_id,
                    &[41; 32],
                    Some(&[7; 32]),
                    deadline(),
                    &cancelled,
                    || {
                        prompts += 1;
                        pin()
                    },
                )
            };
            assert!(result.unwrap_err().is("FIDO_PIN_CEREMONY_CANCELLED"));
            drop(client);
            assert_eq!(prompts, 1);
            assert!(cancelled.load(Ordering::Acquire));
            let expected = vec![
                PinAction::Init,
                PinAction::Info,
                PinAction::KeyAgreement(1),
                PinAction::Token,
                PinAction::KeyAgreement(2),
            ];
            assert_eq!(device.sent, expected);
            assert_eq!(device.completed, expected);
            assert_eq!(
                device.inner.assertion_requests, 0,
                "no new authenticator assertion after PRF cancellation"
            );
            assert_eq!(device.inner.sign_count(), initial_count);
            assert_eq!(device.deadline_ns(), Some(original));
            assert!(device.endpoints.iter().all(|end| *end == Some(original)));
        }
    }

    #[test]
    fn cancellation_at_pin_responses_stops_later_commands_and_never_retries_completed_assertion() {
        for at in [
            PinAction::Info,
            PinAction::KeyAgreement(1),
            PinAction::Token,
            PinAction::Assertion,
        ] {
            let (inner, credential) = fixture();
            let initial_count = inner.sign_count();
            let cancelled = std::sync::Arc::new(AtomicBool::new(false));
            let mut device = CancelAfterResponse::new(inner, cancelled.clone(), Some(at));
            let mut prompts = 0;
            let error = CtapClient::open(&mut device)
                .unwrap()
                .get_assertion_with_pin_provider(
                    Profile::L3,
                    &credential.credential_id,
                    &[42; 32],
                    Some(&[7; 32]),
                    deadline(),
                    &cancelled,
                    || {
                        prompts += 1;
                        pin()
                    },
                )
                .unwrap_err();
            assert!(error.is("FIDO_PIN_CEREMONY_CANCELLED"));
            assert!(cancelled.load(Ordering::Acquire));
            let expected = match at {
                PinAction::Info => vec![PinAction::Init, PinAction::Info],
                PinAction::KeyAgreement(1) => {
                    vec![PinAction::Init, PinAction::Info, PinAction::KeyAgreement(1)]
                }
                PinAction::Token => vec![
                    PinAction::Init,
                    PinAction::Info,
                    PinAction::KeyAgreement(1),
                    PinAction::Token,
                ],
                PinAction::Assertion => vec![
                    PinAction::Init,
                    PinAction::Info,
                    PinAction::KeyAgreement(1),
                    PinAction::Token,
                    PinAction::KeyAgreement(2),
                    PinAction::Assertion,
                ],
                _ => unreachable!(),
            };
            assert_eq!(device.sent, expected);
            assert_eq!(device.completed, expected);
            assert_eq!(prompts, usize::from(at != PinAction::Info));
            let completed = usize::from(at == PinAction::Assertion);
            assert_eq!(device.inner.assertion_requests, completed);
            // An already completed signed assertion cannot be retracted by its
            // later cancellation check. Refuse its output without replaying it.
            assert_eq!(device.inner.sign_count(), initial_count + completed as u32);
        }
    }

    #[test]
    fn uncancelled_pin_response_wrapper_preserves_signed_uv_prf_and_original_endpoint() {
        for dual in [false, true] {
            let (inner, credential) = fixture();
            let cancelled = std::sync::Arc::new(AtomicBool::new(false));
            let mut device = CancelAfterResponse::new(inner, cancelled.clone(), None);
            let original = enclave_core::power::continuous_time_ns() + 9_000_000_000;
            device.set_deadline_ns(Some(original)).unwrap();
            let mut prompts = 0;
            let mut salts = [7; 64];
            salts[32..].copy_from_slice(&[8; 32]);
            let challenge = [43; 32];
            let mut client = CtapClient::open(&mut device).unwrap();
            let (response, shared) = if dual {
                client.get_assertion_dual_prf_with_pin_provider(
                    &credential.credential_id,
                    &challenge,
                    &salts,
                    deadline(),
                    &cancelled,
                    || {
                        prompts += 1;
                        pin()
                    },
                )
            } else {
                client.get_assertion_with_pin_provider(
                    Profile::L3,
                    &credential.credential_id,
                    &challenge,
                    Some(&[7; 32]),
                    deadline(),
                    &cancelled,
                    || {
                        prompts += 1;
                        pin()
                    },
                )
            }
            .unwrap();
            drop(client);
            let verified = verify_assertion(
                &credential,
                &response,
                &challenge,
                true,
                &mut SignCountStore::default(),
            )
            .unwrap();
            assert!(verified.user_verified);
            let prf =
                decrypt_prf(&shared.unwrap(), verified.hmac_secret_enc.as_ref().unwrap()).unwrap();
            assert_eq!(prf.len(), if dual { 64 } else { 32 });
            if dual {
                assert_ne!(&prf.expose()[..32], &prf.expose()[32..]);
            }
            assert_eq!(prompts, 1);
            assert!(!cancelled.load(Ordering::Acquire));
            assert_eq!(device.inner.assertion_requests, 1);
            assert_eq!(device.sent, device.completed);
            assert_eq!(
                device.sent,
                vec![
                    PinAction::Init,
                    PinAction::Info,
                    PinAction::KeyAgreement(1),
                    PinAction::Token,
                    PinAction::KeyAgreement(2),
                    PinAction::Assertion
                ]
            );
            assert_eq!(device.deadline_ns(), Some(original));
            assert!(device.endpoints.iter().all(|end| *end == Some(original)));
        }
    }

    #[test]
    fn make_credential_and_assertion_pin_tokens_cannot_cross_permission_scope() {
        let (mut dev, credential) = fixture();
        let cancelled = AtomicBool::new(false);
        let challenge = [23; 32];
        let mut client = CtapClient::open(&mut dev).unwrap();
        let token = client
            .obtain_pin_token(Profile::L3, 1, deadline(), &cancelled, pin)
            .unwrap();
        assert!(client
            .get_assertion_authorized(
                &credential.credential_id,
                &challenge,
                true,
                None,
                Some(token.expose())
            )
            .unwrap_err()
            .is("PIN_UV_AUTH_INVALID"));
        let (_, ad, _, _) = client
            .make_credential_enrollment(
                &challenge,
                b"fixture-new",
                &[alg::EDDSA],
                false,
                true,
                Some(token.expose()),
            )
            .unwrap();
        assert_ne!(ad.flags & super::super::assertion::FLAG_UV, 0);
        let token = client
            .obtain_pin_token(Profile::L3, 2, deadline(), &cancelled, pin)
            .unwrap();
        assert!(client
            .make_credential_enrollment(
                &challenge,
                b"fixture-new",
                &[alg::EDDSA],
                false,
                true,
                Some(token.expose())
            )
            .unwrap_err()
            .is("PIN_UV_AUTH_INVALID"));
    }

    #[test]
    fn dual_tier_prfs_use_one_pin_assertion_and_keep_distinct_salts() {
        let (mut dev, cred) = fixture();
        let cancelled = AtomicBool::new(false);
        let mut salts = [0; 64];
        salts[..32].copy_from_slice(&[7; 32]);
        salts[32..].copy_from_slice(&[8; 32]);
        let mut prompts = 0;
        let challenge = [29; 32];
        let mut counters = SignCountStore::default();
        let (response, shared) = CtapClient::open(&mut dev)
            .unwrap()
            .get_assertion_dual_prf_with_pin_provider(
                &cred.credential_id,
                &challenge,
                &salts,
                deadline(),
                &cancelled,
                || {
                    prompts += 1;
                    pin()
                },
            )
            .unwrap();
        assert_eq!(prompts, 1);
        let verified = verify_assertion(&cred, &response, &challenge, true, &mut counters).unwrap();
        let result = decrypt_prf(&shared.unwrap(), &verified.hmac_secret_enc.unwrap()).unwrap();
        assert_eq!(result.len(), 64);
        assert_ne!(&result.expose()[..32], &result.expose()[32..]);
        let challenge = [30; 32];
        let (response, shared) = CtapClient::open(&mut dev)
            .unwrap()
            .get_assertion_with_pin_provider(
                Profile::L3,
                &cred.credential_id,
                &challenge,
                Some(&[7; 32]),
                deadline(),
                &cancelled,
                pin,
            )
            .unwrap();
        let verified = verify_assertion(&cred, &response, &challenge, true, &mut counters).unwrap();
        let one = decrypt_prf(&shared.unwrap(), &verified.hmac_secret_enc.unwrap()).unwrap();
        assert_eq!(one.expose(), &result.expose()[..32]);
    }

    #[test]
    fn silent_presence_has_no_action_factor_or_prf_and_shares_durable_counters() {
        use crate::ctap::assertion::verify_presence;
        let (mut dev, cred) = fixture();
        dev.presence = crate::ctap::virtual_device::Presence::NoTouch;
        let challenge = [31; 32];
        let mut counts = SignCountStore::default();
        let response = CtapClient::open(&mut dev)
            .unwrap()
            .get_presence(&cred.credential_id, &challenge)
            .unwrap();
        assert!(
            verify_assertion(&cred, &response, &challenge, false, &mut counts)
                .unwrap_err()
                .is("USER_PRESENCE_MISSING")
        );
        let observation = verify_presence(&cred, &response, &challenge, &mut counts).unwrap();
        assert_eq!(counts.get_credential(&cred), observation.sign_count);
        assert!(verify_presence(&cred, &response, &challenge, &mut counts)
            .unwrap_err()
            .is("SIGN_COUNT_REGRESSION"));
        let other = [32; 32];
        let mut forged = CtapClient::open(&mut dev)
            .unwrap()
            .get_presence(&cred.credential_id, &other)
            .unwrap();
        forged.signature[0] ^= 1;
        assert!(verify_presence(&cred, &forged, &other, &mut counts)
            .unwrap_err()
            .is("ASSERTION_SIGNATURE_INVALID"));
        dev.presence = crate::ctap::virtual_device::Presence::Touch;
        let (action, _) = CtapClient::open(&mut dev)
            .unwrap()
            .get_assertion(&cred.credential_id, &other, false, Some(&[7; 32]))
            .unwrap();
        assert!(verify_presence(&cred, &action, &other, &mut counts)
            .unwrap_err()
            .is("PRESENCE_EXTENSIONS_FORBIDDEN"));
        verify_assertion(&cred, &action, &other, false, &mut counts).unwrap();
        let seal_key = enclave_core::secret::SecretKey32::new([11; 32]);
        let (state, mac) = counts.seal(&seal_key);
        let mut restored = SignCountStore::unseal(&state, &mac, &seal_key).unwrap();
        assert!(
            verify_assertion(&cred, &action, &other, false, &mut restored)
                .unwrap_err()
                .is("SIGN_COUNT_REGRESSION")
        );
    }

    #[test]
    fn protocol2_pin_only_device_produces_signed_uv_and_authenticated_prf() {
        let (mut dev, cred) = fixture();
        let cancelled = AtomicBool::new(false);
        let salt = [8; 32];
        let mut counts = SignCountStore::default();
        let mut first = None;
        for challenge in [[1; 32], [2; 32]] {
            let (response, shared) = CtapClient::open(&mut dev)
                .unwrap()
                .get_assertion_with_pin_provider(
                    Profile::L3,
                    &cred.credential_id,
                    &challenge,
                    Some(&salt),
                    deadline(),
                    &cancelled,
                    pin,
                )
                .unwrap();
            let verified =
                verify_assertion(&cred, &response, &challenge, true, &mut counts).unwrap();
            assert!(verified.user_verified);
            let prf =
                decrypt_prf(&shared.unwrap(), verified.hmac_secret_enc.as_ref().unwrap()).unwrap();
            if let Some(first) = &first {
                assert_eq!(prf.expose(), first);
            } else {
                first = Some(prf.expose().to_vec());
            }
        }
    }

    #[test]
    fn pin_free_profiles_and_cancelled_expired_ceremonies_never_invoke_provider() {
        let (mut dev, cred) = fixture();
        let cancelled = AtomicBool::new(false);
        for profile in [Profile::L1, Profile::L2] {
            assert!(CtapClient::open(&mut dev)
                .unwrap()
                .get_assertion_with_pin_provider(
                    profile,
                    &cred.credential_id,
                    &[1; 32],
                    None,
                    deadline(),
                    &cancelled,
                    || panic!("PIN-free profile prompted")
                )
                .unwrap_err()
                .is("FIDO_TYPED_PIN_FORBIDDEN_FOR_PROFILE"));
        }
        cancelled.store(true, Ordering::Release);
        assert!(CtapClient::open(&mut dev)
            .unwrap()
            .get_assertion_with_pin_provider(
                Profile::L3,
                &cred.credential_id,
                &[1; 32],
                None,
                deadline(),
                &cancelled,
                || panic!("cancelled prompt")
            )
            .unwrap_err()
            .is("FIDO_PIN_CEREMONY_CANCELLED"));
        cancelled.store(false, Ordering::Release);
        assert!(CtapClient::open(&mut dev)
            .unwrap()
            .get_assertion_with_pin_provider(
                Profile::L3,
                &cred.credential_id,
                &[1; 32],
                None,
                0,
                &cancelled,
                || panic!("expired prompt")
            )
            .unwrap_err()
            .is("FIDO_PIN_CEREMONY_DEADLINE"));
        let result = CtapClient::open(&mut dev)
            .unwrap()
            .get_assertion_with_pin_provider(
                Profile::L3,
                &cred.credential_id,
                &[1; 32],
                None,
                deadline(),
                &cancelled,
                || {
                    cancelled.store(true, Ordering::Release);
                    pin()
                },
            );
        assert!(result.unwrap_err().is("FIDO_PIN_CEREMONY_CANCELLED"));
        assert_eq!(dev.assertion_requests, 0);
    }

    #[test]
    fn negative_pin_retry_soft_hard_block_and_restart_are_emulator_only() {
        let (mut dev, cred) = fixture();
        let cancelled = AtomicBool::new(false);
        for attempt in 1..=8 {
            let error = CtapClient::open(&mut dev)
                .unwrap()
                .get_assertion_with_pin_provider(
                    Profile::L3,
                    &cred.credential_id,
                    &[1; 32],
                    None,
                    deadline(),
                    &cancelled,
                    || Ok(SecretBytes::new(b"wrong-synthetic-pin".to_vec())),
                )
                .unwrap_err();
            let expected = if attempt == 8 {
                "FIDO_PIN_BLOCKED"
            } else if attempt % 3 == 0 {
                "FIDO_PIN_AUTH_BLOCKED"
            } else {
                "FIDO_PIN_INVALID"
            };
            assert!(error.is(expected), "{error}");
            if attempt % 3 == 0 {
                dev.power_cycle();
            }
        }
        let mut restored = VirtualAuthenticator::import_state(&dev.export_state()).unwrap();
        assert!(CtapClient::open(&mut restored)
            .unwrap()
            .get_assertion_with_pin_provider(
                Profile::L3,
                &cred.credential_id,
                &[1; 32],
                None,
                deadline(),
                &cancelled,
                pin
            )
            .unwrap_err()
            .is("FIDO_PIN_BLOCKED"));
        assert_eq!(dev.assertion_requests, 0);
    }

    #[test]
    fn invalid_pin_encoding_and_provider_failure_do_not_send_pin_request() {
        let (mut dev, cred) = fixture();
        let cancelled = AtomicBool::new(false);
        for value in [
            b"abc".to_vec(),
            vec![b'x'; 64],
            vec![0xff; 6],
            b"abcd\0".to_vec(),
            "abcde\u{301}".as_bytes().to_vec(),
        ] {
            assert!(CtapClient::open(&mut dev)
                .unwrap()
                .get_assertion_with_pin_provider(
                    Profile::L3,
                    &cred.credential_id,
                    &[1; 32],
                    None,
                    deadline(),
                    &cancelled,
                    || Ok(SecretBytes::new(value))
                )
                .is_err());
        }
        assert!(CtapClient::open(&mut dev)
            .unwrap()
            .get_assertion_with_pin_provider(
                Profile::L3,
                &cred.credential_id,
                &[1; 32],
                None,
                deadline(),
                &cancelled,
                || Err(err!(EACCES, "HOST_PIN_UI_UNAVAILABLE"))
            )
            .unwrap_err()
            .is("HOST_PIN_UI_UNAVAILABLE"));
        // Correct PIN remains usable; malformed inputs did not exhaust retries.
        assert!(CtapClient::open(&mut dev)
            .unwrap()
            .get_assertion_with_pin_provider(
                Profile::L3,
                &cred.credential_id,
                &[1; 32],
                None,
                deadline(),
                &cancelled,
                pin
            )
            .is_ok());
    }
}

#[cfg(test)]
mod scoped_deadline_and_enrollment_tests {
    use super::*;
    use crate::ctap::hid::HidDevice;
    use crate::ctap::virtual_device::VirtualAuthenticator;
    #[test]
    fn ctap_client_deadline_is_scoped_and_cannot_be_extended() {
        let mut device = VirtualAuthenticator::new([1; 16]);
        let deadline = enclave_core::power::continuous_time_ns() + 1_000_000_000;
        assert_eq!(device.deadline_ns(), None);
        {
            let mut client = CtapClient::open_with_deadline(&mut device, deadline).unwrap();
            assert_eq!(client.dev.deadline_ns(), Some(deadline));
            client.get_info().unwrap();
            client.dev.set_deadline_ns(Some(0)).unwrap();
            assert!(client
                .get_info()
                .unwrap_err()
                .is("CTAPHID_DEADLINE_EXCEEDED"));
        }
        assert_eq!(device.deadline_ns(), None);
        assert!(CtapClient::open_with_deadline(&mut device, 0)
            .unwrap_err()
            .is("CTAPHID_DEADLINE_EXCEEDED"));
    }
    #[test]
    fn physical_capable_enrollment_path_never_creates_l3_credential_without_asset_authority() {
        let mut device = VirtualAuthenticator::new([1; 16]);
        let mds = MdsState {
            allowlist: crate::ctap::mds::MdsAllowlist { entries: vec![] },
            refreshed_at: 100,
            expires_at: 200,
        };
        let before = device.sign_count();
        assert!(enroll(
            &mut CtapClient::open(&mut device).unwrap(),
            &mds,
            Profile::L3,
            100
        )
        .unwrap_err()
        .is("L3_INDEPENDENT_ASSET_ENROLLMENT_REQUIRED"));
        assert_eq!(
            device.sign_count(),
            before,
            "refusal must precede makeCredential"
        );
    }
    #[test]
    fn stale_enrollment_metadata_refuses_before_credential_creation() {
        use crate::ctap::mds::{MdsAllowlist, MdsEntry};
        let mut device = VirtualAuthenticator::new([3; 16]);
        let mds = MdsState {
            refreshed_at: 100,
            expires_at: 1_000_000,
            allowlist: MdsAllowlist {
                entries: vec![MdsEntry {
                    aaguid: hex::encode(device.aaguid),
                    description: "synthetic".into(),
                    min_firmware_version: 0x05_07_00,
                    status_reports: vec![],
                    attestation_public_keys: vec![device.attestation_key_mds()],
                    attestation_root_certificates: vec![],
                }],
            },
        };
        let before = device.export_state();
        assert!(enroll(
            &mut CtapClient::open(&mut device).unwrap(),
            &mds,
            Profile::L2,
            100 + 72 * 3600
        )
        .unwrap_err()
        .is("CUSTODY_METADATA_STALE"));
        assert_eq!(
            device.export_state(),
            before,
            "stale metadata must not create an orphan credential"
        );
    }
}
