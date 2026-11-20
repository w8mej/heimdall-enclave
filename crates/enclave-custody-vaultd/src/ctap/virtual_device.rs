//! A software FIDO2 authenticator that speaks real CTAPHID + CTAP2 CBOR
//! (`getInfo`, `clientPIN.getKeyAgreement` with protocol 2,
//! `makeCredential` with packed basic attestation, `getAssertion` with
//! `hmac-secret`). It exists so CI exercises the *same* client, framing,
//! PIN-protocol and verification code that drives a physical YubiKey, and so
//! adversarial behaviours (no touch, unplug, cloned counter, foreign channel
//! traffic, behind-a-hub topology) can be scripted deterministically.

use std::collections::VecDeque;

use ciborium::Value;
use ed25519_dalek::{Signer, SigningKey};
use enclave_core::error::EnclaveResult;
use enclave_core::fail;
use enclave_core::secret::SecretBytes;
use hmac::{Hmac, Mac};
use p256::SecretKey;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use super::cbor::{self, imap, tmap};
use super::hid::{packetize, HidDevice, BROADCAST_CID, CMD_CBOR, CMD_ERROR, CMD_INIT, REPORT};
use super::pin::{cose_to_p256, p256_to_cose, SharedSecret};
use super::{alg, cmd, rp_id_hash, status};

/// Scripted user-presence behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Presence {
    /// The user taps.
    Touch,
    /// The user never taps (`CTAP2_ERR_USER_ACTION_TIMEOUT`).
    NoTouch,
    /// The key is pulled out (transport error).
    Unplugged,
}

#[derive(Clone)]
struct VCred {
    id: Vec<u8>,
    sk: SigningKey,
    cred_random_uv: [u8; 32],
    cred_random_no_uv: [u8; 32],
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedCred {
    #[serde(with = "serde_bytes")]
    id: Vec<u8>,
    #[serde(with = "serde_bytes")]
    seed: Vec<u8>,
    #[serde(with = "serde_bytes")]
    cred_random_uv: Vec<u8>,
    #[serde(with = "serde_bytes")]
    cred_random_no_uv: Vec<u8>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedState {
    v: u8,
    #[serde(with = "serde_bytes")]
    aaguid: Vec<u8>,
    firmware: u32,
    #[serde(with = "serde_bytes")]
    attestation_seed: Vec<u8>,
    uv_capable: bool,
    sign_count: u32,
    creds: Vec<PersistedCred>,
    #[serde(default)]
    pin_hash: Vec<u8>,
    #[serde(default)]
    pin_retries: u8,
}

struct PinState {
    hash: SecretBytes,
    retries: u8,
    consecutive_failures: u8,
    token: Option<SecretBytes>,
    permission: u8,
}

/// The virtual authenticator.
pub struct VirtualAuthenticator {
    /// AAGUID.
    pub aaguid: [u8; 16],
    /// Firmware version reported by `getInfo`.
    pub firmware: u32,
    /// Basic attestation key (its public half is listed in the MDS allowlist).
    pub attestation_key: SigningKey,
    /// Presence behaviour.
    pub presence: Presence,
    /// Whether the device can perform UV (PIN / on-key biometrics).
    pub uv_capable: bool,
    /// USB topology depth (1 = Apple root port).
    pub hub_depth: u8,
    /// Number of `getAssertion` requests that reached the device (the
    /// "YubiKey LED armed" counter used to prove Touch ID gates the tap).
    pub assertion_requests: usize,
    creds: Vec<VCred>,
    sign_count: u32,
    key_agreement: SecretKey,
    pin: Option<PinState>,
    deadline_ns: Option<u64>,
    next_cid: u32,
    rx: Vec<u8>,
    rx_cid: u32,
    rx_cmd: u8,
    rx_total: usize,
    tx: VecDeque<[u8; REPORT]>,
}

impl std::fmt::Debug for VirtualAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VirtualAuthenticator")
            .field("aaguid", &hex::encode(self.aaguid))
            .field("firmware", &format_args!("{:#08x}", self.firmware))
            .field("presence", &self.presence)
            .field("sign_count", &self.sign_count)
            .finish()
    }
}

impl VirtualAuthenticator {
    /// A YubiKey-5-like device (firmware 5.7.1, Ed25519, root port).
    pub fn new(aaguid: [u8; 16]) -> Self {
        Self {
            aaguid,
            firmware: 0x05_07_01,
            attestation_key: SigningKey::generate(&mut rand_core::OsRng),
            presence: Presence::Touch,
            uv_capable: true,
            hub_depth: 1,
            assertion_requests: 0,
            creds: Vec::new(),
            sign_count: 0,
            key_agreement: SecretKey::random(&mut rand_core::OsRng),
            pin: None,
            deadline_ns: None,
            next_cid: 0x1000_0001,
            rx: Vec::new(),
            rx_cid: 0,
            rx_cmd: 0,
            rx_total: 0,
            tx: VecDeque::new(),
        }
    }

    /// MDS-style `"ed25519:<hex>"` attestation key string.
    pub fn attestation_key_mds(&self) -> String {
        format!(
            "ed25519:{}",
            hex::encode(self.attestation_key.verifying_key().to_bytes())
        )
    }

    /// Simulate a cloned emulator replaying an old counter.
    pub fn force_sign_count(&mut self, c: u32) {
        self.sign_count = c;
    }

    /// A byte-for-byte clone of the authenticator's secrets (credentials,
    /// attestation key, counter) with fresh transport state: the "cloned
    /// YubiKey" of GAP-28, and a way to hand the same key to a restarted
    /// daemon in tests.
    pub fn clone_secrets(&self) -> Self {
        Self {
            aaguid: self.aaguid,
            firmware: self.firmware,
            attestation_key: self.attestation_key.clone(),
            presence: self.presence,
            uv_capable: self.uv_capable,
            hub_depth: self.hub_depth,
            assertion_requests: 0,
            creds: self.creds.clone(),
            sign_count: self.sign_count,
            key_agreement: SecretKey::random(&mut rand_core::OsRng),
            pin: self.pin.as_ref().map(|pin| PinState {
                hash: SecretBytes::new(pin.hash.expose().to_vec()),
                retries: pin.retries,
                consecutive_failures: 0,
                token: None,
                permission: 0,
            }),
            deadline_ns: None,
            next_cid: 0x1000_0001,
            rx: Vec::new(),
            rx_cid: 0,
            rx_cmd: 0,
            rx_total: 0,
            tx: VecDeque::new(),
        }
    }

    /// Serialise the device's persistent secrets (what a real authenticator
    /// keeps in flash: attestation key, credentials, `credRandom`s, counter).
    /// The out-of-process emulator stores this so its credential survives a
    /// restart exactly as a physical key's does.
    pub fn export_state(&self) -> Vec<u8> {
        let st = PersistedState {
            v: 1,
            aaguid: self.aaguid.to_vec(),
            firmware: self.firmware,
            attestation_seed: self.attestation_key.to_bytes().to_vec(),
            uv_capable: self.uv_capable,
            sign_count: self.sign_count,
            pin_hash: self
                .pin
                .as_ref()
                .map_or_else(Vec::new, |pin| pin.hash.expose().to_vec()),
            pin_retries: self.pin.as_ref().map_or(0, |pin| pin.retries),
            creds: self
                .creds
                .iter()
                .map(|c| PersistedCred {
                    id: c.id.clone(),
                    seed: c.sk.to_bytes().to_vec(),
                    cred_random_uv: c.cred_random_uv.to_vec(),
                    cred_random_no_uv: c.cred_random_no_uv.to_vec(),
                })
                .collect(),
        };
        let mut out = Vec::new();
        // Infallible for this plain struct.
        let _ = ciborium::into_writer(&st, &mut out);
        out
    }

    /// Restore [`Self::export_state`]; transport state starts fresh.
    pub fn import_state(raw: &[u8]) -> EnclaveResult<Self> {
        let st: PersistedState = ciborium::from_reader(raw)
            .map_err(|e| enclave_core::err!(EINVAL, "EMULATOR_STATE_INVALID", "{e}"))?;
        let b32 = |v: &[u8]| -> EnclaveResult<[u8; 32]> {
            v.try_into()
                .map_err(|_| enclave_core::err!(EINVAL, "EMULATOR_STATE_INVALID", "32-byte field"))
        };
        if st.v != 1 {
            fail!(EINVAL, "EMULATOR_STATE_INVALID", "version {}", st.v);
        }
        let mut d = Self::new(
            st.aaguid
                .as_slice()
                .try_into()
                .map_err(|_| enclave_core::err!(EINVAL, "EMULATOR_STATE_INVALID", "aaguid"))?,
        );
        d.firmware = st.firmware;
        d.attestation_key = SigningKey::from_bytes(&b32(&st.attestation_seed)?);
        d.uv_capable = st.uv_capable;
        d.sign_count = st.sign_count;
        if !st.pin_hash.is_empty() {
            if st.pin_hash.len() != 16 || st.pin_retries > 8 {
                fail!(EINVAL, "EMULATOR_STATE_INVALID");
            }
            d.pin = Some(PinState {
                hash: SecretBytes::new(st.pin_hash),
                retries: st.pin_retries,
                consecutive_failures: 0,
                token: None,
                permission: 0,
            });
        }
        for c in st.creds {
            d.creds.push(VCred {
                id: c.id,
                sk: SigningKey::from_bytes(&b32(&c.seed)?),
                cred_random_uv: b32(&c.cred_random_uv)?,
                cred_random_no_uv: b32(&c.cred_random_no_uv)?,
            });
        }
        Ok(d)
    }

    /// Current signature counter.
    pub fn sign_count(&self) -> u32 {
        self.sign_count
    }

    /// Power-cycle: new key-agreement key, all channels dropped.
    pub fn power_cycle(&mut self) {
        self.key_agreement = SecretKey::random(&mut rand_core::OsRng);
        if let Some(pin) = &mut self.pin {
            pin.consecutive_failures = 0;
            pin.token = None;
        }
        self.tx.clear();
        self.rx.clear();
    }

    /// Configure only the software authenticator's synthetic existing PIN.
    /// This method has no physical transport counterpart and never changes hardware.
    pub fn configure_synthetic_pin(&mut self, pin: &[u8]) {
        let mut digest = Sha256::digest(pin);
        let hash = SecretBytes::new(digest[..16].to_vec());
        digest.as_mut_slice().zeroize();
        self.pin = Some(PinState {
            hash,
            retries: 8,
            consecutive_failures: 0,
            token: None,
            permission: 0,
        });
        self.uv_capable = false;
    }

    /// Invalidate emulator-only token state (expiry/cancel policy injection).
    pub fn invalidate_synthetic_pin_token(&mut self) {
        if let Some(pin) = &mut self.pin {
            pin.token = None;
        }
    }

    fn reply(&mut self, cid: u32, cmd_byte: u8, data: &[u8]) {
        if let Ok(ps) = packetize(cid, cmd_byte, data) {
            self.tx.extend(ps);
        }
    }

    fn ctap_reply(&mut self, cid: u32, st: u8, body: Option<Value>) {
        let mut out = vec![st];
        if let Some(b) = body {
            if let Ok(enc) = cbor::encode(&b) {
                out.extend(enc);
            }
        }
        self.reply(cid, CMD_CBOR, &out);
    }

    fn handle(&mut self, cid: u32, c: u8, data: Vec<u8>) {
        match c {
            CMD_INIT => {
                if data.len() != 8 {
                    self.reply(cid, CMD_ERROR, &[0x03]);
                    return;
                }
                let new = self.next_cid;
                self.next_cid += 1;
                let mut r = data.clone();
                r.extend_from_slice(&new.to_be_bytes());
                r.extend_from_slice(&[2, 5, 7, 1, 0x04 | 0x08]);
                self.reply(cid, CMD_INIT, &r);
            }
            CMD_CBOR => {
                if data.is_empty() {
                    self.ctap_reply(cid, status::INVALID_CBOR, None);
                    return;
                }
                let params = if data.len() > 1 {
                    cbor::decode(&data[1..]).ok()
                } else {
                    None
                };
                let (st, body) = match data[0] {
                    cmd::GET_INFO => (status::OK, Some(self.get_info())),
                    // authenticatorSelection: software user-presence only; no
                    // credential, PIN/token, assertion or persistent state.
                    0x0b => {
                        if data.len() != 1 {
                            (status::INVALID_PARAMETER, None)
                        } else {
                            match self.presence {
                                Presence::Touch => (status::OK, None),
                                _ => (status::USER_ACTION_TIMEOUT, None),
                            }
                        }
                    }
                    cmd::CLIENT_PIN => self.client_pin(params.as_ref()),
                    cmd::MAKE_CREDENTIAL => self.make_credential(params.as_ref()),
                    cmd::GET_ASSERTION => self.get_assertion(params.as_ref()),
                    _ => (status::INVALID_PARAMETER, None),
                };
                self.ctap_reply(cid, st, body);
            }
            _ => self.reply(cid, CMD_ERROR, &[0x01]),
        }
    }

    fn get_info(&self) -> Value {
        imap(vec![
            (
                1,
                Value::Array(vec![
                    Value::Text("FIDO_2_0".into()),
                    Value::Text("FIDO_2_1".into()),
                ]),
            ),
            (2, Value::Array(vec![Value::Text("hmac-secret".into())])),
            (3, Value::Bytes(self.aaguid.to_vec())),
            (
                4,
                tmap(vec![
                    ("rk", Value::Bool(true)),
                    ("up", Value::Bool(true)),
                    ("uv", Value::Bool(self.uv_capable)),
                ]),
            ),
            (
                6,
                Value::Array(vec![Value::Integer(2.into()), Value::Integer(1.into())]),
            ),
            (
                0x0a,
                Value::Array(vec![tmap(vec![
                    ("type", Value::Text("public-key".into())),
                    ("alg", Value::Integer(alg::EDDSA.into())),
                ])]),
            ),
            (0x0e, Value::Integer(self.firmware.into())),
        ])
    }

    fn client_pin(&mut self, p: Option<&Value>) -> (u8, Option<Value>) {
        let Some(p) = p else {
            return (status::MISSING_PARAMETER, None);
        };
        match (cbor::int(cbor::iget(p, 1)), cbor::int(cbor::iget(p, 2))) {
            (Ok(2), Ok(2)) => (
                status::OK,
                Some(imap(vec![(
                    1,
                    p256_to_cose(&self.key_agreement.public_key()),
                )])),
            ),
            (Ok(2), Ok(1)) => (
                status::OK,
                Some(imap(vec![(
                    3,
                    Value::Integer(self.pin.as_ref().map_or(0, |p| p.retries).into()),
                )])),
            ),
            (Ok(2), Ok(9)) => self.pin_token(p),
            _ => (status::INVALID_PARAMETER, None),
        }
    }

    fn pin_token(&mut self, p: &Value) -> (u8, Option<Value>) {
        let Some(pin)=self.pin.as_mut() else { return (0x35,None); }; // PIN_NOT_SET
        if pin.retries == 0 {
            return (0x32, None);
        } // PIN_BLOCKED
        if pin.consecutive_failures >= 3 {
            return (0x34, None);
        } // PIN_AUTH_BLOCKED
        let permission = cbor::int(cbor::iget(p, 9)).ok();
        if !matches!(permission, Some(1 | 2))
            || !matches!(cbor::iget(p,10),Some(Value::Text(rp)) if rp==super::RP_ID)
        {
            return (status::PIN_AUTH_INVALID, None);
        }
        let Some(peer)=cbor::iget(p,3).and_then(|v|cose_to_p256(v).ok()) else { return (status::INVALID_PARAMETER,None); };
        let Ok(enc)=cbor::bytes(cbor::iget(p,6)) else { return (status::MISSING_PARAMETER,None); };
        let z =
            p256::ecdh::diffie_hellman(self.key_agreement.to_nonzero_scalar(), peer.as_affine());
        let Ok(shared)=SharedSecret::from_z(z.raw_secret_bytes().as_slice()) else {return (status::INVALID_PARAMETER,None);};
        let Ok(hash)=shared.decrypt(&enc) else {return (status::INVALID_PARAMETER,None);};
        if hash.len() != 16 {
            return (status::INVALID_PARAMETER, None);
        }
        if !enclave_core::secret::ct_eq(hash.expose(), pin.hash.expose()) {
            pin.token = None;
            pin.retries -= 1;
            pin.consecutive_failures += 1;
            self.key_agreement = SecretKey::random(&mut rand_core::OsRng);
            return (
                if pin.retries == 0 {
                    0x32
                } else if pin.consecutive_failures >= 3 {
                    0x34
                } else {
                    0x31
                },
                None,
            );
        }
        pin.retries = 8;
        pin.consecutive_failures = 0;
        let mut token = SecretBytes::zeroed(32);
        enclave_core::rng::fill(token.expose_mut());
        let Ok(encrypted)=shared.encrypt(token.expose()) else {return (status::INVALID_PARAMETER,None);};
        pin.token = Some(token);
        pin.permission = permission.unwrap() as u8;
        (status::OK, Some(imap(vec![(2, Value::Bytes(encrypted))])))
    }

    fn make_credential(&mut self, p: Option<&Value>) -> (u8, Option<Value>) {
        let Some(p) = p else {
            return (status::MISSING_PARAMETER, None);
        };
        let Ok(cdh) = cbor::bytes(cbor::iget(p, 1)) else {
            return (status::MISSING_PARAMETER, None);
        };
        let rp_ok = cbor::iget(p, 2)
            .and_then(|rp| cbor::tget(rp, "id"))
            .is_some_and(|v| matches!(v, Value::Text(t) if t == super::RP_ID));
        if !rp_ok {
            return (status::INVALID_PARAMETER, None);
        }
        let wants_eddsa = matches!(cbor::iget(p, 4), Some(Value::Array(a)) if a.iter().any(|x| cbor::int(cbor::tget(x, "alg")).ok() == Some(alg::EDDSA)));
        if !wants_eddsa {
            return (status::UNSUPPORTED_ALGORITHM, None);
        }
        if self.presence != Presence::Touch {
            return (status::USER_ACTION_TIMEOUT, None);
        }
        let want_uv =
            cbor::iget(p, 7).is_some_and(|options| cbor::boolean(cbor::tget(options, "uv")));
        let token_uv = if let Some(auth) = cbor::iget(p, 8) {
            if cbor::int(cbor::iget(p, 9)).ok() != Some(2) {
                return (status::PIN_AUTH_INVALID, None);
            }
            let Some(pin)=self.pin.as_ref() else {return (status::PIN_AUTH_INVALID,None);};
            if pin.permission != 1 {
                return (status::PIN_AUTH_INVALID, None);
            }
            let Some(token)=pin.token.as_ref() else {return (status::PIN_AUTH_INVALID,None);};
            let Ok(auth)=cbor::bytes(Some(auth)) else {return (status::PIN_AUTH_INVALID,None);};
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(token.expose()).expect("32 bytes");
            mac.update(&cdh);
            if mac.verify_slice(&auth).is_err() {
                return (status::PIN_AUTH_INVALID, None);
            }
            true
        } else {
            false
        };
        if want_uv && !self.uv_capable {
            return (status::OPERATION_DENIED, None);
        }
        let uv = token_uv || (want_uv && self.uv_capable);
        let mut id = vec![0u8; 16];
        enclave_core::rng::fill(&mut id);
        let mut ru = [0u8; 32];
        let mut rn = [0u8; 32];
        enclave_core::rng::fill(&mut ru);
        enclave_core::rng::fill(&mut rn);
        let cred = VCred {
            id: id.clone(),
            sk: SigningKey::generate(&mut rand_core::OsRng),
            cred_random_uv: ru,
            cred_random_no_uv: rn,
        };
        self.sign_count += 1;
        let mut ad = rp_id_hash().to_vec();
        ad.push(0x01 | 0x40 | 0x80 | if uv { 0x04 } else { 0 });
        ad.extend_from_slice(&self.sign_count.to_be_bytes());
        ad.extend_from_slice(&self.aaguid);
        ad.extend_from_slice(&(id.len() as u16).to_be_bytes());
        ad.extend_from_slice(&id);
        let cose = imap(vec![
            (1, Value::Integer(1.into())),
            (3, Value::Integer(alg::EDDSA.into())),
            (-1, Value::Integer(6.into())),
            (
                -2,
                Value::Bytes(cred.sk.verifying_key().to_bytes().to_vec()),
            ),
        ]);
        ad.extend(cbor::encode(&cose).unwrap_or_default());
        ad.extend(
            cbor::encode(&tmap(vec![("hmac-secret", Value::Bool(true))])).unwrap_or_default(),
        );
        let mut msg = ad.clone();
        msg.extend_from_slice(&cdh);
        let sig = self.attestation_key.sign(&msg);
        self.creds.push(cred);
        (
            status::OK,
            Some(imap(vec![
                (1, Value::Text("packed".into())),
                (2, Value::Bytes(ad)),
                (
                    3,
                    tmap(vec![
                        ("alg", Value::Integer(alg::EDDSA.into())),
                        ("sig", Value::Bytes(sig.to_bytes().to_vec())),
                    ]),
                ),
            ])),
        )
    }

    fn get_assertion(&mut self, p: Option<&Value>) -> (u8, Option<Value>) {
        self.assertion_requests += 1;
        let Some(p) = p else {
            return (status::MISSING_PARAMETER, None);
        };
        if !matches!(cbor::iget(p, 1), Some(Value::Text(t)) if t == super::RP_ID) {
            return (status::NO_CREDENTIALS, None);
        }
        let Ok(cdh) = cbor::bytes(cbor::iget(p, 2)) else {
            return (status::MISSING_PARAMETER, None);
        };
        let allow: Vec<Vec<u8>> = match cbor::iget(p, 3) {
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|c| cbor::bytes(cbor::tget(c, "id")).ok())
                .collect(),
            _ => vec![],
        };
        let Some(cred) = self.creds.iter().find(|c| allow.contains(&c.id)).cloned() else {
            return (status::NO_CREDENTIALS, None);
        };
        let opts = cbor::iget(p, 5);
        let want_up = opts
            .map(|o| cbor::tget(o, "up"))
            .is_none_or(|v| !matches!(v, Some(Value::Bool(false))));
        let want_uv = opts.is_some_and(|o| cbor::boolean(cbor::tget(o, "uv")));
        if want_up && self.presence != Presence::Touch {
            return (status::USER_ACTION_TIMEOUT, None);
        }
        let token_uv = if let Some(auth) = cbor::iget(p, 6) {
            if cbor::int(cbor::iget(p, 7)).ok() != Some(2) {
                return (status::PIN_AUTH_INVALID, None);
            }
            let Ok(auth)=cbor::bytes(Some(auth)) else { return (status::PIN_AUTH_INVALID,None); };
            let Some(pin)=self.pin.as_ref() else {return (status::PIN_AUTH_INVALID,None);};
            if pin.permission != 2 {
                return (status::PIN_AUTH_INVALID, None);
            }
            let Some(token)=pin.token.as_ref() else {return (status::PIN_AUTH_INVALID,None);};
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(token.expose()).expect("32 bytes");
            mac.update(&cdh);
            if mac.verify_slice(&auth).is_err() {
                return (status::PIN_AUTH_INVALID, None);
            }
            true
        } else {
            false
        };
        if want_uv && !self.uv_capable {
            return (status::OPERATION_DENIED, None);
        }
        let uv = token_uv || (want_uv && self.uv_capable);
        let mut ext_out = None;
        if let Some(hs) = cbor::iget(p, 4).and_then(|e| cbor::tget(e, "hmac-secret")) {
            let Some(r) = self.hmac_secret(
                hs,
                if uv {
                    &cred.cred_random_uv
                } else {
                    &cred.cred_random_no_uv
                },
            ) else {
                return (status::PIN_AUTH_INVALID, None);
            };
            ext_out = Some(r);
        }
        self.sign_count += 1;
        let mut flags = 0u8;
        if want_up {
            flags |= 0x01;
        }
        if uv {
            flags |= 0x04;
        }
        if ext_out.is_some() {
            flags |= 0x80;
        }
        let mut ad = rp_id_hash().to_vec();
        ad.push(flags);
        ad.extend_from_slice(&self.sign_count.to_be_bytes());
        if let Some(enc) = ext_out {
            ad.extend(
                cbor::encode(&tmap(vec![("hmac-secret", Value::Bytes(enc))])).unwrap_or_default(),
            );
        }
        let mut msg = ad.clone();
        msg.extend_from_slice(&cdh);
        let sig = cred.sk.sign(&msg);
        (
            status::OK,
            Some(imap(vec![
                (
                    1,
                    tmap(vec![
                        ("type", Value::Text("public-key".into())),
                        ("id", Value::Bytes(cred.id.clone())),
                    ]),
                ),
                (2, Value::Bytes(ad)),
                (3, Value::Bytes(sig.to_bytes().to_vec())),
            ])),
        )
    }

    fn hmac_secret(&self, hs: &Value, cred_random: &[u8; 32]) -> Option<Vec<u8>> {
        let peer = cose_to_p256(cbor::iget(hs, 1)?).ok()?;
        let salt_enc = cbor::bytes(cbor::iget(hs, 2)).ok()?;
        let salt_auth = cbor::bytes(cbor::iget(hs, 3)).ok()?;
        if cbor::int(cbor::iget(hs, 4)).ok()? != 2 {
            return None;
        }
        let z =
            p256::ecdh::diffie_hellman(self.key_agreement.to_nonzero_scalar(), peer.as_affine());
        let ss = SharedSecret::from_z(z.raw_secret_bytes().as_slice()).ok()?;
        if !ss.verify(&salt_enc, &salt_auth) {
            return None;
        }
        let salts = ss.decrypt(&salt_enc).ok()?;
        let mut out = Vec::new();
        for salt in salts.expose().chunks(32) {
            let mut m = <Hmac<Sha256> as Mac>::new_from_slice(cred_random).ok()?;
            m.update(salt);
            out.extend_from_slice(&m.finalize().into_bytes());
        }
        ss.encrypt(&out).ok()
    }
}

impl HidDevice for VirtualAuthenticator {
    fn deadline_ns(&self) -> Option<u64> {
        self.deadline_ns
    }
    fn set_deadline_ns(&mut self, deadline: Option<u64>) -> EnclaveResult<()> {
        self.deadline_ns = deadline;
        Ok(())
    }

    #[cfg(any(test, feature = "simulation"))]
    fn virtual_authenticator(&mut self) -> Option<&mut Self> {
        Some(self)
    }

    fn write_report(&mut self, r: &[u8; REPORT]) -> EnclaveResult<()> {
        if self.presence == Presence::Unplugged {
            fail!(EIO, "DEVICE_REMOVED", "kIOTerminatedNotification");
        }
        let cid = u32::from_be_bytes([r[0], r[1], r[2], r[3]]);
        if r[4] & 0x80 != 0 {
            self.rx_cid = cid;
            self.rx_cmd = r[4] & 0x7f;
            self.rx_total = u16::from_be_bytes([r[5], r[6]]) as usize;
            self.rx.clear();
            let n = self.rx_total.min(57);
            self.rx.extend_from_slice(&r[7..7 + n]);
        } else if cid == self.rx_cid {
            let n = (self.rx_total - self.rx.len()).min(59);
            self.rx.extend_from_slice(&r[5..5 + n]);
        }
        if self.rx.len() == self.rx_total {
            let data = std::mem::take(&mut self.rx);
            if self.rx_cmd == CMD_INIT || self.rx_cid != BROADCAST_CID {
                self.handle(self.rx_cid, self.rx_cmd, data);
            }
        }
        Ok(())
    }

    fn read_report(&mut self) -> EnclaveResult<[u8; REPORT]> {
        if self.presence == Presence::Unplugged {
            fail!(EIO, "DEVICE_REMOVED");
        }
        match self.tx.pop_front() {
            Some(r) => Ok(r),
            None => fail!(ETIMEDOUT, "HID_READ_TIMEOUT"),
        }
    }

    fn hub_depth(&self) -> u8 {
        self.hub_depth
    }
}
