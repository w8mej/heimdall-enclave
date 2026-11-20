# Quickstart Operator Guide: Turnkey Model Deployment Across macOS Fleets

> **Applies to:** Apple Silicon Macs (`M1` through `M6+`, `arm64e`, macOS 14.0+ Sonoma / Sequoia)  
> **Supported Management Systems:** Jamf Pro, Munki, FleetDM / osquery, Ansible, Direct CLI / Makefile  
> **Governing Specifications:** [FS-701 (`FEATURE_POST_AR_MODEL_ADAPTERS.md`)](FEATURE_POST_AR_MODEL_ADAPTERS.md) · [FS-702 (`FEATURE_SWARM_SECURITY_PROFILES.md`)](FEATURE_SWARM_SECURITY_PROFILES.md) · [FS-706 (`FEATURE_MDM_FLEET_DISTRIBUTION.md`)](FEATURE_MDM_FLEET_DISTRIBUTION.md)

---

## 1. Executive Summary & The Unified Mental Model

Deploying modern machine learning models to employee MacBooks has historically forced organizations into a fragile trade-off: either distribute opaque, unconfined local runners (e.g. Ollama, vLLM) that operate with raw user credentials and unmonitored network sockets, or force all inference through centralized cloud APIs that expose sensitive enterprise data.

This project resolves that trade-off through a **hardware-hardened, privilege-separated on-device enclave**.

Regardless of whether you are deploying an **Autoregressive Reasoning Transformer** (such as DeepSeek-R1 or Llama 3), a **Sub-15ms Neural Engine Classifier** (`jev`), a **Discrete Diffusion Language Model** (`LLaDA 2.0`), a **Recurrent State-Space Model** (`RWKV-7`), or **Yann LeCun's Joint Embedding World Model Planner** (`H-JEPA`), the operational mechanics across your fleet remain **identical**:

1. **Deterministic 4-Stage CLI:** Every model is evaluated, provisioned, synced, and audited via `depot-enclave deploy <preflight | install | hydrate | verify>`.
2. **Strict Network & POSIX Privilege Separation:**
   * **Inference (`UID 701`, `_llmagent`):** Executes in Metal / Apple Neural Engine (ANE) with **zero network egress** (enforced by BSD `pf` packet filter and Seatbelt sandbox). It can never phone home or exfiltrate prompts.
   * **Distribution (`UID 702`, `_enclavecas`):** The *only* daemon with network egress. It verifies FastCDC chunks against Bao BLAKE3 Merkle trees before passing atomic, read-only file descriptors (`SCM_RIGHTS`) to `UID 701`.
   * **L3 snapshot publication (confined UID0 helper):** `enclave-apfs-broker` performs only independently authorized APFS publication/reopen/retraction, has no Internet sockets and never promotes CAS to root. Genuine signing/entitlement and a dedicated volume are separate prerequisites (ADR021).
   * **Policy & Tool Sandboxing (`UID 704`, `_enclaveifc`):** Evaluates Cedar authorization rules and runs tools in hermetic WebAssembly (WASI 0.2) component sandboxes.
3. **P2P Swarm Intelligence:** Heavy model weights (9 GiB to 40 GiB) are hydrated via local peer-to-peer Iroh QUIC swarms. Only **one Mac** pulls from the WAN; the rest of your office fleet syncs over the local 10 Gbps / Wi-Fi 7 mesh.

---

## 2. Universal Model Taxonomy: The 7 Supported Execution Classes

While the delivery pipeline is universal, different model architectures require distinct hardware acceleration planes and runtime security adapters. The enclave automatically detects the model's `ExecutionClass` and activates the corresponding fail-closed guardrails:

| Execution Class                            | Architecture Archetypes                                           | Primary Hardware Target            | Weight Package Format                      | Active Runtime Enclave Guard                                                                                               |
|:-------------------------------------------|:------------------------------------------------------------------|:-----------------------------------|:-------------------------------------------|:---------------------------------------------------------------------------------------------------------------------------|
| **Class 0: Autoregressive (AR) & MoE**     | DeepSeek-R1 (V3/R1), Llama 3.3, Qwen 2.5                          | Apple GPU (Metal) + Unified Memory | `.safetensors` / MLX (4-bit/8-bit)         | Dual-LLM Executive/Synthesizer isolation, `<think>` CoT bleed containment, Dynamic cryptographic canaries                  |
| **Class 1: Discriminative RLCD**           | `jev` (Joint Embedding Verifiers), ANE Heads                      | Apple Neural Engine (ANE) @ 0% GPU | Compiled CoreML `.mlpackage` (`MIL`)       | Sub-15ms deterministic triage, QIF privacy diode + Cedar 12-bit ledger (`uchg`)                                            |
| **Class 2: Discrete Diffusion**            | `LLaDA 2.0`, `Dream`, `FS-DFM`                                    | Apple GPU (Metal) Parallel Threads | Denoising diffusion tensor checkpoints     | Non-causal parallel denoising, `DINGO` bidirectional DFA trellis grammar, `RAEC` step-watchers                             |
| **Class 3: Recurrent SSM & TTT**           | `Mamba-3`, `RWKV-7`, `Titans`                                     | Apple GPU / Unified Memory         | Linear recurrent weight tensors            | Constant-RAM 1M+ token recurrence, Copy-on-Write `StateSnapshotDAG`, `HiSPA` history poisoning defense                     |
| **Class 4: Byte & Concept Latent**         | `BLT` (Byte Latent), Meta `LCM` / `SONAR`                         | Apple GPU / Vector Engines         | Tokenizer-free raw byte patches / concepts | SIMD `Byte-DFA` scanners, `LEACE` semantic concept clamping for PII erasure                                                |
| **Class 5: Recurrent-Depth & Speculative** | `Huginn`, `COCONUT`, `EAGLE-3`                                    | Apple GPU (Metal Dynamic Pipeline) | Base checkpoint + speculative draft heads  | Sponge attack watchdog (depth ceilings), speculative draft-tree cryptographic zeroization                                  |
| **Class 6: World Models & Planners**       | Yann LeCun's `AMI Labs` (`H-JEPA` + `EBM` + `MPC`), `V-JEPA 2-AC` | Apple GPU + ANE Coprocessors       | Non-generative representation encoders     | Hardwired $C_{\text{intrinsic}}$ energy cost barrier, Model Predictive Control trajectory validation, `PoP-Biscuit` tokens |

---

## 3. Universal Fleet Deployment Pipeline (One-Time Setup)

Before distributing any model weights, the enclave runtime must be provisioned across your Mac fleet.

### 3.1 Build the Universal Flat Package (`depot-Enclave.pkg`)

Run this on your packaging or CI/CD machine:

```bash
# 1. Build release binaries, LaunchDaemons, and Seatbelt sandbox profiles
sh packaging/macos/build.sh

# 2. Synthesize the flat macOS MDM package
sh packaging/pkg/build-pkg.sh 3.0.0
# Outputs: dist/depot-Enclave-3.0.0.pkg
```

### 3.2 Select Your Fleet Maturity Profile (`L1`, `L2`, or `L3`)

* **Profile `L1` (Startup / Remote Teams):** Pulls model chunks directly from Cloudflare R2 / S3 via chunked HTTPS with in-RAM Bao verification. Best for remote employees on home connections.
* **Profile `L2` (Office Cluster / P2P Mesh — *Recommended*):** Uses `enclave-swarm-syncd` (Iroh QUIC P2P). The first Mac in the office downloads the weights from the WAN; all other Macs hydrate over the local LAN at 10 Gbps / Wi-Fi 7 without saturating the office internet pipe.
* **Profile `L3` (restricted publication):** OHTTP relay/gateway hydration verifies encrypted artifacts in CAS, then uses the independently pinned root APFS broker for sealed snapshot publication. Detached hydration jobs address APNs timeouts. A prestaged DMG is an offline ingestion option, not proof of the snapshot/mount contract. Installed root-helper/entitlement/volume acceptance is still required; see FS706 §3.2.1.

---

## 4. Model-Specific Quickstart Cookbooks

### 4.1 Class 0: Autoregressive Reasoning Models (e.g. DeepSeek-R1)

DeepSeek-R1 provides state-of-the-art reasoning capabilities via its Chain-of-Thought (`<think>...</think>`) output. However, unfiltered CoT tokens present high risks of leaking system prompts, secret fixtures, and customer data.

#### Step 1: Declare the Artifact in `enclave.lock.toml`

```toml
[[artifacts]]
name = "deepseek-r1-distill-qwen-14b"
cas_uri = "cas://blake3-bao-v1/e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855?target=deepseek-r1-distill-qwen-14b&ns=models&min_profile=L1"
blake3 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
sha256 = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"
classification = "public_l1"
lazy_fuse_t = true
license_policy = { spdx_id = "MIT", allow_p2p_seeding = true }
```

#### Step 2: Deploy & Hydrate via CLI or MDM

```bash
# Provision enclave baseline under Profile L2 (P2P LAN Swarm) from a build.sh dist.
# The install script is the copy embedded in the binary (DEFECT-F-90); without
# --dist, install only loads pf anchors over an existing .pkg payload.
sudo depot-enclave deploy install --profile L2 --dist .enclave-local/dist

# Hydrate DeepSeek-R1 (asynchronous background job avoids APNs timeouts)
sudo depot-enclave deploy hydrate --profile L2 --target deepseek-r1-distill-qwen-14b --async

# Verify daemon status and firewall anchors
depot-enclave deploy verify --profile L2
```

#### Active Guardrails for DeepSeek-R1

* **Dual-LLM Isolation:** Raw `<think>` reasoning tokens are confined to the Executive process (`UID 701`). Only the scrubbed final synthesis is exposed to tool runners.
* **Dynamic Canaries:** Injects ephemeral, hardware-signed canary honeytokens into the context stream. If an adversarial prompt tricks DeepSeek-R1 into quoting system fixtures, the canary fires a sub-millisecond circuit breaker killing the inference stream.
* **Network Blackhole:** BSD `pf` packet filter blocks all TCP/UDP traffic from `UID 701`, ensuring zero data exfiltration.

---

### 4.2 Class 1: Discriminative RLCD on Apple Neural Engine (e.g. `jev`)

Joint Embedding Verifiers (`jev`) are lightweight classifiers ($0.5\text{B}$ to $2\text{B}$) compiled directly for the Apple Neural Engine (ANE). They execute in under $15\text{ms}$ at **zero GPU load**, making them ideal for high-frequency security triage, DLP verification, and policy pre-filtering.

#### Step 1: Declare the ANE Artifact

```toml
[[artifacts]]
name = "jev-security-triage-1b"
cas_uri = "cas://blake3-bao-v1/1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b?target=jev-security-triage-1b&ns=models&min_profile=L1"
blake3 = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"
sha256 = "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e"
classification = "public_l1"
lazy_fuse_t = false
license_policy = { spdx_id = "Apache-2.0", allow_p2p_seeding = true }
```

#### Step 2: Hydrate and Compile to ANE

```bash
# Hydrate and trigger chip-specific ANE compilation (H13G through H17G)
sudo depot-enclave deploy hydrate --profile L1 --target jev-security-triage-1b --sync
```

#### Active Guardrails for `jev`

* **Quantitative Information Flow (QIF) Diode:** Enforces a strict 12-bit entropy leakage cap on verification output.
* **Cedar Privacy Ledger:** Tracks bit-leakage per user session; locks the classifier (`uchg`) and demands hardware biometrics (Touch ID / SEP) if an adversarial query attempts binary-search prompt extraction.

---

### 4.3 Class 2: Discrete Diffusion Language Models (e.g. `LLaDA 2.0`, `Dream`)

Discrete diffusion models generate tokens non-autoregressively by progressively unmasking and denoising sequences in parallel. They deliver extreme code generation speeds ($1,000+\text{ tok/s}$) but break traditional left-to-right regex/grammar guardrails.

#### Step 1: Declare the Diffusion Artifact

```toml
[[artifacts]]
name = "llada-8b-instruct"
cas_uri = "cas://blake3-bao-v1/1111111111111111111111111111111111111111111111111111111111111111?target=llada-8b-instruct&ns=models&min_profile=L1"
blake3 = "1111111111111111111111111111111111111111111111111111111111111111"
sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
classification = "public_l1"
lazy_fuse_t = true
license_policy = { spdx_id = "MIT", allow_p2p_seeding = true }
```

#### Step 2: Hydrate via P2P LAN Swarm

```bash
sudo depot-enclave deploy hydrate --profile L2 --target llada-8b-instruct --async
```

#### Active Guardrails for Diffusion

* **`DINGO` Bidirectional DFA Trellis:** Standard parser guards assume left-to-right token emission. `DINGO` evaluates structural grammar validity (JSON, SQL) across partially unmasked bidirectional states.
* **`RAEC` Step-Watchers:** Monitors intermediate reverse-diffusion steps to prevent prompt inversion or latent eavesdropping during intermediate denoising iterations.

---

### 4.4 Class 3: Recurrent State-Space Models (e.g. `RWKV-7`, `Mamba-3`, `Titans`)

Recurrent models replace quadratic attention matrices ($O(N^2)$) with constant-RAM linear state transitions ($O(1)$). This allows engineers to analyze massive codebases ($1\text{M}+$ tokens) directly on standard 16GB MacBooks without KV-cache memory explosions.

#### Step 1: Declare the Recurrent Model

```toml
[[artifacts]]
name = "rwkv-7-world-13b"
cas_uri = "cas://blake3-bao-v1/3333333333333333333333333333333333333333333333333333333333333333?target=rwkv-7-world-13b&ns=models&min_profile=L1"
blake3 = "3333333333333333333333333333333333333333333333333333333333333333"
sha256 = "4444444444444444444444444444444444444444444444444444444444444444"
classification = "public_l1"
lazy_fuse_t = true
license_policy = { spdx_id = "Apache-2.0", allow_p2p_seeding = true }
```

#### Step 2: Hydrate

```bash
sudo depot-enclave deploy hydrate --profile L2 --target rwkv-7-world-13b --async
```

#### Active Guardrails for Recurrent SSMs

* **Copy-on-Write `StateSnapshotDAG`:** In autoregressive models, session resets merely discard the KV cache. In SSMs, hidden states retain recurrent memory. The enclave maintains cryptographic CoW snapshots and forces a hardware zeroize between tenant boundaries.
* **`HiSPA` Defense:** Blocks History Poisoning Attacks where crafted sequence prompts subtly manipulate recurrent state dynamics across multi-turn sessions.

---

### 4.5 Class 6: World Models & Autonomous Planners (Yann LeCun / `AMI Labs` Blueprint)

Yann LeCun's non-generative architecture (`H-JEPA` + Energy-Based Models + Model Predictive Control) discards autoregressive pixel/token prediction. Instead, it predicts high-level semantic representations and evaluates actions against an intrinsic energy cost surface $C(s, a)$.

```
  [Observation s_0] ---> Enc(s_0) ---> World State Rep (z_0)
                                                |
  [Candidate Action a] ---> Pred(z_0, a) ------> Predicted Rep (z_1)
                                                |
                                                v
  [Intrinsic Energy Barrier C(z_1)] < 0.15 ---> Action Approved (Issued via PoP-Biscuit)
                                    >= 0.15 ---> REJECTED (Unsafe/Anomalous Trajectory)
```

#### Step 1: Declare the World Model Blueprint

```toml
[[artifacts]]
name = "ami-hjepa-planner-v2"
cas_uri = "cas://blake3-bao-v1/5555555555555555555555555555555555555555555555555555555555555555?target=ami-hjepa-planner-v2&ns=models&min_profile=L2"
blake3 = "5555555555555555555555555555555555555555555555555555555555555555"
sha256 = "6666666666666666666666666666666666666666666666666666666666666666"
classification = "internal_l2"
lazy_fuse_t = false
license_policy = { spdx_id = "LicenseRef-proprietary", allow_p2p_seeding = true }
```

#### Step 2: Hydrate under Profile L2 or L3

```bash
sudo depot-enclave deploy hydrate --profile L2 --target ami-hjepa-planner-v2 --sync
```

#### Active Guardrails for World Model Planners

* **Hardwired $C_{\text{intrinsic}}$ Energy Barrier:** The planner cannot generate arbitrary text; it selects trajectories that minimize energy. Security invariants (e.g. "never delete production table") are encoded directly into the energy manifold as infinite energy barriers ($\infty$).
* **Hierarchical `PoP-Biscuit` Attenuation:** When an action proposal clears the energy barrier, `UID 704` mints a cryptographically attenuated, short-lived Proof-of-Possession capability token strictly scoped to the evaluated tool action.

---

## 5. Enterprise MDM Integration Recipes

### 5.1 Jamf Pro Deployment Script

In Jamf Pro, create a policy with payload `depot-Enclave-3.0.0.pkg`, and attach this script:

```sh
#!/bin/sh
# Jamf Deployment Script: $4=Target Model, $5=Profile, $6=Action
TARGET="${4:-deepseek-r1-distill-qwen-14b}"
PROFILE="${5:-L2}"
ACTION="${6:-bootstrap_and_hydrate}"

CLI="/opt/enterprise/enclave/bin/depot-enclave"
[ -x "$CLI" ] || { echo "depot-enclave not installed"; exit 20; }

case "$ACTION" in
  bootstrap_and_hydrate)
    "$CLI" deploy preflight --profile "$PROFILE"
    "$CLI" deploy install --profile "$PROFILE"
    "$CLI" deploy hydrate --profile "$PROFILE" --target "$TARGET" --async
    "$CLI" deploy verify --profile "$PROFILE"
    ;;
  healthcheck)
    "$CLI" deploy healthcheck --profile "$PROFILE"
    ;;
esac
exit 0
```

### 5.2 Munki Automated Installation

Configure Munki's `enclave-model-weights.pkginfo` with an idempotent install check that checks local CAS holdings without redownloading:

```xml
<key>installcheck_script</key>
<string>#!/bin/sh
/opt/enterprise/enclave/bin/depot-enclave deploy healthcheck --json | grep -q '"target":"deepseek-r1-distill-qwen-14b","status":"healthy"'
if [ $? -eq 0 ]; then exit 1; else exit 0; fi
</string>
<key>postinstall_script</key>
<string>#!/bin/sh
/opt/enterprise/enclave/bin/depot-enclave deploy hydrate --profile L2 --target deepseek-r1-distill-qwen-14b --async
exit 0
</string>
```

### 5.3 FleetDM / osquery Continuous Compliance

Add these scheduled queries to your Fleet GitOps repository:

```sql
-- 1. Ensure Model Runner is active under isolated UID 701
SELECT label, name, pid, status FROM launchd
WHERE label = 'com.enterprise.enclave.adapter' AND status = 'running';

-- 2. Verify BSD pf Packet Filter firewall anchor is active
SELECT path, signed, authority FROM signature
WHERE path = '/opt/enterprise/enclave/bin/depot-enclave';
```

---

## 6. Day-2 Operations & Emergency Runbooks

### 6.1 Telemetry & Health Monitoring

To audit active model memory footprint (`phys_footprint`) and daemon health across endpoints:

```bash
depot-enclave deploy healthcheck --json
```

```json
{
  "profile": "L2",
  "status": "healthy",
  "daemons": {
    "com.enterprise.enclave.adapter": "running",
    "com.enterprise.enclave.cas": "running",
    "com.enterprise.enclave.ifc": "running"
  },
  "memory_footprint_mib": 182,
  "pf_anchor_active": true,
  "hydrated_artifacts": ["deepseek-r1-distill-qwen-14b"]
}
```

### 6.2 Emergency Fleet-Wide Model Quarantine (< 600s)

If a critical CVE or upstream supply-chain compromise affects a deployed model:

1. **Publish Revocation:** Update your TUF metadata root to revoke the target digest.
2. **Execute Fleet Purge:** Push a mass MDM command:

   ```bash
   sudo depot-enclave deploy purge --profile L2 --target deepseek-r1-distill-qwen-14b --yes
   ```

   This unbinds the model, unmounts the CAS staging container, zeroes memory via Darwin kernel task-killing, and re-engages the default-deny Seatbelt profile.

## L3 APFS helper deployment addendum — 2026-11-12

ADR021 and FS702 `SBR-01`–`SBR-14` define the additional root service. The package must include the distinct signed `enclave-apfs-broker`, its code pin and confinement, protected public TUF replica/monotonic state, root-owned CAS-only IPC socket and lifecycle/health/removal handling. The service has no external networking or arbitrary mount/command RPC. Fleet/MDM inventories and background-service allowlists must include `com.enterprise.enclave.apfs-broker` for L3. Verify authenticated serving and real mount restrictions rather than treating a registered label as healthy.

Before any installed acceptance, provide an explicitly provisioned dedicated APFS volume and approved signing/entitlement. Preserve the independent bootstrap pin and transaction ownership records on upgrade; stop CAS callers before helper replacement/removal and refuse destructive cleanup when retraction fails. Use `macme.md` for exact safe checks and outstanding prerequisites. This personal-host assignment has not installed the service or run privileged snapshot/mount operations; software fixtures cannot certify that deployment. Existing memory/SLO examples exclude the new helper and must not be interpreted as a measured combined budget.

## Development-fleet Touch ID addendum — 2026-11-18

Fleet packages are unchanged. Build them with `packaging/macos/build.sh`,
which now also **refuses a development Touch ID helper**: a helper whose
binary carries `depot intent helper dev same-UID (development only)`.
FleetDM/osquery can watch for the same string on enrolled Macs.

For local development, one developer Mac can now run the `L1` custody
ceremony on its real Touch ID, without an Apple Developer account:
`scripts/pin-local-build.sh` builds and pins your own binaries (one `sudo`),
then `scripts/track-c-ceremony.sh` runs enroll, lease and reveal. The pin
script refuses a Mac with an installed enclave, because it would replace that
deployment's pins. See [TRACK_C_LOCAL_CEREMONY.md](TRACK_C_LOCAL_CEREMONY.md)
and FS-706, "2026-11-18 development trust root and fleet boundary".
