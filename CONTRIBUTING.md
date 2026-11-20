# Contributing to Heimdall-Enclave

* **Document ID:** `GOV-CONTRIB` · **Version:** 3.0.0 (remediation of `ADVERSARIAL_SPEC_REVIEW_2026-11-04`, `F-036`)
* **Generation:** applies to all generations — `v1.0-Legacy` runnable simulation (`examples/executive-poc/`, `scripts/`, `tests/`) and `v3.0-Target` specifications (`docs/FEATURE_*.md`, `schemas/`).
* **Status:** `ACTIVE`
* **License:** contributions are accepted under [Apache-2.0](LICENSE) (inbound = outbound). Security issues go through [`SECURITY.md`](SECURITY.md), never public issues.

---

## 1. Principles & Quality Bar

1. **Zero-PII invariant.** No change may introduce a path where unmasked `C4` data (SSN, PAN, credentials, clinical identifiers) reaches model context, unencrypted storage, or audit logs. Audit lines record hashes (`sql_sha256`), never raw SQL or values.
2. **Truth in claims.** Do not describe an unbuilt component (Rust daemons, Cedar, Lean 4 proofs, WASI, CoreML, Plonky3, SEP custody) as implemented. Benchmarks are cited only with a reproducible artifact. Compliance attestations (SOC 2, HIPAA, PCI) are not claimed by this repository. Check `V19` enforces part of this.
3. **Normative precision.** Spec changes use `MUST`/`MUST NOT` with a testable verification statement, bump the document `Rev`, and add a `§10 Revision History` row. Constants (`152 MiB`/`200 MiB`/`232 MiB` budget, `12,000 mb` QIF cap, `p99 <= 45µs` Cedar, `128 KiB` `L3` frames) live in `schemas/enclave.lock.toml` and must stay consistent across the corpus.
4. **Apple Silicon baseline.** Designs must fit an **8GB `M1`** (`macOS 14+`), with progressive `M2`–`M4` (`PAC`) and `M5+` (`EMTE`, pending the `FS-705` entitlement verification gate).
5. **Latency.** Policy and proxy interceptors in the simulation target `p99 < 5 ms`; avoid backtracking regexes (Rego uses RE2).

---

## 2. Local Development Setup

Prerequisites: Python 3.10+ with `cryptography` and `jsonschema`, OPA `v0.70.0` on `PATH`, OpenSSL, Git. Apple Silicon is required only for the hardware checks (`V01`–`V03`).

```bash
git clone git@github.com:<org>/heimdall-enclave.git && cd heimdall-enclave
python3 -m pip install "cryptography==43.0.3" "jsonschema==4.23.0"
./scripts/bootstrap-laptop.sh --ci-vm --prefix "$PWD/.enclave-local/enclave"   # no root, no /opt writes
./scripts/verify-enclave.sh --ci-vm        # V04–V22; V01–V03 skipped
sudo ./scripts/verify-enclave.sh           # on bare-metal Apple Silicon: all V01–V22
```

`./scripts/verify-enclave.sh --list` prints every check; `--only V11` runs one.

**Rust fleet and real Touch ID (Apple Silicon).** The development fleet runs
all five daemons as you (`depot-enclave --dev`); `scripts/l1-alpha-smoke.sh`
exercises it. To run the `L1` custody ceremony on your own Touch ID, without
an Apple Developer account, run `scripts/pin-local-build.sh` (it builds,
ad-hoc signs and root-pins your own binaries; one `sudo`), then
`scripts/track-c-ceremony.sh`. See
[`docs/TRACK_C_LOCAL_CEREMONY.md`](docs/TRACK_C_LOCAL_CEREMONY.md). Never run
the pin script on a Mac with an installed enclave deployment; it refuses.

---

## 3. Policies, Schemas & Code

* `examples/executive-poc/policies/*.rego` (`v1.0` simulation; `v3.0` uses Cedar only, `ADR-008`): keep `default allow := false`, explain denials in `reason`, add a `_test.rego` case for every new rule, run `opa fmt -w examples/executive-poc/policies && opa test examples/executive-poc/policies -v`. Any change to `depot_authz.rego` must keep Python/Rego parity (`V08`).
* `schemas/*.schema.json`: add a valid example in `schemas/examples/` **and** an invalid example in `schemas/examples/invalid/` for every new constraint. JSON samples in docs that claim a schema carry `<!-- schema: NAME -->` immediately before the code block (`V18`).
* `examples/executive-poc/depot/sql_guard.py`, `examples/executive-poc/depot/auth_proxy.py`, `examples/executive-poc/identity/*`: add a negative test to `tests/checks.py` for every new rejection path.

---

## 4. Review & Merge Requirements

| Rule                             | Requirement                                                                                                                                                                                                                               |
|:---------------------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Signed commits (`MUST`)**      | Every commit is signed (`git commit -S`, SSH or GPG) and branch protection requires *verified* signatures on `main`.                                                                                                                      |
| **Two-reviewer rule (`MUST`)**   | PRs touching `policies/`, `schemas/`, `identity/`, `gateway/`, `scripts/`, `.github/` or `depot/auth_proxy.py`/`depot/sql_guard.py` require **two** approvals including one from the `security-reviewers` code owners (`.github/CODEOWNERS`). |
| **Threat model update (`MUST`)** | Any PR that adds or changes a daemon, IPC socket, cryptographic envelope, parser or trust boundary updates `docs/THREAT_MODEL_STRIDE.md` (`TB-*` table and affected risk rows) in the same PR.                                            |
| **ADR (`MUST`)**                 | Architectural decisions get a new `ADR-0NN` in `docs/ARCHITECTURE_DECISION_RECORDS.md` with Context / Decision / Consequences / Verification.                                                                                             |
| **CI (`MUST`)**                  | The `ci-vm-compatible` job passes. Changes to hardware paths (`V01`–`V03`) are additionally run on the opt-in `bare-metal-sep` runner.                                                                                                    |
| **Supply chain**                 | GitHub Actions are pinned by full commit SHA; dependencies are version-pinned; no new network fetches in scripts without review.                                                                                                          |
| **Audit report**                 | Files under `docs/reviews/` are immutable records; remediation is tracked in a separate ledger.                                                                                                                                           |

---

## 5. Pull Request Checklist

* [ ] `./scripts/verify-enclave.sh --ci-vm` passes (all executed checks green; `V01`–`V03` skip only off-hardware).
* [ ] Commits are signed; Conventional Commit messages (`feat:`, `fix:`, `docs:`).
* [ ] No credentials, private keys, `.swp` files or audit logs committed (`V04`).
* [ ] Spec edits bump `Rev`, add a Revision History row, and keep constants consistent.
* [ ] `THREAT_MODEL_STRIDE.md` updated if a trust boundary changed.
* [ ] No implementation or compliance overclaims (`V19`).
