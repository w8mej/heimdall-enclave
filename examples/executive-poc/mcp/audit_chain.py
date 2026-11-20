#!/usr/bin/env python3
"""
Hash-Chained JSONL Audit Journal (remediates F-035 / F-039 for the Python simulation).

Each line is an `EnclaveAuditEnvelopeV1` object (schemas/enclave-audit-envelope-v1.schema.json):
  prev_sha256  — SHA-256 over the previous line's exact UTF-8 bytes (always present)
  prev_blake3  — BLAKE3 over the previous line (present when the optional `blake3` package exists)
  prev_poseidon2 — reserved for the v3.0 ZK journal fold (FS-705); null in the simulation
The first line chains to the all-zero genesis digest. `verify_chain()` recomputes every link
and reports the first break, so insertion, mid-file deletion, reordering or edits are detected.

TAIL TRUNCATION is NOT detectable from the file alone: dropping the last k lines (or emptying
the file) leaves a valid shorter chain. It is detected only against an external anchor —
`chain_tip()` returns (entries, sha256 of the last line), which the operator copies off-host
(SIEM, ticket, signed checkpoint) and later passes to `verify_chain(path, anchor=...)`.
In v3.0 the anchor is the SEP-signed hourly checkpoint (FS-703 §4.1, ADR-010). Tamper
*evidence* only: a local administrator can still delete the file.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from typing import Any, Dict, Optional, Tuple

try:
    import blake3 as _blake3  # optional
except Exception:  # pragma: no cover - optional dependency
    _blake3 = None

GENESIS = "0" * 64


def _b3(data: bytes) -> Optional[str]:
    return _blake3.blake3(data).hexdigest() if _blake3 else None


def _canonical(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class HashChainedAuditLog:
    def __init__(
        self,
        path: str,
        daemon_uid: int,
        spiffe_id: str,
        boot_epoch_id: Optional[str] = None,
    ):
        self.path = path
        self.daemon_uid = daemon_uid
        self.spiffe_id = spiffe_id
        self.boot_epoch_id = boot_epoch_id or str(uuid.uuid4())
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)), mode=0o700, exist_ok=True)
        self._prev_sha, self._prev_b3, self._seq = self._resume()

    def _resume(self) -> Tuple[str, Optional[str], int]:
        if not os.path.exists(self.path):
            return GENESIS, (GENESIS if _blake3 else None), 0
        last = None
        seq = 0
        with open(self.path, "rb") as fh:
            for raw in fh:
                raw = raw.rstrip(b"\n")
                if raw:
                    last = raw
                    seq += 1
        if last is None:
            return GENESIS, (GENESIS if _blake3 else None), 0
        return hashlib.sha256(last).hexdigest(), _b3(last), seq

    def append(
        self, payload: Dict[str, Any], rpc_seq_u64: Optional[int] = None
    ) -> Dict[str, Any]:
        with self._lock:
            self._seq += 1
            env = {
                "v": 1,
                "daemon_uid": self.daemon_uid,
                "boot_epoch_id": self.boot_epoch_id,
                "log_seq_u64": self._seq,
                "rpc_seq_u64": rpc_seq_u64 if rpc_seq_u64 is not None else self._seq,
                "ts_utc_ms": int(time.time() * 1000),
                "spiffe_id": self.spiffe_id,
                "prev_sha256": self._prev_sha,
                "prev_blake3": self._prev_b3,
                "prev_poseidon2": None,
                "payload": payload,
            }
            line = _canonical(env).encode("utf-8")
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            try:
                os.write(fd, line + b"\n")
                os.fsync(fd)
            finally:
                os.close(fd)
            self._prev_sha = hashlib.sha256(line).hexdigest()
            self._prev_b3 = _b3(line)
            return env


def chain_tip(path: str) -> Tuple[int, str]:
    """Return (entries, sha256-of-last-line) — the value to anchor off-host."""
    n, last = 0, GENESIS
    with open(path, "rb") as fh:
        for raw in fh:
            raw = raw.rstrip(b"\n")
            if raw:
                n, last = n + 1, hashlib.sha256(raw).hexdigest()
    return n, last


def verify_chain(
    path: str, anchor: Optional[Tuple[int, str]] = None
) -> Tuple[bool, int, str]:
    """Return (ok, entries_checked, message). With `anchor=(entries, tip_sha256)` from an earlier
    `chain_tip()`, the journal must still contain that exact entry at that position (detects tail
    truncation and rollback)."""
    anchor_hit = anchor is None
    prev_sha = GENESIS
    prev_b3: Optional[str] = GENESIS if _blake3 else None
    n = 0
    with open(path, "rb") as fh:
        for lineno, raw in enumerate(fh, 1):
            raw = raw.rstrip(b"\n")
            if not raw:
                continue
            try:
                env = json.loads(raw)
            except json.JSONDecodeError:
                return False, n, f"line {lineno}: not valid JSON"
            if env.get("prev_sha256") != prev_sha:
                return False, n, f"line {lineno}: prev_sha256 mismatch (chain broken)"
            if _blake3 and env.get("prev_blake3") != prev_b3:
                return False, n, f"line {lineno}: prev_blake3 mismatch (chain broken)"
            if env.get("log_seq_u64") != n + 1:
                return False, n, f"line {lineno}: log_seq_u64 gap (expected {n + 1})"
            if _canonical(env).encode("utf-8") != raw:
                return False, n, f"line {lineno}: non-canonical encoding (edited)"
            prev_sha = hashlib.sha256(raw).hexdigest()
            prev_b3 = _b3(raw)
            n += 1
            if anchor is not None and n == anchor[0]:
                if prev_sha != anchor[1]:
                    return (
                        False,
                        n,
                        f"line {lineno}: does not match anchored tip (rewritten history)",
                    )
                anchor_hit = True
    if not anchor_hit:
        return (
            False,
            n,
            f"journal has {n} entries; anchor expects >= {anchor[0]} (tail truncated)",
        )
    return True, n, f"{n} entries verified"
