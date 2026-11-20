#!/usr/bin/env python3
"""
macOS Hardware & Workload Identity Attestation Utility — v1.0 Python Architectural Simulation

This module performs:
1. Hardware Secure Enclave Processor (SEP) presence checks (ioreg) and FileVault status.
2. Binary code-signature VERIFICATION via `codesign --verify --strict --verbose=4`
   (remediates F-011: `codesign -dvvv` only *displays* metadata and verifies nothing), with
   `returncode == 0` enforced, an optional designated requirement pinning the Apple Team ID,
   and strict parsing of `flags=0x...(runtime)` on the `CodeDirectory` line only.
3. Re-export of the RFC 9449 DPoP generator/verifier from `identity/dpop.py`.

KEY CUSTODY: DPoP keys produced here are SIMULATION_ONLY exportable software keys, not SEP
keys. CORE-V1 Invariant 4 is NOT satisfied by this simulation.
"""

import os
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

try:
    from identity.dpop import (  # noqa: F401
        KEY_CUSTODY,
        DPoPProofGenerator,
        DPoPVerificationError,
        DPoPVerifier,
    )

    ec = True
except ImportError:  # cryptography not installed
    ec = None
    DPoPProofGenerator = None
    DPoPVerifier = None
    KEY_CUSTODY = "SIMULATION_ONLY_SOFTWARE_KEY"

# Strict CodeDirectory flag parser: e.g. "CodeDirectory v=20500 size=1234 flags=0x10000(runtime) hashes=..."
_CODEDIR_RE = re.compile(
    r"^CodeDirectory v=\S+ size=\d+ flags=0x([0-9a-fA-F]+)\(([^)]*)\)"
)
_RUNTIME_FLAG = 0x10000


class MacOSHardwareAttestation:
    """Verifies that the execution environment is an Apple Silicon Mac with an active SEP."""

    @staticmethod
    def verify_apple_silicon() -> Tuple[bool, str]:
        """Verifies if the host CPU architecture is Apple Silicon (ARM64)."""
        try:
            res = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True,
                text=True,
                check=True,
            )
            brand = res.stdout.strip()
            if "Apple" in brand:
                return True, f"Verified Apple Silicon hardware: {brand}"
            return False, f"Non-Apple CPU detected: {brand}"
        except Exception as e:
            return False, f"Failed to query CPU brand: {e}"

    @staticmethod
    def verify_secure_enclave() -> Tuple[bool, str]:
        """Queries macOS ioreg to confirm Apple Secure Enclave Processor (SEP) status."""
        try:
            res = subprocess.run(
                ["ioreg", "-r", "-c", "AppleSEPManager"],
                capture_output=True,
                text=True,
                check=True,
            )
            if "AppleSEPManager" in res.stdout:
                return (
                    True,
                    "Apple Secure Enclave Processor (SEP) hardware is active and online.",
                )
            return False, "AppleSEPManager registry entry not found."
        except Exception as e:
            return False, f"Error inspecting hardware registry: {e}"

    @staticmethod
    def verify_filevault() -> Tuple[bool, str]:
        """Verifies FileVault full disk encryption is actively enabled."""
        try:
            res = subprocess.run(
                ["fdesetup", "status"], capture_output=True, text=True, check=True
            )
            output = res.stdout.strip()
            if "FileVault is On" in output:
                return True, "FileVault full disk encryption is active."
            return False, f"FileVault is not active: {output}"
        except Exception as e:
            return False, f"Failed to check FileVault status: {e}"


class MacOSCodeSignAttestation:
    """Verifies code signatures (cryptographically), Team IDs, and the Hardened Runtime flag."""

    @staticmethod
    def parse_codesign_display(display_stderr: str) -> Dict[str, Any]:
        """Parse `codesign -d --verbose=4` output. Only the CodeDirectory line can set hardened_runtime."""
        info: Dict[str, Any] = {
            "team_id": None,
            "hardened_runtime": False,
            "codedir_flags": None,
            "authority": [],
        }
        for raw in display_stderr.splitlines():
            line = raw.strip()
            m = _CODEDIR_RE.match(line)
            if m:
                flags = int(m.group(1), 16)
                names = {n.strip() for n in m.group(2).split(",")}
                info["codedir_flags"] = flags
                info["hardened_runtime"] = (
                    bool(flags & _RUNTIME_FLAG) and "runtime" in names
                )
            elif line.startswith("TeamIdentifier="):
                info["team_id"] = line.split("=", 1)[1]
            elif line.startswith("Authority="):
                info["authority"].append(line.split("=", 1)[1])
        return info

    @staticmethod
    def verify_binary(
        binary_path: str,
        expected_team_id: Optional[str] = None,
        require_hardened_runtime: bool = False,
        codesign_bin: Optional[str] = None,
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Fail-closed signature verification. Returns (valid, info). `valid` is True only if
        `codesign --verify --strict` exits 0 (plus the Team ID requirement and, optionally,
        the Hardened Runtime flag).
        """
        result: Dict[str, Any] = {"path": binary_path, "valid": False}
        if not os.path.isfile(binary_path):
            result["error"] = f"Binary not found: {binary_path}"
            return False, result
        codesign = codesign_bin or shutil.which("codesign")
        if not codesign:
            result["error"] = (
                "codesign not available (non-macOS host): cannot verify — fail closed"
            )
            return False, result
        verify_cmd: List[str] = [
            codesign, "--verify", "--strict", "--verbose=4"]
        if expected_team_id:
            if not re.fullmatch(r"[A-Z0-9]{10}", expected_team_id):
                result["error"] = (
                    "expected_team_id must be a 10-character Apple Team ID"
                )
                return False, result
            verify_cmd += [
                "-R",
                f'=anchor apple generic and certificate leaf[subject.OU] = "{expected_team_id}"',
            ]
        verify_cmd.append(binary_path)
        try:
            verify = subprocess.run(
                verify_cmd, capture_output=True, text=True, timeout=10
            )
        except Exception as exc:
            result["error"] = f"codesign --verify failed to run: {exc}"
            return False, result
        result["verify_returncode"] = verify.returncode
        if verify.returncode != 0:
            result["error"] = (
                f"signature verification failed: {verify.stderr.strip()[:300]}"
            )
            return False, result
        try:
            display = subprocess.run(
                [codesign, "-d", "--verbose=4", binary_path],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except Exception as exc:
            result["error"] = f"codesign -d failed to run: {exc}"
            return False, result
        result.update(
            MacOSCodeSignAttestation.parse_codesign_display(display.stderr))
        if expected_team_id and result.get("team_id") != expected_team_id:
            result["error"] = (
                f"Team ID mismatch: expected {expected_team_id!r}, got {result.get('team_id')!r}"
            )
            return False, result
        if require_hardened_runtime and not result.get("hardened_runtime"):
            result["error"] = (
                "Hardened Runtime flag (0x10000 runtime) absent on CodeDirectory"
            )
            return False, result
        result["valid"] = True
        return True, result


def main():
    print("=================================================================")
    print(" macOS Hardware & Workload Identity Attestation")
    print(" Target: Apple Silicon M1+ | Zero-Trust Local Enclave")
    print("=================================================================\n")

    # 1. Hardware checks
    ok_cpu, msg_cpu = MacOSHardwareAttestation.verify_apple_silicon()
    print(f"[{'PASS' if ok_cpu else 'FAIL'}] CPU Architecture: {msg_cpu}")

    ok_sep, msg_sep = MacOSHardwareAttestation.verify_secure_enclave()
    print(f"[{'PASS' if ok_sep else 'FAIL'}] Apple Secure Enclave: {msg_sep}")

    ok_fv, msg_fv = MacOSHardwareAttestation.verify_filevault()
    print(f"[{'PASS' if ok_fv else 'FAIL'}] FileVault Encryption: {msg_fv}")

    # 2. Binary code-signature VERIFICATION on the Python interpreter (informational)
    python_path = os.path.realpath(sys.executable)
    ok_cs, cs_info = MacOSCodeSignAttestation.verify_binary(python_path)
    print(
        f"[{'PASS' if ok_cs else 'WARN'}] Code Signature ({python_path}): "
        f"{'valid, team=' + str(cs_info.get('team_id')) if ok_cs else cs_info.get('error')}"
    )

    # 3. DPoP test (software key — SIMULATION_ONLY)
    if ec and DPoPProofGenerator is not None and DPoPVerifier is not None:
        dpop = DPoPProofGenerator()
        proof = dpop.create_proof(
            "POST", "https://127.0.0.1:8443/depot/tools/call")
        DPoPVerifier().verify(proof, "POST", "https://127.0.0.1:8443/depot/tools/call")
        print(
            f"[PASS] DPoP proof minted and verified with {KEY_CUSTODY} key "
            f"(NOT hardware-bound): {proof[:32]}... ({len(proof)} chars)"
        )
    else:
        print(
            "[SKIP] cryptography package not installed; skipping DPoP token creation."
        )

    overall = ok_cpu and ok_sep and ok_fv
    print(
        f"\nFinal Pre-Flight Posture Assessment: {'READY' if overall else 'NON-COMPLIANT'}"
    )
    sys.exit(0 if overall else 1)


if __name__ == "__main__":
    main()
