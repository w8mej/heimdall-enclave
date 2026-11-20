#!/usr/bin/env python3
"""
MCP Authorization & Inline PII Redaction Proxy — v1.0-Legacy Python Architectural Simulation

SIMULATION ONLY. Software keys, regex + column-rule DLP, mock data. This module is an
educational reference for the v1.0 Envoy + OPA + Python prototype (ADR-008).
It does NOT satisfy HIPAA Safe Harbor, SOC 2, or PCI-DSS, and MUST NOT protect real customer data.

Remediations (ADVERSARIAL_SPEC_REVIEW_2026-11-04):
  F-006  128-bit keyed HMAC-SHA256 surrogates under a per-session 256-bit ephemeral key
         (replacing unsalted SHA-256[:8]); column-level classification with fail-closed
         default; customer names tokenized; fixed phone boundary `(?<!\\w)\\+?1`; spaced and
         unhyphenated SSNs; dates/ZIPs/credentials redacted; bounded TTL vault eviction.
  F-002  ADR-007 Level-4 policy: PANs, credentials and SSNs are irreversibly erased; nothing
         C4 ever enters the vault (the simulation has no HPKE vault, so it behaves as L1).
  F-007  RFC 9449 DPoP proofs are verified (htm, htu, iat, jti replay cache, ES256 signature,
         optional jkt binding) before any authorization decision.
  F-037  SQL validated by the recursive-descent AST guard (mcp/sql_guard.py); unified tool
         aliases (`execute_customer_query` == `query_customer_db`); no fail-open catch-all.
  F-035  Hash-chained JSONL audit journal (mcp/audit_chain.py) — never stdout-only.
  F-039  SPIFFE trust domain is a parameter (default `corporate.internal`).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections import OrderedDict
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from mcp.audit_chain import HashChainedAuditLog  # noqa: E402
from mcp.sql_guard import validate_select  # noqa: E402

try:
    from identity.dpop import DPoPVerificationError, DPoPVerifier  # noqa: E402
except Exception:  # cryptography missing
    DPoPVerifier = None  # type: ignore
    DPoPVerificationError = Exception  # type: ignore

DEFAULT_TRUST_DOMAIN = os.environ.get("MCPMAC_TRUST_DOMAIN", "corporate.internal")
DEFAULT_TEAM_ID = os.environ.get("MCPMAC_TEAM_ID", "ABC123XYZ0")

# ----------------------------------------------------------------------------------------
# Tool registry — every tool has an explicit validator; unknown tools are denied (F-037).
# ----------------------------------------------------------------------------------------
TOOL_ALIASES = {
    "query_customer_db": "query_customer_db",
    "execute_customer_query": "query_customer_db",  # CORE-V1 §4.2 name, same validator
    "search_documentation": "search_documentation",
    "format_code": "format_code",
    "generate_test_stubs": "generate_test_stubs",
    "inspect_ticket_logs": "inspect_ticket_logs",
}
CLEARANCE_MATRIX = {
    "developer_l1": {"search_documentation", "format_code", "generate_test_stubs"},
    "developer_l2": {
        "search_documentation",
        "format_code",
        "generate_test_stubs",
        "query_customer_db",
        "inspect_ticket_logs",
    },
    "sre_incident_commander": {
        "*"
    },  # "*" = every REGISTERED tool, still parameter-validated
}
FORMAT_LANGUAGES = {
    "python",
    "rust",
    "go",
    "typescript",
    "javascript",
    "swift",
    "sql",
    "shell",
}
TICKET_RE = re.compile(r"^T-[0-9]{1,8}$")


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


class InlinePIITokenizationVault:
    """
    Inline DLP vault (SIMULATION). C3 identifiers -> keyed-HMAC surrogates held in a TTL-bounded
    RAM map; C4 identifiers -> irreversible constant erasure, never stored.
    """

    ERASE_COLUMNS = {
        "ssn": "[REDACTED_SSN_C4]",
        "social_security_number": "[REDACTED_SSN_C4]",
        "national_id": "[REDACTED_SSN_C4]",
        "credit_card": "[REDACTED_PAN_C4]",
        "card_number": "[REDACTED_PAN_C4]",
        "pan": "[REDACTED_PAN_C4]",
        "cvv": "[REDACTED_PAN_C4]",
        "password": "[REDACTED_CREDENTIAL_C4]",
        "secret": "[REDACTED_CREDENTIAL_C4]",
        "api_key": "[REDACTED_CREDENTIAL_C4]",
        "private_key": "[REDACTED_CREDENTIAL_C4]",
        "access_token": "[REDACTED_CREDENTIAL_C4]",
        "medical_notes": "[REDACTED_CLINICAL_C4]",
        "diagnosis": "[REDACTED_CLINICAL_C4]",
        "mrn": "[REDACTED_CLINICAL_C4]",
    }
    TOKENIZE_COLUMNS = {
        "email": "CUST_EMAIL",
        "user_email": "CUST_EMAIL",
        "name": "CUST_NAME",
        "full_name": "CUST_NAME",
        "customer_name": "CUST_NAME",
        "first_name": "CUST_NAME",
        "last_name": "CUST_NAME",
        "phone": "CUST_PHONE",
        "phone_number": "CUST_PHONE",
    }
    GENERALIZE_COLUMNS = {
        "dob": "[REDACTED_DATE]",
        "date_of_birth": "[REDACTED_DATE]",
        "birth_date": "[REDACTED_DATE]",
        "zip": "[REDACTED_ZIP]",
        "postal_code": "[REDACTED_ZIP]",
        "address": "[REDACTED_ADDRESS]",
        "street": "[REDACTED_ADDRESS]",
        "ip_address": "[REDACTED_IP]",
        "account_balance": "[REDACTED_FINANCIAL_C3]",
        "salary": "[REDACTED_FINANCIAL_C3]",
    }
    PASS_COLUMNS = {
        "id",
        "customer_id",
        "ticket_id",
        "tier",
        "status",
        "created_at",
        "updated_at",
        "deleted_at",
        "is_deleted",
        "count",
        "records",
        "rows",
    }
    FREE_TEXT_COLUMNS = {
        "notes",
        "subject",
        "comment",
        "description",
        "message",
        "summary",
    }
    _known_columns = (
        set(ERASE_COLUMNS)
        | set(TOKENIZE_COLUMNS)
        | set(GENERALIZE_COLUMNS)
        | PASS_COLUMNS
        | FREE_TEXT_COLUMNS
    )

    def __init__(
        self,
        ttl_seconds: int = 900,
        max_entries: int = 10_000,
        session_key: Optional[bytes] = None,
    ):
        self._key = session_key or os.urandom(
            32
        )  # 256-bit ephemeral per-session HMAC key
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._vault: "OrderedDict[str, Tuple[str, float]]" = (
            OrderedDict()
        )  # surrogate -> (raw, expiry)
        self._lock = threading.Lock()
        self._patterns: List[Tuple[str, "re.Pattern[str]"]] = [
            # Credentials (ADR-007: always erased). PEM blocks are matched without a leading \b,
            # which can never match before "-----" (audit 2026-11-05).
            (
                "credential",
                re.compile(
                    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)"
                    r"|(?i:\bbearer\s+[a-z0-9_\-.~+/]{20,}=*)"
                    r"|\bghp_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b"
                    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}"
                    r"|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
                    r"|\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}"
                    r"|\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"
                    r"|(?i:\b(?:password|passwd|pwd|secret|client_secret|api[_-]?key|access[_-]?token|aws_secret_access_key)\b\s*[:=]\s*)[^\s,;\"']+"
                ),
            ),
            ("credit_card", re.compile(r"(?<![\w-])(?:\d[ .-]?){12,18}\d(?![\w-])")),
            ("ssn", re.compile(r"(?<![\w.-])\d{3}([- .]?)\d{2}\1\d{4}(?![\w-]|\.\d)")),
            (
                "email",
                re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
            ),
            (
                "phone",
                re.compile(
                    r"(?<!\w)(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
                ),
            ),
            (
                "phone_intl",
                re.compile(
                    r"(?<![\w+])\+(?:[2-9]\d{0,2})(?:[-.\s]?\(?\d{1,4}\)?){2,5}(?!\w)"
                ),
            ),
            (
                "date",
                re.compile(
                    r"\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b|\b(?:0?[1-9]|1[0-2])/(?:0?[1-9]|[12]\d|3[01])/(?:19|20)\d{2}\b"
                ),
            ),
            ("zip", re.compile(r"(?<![\w-])\d{5}(?:-\d{4})?(?![\w-])")),
        ]

    # -- vault --------------------------------------------------------------------------
    def _evict(self, now: float) -> None:
        while self._vault:
            k, (_, exp) = next(iter(self._vault.items()))
            if exp > now and len(self._vault) < self.max_entries:
                break
            self._vault.popitem(last=False)

    def surrogate(self, prefix: str, raw: str) -> str:
        tag = hmac.new(
            self._key, f"{prefix}:{raw}".encode("utf-8"), hashlib.sha256
        ).hexdigest()[:32]
        sur = f"{prefix}_{tag}"
        now = time.time()
        with self._lock:
            self._evict(now)
            self._vault[sur] = (raw, now + self.ttl_seconds)
            self._vault.move_to_end(sur)
        return sur

    def detokenize(self, sur: str) -> Optional[str]:
        """C3 only. Returns None after TTL expiry. (Test hook; v3.0 gates this behind A3.)"""
        now = time.time()
        with self._lock:
            self._evict(now)
            entry = self._vault.get(sur)
            return entry[0] if entry and entry[1] > now else None

    def vault_size(self) -> int:
        with self._lock:
            self._evict(time.time())
            return len(self._vault)

    def vault_contains_raw(self, raw: str) -> bool:
        with self._lock:
            return any(v[0] == raw for v in self._vault.values())

    # -- scrubbing ----------------------------------------------------------------------
    def scrub_text(self, text: str) -> Tuple[str, Dict[str, int]]:
        counts = {
            "ssn": 0,
            "credit_card": 0,
            "email": 0,
            "phone": 0,
            "name": 0,
            "credential": 0,
            "date": 0,
            "zip": 0,
            "clinical": 0,
            "unclassified": 0,
        }

        def repl_factory(kind: str):
            def _r(m: "re.Match[str]") -> str:
                raw = m.group(0)
                if kind == "credit_card":
                    digits = re.sub(r"\D", "", raw)
                    if not (13 <= len(digits) <= 19 and _luhn_ok(digits)):
                        return raw
                if kind == "phone_intl" and len(re.sub(r"\D", "", raw)) < 8:
                    return raw
                counts["phone" if kind == "phone_intl" else kind] += 1
                if kind == "credential":
                    return "[REDACTED_CREDENTIAL_C4]"
                if kind == "credit_card":
                    return "[REDACTED_PAN_C4]"
                if kind == "ssn":
                    return "[REDACTED_SSN_C4]"
                if kind == "email":
                    return self.surrogate("CUST_EMAIL", raw)
                if kind in ("phone", "phone_intl"):
                    return self.surrogate("CUST_PHONE", raw)
                if kind == "date":
                    return "[REDACTED_DATE]"
                return "[REDACTED_ZIP]"

            return _r

        for kind, pat in self._patterns:
            text = pat.sub(repl_factory(kind), text)
        return text, counts

    def scrub_object(self, obj: Any) -> Tuple[Any, Dict[str, int]]:
        total = {
            "ssn": 0,
            "credit_card": 0,
            "email": 0,
            "phone": 0,
            "name": 0,
            "credential": 0,
            "date": 0,
            "zip": 0,
            "clinical": 0,
            "unclassified": 0,
        }

        def add(c: Dict[str, int]) -> None:
            for k, v in c.items():
                total[k] = total.get(k, 0) + v

        def walk(item: Any, key: Optional[str]) -> Any:
            k = (key or "").lower()
            if isinstance(item, dict):
                out = {}
                for kk, vv in item.items():
                    nk = kk
                    if isinstance(kk, str) and kk.lower() not in self._known_columns:
                        nk, c = self.scrub_text(
                            kk
                        )  # PII used as a dict key never leaks
                        add(c)
                    out[nk] = walk(vv, kk)
                return out
            if isinstance(item, list):
                return [walk(e, key) for e in item]
            if item is None or isinstance(item, bool):
                return item
            if k in self.ERASE_COLUMNS:
                marker = self.ERASE_COLUMNS[k]
                bucket = {
                    "[REDACTED_SSN_C4]": "ssn",
                    "[REDACTED_PAN_C4]": "credit_card",
                    "[REDACTED_CREDENTIAL_C4]": "credential",
                }.get(marker, "clinical")
                total[bucket] += 1
                return marker
            if k in self.TOKENIZE_COLUMNS:
                prefix = self.TOKENIZE_COLUMNS[k]
                total[
                    {"CUST_EMAIL": "email", "CUST_NAME": "name", "CUST_PHONE": "phone"}[
                        prefix
                    ]
                ] += 1
                return self.surrogate(prefix, str(item))
            if k in self.GENERALIZE_COLUMNS:
                total[
                    (
                        "date"
                        if "DATE" in self.GENERALIZE_COLUMNS[k]
                        else (
                            "zip"
                            if "ZIP" in self.GENERALIZE_COLUMNS[k]
                            else "unclassified"
                        )
                    )
                ] += 1
                return self.GENERALIZE_COLUMNS[k]
            if k in self.PASS_COLUMNS:
                if isinstance(item, str):
                    s, c = self.scrub_text(item)
                    add(c)
                    return s
                return item
            if k in self.FREE_TEXT_COLUMNS or key is None:
                if (
                    isinstance(item, int) and len(str(abs(item))) >= 9
                ):  # e.g. an SSN/PAN stored as an integer
                    s, c = self.scrub_text(str(item))
                    if s != str(item):
                        add(c)
                        return s
                    return item
                if isinstance(item, str):
                    s, c = self.scrub_text(item)
                    add(c)
                    return s
                return item
            # Fail-closed: unclassified scalar columns never reach the model context.
            total["unclassified"] += 1
            return "[REDACTED_UNCLASSIFIED]"

        return walk(obj, None), total


class OPACliEvaluator:
    """Evaluates the real Rego policy with `opa eval` (used by the policy-parity check)."""

    def __init__(
        self,
        policy_dir: str = os.path.join(_ROOT, "policies"),
        opa_bin: Optional[str] = None,
    ):
        self.policy_dir = policy_dir
        self.opa_bin = opa_bin or shutil.which("opa")

    def available(self) -> bool:
        return bool(self.opa_bin)

    def evaluate(
        self, opa_input: Dict[str, Any], trust_domain: str, team_id: str
    ) -> Tuple[bool, str]:
        with tempfile.TemporaryDirectory() as td:
            ip = os.path.join(td, "input.json")
            dp = os.path.join(td, "data.json")
            json.dump(opa_input, open(ip, "w"))
            json.dump(
                {"config": {"trust_domain": trust_domain, "team_id": team_id}},
                open(dp, "w"),
            )
            out = subprocess.run(
                [
                    self.opa_bin,
                    "eval",
                    "--format",
                    "json",
                    "-d",
                    os.path.join(self.policy_dir, "mcp_authz.rego"),
                    "-d",
                    dp,
                    "-i",
                    ip,
                    "data.agent.authz",
                ],
                capture_output=True,
                text=True,
                timeout=20,
                check=True,
            )
            res = json.loads(out.stdout)["result"][0]["expressions"][0]["value"]
            return bool(res.get("allow", False)), str(res.get("reason", ""))


class MCPAuthorizationEngine:
    """Embedded fast-path mirror of policies/mcp_authz.rego (parity checked by verify-enclave V08)."""

    def __init__(
        self, trust_domain: str = DEFAULT_TRUST_DOMAIN, team_id: str = DEFAULT_TEAM_ID
    ):
        self.trust_domain = trust_domain
        self.team_id = team_id

    def build_opa_input(
        self,
        actor: Dict[str, Any],
        tool_name: str,
        parameters: Dict[str, Any],
        environment: Dict[str, Any],
    ) -> Dict[str, Any]:
        canonical = TOOL_ALIASES.get(tool_name)
        resource: Dict[str, Any] = {"tool_name": tool_name, "parameters": parameters}
        if canonical == "query_customer_db":
            resource["sql_ast_verdict"] = validate_select(
                parameters.get("query", ""), parameters.get("max_records", 0)
            ).as_dict()
        return {
            "actor": actor,
            "action": "mcp:tools:call",
            "resource": resource,
            "environment": environment,
        }

    def evaluate(self, opa_input: Dict[str, Any]) -> Tuple[bool, str]:
        actor, env, res = (
            opa_input["actor"],
            opa_input["environment"],
            opa_input["resource"],
        )
        if not (
            env.get("filevault_active") is True
            and env.get("network_isolated") is True
            and actor.get("hardware_attested") is True
        ):
            return (
                False,
                "Access denied: Hardware posture failed (FileVault, pf firewall, or SEP unverified).",
            )
        prefix = f"spiffe://{self.trust_domain}/ns/developer/workload/"
        if not (
            str(actor.get("spiffe_id", "")).startswith(prefix)
            and actor.get("team_id") == self.team_id
            and actor.get("code_signature_valid") is True
        ):
            return (
                False,
                "Access denied: Untrusted workload identity (Invalid SPIFFE ID, Team ID, or binary signature).",
            )
        canonical = TOOL_ALIASES.get(res.get("tool_name"))
        allowed = CLEARANCE_MATRIX.get(actor.get("clearance"), set())
        if canonical is None or not ("*" in allowed or canonical in allowed):
            return (
                False,
                "Access denied: Tool not registered or clearance entitlement not satisfied.",
            )
        if not self._params_ok(canonical, res):
            return (
                False,
                "Access denied: Parameter safety violated (per-tool validator or SQL AST guard rejected the call).",
            )
        return (
            True,
            "Access granted: Hardware posture, identity, entitlement and per-tool parameter validation passed.",
        )

    @staticmethod
    def _params_ok(tool: str, res: Dict[str, Any]) -> bool:
        p = res.get("parameters", {})
        if tool == "query_customer_db":
            v = res.get("sql_ast_verdict") or {}
            mr = p.get("max_records")
            q = p.get("query")
            return (
                set(p) == {"query", "max_records"}
                and isinstance(q, str)
                and isinstance(mr, int)
                and not isinstance(mr, bool)
                and 1 <= mr <= 50
                and v.get("valid") is True
                and v.get("statement_kind") == "select"
                and isinstance(v.get("limit"), int)
                and v["limit"] <= mr
                and v.get("sql_sha256") == hashlib.sha256(q.encode("utf-8")).hexdigest()
            )
        if tool == "search_documentation":
            q = p.get("query")
            return isinstance(q, str) and 1 <= len(q) <= 512 and set(p) == {"query"}
        if tool == "format_code":
            return (
                p.get("language") in FORMAT_LANGUAGES
                and isinstance(p.get("source"), str)
                and len(p["source"]) <= 65536
                and set(p) == {"language", "source"}
            )
        if tool == "generate_test_stubs":
            return (
                isinstance(p.get("module"), str)
                and 1 <= len(p["module"]) <= 256
                and set(p) == {"module"}
            )
        if tool == "inspect_ticket_logs":
            return (
                isinstance(p.get("ticket_id"), str)
                and bool(TICKET_RE.match(p["ticket_id"]))
                and set(p) == {"ticket_id"}
            )
        return False

    async def evaluate_mcp_authz(
        self, actor, tool_name, parameters, environment
    ) -> Tuple[bool, str, Dict[str, Any]]:
        opa_input = self.build_opa_input(actor, tool_name, parameters, environment)
        ok, reason = self.evaluate(opa_input)
        return ok, reason, opa_input


def _default_audit_path() -> str:
    return os.environ.get("MCPMAC_AUDIT_LOG") or os.path.join(
        _ROOT, ".enclave-local", "logs", "llm-audit.jsonl"
    )


class MCPAuthProxy:
    """Coordinates DPoP authentication, authorization, data scrubbing and audit for MCP JSON-RPC."""

    def __init__(
        self,
        require_dpop: bool = True,
        audit_path: Optional[str] = None,
        trust_domain: str = DEFAULT_TRUST_DOMAIN,
        team_id: str = DEFAULT_TEAM_ID,
        vault: Optional[InlinePIITokenizationVault] = None,
    ):
        self.vault = vault or InlinePIITokenizationVault()
        self.authz_engine = MCPAuthorizationEngine(trust_domain, team_id)
        self.require_dpop = require_dpop
        if require_dpop and DPoPVerifier is None:
            raise RuntimeError("cryptography package required for DPoP verification")
        self.dpop = DPoPVerifier() if DPoPVerifier else None
        self.audit = HashChainedAuditLog(
            audit_path or _default_audit_path(),
            daemon_uid=os.getuid() if hasattr(os, "getuid") else 0,
            spiffe_id=f"spiffe://{trust_domain}/ns/enclave/mcp-auth-proxy",
        )
        self._rpc_seq = 0

    def _err(self, req_id, code: int, message: str) -> Dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": code, "message": message},
        }

    async def handle_jsonrpc_request(
        self,
        raw_request: Dict[str, Any],
        actor_context: Dict[str, Any],
        env_context: Dict[str, Any],
        tool_dispatcher: Optional[Callable[[str, Dict[str, Any]], Awaitable[Any]]],
        dpop_proof: Optional[str] = None,
        htm: str = "POST",
        htu: str = "https://127.0.0.1:8443/mcp/",
    ) -> Dict[str, Any]:
        start = time.perf_counter()
        self._rpc_seq += 1
        req_id, method, params = (
            raw_request.get("id"),
            raw_request.get("method"),
            raw_request.get("params", {}) or {},
        )
        audit: Dict[str, Any] = {
            "method": method,
            "decision": "DENY",
            "reason": "",
            "actor_spiffe_id": actor_context.get("spiffe_id"),
            "pii_redacted": {},
        }

        def finish(resp: Dict[str, Any]) -> Dict[str, Any]:
            audit["eval_duration_ms"] = round((time.perf_counter() - start) * 1000, 3)
            env = self.audit.append(audit, rpc_seq_u64=self._rpc_seq)
            print(json.dumps(env, sort_keys=True))
            return resp

        # 1. DPoP proof-of-possession (RFC 9449) — before anything else.
        if self.require_dpop:
            if not dpop_proof:
                audit["reason"] = "DPoP proof missing"
                return finish(
                    self._err(
                        req_id, -32002, "Authentication failed: DPoP proof required"
                    )
                )
            if not actor_context.get("dpop_jkt"):
                # Without a bound key thumbprint (cnf.jkt) any self-generated key would verify.
                audit["reason"] = "no DPoP key bound to actor"
                return finish(
                    self._err(
                        req_id,
                        -32002,
                        "Authentication failed: no DPoP key bound to this workload",
                    )
                )
            try:
                info = self.dpop.verify(
                    dpop_proof, htm, htu, expected_jkt=actor_context.get("dpop_jkt")
                )
                audit["dpop_jkt"] = info["jkt"]
            except DPoPVerificationError as exc:
                audit["reason"] = f"DPoP rejected: {exc}"
                return finish(
                    self._err(req_id, -32002, f"Authentication failed: {exc}")
                )

        if method == "tools/list":
            audit["decision"] = "ALLOW"
            return finish(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "tools": [
                            {
                                "name": "query_customer_db",
                                "description": "Read-only SELECT over the mock schema; AST-validated; PII scrubbed.",
                                "inputSchema": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "properties": {
                                        "query": {"type": "string", "maxLength": 4096},
                                        "max_records": {
                                            "type": "integer",
                                            "minimum": 1,
                                            "maximum": 50,
                                        },
                                    },
                                    "required": ["query", "max_records"],
                                },
                            },
                            {
                                "name": "search_documentation",
                                "description": "Searches internal architecture documentation.",
                                "inputSchema": {
                                    "type": "object",
                                    "additionalProperties": False,
                                    "properties": {
                                        "query": {"type": "string", "maxLength": 512}
                                    },
                                    "required": ["query"],
                                },
                            },
                        ]
                    },
                }
            )

        if method != "tools/call":
            audit["reason"] = "method not found"
            return finish(self._err(req_id, -32601, f"Method '{method}' not found"))

        tool_name, arguments = params.get("name"), params.get("arguments", {}) or {}
        allowed, reason, opa_input = await self.authz_engine.evaluate_mcp_authz(
            actor_context, tool_name, arguments, env_context
        )
        audit.update({"tool": tool_name, "reason": reason})
        verdict = opa_input["resource"].get("sql_ast_verdict")
        if verdict:
            audit["sql_sha256"] = verdict[
                "sql_sha256"
            ]  # never the raw SQL (may contain PII literals)
            audit["sql_ast_reason"] = verdict["reason"]
        if not allowed:
            return finish(
                self._err(req_id, -32001, f"Authorization Policy Denied: {reason}")
            )
        if tool_dispatcher is None:
            audit["reason"] = "no dispatcher configured"
            return finish(self._err(req_id, -32603, "No tool dispatcher configured"))

        audit["decision"] = "ALLOW"
        dispatch_args = dict(arguments)
        if verdict:
            dispatch_args["query"] = verdict[
                "normalized_sql"
            ]  # LIMIT injected / clamped
        raw_result = await tool_dispatcher(TOOL_ALIASES[tool_name], dispatch_args)
        scrubbed, counts = self.vault.scrub_object(raw_result)
        audit["pii_redacted"] = {k: v for k, v in counts.items() if v}
        return finish({"jsonrpc": "2.0", "id": req_id, "result": scrubbed})


async def _demo_run() -> None:
    print(
        "SIMULATION ONLY — software DPoP key, regex/column DLP, mock data. Do not use on real data.\n"
    )
    from identity.dpop import DPoPProofGenerator
    from mcp.mock_customer_db import MockCustomerDatabase

    os.environ.setdefault(
        "MCPMAC_AUDIT_LOG",
        os.path.join(tempfile.gettempdir(), "mcpmac-demo-audit.jsonl"),
    )
    proxy = MCPAuthProxy()
    db = MockCustomerDatabase()
    key = DPoPProofGenerator()
    actor = {
        "spiffe_id": f"spiffe://{DEFAULT_TRUST_DOMAIN}/ns/developer/workload/code-assistant/501",
        "team_id": DEFAULT_TEAM_ID,
        "clearance": "developer_l2",
        "code_signature_valid": True,
        "hardware_attested": True,
        "dpop_jkt": key.thumbprint(),
    }
    env = {"filevault_active": True, "network_isolated": True}
    htu = "https://127.0.0.1:8443/mcp/"

    async def dispatcher(tool, args):
        return db.execute_query(args["query"], args["max_records"])

    req1 = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "query_customer_db",
            "arguments": {
                "query": "SELECT customer_id, name, email, ssn, phone, dob, zip, notes FROM customers WHERE customer_id = 'CUST_1001'",
                "max_records": 10,
            },
        },
    }
    print("--- TEST 1: Authorized request (scrubbed result) ---")
    print(
        json.dumps(
            await proxy.handle_jsonrpc_request(
                req1, actor, env, dispatcher, key.create_proof("POST", htu)
            ),
            indent=2,
        )
    )

    req2 = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "query_customer_db",
            "arguments": {"query": "SELECT  * FROM customers", "max_records": 10},
        },
    }
    print("\n--- TEST 2: Wildcard SQL (denied by AST guard) ---")
    print(
        json.dumps(
            await proxy.handle_jsonrpc_request(
                req2, actor, env, dispatcher, key.create_proof("POST", htu)
            ),
            indent=2,
        )
    )

    print("\n--- TEST 3: Replayed DPoP proof (denied) ---")
    proof = key.create_proof("POST", htu)
    await proxy.handle_jsonrpc_request(
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list"}, actor, env, None, proof
    )
    print(
        json.dumps(
            await proxy.handle_jsonrpc_request(
                {"jsonrpc": "2.0", "id": 4, "method": "tools/list"},
                actor,
                env,
                None,
                proof,
            ),
            indent=2,
        )
    )


if __name__ == "__main__":
    asyncio.run(_demo_run())
