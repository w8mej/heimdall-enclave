#!/usr/bin/env python3
"""
v2.0 Dual-LLM Enclave — PYTHON ARCHITECTURAL SIMULATION

    WARNING: SIMULATION ONLY — MOCK KEYS & MOCK REGEX; DO NOT USE ON REAL DATA.

This file simulates, in plain Python, the *shape* of the CORE-V2 target design. It is NOT:
  * a Cedar engine (the "policy engine" below is a Python dict + the SQL AST guard),
  * a Secure Enclave key (the canary HMAC key is a random per-process software key),
  * an Apple Neural Engine model (the "semantic guard" is a keyword/phrase list),
  * a WASI sandbox (tools are ordinary Python coroutines).
Latency numbers it prints measure this Python code only; they say nothing about the
`p99 <= 45µs` native Cedar target (ADR-008).

Remediations (ADVERSARIAL_SPEC_REVIEW_2026-11-04):
  F-005  Explicit simulation banner; the hardcoded mock "SEP" key literal is removed;
         every matched clinical trigger span is redacted (previously only the literal
         phrase "diagnosed with schizophrenia" was replaced, leaking "bipolar"/"cardiac").
  F-037  SQL validated by depot/sql_guard.py instead of substring checks.
"""

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import sys
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
from depot.sql_guard import validate_select  # noqa: E402

SIMULATION_BANNER = (
    "WARNING: SIMULATION ONLY — MOCK KEYS & MOCK REGEX; DO NOT USE ON REAL DATA."
)
print(SIMULATION_BANNER, file=sys.stderr)

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("bleeding_edge_enclave")


class InProcessCedarPolicyEngine:
    """
    SIMULATION of an in-process Cedar policy decision point (CORE-V2 §2.4 / ADR-008).
    This is a Python dict lookup plus the SQL AST guard — it is not Cedar and is not verified.
    """

    def __init__(self):
        # Cedar-style schema & permission definitions
        self.role_capabilities = {
            "developer_l1": {"search_docs", "format_code"},
            "developer_l2": {"search_docs", "format_code", "query_customer_db"},
            "sre_fellow": {"*"},
        }

    def evaluate(
        self, principal: Dict[str, Any], action: str, resource: Dict[str, Any]
    ) -> Tuple[bool, str, float]:
        """Evaluates policy in-process with microsecond precision."""
        start = time.perf_counter()

        role = principal.get("role", "anonymous")
        allowed_actions = self.role_capabilities.get(role, set())

        # 1. Capability Check
        if "*" not in allowed_actions and action not in allowed_actions:
            elapsed_us = (time.perf_counter() - start) * 1_000_000
            return (
                False,
                f"Principal '{role}' lacks capability for action '{action}'.",
                elapsed_us,
            )

        # 2. AST and Projection Constraints for Database Tools (recursive-descent guard, F-037)
        if action == "query_customer_db":
            verdict = validate_select(
                resource.get("query", ""), resource.get("max_records", 0)
            )
            if not verdict.valid:
                elapsed_us = (time.perf_counter() - start) * 1_000_000
                return (
                    False,
                    f"SQL AST guard rejected query: {verdict.reason}",
                    elapsed_us,
                )

        elapsed_us = (time.perf_counter() - start) * 1_000_000
        return (
            True,
            "Authorized by simulated in-process policy engine (not Cedar).",
            elapsed_us,
        )


class CryptographicCanaryTripwire:
    """
    Canary honeytoken generator (SIMULATION). The v3.0 target keys this HMAC inside the SEP and
    emits canaries from `_piivault` (UID 703, OQ-04). Here the key is a random per-process
    software key labelled SIMULATION_ONLY — never a hardcoded literal.
    """

    key_custody = "SIMULATION_ONLY_SOFTWARE_KEY"

    def __init__(self, hmac_key: Optional[bytes] = None):
        self._key = hmac_key or os.urandom(32)
        self.active_canaries: Dict[str, Dict[str, Any]] = {}

    def mint_canary(self, record_id: str) -> str:
        """Mints a verifiable cryptographic honeytoken bound to record ID."""
        ts = str(int(time.time()))
        digest = hmac.new(
            self._key, f"{record_id}:{ts}".encode(), hashlib.sha256
        ).hexdigest()[:16]
        canary_token = f"CNRY_SEP_{digest}"
        self.active_canaries[canary_token] = {
            "record_id": record_id,
            "created_at": ts,
            "tripped": False,
        }
        return canary_token

    def scan_for_canary_trip(self, text_output: str) -> Optional[str]:
        """Scans outgoing text for canary leakage. Returns the canary if tripped."""
        for canary in self.active_canaries:
            if canary in text_output:
                self.active_canaries[canary]["tripped"] = True
                return canary
        return None


class NeuralContextualDLP:
    """
    SIMULATION of the CORE-V2 §2.2 ANE semantic guard: a phrase/keyword list, not a model.
    Every matched span is redacted (F-005). Unlisted conditions are NOT detected — which is
    exactly why this must never be used on real data.
    """

    # Phrases whose *object* is clinical: redact the phrase and the following clause.
    _CLAUSE_TRIGGERS = re.compile(
        r"(?i)\b(diagnosed with|prescribed|history of|treated for|suffers from|admitted for)\s+[^.;,\n]+"
    )
    # Standalone clinical terms: redact the term itself wherever it appears.
    _TERMS = re.compile(
        r"(?i)\b(schizophreni\w*|bipolar\w*|cardiac\w*|psychiatric\w*|depress\w*|arrhythmi\w*|"
        r"diabet\w*|oncolog\w*|hiv|sertraline|\d+\s?mg)\b"
    )
    _FIN = re.compile(r"(?i)\b(account balance|salary)\b")

    @classmethod
    def classify_and_scrub(cls, text: str) -> Tuple[str, List[str]]:
        flags: List[str] = []
        scrubbed, n1 = cls._CLAUSE_TRIGGERS.subn(
            lambda m: f"{m.group(1)} [REDACTED_CLINICAL_C4]", text
        )
        scrubbed, n2 = cls._TERMS.subn("[REDACTED_CLINICAL_C4]", scrubbed)
        if n1 or n2:
            flags.append("HEALTH_DATA_RESTRICTED_C4")
        if cls._FIN.search(scrubbed):
            flags.append("FINANCIAL_RESTRICTED_C3")
        return scrubbed, flags


class DualLLMEnclaveCoordinator:
    """
    Enforces Dual-LLM Privilege Separation:
    1. Privileged Orchestrator: Directs workflow, invokes tools, NEVER SEES CUSTOMER PII.
    2. Quarantined Synthesizer: Ingests masked data, computes results, HAS ZERO TOOL CAPABILITIES.
    """

    def __init__(self):
        self.policy_engine = InProcessCedarPolicyEngine()
        self.tripwire = CryptographicCanaryTripwire()
        self.neural_dlp = NeuralContextualDLP()

    async def execute_secure_workflow(
        self, user_prompt: str, principal: Dict[str, Any], mock_tool_executor
    ) -> Dict[str, Any]:
        """
        Executes an end-to-end user query through the Dual-LLM boundary.
        """
        workflow_id = str(uuid.uuid4())
        logger.info(
            f"\n[WORKFLOW START: {workflow_id[:8]}] User: '{user_prompt}'")

        # ----------------------------------------------------------------------
        # Step 1: Privileged Orchestrator decides tool invocation
        # (Has zero access to customer data; only generates intent)
        # ----------------------------------------------------------------------
        tool_action = "query_customer_db"
        tool_args = {
            "query": "SELECT customer_id, name, medical_notes FROM customers WHERE id = '1001'",
            "max_records": 5,
        }
        logger.info(
            f" -> [Privileged Orchestrator] Plan: Invoke '{tool_action}' with parameters: {tool_args}"
        )

        # ----------------------------------------------------------------------
        # Step 2: In-Process Cedar Microsecond Policy Evaluation
        # ----------------------------------------------------------------------
        allowed, reason, eval_us = self.policy_engine.evaluate(
            principal, tool_action, tool_args
        )
        logger.info(
            f" -> [Cedar Engine] Decision: {'ALLOW' if allowed else 'DENY'} ({eval_us:.2f} µs) - {reason}"
        )

        if not allowed:
            return {"error": f"Policy Violation: {reason}", "latency_us": eval_us}

        # ----------------------------------------------------------------------
        # Step 3: Tool Execution (simulated; a plain Python coroutine, NOT a WASI sandbox)
        # ----------------------------------------------------------------------
        raw_tool_output = await mock_tool_executor(tool_action, tool_args)

        # ----------------------------------------------------------------------
        # Step 4: Inject Cryptographic Canary Honeytoken into Data Stream
        # ----------------------------------------------------------------------
        canary = self.tripwire.mint_canary(record_id="1001")
        raw_tool_output["_enclave_canary"] = canary
        logger.info(
            f" -> [Canary Tripwire] Minted SIMULATION_ONLY honeytoken: '{canary}'"
        )

        # ----------------------------------------------------------------------
        # Step 5: Apple Neural Engine (ANE) Contextual Semantic DLP
        # ----------------------------------------------------------------------
        notes = raw_tool_output.get("medical_notes", "")
        scrubbed_notes, semantic_flags = self.neural_dlp.classify_and_scrub(
            notes)
        raw_tool_output["medical_notes"] = scrubbed_notes
        if "name" in raw_tool_output:
            raw_tool_output["name"] = "[REDACTED_NAME_C3]"
        logger.info(
            f" -> [Simulated Semantic Guard] Processed notes. Scrubbed flags: {semantic_flags}"
        )

        # ----------------------------------------------------------------------
        # Step 6: Quarantined Synthesis Worker (Processes data, ZERO tool rights)
        # ----------------------------------------------------------------------
        logger.info(
            " -> [Quarantined Synthesizer] Ingesting data (simulated; no Seatbelt profile is applied)..."
        )

        # Simulation of Quarantined Model generating answer
        synthesized_answer = (
            f"The customer (ID: {raw_tool_output['customer_id']}) is documented as "
            f"{raw_tool_output['medical_notes']}. No external actions recommended."
        )

        # ----------------------------------------------------------------------
        # Step 7: Canary Leakage Scan on Synthesizer Output
        # ----------------------------------------------------------------------
        tripped_canary = self.tripwire.scan_for_canary_trip(synthesized_answer)
        if tripped_canary:
            logger.error(
                f"[SECURITY ALERT] Canary '{tripped_canary}' detected in output! Simulated circuit breaker tripped."
            )
            return {
                "error": "Exfiltration Circuit Breaker Tripped: Unauthorized token detected."
            }

        logger.info(" -> [Canary Check] Zero honeytoken leakage detected.")
        logger.info(
            f"[WORKFLOW COMPLETE] Final Answer Returned: '{synthesized_answer}'"
        )

        return {
            "status": "SUCCESS",
            "policy_eval_latency_us": eval_us,
            "answer": synthesized_answer,
            "semantic_flags": semantic_flags,
        }


# Demonstration test suite
async def _demo():
    print("=================================================================")
    print(" v2.0 Dual-LLM Enclave — PYTHON SIMULATION")
    print(" " + SIMULATION_BANNER)
    print("=================================================================")

    coordinator = DualLLMEnclaveCoordinator()

    async def mock_tool(tool_name, args):
        return {
            "customer_id": "CUST_1001",
            "name": "Jane Doe",  # mock raw tool input; scrubbed before output
            "medical_notes": "Patient was diagnosed with bipolar disorder, has a cardiac condition and was prescribed 20mg medication.",
        }

    # Scenario 1: Authorized Developer L2 invoking query
    principal_ok = {"user": "alice", "role": "developer_l2"}
    res1 = await coordinator.execute_secure_workflow(
        user_prompt="Summarize customer 1001 clinical notes",
        principal=principal_ok,
        mock_tool_executor=mock_tool,
    )
    print("\nScenario 1 Result:", json.dumps(res1, indent=2))

    # Scenario 2: Prompt Injection Canary Extraction Attack
    print("\n-----------------------------------------------------------------")
    print(" Scenario 2: Adversarial Attack Attempting Canary Exfiltration")
    print("-----------------------------------------------------------------")

    # Simulate an adversarial synthesizer hijacked by prompt injection
    active_canary = list(coordinator.tripwire.active_canaries.keys())[0]
    attack_output = f"Hacked! Exfiltrating secret token: {active_canary}"
    print(f"Adversarial Output to scan: '{attack_output}'")
    tripped = coordinator.tripwire.scan_for_canary_trip(attack_output)
    if tripped:
        print(
            f"✔ [SIMULATED CIRCUIT BREAKER] Caught exfiltration of '{tripped}'.")


if __name__ == "__main__":
    asyncio.run(_demo())
