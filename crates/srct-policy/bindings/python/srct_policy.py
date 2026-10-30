"""srct_policy — Python binding for the chain-agnostic SRCT policy engine.

The engine itself stays in Rust (one implementation of every rule, in
``crates/srct-policy``): this module is the JSON codec + client seam. It builds
payment intents, parses decisions, and structurally reads portable documents —
it never re-implements a budget, narrowing, or signature rule. Verification
that matters (signatures, chains, bindings) runs in Rust behind the injected
backend (a callable, a subprocess, or node HTTP — the caller provides it).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, Optional


@dataclass(frozen=True)
class PaymentIntent:
    """What an agent wants to do — mirrors ``portable::PaymentIntent``."""

    agent_id: str  # 20-byte agent id, hex (0x optional)
    recipient: str  # 20-byte recipient, hex
    amount_sat: int
    service: Optional[str]  # 32-byte service tag hex, or None
    height: int
    nonce: int
    network_id: str

    def to_json(self) -> str:
        if self.amount_sat < 0:
            raise ValueError("amount_sat must be non-negative")
        return json.dumps(
            {
                "agent_id": self.agent_id,
                "recipient": self.recipient,
                "amount_sat": self.amount_sat,
                "service": self.service,
                "height": self.height,
                "nonce": self.nonce,
                "network_id": self.network_id,
            }
        )


@dataclass(frozen=True)
class PolicyDecision:
    """The engine's answer: allow, deny, or approval-needed."""

    decision: str  # "allow" | "deny" | "needs_approval"
    reason: str = ""

    @staticmethod
    def parse(raw: str) -> "PolicyDecision":
        doc = json.loads(raw)
        decision = doc.get("decision")
        if decision == "allow":
            return PolicyDecision(decision="allow")
        if decision in ("deny", "needs_approval") and isinstance(doc.get("reason"), str):
            return PolicyDecision(decision=decision, reason=doc["reason"])
        raise ValueError("malformed policy decision")

    def is_allow(self) -> bool:
        return self.decision == "allow"


def parse_portable_policy(raw: str) -> dict:
    """Structurally read a portable policy (routing without trusting)."""
    doc = json.loads(raw)
    for field in ("policy_hex", "policy_hash", "owner", "network_id"):
        if not isinstance(doc.get(field), str):
            raise ValueError(f"malformed portable policy: {field}")
    if doc.get("version") != 1:
        raise ValueError("unsupported portable version")
    return doc


def parse_delegation_proof(raw: str) -> dict:
    """Structurally read a delegation proof (routing without trusting)."""
    doc = json.loads(raw)
    if doc.get("version") != 1 or not isinstance(doc.get("links"), list) or not doc["links"]:
        raise ValueError("malformed delegation proof")
    return doc


class PolicyClient:
    """The agent wallet guard: allow, deny, or approval-needed, via a backend.

    ``decide`` is any callable ``(policy_json, intent_json, threshold) -> str``
    backed by the Rust engine (FFI, subprocess, or node HTTP).
    """

    def __init__(
        self,
        decide: Callable[[str, str, Optional[int]], str],
        verify_proof: Optional[Callable[[str], str]] = None,
        verify_audit: Optional[Callable[[str], int]] = None,
    ) -> None:
        self._decide = decide
        self._verify_proof = verify_proof
        self._verify_audit = verify_audit

    def decide(
        self,
        policy_portable_json: str,
        intent: PaymentIntent,
        approval_threshold_sat: Optional[int] = None,
    ) -> PolicyDecision:
        out = self._decide(policy_portable_json, intent.to_json(), approval_threshold_sat)
        return PolicyDecision.parse(out)

    def verify_proof(self, proof_json: str) -> str:
        if self._verify_proof is None:
            raise NotImplementedError("no proof backend wired")
        return self._verify_proof(proof_json)

    def verify_audit(self, audit_json: str) -> int:
        if self._verify_audit is None:
            raise NotImplementedError("no audit backend wired")
        return self._verify_audit(audit_json)
