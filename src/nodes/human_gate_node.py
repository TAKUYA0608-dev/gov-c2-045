"""GOV-C2-045 — inner workflow step 4: human_gate.

Deterministic human-in-the-loop gate. Every redaction candidate is routed to an authorized official for
confirmation — the agent never finalises a redaction or a disclosure decision. Low-confidence candidates
(< threshold) are additionally surfaced as `exceptions` (要確認) so uncertain flags get extra attention.
Skips (no-op) on rejected / 0-record input, preserving the out-of-scope safe answer.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.utils.audit import emit_trace_event

_LOW_CONFIDENCE = 0.7


class HumanGateNode(FunctionNode):
    """Route all candidates to authorized human review; surface low-confidence exceptions."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        if state.get("error_code") or state.get("record_count", 0) == 0:
            # Skip path still emits a count-only S-4 event (no empty/silent execute path).
            emit_trace_event(
                "human_gate.skip", {"reason": state.get("error_code") or "no_records", "items_for_review": 0}, state
            )
            return {}

        packet: dict[str, Any] = json.loads(state.get("result") or "{}")
        candidates = packet.get("candidates", [])

        exceptions = [
            {
                "record_id": c["record_id"],
                "exemption_category": c["exemption_category"],
                "confidence": c["confidence"],
                "note": "低確信のため要確認（authorized 職員の確定必須）",
            }
            for c in candidates
            if c.get("confidence", 0) < _LOW_CONFIDENCE
        ]
        human_review = {
            # Agent proposes only — the authorized official confirms every candidate.
            "human_review_status": "pending_human_review",
            "review_owner": "authorized_disclosure_official",
            "items_for_review": len(candidates),
            "low_confidence_exceptions": exceptions,
            "note": (
                "黒塗りの確定・開示可否・最終開示決定は authorized 職員が HumanGate で行う。"
                "本エージェントは候補提示のみで、公文書の改変・公開は一切行わない。"
            ),
        }
        packet["human_review"] = human_review
        packet["exceptions"] = exceptions

        emit_trace_event(
            "human_gate.complete",
            {
                "items_for_review": len(candidates),
                "low_confidence_exceptions": len(exceptions),
                "human_review_status": "pending_human_review",
            },
            state,
        )
        return {
            "human_review": json.dumps(human_review, ensure_ascii=False),
            "result": json.dumps(packet, ensure_ascii=False),
            "status": AgentStatus.SUCCESS.value,
        }
