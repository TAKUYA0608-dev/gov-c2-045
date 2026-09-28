"""GOV-C2-045 — inner workflow step 2: policy_flag.

Flags sensitive fields (personal information / non-disclosure exemptions) in each classified record as
**redaction candidates** with an exemption category, a statute-linked rationale, and a confidence score.
Candidates are proposals only — the agent never finalises a redaction (that is the authorized official's
job, via the HumanGate). Skips (no-op) on rejected / 0-record input.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.services.service import DisclosurePolicyKB
from src.utils.audit import emit_trace_event


class PolicyFlagNode(FunctionNode):
    """Flag redaction candidates (personal info + exemption grounds) per classified record."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        if state.get("error_code") or state.get("record_count", 0) == 0:
            # Skip path still emits a count-only S-4 event (no empty/silent execute path).
            emit_trace_event(
                "policy_flag.skip", {"reason": state.get("error_code") or "no_records", "candidate_count": 0}, state
            )
            return {}

        parsed = json.loads(state.get("validated_input") or "{}")
        records_by_id = {r.get("record_id", "UNKNOWN"): r for r in parsed.get("records", [])}
        inventory = json.loads(state.get("record_inventory") or "[]")

        candidates: list[dict[str, Any]] = []
        for classified in inventory:
            record = records_by_id.get(classified["record_id"], {})
            candidates.extend(DisclosurePolicyKB.flag_candidates(record, classified))

        by_category: dict[str, int] = {}
        for c in candidates:
            by_category[c["exemption_category"]] = by_category.get(c["exemption_category"], 0) + 1
        emit_trace_event(
            "policy_flag.complete", {"candidate_count": len(candidates), "by_category": by_category}, state
        )
        return {"redaction_candidates": json.dumps(candidates, ensure_ascii=False), "status": AgentStatus.SUCCESS.value}
