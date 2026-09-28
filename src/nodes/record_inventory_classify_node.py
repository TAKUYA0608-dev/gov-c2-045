"""GOV-C2-045 — inner workflow step 1: record_inventory_classify.

Deterministic inventory of the authorized target records and routing of each record to the applicable
non-disclosure exemption rulesets. Sets `record_count`; **0 records (rejected input or none attached)
routes to the out-of-scope safe answer** — the agent never fabricates candidates for records it did not
receive.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.services.service import DisclosurePolicyKB
from src.utils.audit import emit_trace_event


class RecordInventoryClassifyNode(FunctionNode):
    """Inventory + classify each authorized record against the exemption taxonomy."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        # Inner-input contract: the outer GraphNode.extract_input() feeds the inner graph via
        # `user_input`; the outer `validated_input` is NOT auto-carried into the fresh inner state. Read
        # validated_input if already re-persisted, else the inner user_input, and re-persist the canonical
        # body so downstream inner nodes (policy_flag / synthesize / human_gate) can read validated_input.
        canonical = state.get("validated_input") or state.get("user_input") or "{}"
        parsed = json.loads(canonical)
        records = parsed.get("records", []) if isinstance(parsed, dict) else []

        if state.get("error_code") or not records:
            emit_trace_event("record_inventory.skip", {"reason": state.get("error_code") or "no_records"}, state)
            return {
                "validated_input": canonical,
                "record_inventory": "[]",
                "record_count": 0,
                "error_code": state.get("error_code") or "NO_RECORDS",
                "status": AgentStatus.SUCCESS.value,
            }

        inventory = [DisclosurePolicyKB.classify_record(r) for r in records]
        emit_trace_event(
            "record_inventory.complete",
            {"record_count": len(inventory), "record_types": sorted({c["record_type"] for c in inventory})},
            state,
        )
        return {
            "validated_input": canonical,
            "record_inventory": json.dumps(inventory, ensure_ascii=False),
            "record_count": len(inventory),
            "status": AgentStatus.SUCCESS.value,
        }
