"""GOV-C2-045 — inner workflow step 3: review_packet_synthesize.

Composes the redaction candidates + rationale + exemption citations into a single traceable review-packet
body (grouped per record, with a per-category exemption-citation list). On the rejected / 0-record branch
it emits the out-of-scope safe answer — no fabricated packet.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.services.service import EXEMPTION_TAXONOMY, PERSONAL_DATA_MASKED, masked_candidate_count, masked_note
from src.utils.audit import emit_trace_event

_OUT_OF_SCOPE = (
    "開示準備の対象となる認可済み記録が入力に含まれていません。開示請求に対応する対象記録（認可済み・"
    "provenance 付き）を添付いただくか、所管の情報公開担当窓口にご確認ください。"
)


class ReviewPacketSynthesizeNode(FunctionNode):
    """Synthesize redaction candidates + rationale + exemption citations into a review packet."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        inventory = json.loads(state.get("record_inventory") or "[]")
        if state.get("error_code") or state.get("record_count", 0) == 0 or not inventory:
            emit_trace_event("review_packet.safe", {"reason": state.get("error_code") or "no_records"}, state)
            report = {
                "status_kind": "out_of_scope",
                "message": _OUT_OF_SCOPE,
                "records": [],
                "candidates": [],
                "citations": [],
            }
            return {"result": json.dumps(report, ensure_ascii=False), "status": AgentStatus.SUCCESS.value}

        candidates = json.loads(state.get("redaction_candidates") or "[]")
        by_record: dict[str, list[dict[str, Any]]] = {c["record_id"]: [] for c in candidates}
        for c in candidates:
            by_record[c["record_id"]].append(c)

        records_block: list[dict[str, Any]] = []
        for inv in inventory:
            rid = inv["record_id"]
            records_block.append(
                {
                    "record_id": rid,
                    "title": inv["title"],
                    "record_type": inv["record_type"],
                    "exemption_rulesets": inv["exemption_rulesets"],
                    "redaction_candidates": by_record.get(rid, []),
                    "candidate_count": len(by_record.get(rid, [])),
                }
            )

        # exemption citations — unique (category, statute) pairs actually used
        used = sorted({c["exemption_category"] for c in candidates})
        citations = [
            {
                "exemption_category": cat,
                "exemption_label": EXEMPTION_TAXONOMY[cat]["label"],
                "statute": EXEMPTION_TAXONOMY[cat]["statute"],
            }
            for cat in used
        ]

        # Spans the platform masked are listed as low-confidence candidates; `limitations` carries the
        # stable code only and `message` explains it.
        masked = masked_candidate_count(candidates)
        review_packet: dict[str, Any] = {
            "status_kind": "review_packet",
            "records": records_block,
            "candidates": candidates,
            "citations": citations,
            "candidate_total": len(candidates),
            "exceptions": [],
            "limitations": [PERSONAL_DATA_MASKED] if masked else [],
        }
        if masked:
            review_packet["message"] = masked_note(masked)
        emit_trace_event(
            "review_packet.complete",
            {
                "record_count": len(records_block),
                "candidate_total": len(candidates),
                "citation_count": len(citations),
                "platform_masked": masked,
            },
            state,
        )
        return {
            "review_packet": json.dumps(review_packet, ensure_ascii=False),
            "result": json.dumps(review_packet, ensure_ascii=False),
            "status": AgentStatus.SUCCESS.value,
        }
