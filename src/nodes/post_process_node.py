"""GOV-C2-045 — post_process node: PacketCompose (S-3 output gate + S-4 audit).

S-3: (1) recursively **redact personal information** and **neutralize injection markers** across every
string in the composed packet — defense-in-depth so the review packet never reproduces raw PII or
propagates instruction-like text from an echoed record; (2) verify exemption-citation completeness;
(3) append the mandatory DRAFT / advisory disclaimer (final redaction & disclosure decisions are the
authorized official's). S-4: emit a terminal audit event (record / candidate counts only — no PII).
Runs on both the full review packet and the out-of-scope safe branch.
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from framework.nodes.function_node import FunctionNode
from framework.schemas.agent_status import AgentStatus
from framework.schemas.trust_level import TrustLevel

from src.services.service import neutralize_injection, redact_pii, redact_secrets
from src.utils.audit import emit_trace_event

_DISCLAIMER = (
    "本パケットは公開請求対象記録に対する黒塗り候補と根拠を提示する参考資料（DRAFT）であり、黒塗りの確定・"
    "開示可否・最終開示決定・法的判断は一切含みません。すべての候補は authorized な情報公開担当職員が窓口で"
    "確認・確定する必要があります。本エージェントは候補提示のみを行い、公文書の改変・公開・代理開示は行いません。"
)


def _sanitize(value: Any) -> Any:
    """Recursively redact PII + credential tokens + neutralize injection markers across all string
    leaves (S-3 defense-in-depth) — so neither raw personal information nor an inadvertently-supplied
    credential (e.g. one embedded in a record's content) survives into the composed packet."""
    if isinstance(value, str):
        return neutralize_injection(redact_secrets(redact_pii(value)))
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items()}
    return value


class PacketComposeNode(FunctionNode):
    """Sanitize + verify citations + append DRAFT disclaimer + emit terminal audit."""

    required_trust_level: ClassVar[TrustLevel] = TrustLevel.VERIFIED_EXTERNAL

    def _extra_security_gate_output(self, result: dict[str, Any]) -> dict[str, Any]:
        """S-3 preservation check: the mandatory DRAFT disclaimer must be present in the envelope.

        SDK 1.0.0 contract: receives the **result dict from `execute()`**; returns the (possibly
        filtered) result. MAY raise to block an output missing the mandatory disclaimer.
        """
        out = result.get("formatted_output", "")
        if out and "DRAFT" not in out and "窓口" not in out:
            raise ValueError("S-3: mandatory DRAFT/advisory disclaimer missing from output")
        return dict(result)

    def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        report: dict[str, Any] = json.loads(state.get("result", "{}") or "{}")
        report = _sanitize(report)  # S-3: no raw PII / injection markers survive into the output

        status_kind = report.get("status_kind")
        citations = report.get("citations", [])
        grounded = status_kind == "review_packet"
        candidate_total = report.get("candidate_total", 0)
        # A review packet with candidates must cite exemptions; a clean packet (0 candidates) needs none.
        citation_complete = (not grounded) or candidate_total == 0 or bool(citations)
        human_review_status = (report.get("human_review", {}) or {}).get("human_review_status")

        formatted = {
            "status_kind": status_kind,
            "packet": report,
            "citations": citations,
            "citation_complete": citation_complete,
            "candidate_total": candidate_total,
            "human_review_status": human_review_status,
            "message": report.get("message"),
            # stable codes only (see service.py); the explanation is in `message`
            "limitations": report.get("limitations", []),
            "disclaimer": _DISCLAIMER,
        }
        emit_trace_event(
            "packet_compose.complete",
            {
                "status_kind": status_kind,
                "record_count": len(report.get("records", [])),
                "candidate_total": candidate_total,
                "citation_complete": citation_complete,
                "human_review_status": human_review_status,
                "error_code": state.get("error_code"),
                "limitations": report.get("limitations", []),
            },
            state,
        )
        return {
            "formatted_output": json.dumps(formatted, ensure_ascii=False),
            "disclaimer": _DISCLAIMER,
            "audit_logged": True,
            "status": AgentStatus.SUCCESS.value,
        }
