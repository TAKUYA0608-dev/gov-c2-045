# GOV-C2-045 — Integration: the real invoke() path, with the platform's S-2 masking active.
#
# The existing e2e test drives the nodes by hand, so the framework's own input gate never runs. On the
# platform that gate replaces My-Number / e-mail / phone values, labelled names ("氏名 山田太郎", label
# included) and runs of two or more Title-Case words with "[MASKED]" before this template's code sees the
# records. Measured on AgentCore 1.0.3: the resident-application record lost its My-Number (0.95), e-mail
# (0.9) and 氏名 candidates, and nothing in the packet said so. These tests call Graph().invoke() as a
# VERIFIED_EXTERNAL caller, so the masking is part of every run.

import json
import re
from collections.abc import Iterator
from typing import Any

import framework.nodes.function_node as function_node
import pytest
from framework.schemas.invocation_context import InvocationContext
from framework.schemas.trust_level import TrustLevel

from src.graph.graph import Graph

_RESIDENT = {
    "record_id": "R-001",
    "title": "住民申請書",
    "authorized": True,
    "content": "氏名 山田太郎 住所 東京都新宿区西新宿2-8-1 個人番号 123456789012 メール taro@example.com",
}
_MEMO = {
    "record_id": "R-002",
    "title": "契約検討メモ",
    "authorized": True,
    "content": "本件は審議中であり取引先の見積・原価を含む。方針は未確定。",
}
_COMPLAINT = {
    "record_id": "R-003",
    "title": "苦情記録",
    "authorized": True,
    "content": "申出人 Hanako Suzuki 様（連絡先 090-1234-5678）について、担当者：佐藤一郎 が対応した。",
}
_CODE = "PERSONAL_DATA_MASKED"


def _ctx() -> InvocationContext:
    return InvocationContext(caller_id="integration-test", caller_trust_level=TrustLevel.VERIFIED_EXTERNAL)


def _envelope(records: list[dict[str, Any]]) -> dict[str, Any]:
    request = json.dumps({"request": {"request_id": "REQ-1"}, "records": records}, ensure_ascii=False)
    out: dict[str, Any] = Graph().invoke(request, ctx=_ctx())
    assert str(out.get("status")).lower().endswith("success"), out.get("status")
    body = out["output"]
    envelope: dict[str, Any] = json.loads(body) if isinstance(body, str) else body
    return envelope


def _masked(packet: dict[str, Any]) -> list[dict[str, Any]]:
    return [c for c in packet["candidates"] if c.get("limitation") == _CODE]


def _platform_view(text: str) -> str:
    """What the template's nodes receive: the text after the framework's S-2 masking."""
    return str(function_node.mask_pii(text, function_node.detect_pii(text)))


@pytest.fixture
def no_platform_masking(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """A deployment whose S-2 pass does not mask (the template's own regexes decide)."""
    monkeypatch.setattr(function_node, "detect_pii", lambda text: [])
    yield


class TestPlatformMaskedRecord:
    def test_every_masked_span_becomes_a_low_confidence_candidate(self) -> None:
        view = _platform_view(_RESIDENT["content"])
        assert view.count("[MASKED]") == 3 and "氏名" not in view, "precondition: name+label, number, e-mail masked"
        env = _envelope([_RESIDENT])
        packet = env["packet"]
        masked = _masked(packet)
        assert len(masked) == 3, packet["candidates"]
        assert all(c["exemption_category"] == "personal_info" and c["confidence"] == 0.65 for c in masked)
        assert all(c["confidence"] < 0.7 for c in masked)  # below the HumanGate line → exceptions
        assert len([e for e in packet["exceptions"] if e["confidence"] == 0.65]) == 3
        assert env["limitations"] == [_CODE], env
        assert packet["limitations"] == [_CODE]
        assert "3 箇所を [MASKED] に置換" in env["message"], env["message"]

    def test_no_raw_value_reaches_the_packet(self) -> None:
        blob = json.dumps(_envelope([_RESIDENT]), ensure_ascii=False)
        for raw in ("123456789012", "taro@example.com", "山田太郎"):
            assert raw not in blob

    def test_an_unmasked_address_hit_does_not_hide_a_masked_labelled_name(self) -> None:
        # Mixed case: the address is not masked and is still flagged by the template's own regex (0.8);
        # the labelled name was masked together with its label, so no regex or label rule sees it.
        record = {**_RESIDENT, "content": "氏名 山田太郎 住所 東京都新宿区西新宿2-8-1"}
        view = _platform_view(record["content"])
        assert view.startswith("[MASKED] 住所 東京都"), "precondition: name + label masked, address intact"
        env = _envelope([record])
        packet = env["packet"]
        confidences = sorted((c["confidence"] for c in packet["candidates"]), reverse=True)
        assert confidences == [0.8, 0.65, 0.6], packet["candidates"]  # address, masked span, 住所 label
        assert len(_masked(packet)) == 1
        assert env["limitations"] == [_CODE], env

    def test_a_latin_name_a_phone_and_a_labelled_staff_name_are_all_listed(self) -> None:
        env = _envelope([_COMPLAINT])
        assert len(_masked(env["packet"])) == 3, env["packet"]["candidates"]
        assert env["limitations"] == [_CODE], env

    def test_evidence_snippets_never_carry_part_of_a_value(self) -> None:
        # Side fix: the snippet window used to be cut first and redacted afterwards, so a value crossing
        # the window edge escaped the regex (measured: an address tail such as "西新宿2-8-1").
        env = _envelope([_RESIDENT])
        for c in env["packet"]["candidates"]:
            assert not re.search(r"\d", c["evidence"]), c["evidence"]


class TestUnmaskedRecordsAreUnchanged:
    def test_a_record_without_masked_text_has_no_limitation(self) -> None:
        assert _platform_view(_MEMO["content"]) == _MEMO["content"], "precondition: nothing masked"
        env = _envelope([_MEMO])
        assert _masked(env["packet"]) == []
        assert env["limitations"] == []
        assert env["message"] is None
        assert env["packet"]["candidate_total"] == 5
        assert set(env) == {
            "status_kind",
            "packet",
            "citations",
            "citation_complete",
            "candidate_total",
            "human_review_status",
            "message",
            "limitations",
            "disclaimer",
        }

    @pytest.mark.usefixtures("no_platform_masking")
    def test_without_platform_masking_the_regex_candidates_are_back(self) -> None:
        env = _envelope([_RESIDENT])
        confidences = sorted(c["confidence"] for c in env["packet"]["candidates"])
        assert 0.95 in confidences and 0.9 in confidences  # My Number and e-mail flagged by the template
        assert _masked(env["packet"]) == []
        assert env["limitations"] == []

    @pytest.mark.usefixtures("no_platform_masking")
    def test_without_platform_masking_no_snippet_leaks_part_of_a_value(self) -> None:
        # Measured on develop: "メール taro@ex" and "個人番号 1234" (values cut at the window edge).
        env = _envelope([_RESIDENT])
        for c in env["packet"]["candidates"]:
            evidence = c["evidence"]
            assert "@" not in evidence and not re.search(r"\d", evidence), evidence
