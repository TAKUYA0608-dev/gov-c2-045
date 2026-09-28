"""GOV-C2-045 — deterministic domain services (no framework imports).

DisclosurePolicyKB: a seeded, auditable engine for municipal public-records disclosure review. It
classifies authorized target records against a non-disclosure **exemption taxonomy** (personal info /
corporate info / deliberation / administrative operations / public safety) modelled on the exemption
grounds of Japan's information-disclosure statutes, and flags **redaction candidates** with an exemption
category, a rationale, and a confidence score.

Everything here is deterministic — keyword / regex scoring plus fixed-template rationale composition. **No
LLM is used** (there is no model configured in ``config/agent.yaml`` and no LLM dependency in
``pyproject.toml``), so both the flagging and the candidate rationale phrasing are fully reproducible and
auditable. Redaction candidates are proposals — the agent never finalises a redaction or a disclosure
decision (that is the authorized official's job, via the mandatory HumanGate). The module also exposes S-3
output helpers (`redact_pii`, `neutralize_injection`) so the composed review packet does not reproduce raw
personal information or propagate injection markers.
"""

from __future__ import annotations

import re
from typing import Any

# ── S-3 / defense-in-depth: personal-information (PII) patterns ────────────────
# Redacted in the OUTPUT packet so the review packet locates PII without reproducing raw values.
_MY_NUMBER = re.compile(r"(?<![\d.])\d{12}(?![\d.])")  # 個人番号 / My-Number (12 digits)
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63}){0,3}\.[A-Za-z]{2,24}")
_PHONE = re.compile(r"0\d{1,4}-\d{1,4}-\d{3,4}")  # Japanese phone (hyphenated)
# Address run: prefecture/city … up to a number+丁目/番地/号 (kept conservative to avoid over-masking).
_ADDRESS = re.compile(
    r"[一-龥ぁ-んァ-ヶ]{1,8}[都道府県][一-龥ぁ-んァ-ヶ]{1,10}[市区町村][^\s、。]{0,20}\d[-\d丁目番地号]+"
)

_PII_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("my_number", _MY_NUMBER, "[MY-NUMBER-REDACTED]"),
    ("email", _EMAIL, "[EMAIL-REDACTED]"),
    ("phone", _PHONE, "[PHONE-REDACTED]"),
    ("address", _ADDRESS, "[ADDRESS-REDACTED]"),
]

# ── S-1 hygiene: control chars + credential-shaped tokens ─────────────────────
# A supplied request / record field may inadvertently paste a device token / API key. Prefixes are
# concatenated so this module carries NO literal secret (S-5 / gate-credential-scan). Credential tokens
# are redacted in supplied fields on the way into State (S-1 input hygiene) and in the output (S-3).
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
_CRED_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\b(?:api[_-]?key|secret|password|passwd|token|bearer)\b\s*[:=]?\s*[A-Za-z0-9._\-]{12,}"),
    re.compile(r"\b" + "AKIA" + r"[0-9A-Z]{12,}\b"),  # AWS access-key id shape
    re.compile(r"(?i)\b" + "sk" + r"-[A-Za-z0-9]{16,}"),  # provider secret-key shape
    re.compile(r"\b" + "eyJ" + r"[A-Za-z0-9._\-]{10,}\.[A-Za-z0-9._\-]{6,}\.[A-Za-z0-9._\-]{6,}"),  # JWT
)
_CRED_MASK = "[CREDENTIAL-REDACTED]"

# Personal-info label markers (a field labelled 氏名/住所/etc. is a personal-info exemption candidate).
_PERSONAL_LABELS = ("氏名", "住所", "生年月日", "電話", "連絡先", "メール", "個人番号", "口座", "本籍")

# Injection markers — rejected at the pre_process execute() level (degraded INJECTION_REJECTED);
# this S-3 helper neutralizes them in the OUTPUT packet as defense-in-depth so any echoed
# record content that reaches the packet can't act as an instruction downstream.
_INJECTION_MARKERS = (
    "ignore previous",
    "ignore all previous",
    "disregard the above",
    "system prompt",
    "you are now",
    "###system",
    "<|im_start|>",
)


# ── non-disclosure exemption taxonomy (公文書開示 非開示事由) ───────────────────
# Each entry: category code -> {label, statute, keywords}. `personal_info` additionally uses the PII
# regex above. These keywords encode legal/policy exemption grounds — any change is a change-controlled
# edit to this module (human-engineer MR + legal/policy specialist review before merge), NOT a
# runtime-tunable knob.
EXEMPTION_TAXONOMY: dict[str, dict[str, Any]] = {
    "personal_info": {
        "label": "個人情報",
        "statute": "情報公開法 第5条第1号 / 個人情報保護法",
        "keywords": ("個人情報", "氏名", "住所", "生年月日", "電話番号", "個人番号", "マイナンバー", "口座"),
    },
    "corporate_info": {
        "label": "法人情報（事業活動情報）",
        "statute": "情報公開法 第5条第2号",
        "keywords": ("営業秘密", "取引先", "見積", "原価", "ノウハウ", "法人の正当な利益", "契約単価"),
    },
    "deliberation": {
        "label": "審議・検討・協議情報",
        "statute": "情報公開法 第5条第5号",
        "keywords": ("審議中", "検討中", "未確定", "素案", "内部検討", "協議", "意思形成過程"),
    },
    "admin_operations": {
        "label": "事務・事業情報",
        "statute": "情報公開法 第5条第6号",
        "keywords": ("試験問題", "監査", "交渉方針", "予定価格", "入札", "契約交渉", "検査手法"),
    },
    "public_safety": {
        "label": "公共の安全・秩序情報",
        "statute": "情報公開法 第5条第4号",
        "keywords": ("警備", "保安", "防犯", "施設図面", "セキュリティ", "非常口配置"),
    },
}

# Confidence per evidence type. <0.7 → HumanGate flags for extra attention.
_PII_CONFIDENCE = {"my_number": 0.95, "email": 0.9, "phone": 0.85, "address": 0.8}
_LABEL_CONFIDENCE = 0.6
_KEYWORD_CONFIDENCE = {"corporate_info": 0.6, "deliberation": 0.55, "admin_operations": 0.6, "public_safety": 0.65}

# ── platform masking (S-2) ────────────────────────────────────────────────────
# The platform's S-2 personal-data pass runs before this template's code and replaces My-Number / e-mail /
# phone values, labelled names ("氏名 山田太郎" — the label included) and runs of two or more Title-Case
# words with this token; the template cannot switch it off. The value is gone, so the regexes above
# cannot flag it — but the token marks where personal data was. Each one becomes a personal_info
# candidate below the HumanGate threshold (0.7) on purpose: its type is unknown, so the official must look.
PLATFORM_MASK_TOKEN = "[MASKED]"
_PLATFORM_MASKED_CONFIDENCE = 0.65
_PLATFORM_MASK_RE = re.compile(re.escape(PLATFORM_MASK_TOKEN))
# Stable machine-readable limitation code (the human-readable explanation goes in the packet `message`).
PERSONAL_DATA_MASKED = "PERSONAL_DATA_MASKED"


def redact_pii(text: str) -> str:
    """Mask personal-information runs in *text* (S-3 output defense-in-depth)."""
    out = text or ""
    for _kind, pattern, mask in _PII_PATTERNS:
        out = pattern.sub(mask, out)
    return out


def neutralize_injection(text: str) -> str:
    """Neutralize prompt-injection markers in echoed record text (S-3 output side)."""
    out = text or ""
    for marker in _INJECTION_MARKERS:
        out = re.sub(re.escape(marker), "[NEUTRALIZED]", out, flags=re.IGNORECASE)
    return out


def redact_secrets(text: str) -> str:
    """Mask credential-shaped tokens (S-1 input hygiene + S-3 output). No literal secret lives in src (S-5)."""
    out = text or ""
    for pat in _CRED_PATTERNS:
        out = pat.sub(_CRED_MASK, out)
    return out


def hygiene_metadata(value: Any) -> Any:
    """S-1 field hygiene for a **supplied metadata / identifier** value before it persists to State.

    Recursive over a JSON-like value (the request dict, nested lists): strip control chars, redact
    credential-shaped tokens **and** personal information (My-Number / phone / email / address), and
    neutralize injection markers. Applied to record_id / title / provenance / the request dict /
    policy_hint — the supplied fields that flow verbatim into the inventory / candidates / review packet —
    so no raw credential or PII is persisted for anything other than the authorized record content under
    review (design: no raw PII / credentials in State beyond the records under review).
    """
    if isinstance(value, str):
        return neutralize_injection(redact_secrets(redact_pii(_CONTROL.sub("", value))))
    if isinstance(value, list):
        return [hygiene_metadata(v) for v in value]
    if isinstance(value, dict):
        return {k: hygiene_metadata(v) for k, v in value.items()}
    return value


def hygiene_content(text: str) -> str:
    """S-1 hygiene for a record's ``content`` — the payload **under review**.

    Strips control chars and redacts credential-shaped tokens (a secret is never a legitimate review
    target), but **keeps personal information** so the deterministic scan can locate & flag redaction
    candidates. Design carve-out: raw PII persists only for the authorized records under review, and the
    output packet is fully PII-redacted at S-3.
    """
    return redact_secrets(_CONTROL.sub("", text or ""))


def _snippet(text: str, center: int, width: int = 24) -> str:
    """A short, PII-redacted context snippet around *center* for the rationale (no raw PII).

    The window is widened to whole personal-data matches (and whole platform mask tokens) before it is
    redacted: a value cut at the window edge no longer matches its pattern, so redacting the cut window
    leaked part of it (the first digits of a My Number, the start of an e-mail address, an address tail).
    """
    start = max(0, center - width)
    end = min(len(text), center + width)
    spans = [(m.start(), m.end()) for _kind, pattern, _mask in _PII_PATTERNS for m in pattern.finditer(text)]
    spans += [(m.start(), m.end()) for m in _PLATFORM_MASK_RE.finditer(text)]
    widened = True
    while widened:
        widened = False
        for s_start, s_end in spans:
            if s_start < end and s_end > start and (s_start < start or s_end > end):
                start, end = min(start, s_start), max(end, s_end)
                widened = True
    return redact_pii(text[start:end]).strip()


def masked_candidate_count(candidates: list[dict[str, Any]]) -> int:
    """How many candidates stand for a span the platform masked before scanning."""
    return sum(1 for c in candidates if c.get("limitation") == PERSONAL_DATA_MASKED)


def masked_note(count: int) -> str:
    """Human-readable explanation of PERSONAL_DATA_MASKED (the packet `message`)."""
    return (
        f"個人データ保護のため、プラットフォームが本エージェントの処理前に {count} 箇所を [MASKED] に置換しました"
        "（個人番号・メール・電話・氏名など。「氏名」等のラベルごと置換される場合があります）。種別を判別できない"
        f"ため、各箇所を信頼度 {_PLATFORM_MASKED_CONFIDENCE} の個人情報候補として要確認に回しています。"
        "原本の該当箇所を確認してから黒塗りを判断してください。"
    )


class DisclosurePolicyKB:
    """Deterministic record classification + redaction-candidate flagging over the exemption taxonomy."""

    @staticmethod
    def classify_record(record: dict[str, Any]) -> dict[str, Any]:
        """Inventory + route one record to the exemption rulesets whose signals appear in its content.

        `personal_info` is always included (the PII regex scan is universal). `record_type` is the
        dominant matched exemption label, or '一般記録' when only PII / no keyword signals are present.
        """
        content = str(record.get("content", "") or "")
        rulesets = ["personal_info"]
        matched_labels: list[str] = []
        for cat, spec in EXEMPTION_TAXONOMY.items():
            if cat == "personal_info":
                continue
            if any(kw in content for kw in spec["keywords"]):
                rulesets.append(cat)
                matched_labels.append(spec["label"])
        record_type = matched_labels[0] if matched_labels else "一般記録"
        return {
            "record_id": record.get("record_id", "UNKNOWN"),
            "title": str(record.get("title", "") or "(無題)"),
            "record_type": record_type,
            "exemption_rulesets": rulesets,
        }

    @staticmethod
    def flag_candidates(record: dict[str, Any], classified: dict[str, Any]) -> list[dict[str, Any]]:
        """Flag redaction candidates for one record against its routed exemption rulesets.

        Returns [{record_id, field, exemption_category, exemption_label, statute, rationale, confidence,
        evidence}] — evidence is PII-redacted context only. Candidates are proposals, never final.
        """
        content = str(record.get("content", "") or "")
        rid = record.get("record_id", "UNKNOWN")
        rulesets = classified.get("exemption_rulesets", ["personal_info"])
        out: list[dict[str, Any]] = []

        # personal_info — PII regex hits (universal)
        if "personal_info" in rulesets:
            spec = EXEMPTION_TAXONOMY["personal_info"]
            for kind, pattern, _mask in _PII_PATTERNS:
                for m in pattern.finditer(content):
                    out.append(
                        {
                            "record_id": rid,
                            "field": "content",
                            "exemption_category": "personal_info",
                            "exemption_label": spec["label"],
                            "statute": spec["statute"],
                            "rationale": f"個人情報（{kind}）に該当し得るため黒塗り候補。根拠: {spec['statute']}。",
                            "confidence": _PII_CONFIDENCE.get(kind, 0.7),
                            "evidence": _snippet(content, m.start()),
                        }
                    )
            # spans the platform masked before this node ran (type unknown — see PLATFORM_MASK_TOKEN)
            for m in _PLATFORM_MASK_RE.finditer(content):
                out.append(
                    {
                        "record_id": rid,
                        "field": "content",
                        "exemption_category": "personal_info",
                        "exemption_label": spec["label"],
                        "statute": spec["statute"],
                        "rationale": (
                            "個人データ保護のためプラットフォームが処理前に伏字化した箇所（[MASKED]・種別不明）。"
                            f"原本の同じ位置を確認し黒塗り要否を判断してください。根拠: {spec['statute']}。"
                        ),
                        "confidence": _PLATFORM_MASKED_CONFIDENCE,
                        "evidence": _snippet(content, m.start()),
                        "limitation": PERSONAL_DATA_MASKED,
                    }
                )
            # personal-info label markers (氏名/住所/…)
            for label in _PERSONAL_LABELS:
                idx = content.find(label)
                if idx != -1:
                    out.append(
                        {
                            "record_id": rid,
                            "field": label,
                            "exemption_category": "personal_info",
                            "exemption_label": spec["label"],
                            "statute": spec["statute"],
                            "rationale": f"個人情報の項目「{label}」が含まれるため黒塗り候補。根拠: {spec['statute']}。",
                            "confidence": _LABEL_CONFIDENCE,
                            "evidence": _snippet(content, idx),
                        }
                    )

        # other exemption categories — keyword evidence
        for cat in rulesets:
            if cat == "personal_info":
                continue
            spec = EXEMPTION_TAXONOMY[cat]
            for kw in spec["keywords"]:
                idx = content.find(kw)
                if idx != -1:
                    out.append(
                        {
                            "record_id": rid,
                            "field": "content",
                            "exemption_category": cat,
                            "exemption_label": spec["label"],
                            "statute": spec["statute"],
                            "rationale": f"{spec['label']}（非開示事由）の指標「{kw}」に該当し得るため黒塗り候補。根拠: {spec['statute']}。",
                            "confidence": _KEYWORD_CONFIDENCE.get(cat, 0.6),
                            "evidence": _snippet(content, idx),
                        }
                    )
        # deterministic order: record_id, then descending confidence, then category
        out.sort(key=lambda c: (c["record_id"], -c["confidence"], c["exemption_category"]))
        return out
