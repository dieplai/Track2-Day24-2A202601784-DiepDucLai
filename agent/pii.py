"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc Guide.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re
import unicodedata

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_DIGITS_RE = re.compile(r"(?<!\d)\d{8,17}(?!\d)")

# ponytail: dataset tiếng Việt luôn viết STK liền trước số tài khoản trong
# khoảng vài chục ký tự — đủ để phân biệt với CCCD/SĐT cùng độ dài mà
# không cần NER. Nới cửa sổ / thêm keyword nếu gặp câu dài hơn.
_BANK_KEYWORDS = ("stk", "tai khoan")
_BANK_CONTEXT_WINDOW = 30


def _normalize(text: str) -> str:
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(c for c in nfkd if not unicodedata.combining(c)).lower()


def _classify_digits(value: str, context_before: str) -> str:
    if any(k in _normalize(context_before) for k in _BANK_KEYWORDS):
        return "VN_BANK_ACCOUNT"
    if len(value) == 12:
        return "VN_CCCD"
    if len(value) == 10 and value.startswith("0"):
        return "VN_PHONE"
    return "VN_BANK_ACCOUNT"


def detect(text: str) -> list[dict]:
    entities: list[dict] = []
    email_spans: list[tuple[int, int]] = []
    for m in _EMAIL_RE.finditer(text):
        entities.append({"type": "EMAIL", "start": m.start(), "end": m.end()})
        email_spans.append((m.start(), m.end()))

    for m in _DIGITS_RE.finditer(text):
        if any(start <= m.start() < end for start, end in email_spans):
            continue
        context_before = text[max(0, m.start() - _BANK_CONTEXT_WINDOW) : m.start()]
        entities.append(
            {
                "type": _classify_digits(m.group(), context_before),
                "start": m.start(),
                "end": m.end(),
            }
        )

    entities.sort(key=lambda e: e["start"])
    return entities


def redact(text: str) -> str:
    result = text
    for entity in sorted(detect(text), key=lambda e: e["start"], reverse=True):
        result = result[: entity["start"]] + f"[REDACTED_{entity['type']}]" + result[entity["end"] :]
    return result


def _demo() -> None:
    text = "CCCD của khách là 012345678912, SĐT 0912345678, STK 1970848762102888."
    entities = detect(text)
    assert {e["type"] for e in entities} == {"VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT"}
    redacted = redact(text)
    for e in entities:
        assert text[e["start"] : e["end"]] not in redacted
    print("agent/pii.py self-check OK:", entities)


if __name__ == "__main__":
    _demo()
