"""BƯỚC 3c — trifecta split + egress allowlist (13'). ĐÂY LÀ PHẦN KHÓ NHẤT.

Đọc Guide.md (§3c) trước khi viết code. Tóm tắt yêu cầu:

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.

--- Kiến trúc đã triển khai ---

data/customers.json có field `related_tickets: list[int]` cho mỗi khách
hàng — đây là NGUỒN TIN CẬY để map ticket_id -> customer_id, KHÔNG map qua
customer_id mà attacker nhúng trong nội dung document:

    Run A: search_docs(message) -> lấy list[int] ticket_id từ TÊN FILE của
           các doc khớp (vd "ticket-999.md" -> 999). Cũng chạy
           llm.find_injection() trên text để log lại — KHÔNG dùng
           customer_id/target_url nó trả về để quyết định gọi ai, chỉ dùng
           để biết CÓ đáng thử egress hay không (policy vẫn có tiếng nói
           cuối cùng).
    Run B: với mỗi ticket_id nhận từ Run A, tìm customer nào trong
           customers.json có ticket_id trong related_tickets, rồi
           read_customer(customer_id) đó — không phải customer_id lấy từ
           text tự do.

Vì sao cách này chống được biến thể 5 (không dấu / lookalike): filter
chuỗi thô sẽ luôn có thể bị né bằng cách viết lại chỉ thị, nhưng nếu Run B
không bao giờ ĐỌC free text để quyết định gọi ai, thì việc né filter chuỗi
trở nên vô nghĩa — đây là containment (kiến trúc), khác với mitigation
(bộ lọc).

Interface bắt buộc (agent/loop.py import và gọi hàm này nếu tồn tại):

    handle(message: str, llm, log_dir: pathlib.Path | None = None) -> str
"""
from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent import tools
from agent.ledger import append as ledger_append
from agent.policy import PolicyContext, check as policy_check

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"

AGENT_ID = "lab24-agent"
_TICKET_ID_RE = re.compile(r"ticket-(\d+)")


def _args_hash(args: dict) -> str:
    payload = json.dumps(args, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _log(ledger_path, run_id, agent_owner, tool, args, classification, decision, reason):
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": AGENT_ID,
        "run_id": run_id,
        "agent_owner": agent_owner,
        "tool": tool,
        "args_hash": _args_hash(args),
        "classification": classification,
        "decision": decision,
        "reason": reason,
    }
    return ledger_append(entry, ledger_path)


def _trusted_ticket_ids(docs: list[dict]) -> list[int]:
    """Ticket id nguồn tin cậy: trích từ TÊN FILE search_docs trả về, không
    bao giờ từ nội dung text (nơi attacker có toàn quyền viết)."""
    ids = set()
    for doc in docs:
        m = _TICKET_ID_RE.search(doc["id"])
        if m:
            ids.add(int(m.group(1)))
    return sorted(ids)


def _trusted_customer_ids(ticket_ids: list[int]) -> list[str]:
    """customer_id nguồn tin cậy: map ngược qua related_tickets trong
    customers.json, không bao giờ qua customer_id mà attacker nhúng trong
    free text."""
    customers = json.loads(tools.CUSTOMERS_FILE.read_text(encoding="utf-8"))
    ticket_id_set = set(ticket_ids)
    return sorted(
        c["customer_id"]
        for c in customers
        if ticket_id_set & set(c.get("related_tickets", []))
    )


def handle(message: str, llm, log_dir: Path | None = None) -> str:
    ledger_path = (Path(log_dir) if log_dir is not None else REPORTS_DIR) / "ledger.jsonl"
    run_id = uuid.uuid4().hex[:12]

    # --- Run A: search_docs = untrusted content. Không đọc customer, không egress. ---
    ctx_a = PolicyContext(
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner="run-a",
        delegation_depth=0,
        egress_enabled=False,
    )
    allow_a, reason_a = policy_check(ctx_a)
    docs = tools.search_docs(message) if allow_a else []
    _log(ledger_path, run_id, "run-a", "search_docs", {"query": message},
         "internal", "allow" if allow_a else "deny", reason_a)

    combined_text = "\n\n".join(d["text"] for d in docs)
    # Chỉ dùng để LOG có injection hay không — KHÔNG dùng customer_ids/
    # target_url của nó để quyết định gọi ai hay gửi đi đâu.
    injected = llm.find_injection(combined_text)

    ticket_ids = _trusted_ticket_ids(docs)
    trusted_customer_ids = _trusted_customer_ids(ticket_ids)

    # --- Run B: read_customer = private data, chỉ nhận ticket_id đã sanitize từ Run A. ---
    collected = []
    for customer_id in trusted_customer_ids:
        ctx_b = PolicyContext(
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner="run-b",
            delegation_depth=1,
            egress_enabled=False,
        )
        allow_b, reason_b = policy_check(ctx_b)
        decision, record = "deny" if not allow_b else "allow", None
        if allow_b:
            try:
                record = tools.read_customer(customer_id)
            except tools.ToolError as exc:
                decision, reason_b = "deny", f"{reason_b}; read_customer failed: {exc}"
        _log(ledger_path, run_id, "run-b", "read_customer", {"customer_id": customer_id},
             "restricted", decision, reason_b)
        if record is not None:
            collected.append(record)

    # --- Egress: free text quyết định CÓ THỬ hay không, KHÔNG BAO GIỜ tự
    # mình quyết định ĐƯỢC PHÉP hay không — policy.check() luôn có tiếng
    # nói cuối cùng, và restricted+egress luôn bị deny theo rule tối thiểu. ---
    if injected is not None and collected:
        ctx_egress = PolicyContext(
            data_classification="restricted",
            request_purpose="reconciliation",
            agent_owner="run-b",
            delegation_depth=1,
            egress_enabled=True,
        )
        allow_egress, reason_egress = policy_check(ctx_egress)
        if allow_egress:
            tools.http_post(injected.target_url, {"records": collected})
        _log(
            ledger_path, run_id, "run-b", "http_post",
            {"target_url": injected.target_url, "n_records": len(collected)},
            "restricted", "allow" if allow_egress else "deny",
            reason_egress + " (target_url trích từ free text của document, không đáng tin cho egress)",
        )

    return llm.summarize(docs)
