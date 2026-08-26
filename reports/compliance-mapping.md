# Compliance mapping

Điền evidence là **đường dẫn file/dòng thật** trong repo của bạn — không
phải mô tả chung. Xem `Guide.md` Bước 4 và `Rubric.md`.

| Requirement | Control | Evidence |
|---|---|---|
| Luật 91/2025 — quyền yêu cầu xoá | Chưa implement delete cascade — xem `Guide.md` stretch #4 | — |
| NĐ 356/2025 — hồ sơ xuyên biên giới 60 ngày | Data-flow inventory cho LLM API call (kể cả khi dùng `--model`) | `reports/dpia-lite.md` §3 |
| ASI03 — privilege abuse | Per-agent/per-run identity trong mọi dòng ledger (`agent_id`, `run_id`, `agent_owner`); TTL/expiry chưa implement | `agent/policy.py:31-37` (`PolicyContext.agent_owner`), `agent/runner.py:73-90` (`_log()` ghi field `agent_owner`), thực tế trong `reports/ledger.jsonl` mỗi dòng |
| ASI01 — goal hijack | Trifecta split: Run A (search_docs) không bao giờ đọc customer, Run B (read_customer) không bao giờ đọc free text | `agent/runner.py:117-176` (`handle()`), bằng chứng chạy thật ở `reports/attack-after.log` |
| ISO 42001 Clause 5-6 | Policy-as-code (`agent/policy.py`) có review qua git history, không phải quyết định thủ công | `git log --oneline -- agent/policy.py` → `2b9ddda lab24: implement policy enforcement point (Bước 3b)` |
