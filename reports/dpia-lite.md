# DPIA-lite (1 trang)

## 1. Dữ liệu gì

- `search_docs` (`agent/tools.py`, đọc `corpus/*.md`): toàn văn ticket hỗ
  trợ khách hàng — có thể chứa tên, mã khách hàng (`KH-000NNN`), nội dung
  yêu cầu tự do do khách/attacker viết. Đây là **untrusted content**,
  không phải nguồn tin cậy cho quyết định.
- `read_customer` (`agent/tools.py`, đọc `data/customers.json`): dữ liệu
  cá nhân đầy đủ của một khách hàng — `name`, `cccd` (căn cước 12 số),
  `phone`, `bank_account`, `email`. Đây là **restricted** theo
  `agent/policy.py` (mọi lần đọc được ghi vào `reports/ledger.jsonl` với
  `classification=restricted`).
- `http_post`: payload gửi ra ngoài, nếu được phép, sẽ chứa nguyên các
  field ở trên (`{"records": [...]}` — xem `agent/runner.py` phần egress).

## 2. Mục đích gì

Agent cần đọc ticket (`search_docs`) để tổng hợp yêu cầu hỗ trợ đang mở.
Nó chỉ cần đọc `read_customer` khi ticket đó thực sự thuộc về khách hàng
đó — xác định qua `related_tickets` trong `data/customers.json` (nguồn
tin cậy), không qua bất kỳ tuyên bố nào trong nội dung ticket. Agent
**không có mục đích hợp lệ nào cần gọi `http_post`** trong luồng "tổng
hợp ticket" — mọi lần thử egress trong lab này đều bắt nguồn từ một chỉ
thị injection trong tài liệu, và bị `agent/policy.py:check()` deny do
`classification=restricted and egress_enabled=True`.

## 3. Chảy đi đâu

- **Log nội bộ:** `reports/ledger.jsonl` — chỉ lưu `args_hash` (sha256 của
  tham số gọi tool), KHÔNG lưu PII thô, nên bản thân ledger không phải là
  một điểm rò rỉ mới.
- **Sink nội bộ (chỉ trong lab):** `http://localhost:9999` — hard-allowlist
  trong `agent/tools.py:http_post`, không bao giờ ra Internet thật. Sau
  containment, `reports/sink.log` luôn rỗng cho dữ liệu của `KH-000999`
  (xem `reports/attack-after.log`).
- **API của model provider (chỉ khi dùng `--model claude-...`):**
  `agent/llm.py:RealLLM.summarize()` gửi toàn văn các ticket khớp query
  (bao gồm mọi PII trong `corpus/`) tới Anthropic API để tóm tắt. Đây là
  **chuyển dữ liệu xuyên biên giới** theo NĐ 356/2025 nếu provider đặt
  server ngoài Việt Nam. Lab này mặc định chạy `--mock` (không gọi mạng,
  không xuyên biên giới) và **được chấm bằng `--mock`** — xem `README.md`
  §"Model dùng cho lab này". `RealLLM` hiện KHÔNG có egress control nào
  che PII trước khi gửi (không gọi `agent/pii.py:redact()`) — đây là một
  khoảng trống thật nếu triển khai `--model` ngoài phạm vi lab, nên ghi
  nhận ở đây thay vì fix ngoài rubric.
