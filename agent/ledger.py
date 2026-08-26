"""BƯỚC 3d — audit ledger append-only, tamper-evident (10').

JSONL, mỗi tool call một dòng. Đọc Guide.md (§3d).

Interface bắt buộc (tests/test_ledger.py và agent/runner.py gọi trực tiếp):

    append(entry: dict, path: pathlib.Path) -> dict
        `entry` phải có tối thiểu các field:
            ts, agent_id, run_id, tool, args_hash, classification,
            decision, reason
        Hàm tự thêm 2 field:
            prev_hash  = hash của dòng ngay trước trong file này, hoặc
                         "0" * 64 nếu là dòng đầu tiên
            hash       = sha256 tính từ nội dung dòng NÀY (bao gồm cả
                         prev_hash, KHÔNG bao gồm field hash) — dùng
                         json.dumps(..., sort_keys=True) trước khi hash
                         để thứ tự field không ảnh hưởng kết quả.
        Append 1 dòng JSON (utf-8, ensure_ascii=False) vào cuối `path`,
        tạo file/thư mục cha nếu chưa có. Trả về dict đầy đủ đã ghi
        (bao gồm prev_hash/hash).

    verify(path: pathlib.Path) -> bool
        Đọc toàn bộ file, trả về True nếu TẤT CẢ đều đúng:
          - mọi dòng có `reason` non-empty
          - prev_hash của dòng n == hash đã lưu của dòng n-1 (dòng đầu so
            với "0" * 64)
          - hash lưu trong dòng n khớp lại khi tính lại từ nội dung dòng đó
        Trả về False nếu bất kỳ dòng nào bị sửa/xoá/chèn giữa file, hoặc
        thiếu reason.

Sinh viên phải tự tay chứng minh được: sửa 1 ký tự trong 1 dòng giữa file
rồi gọi verify() phải trả về False.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

GENESIS_HASH = "0" * 64


def _hash_record(record: dict) -> str:
    payload = json.dumps(record, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _last_hash(path: Path) -> str:
    if not path.exists():
        return GENESIS_HASH
    last_line = None
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                last_line = line
    return json.loads(last_line)["hash"] if last_line else GENESIS_HASH


def append(entry: dict, path: Path) -> dict:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    record = dict(entry)
    record["prev_hash"] = _last_hash(path)
    record["hash"] = _hash_record(record)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record


def verify(path: Path) -> bool:
    path = Path(path)
    if not path.exists():
        return True
    expected_prev = GENESIS_HASH
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if not record.get("reason"):
                return False
            if record.get("prev_hash") != expected_prev:
                return False
            stored_hash = record.get("hash")
            recomputed = {k: v for k, v in record.items() if k != "hash"}
            if _hash_record(recomputed) != stored_hash:
                return False
            expected_prev = stored_hash
    return True


def _demo() -> None:
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "ledger.jsonl"
        base = {
            "ts": "2026-08-26T00:00:00Z",
            "agent_id": "lab24-agent",
            "run_id": "demo",
            "tool": "search_docs",
            "args_hash": "deadbeef",
            "classification": "internal",
            "decision": "allow",
            "reason": "demo entry",
        }
        r1 = append(base, path)
        r2 = append({**base, "tool": "http_post", "decision": "deny"}, path)
        assert r2["prev_hash"] == r1["hash"]
        assert verify(path) is True

        lines = path.read_text(encoding="utf-8").splitlines()
        tampered = json.loads(lines[0])
        tampered["tool"] = "TAMPERED"
        lines[0] = json.dumps(tampered, ensure_ascii=False)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        assert verify(path) is False
        print("agent/ledger.py self-check OK: tamper detected correctly")


if __name__ == "__main__":
    _demo()
