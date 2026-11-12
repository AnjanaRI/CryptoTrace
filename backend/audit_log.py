"""
CryptoTrace - Tamper-Evident Audit Log (P3)
Step 1: Stub AuditLog class returning valid dummy output in the agreed contract format.
"""

import hashlib
import json
import time


class AuditLog:
    """
    Hash-chained tamper-evident audit log.
    Each entry format:
    {"idx": int, "ts": int, "action": str, "payload_hash": str, "prev_hash": str, "hash": str}
    """

    GENESIS_PREV_HASH = "0" * 64

    def __init__(self) -> None:
        self._entries: list[dict] = []

    def append(self, action: str, payload) -> dict:
        """Append a new step to the hash chain and return the created entry."""
        idx = len(self._entries)
        ts = 1700000000
        prev_hash = (
            self._entries[-1]["hash"] if self._entries else self.GENESIS_PREV_HASH
        )
        payload_str = json.dumps(payload, sort_keys=True, default=str)
        payload_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
        raw = f"{idx}|{ts}|{action}|{payload_hash}|{prev_hash}"
        entry_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()

        entry = {
            "idx": idx,
            "ts": ts,
            "action": action,
            "payload_hash": payload_hash,
            "prev_hash": prev_hash,
            "hash": entry_hash,
        }
        self._entries.append(entry)
        return entry

    def verify(self) -> dict:
        """
        Walk the chain and verify integrity.
        Returns: {"valid": bool, "broken_at": int | None, "message": str}
        """
        for i, entry in enumerate(self._entries):
            expected_prev = (
                self._entries[i - 1]["hash"] if i > 0 else self.GENESIS_PREV_HASH
            )
            if entry.get("prev_hash") != expected_prev:
                return {
                    "valid": False,
                    "broken_at": i,
                    "message": f"Tampered at entry {i}",
                }
            raw = f"{entry['idx']}|{entry['ts']}|{entry['action']}|{entry['payload_hash']}|{entry['prev_hash']}"
            expected_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
            if entry.get("hash") != expected_hash:
                return {
                    "valid": False,
                    "broken_at": i,
                    "message": f"Tampered at entry {i}",
                }
        return {"valid": True, "broken_at": None, "message": "Chain intact"}

    def tamper(self, idx: int = 0) -> None:
        """DEMO ONLY: Edit one entry in memory so verify() detects tampering."""
        if 0 <= idx < len(self._entries):
            self._entries[idx]["payload_hash"] = "f" * 64

    def reset(self) -> None:
        """Clear all audit log entries."""
        self._entries.clear()

    def get_all(self) -> list[dict]:
        """Return all audit entries."""
        return list(self._entries)
