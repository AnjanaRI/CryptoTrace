"""
Tests for backend/audit_log.py (P3 Step 1)
"""

from backend.audit_log import AuditLog


def test_audit_log_append_and_get_all():
    log = AuditLog()
    entry = log.append("validate_input", {"input": "bc1qtest"})
    assert entry["idx"] == 0
    assert entry["action"] == "validate_input"
    assert entry["prev_hash"] == "0" * 64
    assert len(entry["hash"]) == 64
    assert len(log.get_all()) == 1


def test_audit_log_verify_and_tamper():
    log = AuditLog()
    log.append("validate_input", {"input": "bc1qtest"})
    log.append("fetch_txs", {"count": 5})

    res = log.verify()
    assert res["valid"] is True
    assert res["broken_at"] is None

    log.tamper(1)
    res_tampered = log.verify()
    assert res_tampered["valid"] is False
    assert res_tampered["broken_at"] == 1


def test_audit_log_reset():
    log = AuditLog()
    log.append("validate_input", {"input": "bc1qtest"})
    log.reset()
    assert log.get_all() == []
