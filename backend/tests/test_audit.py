"""
Tests for backend/audit_log.py and backend/audit_routes.py (P3 Step 2)
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.audit_log import AuditLog, audit
from backend.audit_routes import router


def test_audit_log_hash_chain_format():
    log = AuditLog()
    e0 = log.append("validate_input", {"input": "bc1qsrc0000000000000000000000000000000000"})
    e1 = log.append("fetch_txs", {"count": 8, "mode": "sample"})
    e2 = log.append("run_detectors", {"findings": 3})

    assert e0["idx"] == 0
    assert e0["prev_hash"] == "0" * 64
    assert len(e0["payload_hash"]) == 64
    assert len(e0["hash"]) == 64

    assert e1["idx"] == 1
    assert e1["prev_hash"] == e0["hash"]

    assert e2["idx"] == 2
    assert e2["prev_hash"] == e1["hash"]

    entries = log.get_all()
    assert len(entries) == 3


def test_audit_log_reproducible_payload_hashes():
    log1 = AuditLog()
    log2 = AuditLog()

    e1 = log1.append("params", {"b": 2, "a": 1})
    e2 = log2.append("params", {"a": 1, "b": 2})
    assert e1["payload_hash"] == e2["payload_hash"]
    assert e1["hash"] == e2["hash"]


def test_audit_log_verify_and_tamper_at_specific_index():
    log = AuditLog()
    for step in ["validate_input", "fetch", "validate_response", "build_graph", "detectors"]:
        log.append(step, {"step": step})

    # Valid chain verifies
    res = log.verify()
    assert res == {"valid": True, "broken_at": None, "message": "Chain intact"}

    # Tamper at entry 3
    log.tamper(3)
    res_tampered = log.verify()
    assert res_tampered["valid"] is False
    assert res_tampered["broken_at"] == 3
    assert res_tampered["message"] == "Tampered at entry 3"


def test_audit_routes_endpoints():
    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    # Reset first
    r_reset = client.post("/audit/reset")
    assert r_reset.status_code == 200
    assert client.get("/audit").json() == []

    # Append 3 entries to shared audit log
    audit.append("validate_input", {"input": "addr1"})
    audit.append("build_graph", {"nodes": 10})
    audit.append("score", {"top": "addr9"})

    # GET /audit
    r_list = client.get("/audit")
    assert r_list.status_code == 200
    assert len(r_list.json()) == 3

    # GET /audit/verify (valid)
    r_verify = client.get("/audit/verify")
    assert r_verify.status_code == 200
    assert r_verify.json() == {"valid": True, "broken_at": None, "message": "Chain intact"}

    # POST /audit/tamper at index 1
    r_tamper = client.post("/audit/tamper", json={"idx": 1})
    assert r_tamper.status_code == 200

    # GET /audit/verify (broken at 1)
    r_verify_after = client.get("/audit/verify")
    assert r_verify_after.status_code == 200
    assert r_verify_after.json() == {
        "valid": False,
        "broken_at": 1,
        "message": "Tampered at entry 1",
    }

    # Clean up
    client.post("/audit/reset")
