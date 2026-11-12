"""
Tests for backend/security.py (P3 Step 1)
"""

import networkx as nx
from backend.security import (
    adversarial_score,
    run_detectors,
    validate_input,
    validate_response,
)


def test_validate_input_stub():
    ok, kind, msg = validate_input("bc1qsrc0000000000000000000000000000000000")
    assert isinstance(ok, bool)
    assert kind in ("address", "txid", None)
    assert isinstance(msg, str)


def test_validate_response_stub():
    ok, issues = validate_response([])
    assert isinstance(ok, bool)
    assert isinstance(issues, list)


def test_run_detectors_stub():
    g = nx.MultiDiGraph()
    findings = run_detectors(g)
    assert isinstance(findings, list)
    for f in findings:
        assert "type" in f
        assert f["severity"] in ("low", "medium", "high")
        assert "text" in f
        assert "nodes" in f


def test_adversarial_score_stub():
    g = nx.MultiDiGraph()
    score = adversarial_score(g, [])
    assert isinstance(score, float)
    assert 0.0 <= score <= 1.0
