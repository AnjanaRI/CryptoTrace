"""
Tests for backend/security.py (P3 Step 2)
"""

import base58
import networkx as nx

from backend.security import (
    adversarial_score,
    run_detectors,
    validate_input,
    validate_response,
)


def test_validate_input_valid_txid():
    txid = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11"
    ok, kind, msg = validate_input(txid)
    assert ok is True
    assert kind == "txid"
    assert "txid" in msg.lower()


def test_validate_input_valid_bech32_addresses():
    # Synthetic sample address from PROJECT_CONTEXT.md (bc1q + 38 valid bech32 chars)
    sample_addr = "bc1q" + "q" * 38
    ok, kind, msg = validate_input(sample_addr)
    assert ok is True
    assert kind == "address"

    # Real mainnet Bech32 P2WPKH address
    real_bech32 = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    ok2, kind2, _ = validate_input(real_bech32)
    assert ok2 is True
    assert kind2 == "address"


def test_validate_input_valid_legacy_base58_address():
    # Generate a valid Base58Check P2PKH address (version 0x00 + 20-byte hash)
    valid_b58 = base58.b58encode_check(b"\x00" + b"\x11" * 20).decode("ascii")
    ok, kind, _ = validate_input(valid_b58)
    assert ok is True
    assert kind == "address"


def test_validate_input_rejects_bad_inputs():
    # Empty string
    ok, kind, _ = validate_input("")
    assert ok is False
    assert kind is None

    # Bad Bech32 characters ('b', 'i', 'o', '1' in data part)
    bad_bech32 = "bc1qsrc0000000000000000000000000000000000b"
    ok, kind, _ = validate_input(bad_bech32)
    assert ok is False
    assert kind is None

    # Invalid Base58 checksum (corrupt last char of a valid Base58Check address)
    valid_b58 = base58.b58encode_check(b"\x00" + b"\x11" * 20).decode("ascii")
    corrupted_b58 = valid_b58[:-1] + ("2" if valid_b58[-1] != "2" else "3")
    ok, kind, msg = validate_input(corrupted_b58)
    assert ok is False
    assert kind is None
    assert "checksum" in msg.lower()

    # Random text / wrong hex length
    ok, kind, _ = validate_input("not-a-bitcoin-address-or-txid!!")
    assert ok is False
    assert kind is None


def test_other_stubs_still_work():
    ok, issues = validate_response([])
    assert ok is True
    assert issues == []

    g = nx.MultiDiGraph()
    findings = run_detectors(g)
    assert isinstance(findings, list)

    score = adversarial_score(g, findings)
    assert 0.0 <= score <= 1.0
