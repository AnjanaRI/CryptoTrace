"""
CryptoTrace - Security Layer (P3)
Step 2: Full input validation (64-hex txid, bech32 address regex, legacy base58 checksum)
plus stubs for validate_response, run_detectors, and adversarial_score.
"""

import re
import base58

# 64 hexadecimal characters = Bitcoin transaction ID (txid)
_TXID_RE = re.compile(r"^[0-9a-fA-F]{64}$")

# Bech32 / Bech32m address regex (mainnet bc1 or testnet tb1)
# Bech32 data-part alphabet: qpzry9x8gf2tvdw0s3jn54khce6mua7l (no 1, b, i, o)
# Standard SegWit v0 P2WPKH is 42 chars ("bc1q" + 38 chars), P2WSH / Taproot up to 62 chars;
# Bech32 spec allows up to 90 chars total.
_BECH32_RE = re.compile(
    r"^(?:bc1|tb1)[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{25,87}$",
    re.IGNORECASE,
)

# Legacy Base58 address prefixes (1, 3 for mainnet; m, n, 2 for testnet)
_BASE58_CHARS_RE = re.compile(r"^[123mn][1-9A-HJ-NP-Za-km-z]{24,34}$")


def validate_input(text: str) -> tuple[bool, str | None, str]:
    """
    Validate user input (Bitcoin address or transaction ID).
    Rules (from P3_Security_Prompts.md Step 2 & PROJECT_CONTEXT.md):
    - 64 hex characters -> (True, "txid", ...)
    - Bech32-style address by regex -> (True, "address", ...)
    - Legacy address by base58 checksum using base58 library -> (True, "address", ...)
    - Anything else is rejected with (False, None, "<simple message>")
    """
    if not isinstance(text, str):
        return (False, None, "Input must be a text string.")

    cleaned = text.strip()
    if not cleaned:
        return (False, None, "Input cannot be empty. Please paste a Bitcoin address or txid.")

    if len(cleaned) > 100:
        return (False, None, "Input is too long to be a valid Bitcoin address or transaction ID.")

    # 1. Check 64-character hex txid
    if _TXID_RE.match(cleaned):
        return (True, "txid", "Valid Bitcoin transaction ID (txid).")

    # 2. Check Bech32 address (bc1... or tb1...)
    # Note: Bech32 addresses must not mix upper and lower case
    if cleaned.lower().startswith(("bc1", "tb1")):
        if cleaned != cleaned.lower() and cleaned != cleaned.upper():
            return (False, None, "Invalid Bech32 address: cannot mix uppercase and lowercase.")
        if _BECH32_RE.match(cleaned):
            return (True, "address", "Valid Bech32 Bitcoin address.")
        return (False, None, "Invalid Bech32 Bitcoin address format.")

    # 3. Check Legacy Base58Check address (starts with 1, 3, m, n, or 2)
    if _BASE58_CHARS_RE.match(cleaned):
        try:
            decoded = base58.b58decode_check(cleaned)
            # Standard Bitcoin Base58Check payload is 1 version byte + 20-byte hash = 21 bytes
            if len(decoded) == 21:
                return (True, "address", "Valid Base58 Bitcoin address.")
            return (False, None, "Invalid Base58 address payload length.")
        except Exception:
            return (False, None, "Invalid Bitcoin address: Base58 checksum verification failed.")

    return (
        False,
        None,
        "Invalid input. Expected a 64-character hex txid or a valid Bitcoin address.",
    )


def validate_response(
    txs: list[dict], second_source: list[dict] | None = None
) -> tuple[bool, list[str]]:
    """
    Validate API transaction responses and optional second-source cross-check.
    Returns: (ok, issues)
    """
    return (True, [])


def run_detectors(graph) -> list[dict]:
    """
    Run adversarial detectors on the transaction graph:
    DUSTING, LOOKALIKE, DECOY.
    Returns a list of finding dicts matching the contract:
    {"type": ..., "severity": "low"|"medium"|"high", "text": ..., "nodes": [...]}
    """
    return [
        {
            "type": "DUSTING",
            "severity": "medium",
            "text": "15 outputs of 546 sats (stub)",
            "nodes": [],
        }
    ]


def adversarial_score(graph, findings: list[dict]) -> float:
    """
    Calculate the adversarial risk component in the range 0..1.
    """
    return 0.3
