"""
CryptoTrace - Security Layer (P3)
Step 1: Stubs returning valid dummy output in the agreed contract format.
"""


def validate_input(text: str) -> tuple[bool, str | None, str]:
    """
    Validate user input (Bitcoin address or transaction ID).
    Returns: (ok, "address" | "txid" | None, message)
    """
    if not text or not isinstance(text, str):
        return (False, None, "Input cannot be empty")
    return (True, "address", "Valid input (stub)")


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
