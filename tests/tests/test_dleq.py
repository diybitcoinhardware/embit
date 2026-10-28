"""BIP-374 DLEQ proof test vectors."""

import csv
from binascii import unhexlify
from pathlib import Path

import pytest

import embit.silent_payments.dleq as dleq

DATA_DIR = Path(__file__).parent / "data"
GENERATE_CSV = DATA_DIR / "test_vectors_generate_proof.csv"
VERIFY_CSV = DATA_DIR / "test_vectors_verify_proof.csv"

# x=0 is not on secp256k1; test vectors use this as an infinity stand-in
INFINITY_SEC = b"\x02" + b"\x00" * 32


def _load_csv(path: Path) -> list[dict[str, str]]:
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


def _point_from_hex(hex_str: str) -> bytes:
    return INFINITY_SEC if hex_str == "INFINITY" else unhexlify(hex_str)


def _message_from_row(row: dict[str, str]) -> bytes | None:
    msg = row.get("message", "")
    return unhexlify(msg) if msg else None


def _vector_id(row: dict[str, str]) -> str:
    return f"{row['index']}-{row['comment']}"


@pytest.mark.parametrize("row", _load_csv(GENERATE_CSV), ids=_vector_id)
def test_generate_proof_vectors(row: dict[str, str]) -> None:
    """Official BIP-374 generate-proof vectors."""
    G = unhexlify(row["point_G"])
    a = unhexlify(row["scalar_a"])
    r = unhexlify(row["auxrand_r"])
    B = _point_from_hex(row["point_B"])
    m = _message_from_row(row)
    expected = row["result_proof"]

    if expected == "INVALID":
        with pytest.raises(dleq.DLEQError):
            dleq.generate_dleq_proof(a, B, r=r, m=m, G=G)
    else:
        proof = dleq.generate_dleq_proof(a, B, r=r, m=m, G=G)
        assert proof == unhexlify(expected)


@pytest.mark.parametrize("row", _load_csv(VERIFY_CSV), ids=_vector_id)
def test_verify_proof_vectors(row: dict[str, str]) -> None:
    """Official BIP-374 verify-proof vectors."""
    G = unhexlify(row["point_G"])
    A = unhexlify(row["point_A"])
    B = unhexlify(row["point_B"])
    C = unhexlify(row["point_C"])
    proof = unhexlify(row["proof"])
    m = _message_from_row(row)
    expected_success = row["result_success"] == "TRUE"

    result = dleq.verify_dleq_proof(A, B, C, proof, m=m, G=G)
    assert result is expected_success
