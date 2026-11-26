#!/usr/bin/env python3
"""Reproduce the synthetic tag-5 request encoding and its target-derived digest."""

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def load_sponge_model():
    source = ROOT / "tools/evm_keccak_ripemd_115.py"
    spec = importlib.util.spec_from_file_location("node115_sponge", source)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load target-derived sponge model")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main():
    vector = json.loads((PACKET / "synthetic-vector.json").read_text())
    if vector["target_sha256"] != TARGET_SHA256:
        raise ValueError("vector target digest mismatch")

    fields = vector["input"]
    value0 = bytes.fromhex(fields["bytes20_0_hex"])
    value1 = bytes.fromhex(fields["bytes20_1_hex"])
    if len(value0) != 20 or len(value1) != 20:
        raise ValueError("fixed-width input length")
    label = fields["label_ascii"].encode("ascii")
    if label != b"requestWithdrawal":
        raise ValueError("label mismatch")

    def word(value):
        return value.to_bytes(32, "big")

    encoded = (
        bytes(12) + value0
        + bytes(12) + value1
        + word(int(fields["u64_0"], 16))
        + word(int(fields["u64_1"], 16))
        + word(160)
        + word(len(label))
        + label + bytes(32 - len(label))
    )
    if len(encoded) != vector["encoded_length"] or len(encoded) != 224:
        raise ValueError("encoded length mismatch")
    encoded_digest = hashlib.sha256(encoded).hexdigest()
    if encoded_digest != vector["encoded_sha256"]:
        raise ValueError("encoded input digest mismatch")

    model = load_sponge_model()
    binary = model.Binary()
    if hashlib.sha256(binary.image.blob).hexdigest() != TARGET_SHA256:
        raise ValueError("target binary digest mismatch")
    digest = model.keccak256_model(encoded, binary.rc_table()).hex()
    if digest != vector["keccak256"]:
        raise ValueError("Keccak-256 vector mismatch")
    reference = subprocess.run(
        ["openssl", "dgst", "-KECCAK-256"],
        input=encoded,
        capture_output=True,
        check=True,
    ).stdout.decode("ascii").strip().rsplit("= ", 1)[-1]
    if reference != digest:
        raise ValueError("OpenSSL KECCAK-256 reference mismatch")
    print(json.dumps({
        "encoded_length": len(encoded),
        "encoded_sha256": encoded_digest,
        "keccak256": digest,
        "openssl_keccak256": reference,
        "target_sha256": TARGET_SHA256,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
