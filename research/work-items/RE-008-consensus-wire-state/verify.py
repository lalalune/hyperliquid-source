#!/usr/bin/env python3
"""Verify the RE-008 packet: manifest, regenerated evidence, and pinned facts."""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
WIRE_SHA256 = "c3be6de771cf5856b5e36560f3ac93d13168f78e7991870b7b870fef4ad3dd3a"


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def check(cond, msg):
    if not cond:
        fail(msg)


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"tools/{name}.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


PACKET_FILES = frozenset({
    "README.md", "consensus-wire.json", "objdump-excerpts.txt", "verify.py",
})


def main():
    listed = set()
    for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
        digest, name = line.split("  ", 1)
        got = hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        check(got == digest, f"manifest mismatch for {name}")
        listed.add(name)
    # The manifest pins every packet file except itself (README). Comparing
    # it only against the directory is not enough: a file deleted together
    # with its manifest row leaves the two sets equal. So the listed set
    # must also equal the packet's pinned file set, and the directory must
    # not hold unlisted files.
    check(listed == PACKET_FILES, f"manifest file set differs from the pinned packet files: "
          f"missing rows {sorted(PACKET_FILES - listed)}, unexpected rows {sorted(listed - PACKET_FILES)}")
    present = {p.name for p in HERE.iterdir() if p.is_file()} - {"MANIFEST.sha256"}
    check(listed == present, f"manifest file set differs from packet contents: "
          f"unlisted {sorted(present - listed)}, missing {sorted(listed - present)}")
    binary = (ROOT / "artifacts/node/94/hl-node").read_bytes()
    check(hashlib.sha256(binary).hexdigest() == BIN_SHA256, "binary sha256")
    cw = load("consensus_wire")
    r = cw.build(binary)
    text = cw.render(r)
    check(hashlib.sha256(text).hexdigest() == WIRE_SHA256, "regenerated consensus-wire.json hash")
    check((HERE / "consensus-wire.json").read_bytes() == text, "consensus-wire.json differs from tool output")
    d = json.loads(text)
    check(d["fde_count"] == 121299, "fde_count")
    check(d["first_party_location_count"] == 1186, "first_party_location_count")
    check(d["scoped_location_counts"] == {
        "node/src/consensus/signed.rs": 1,
        "node/src/consensus/state.rs": 11,
        "node/src/consensus/types.rs": 1,
    }, "scoped_location_counts")
    check(sum(1 for f in d["functions"] if f["scoped"]) == 8, "scoped function count")
    check(len(d["tags"]) == 24, "tag count")
    check(d["reconstruction_status_counts"] == {
        "fde_start_no_own_location": 13,
        "fde_start_with_own_location": 7,
        "inside_fde": 12,
    }, "reconstruction statuses")
    seeds = {s["name"]: s for s in d["seeds"]}
    check(seeds["signed_verify_signed_block"]["fde_start"] is True, "vsb fde")
    check(seeds["signed_verify_qc"]["fde_start"] is True, "vqc fde")
    check(seeds["types_Timeout_ser_a"]["fde_start"] is False, "timeout ser not fde")
    edges = {(e["from"], e["to"], e["kind"]) for e in d["signature_map"]["cross_verifier_edges"]}
    check(edges == {
        ("verify_signed_block", "0x4758d70", "rel32"),
        ("verify_signed_block", "0x47594f0", "rel32"),
        ("verify_signed_timeout", "0x4758d70", "rel32"),
        ("verify_tc", "0x454aa10", "rel32"),
    }, "cross-verifier edges")
    check(d["signature_map"]["proposer_mismatch_template_owner"] == ["0x47b01b0"], "proposer owner")
    q = d["quorum"]
    check(q["function"] == "0x4ad90d0", "quorum function")
    check(q["instruction_starts"] == {
        "add_rcx_rcx": "0x4ad961d",
        "cmp_rcx_rax": "0x4ad9620",
        "mov_edx_3": "0x4ad9612",
        "mov_rax_r10": "0x4ad9617",
        "mul_rdx": "0x4ad961a",
        "sbb_rsi_rdx": "0x4ad9623",
        "setb_al": "0x4ad9626",
    }, "quorum instruction starts")
    check(q["verify_qc_call"] == {
        "kind": "slot", "site": "0x47590ca", "slot": "0x5776ae8", "to": "0x4ad90d0",
    }, "verify_qc quorum call")
    check(q["instruction_bytes"]["0x4ad9612"] == "ba03000000", "mov edx,3 bytes")
    check(q["instruction_bytes"]["0x4ad9626"] == "0f92c0", "setb al bytes")
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
