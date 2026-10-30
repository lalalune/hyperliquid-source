#!/usr/bin/env python3
"""Verify the RE-009 packet: manifest, regenerated evidence, and pinned facts."""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
STATE_ROOTS_SHA256 = "1ac3af0abe3b12e44819f117d3288a2e7e7ae336934cb6927d566142bc8387a8"
SCHEMA_SHA256 = "ae0c6815914486fefb7092a697f3748c39caaad6131a6f93de339814c45429e4"
HASHERS_SHA256 = "1e7fbe921766315fb37f5c72227b24ba8ceb07822ad950de570b4553480855fa"


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


def main():
    for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
        digest, name = line.split("  ", 1)
        got = hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        check(got == digest, f"manifest mismatch for {name}")
    binary = (ROOT / "artifacts/node/94/hl-node").read_bytes()
    check(hashlib.sha256(binary).hexdigest() == BIN_SHA256, "binary sha256")
    sr = load("state_roots")
    r = sr.build(binary)
    text = sr.render(r)
    schema = sr.render(r["fixture_schema"])
    check(hashlib.sha256(text).hexdigest() == STATE_ROOTS_SHA256, "regenerated state-roots.json hash")
    check(hashlib.sha256(schema).hexdigest() == SCHEMA_SHA256, "regenerated fixture-schema.json hash")
    check((HERE / "state-roots.json").read_bytes() == text, "state-roots.json differs from tool output")
    check((HERE / "fixture-schema.json").read_bytes() == schema, "fixture-schema.json differs from tool output")
    d = json.loads(text)
    check(d["fde_count"] == 121299, "fde_count")
    check(d["first_party_location_count"] == 1186, "first_party_location_count")
    check(sum(d["scoped_location_counts"].values()) == 57, "scoped location total")
    check(d["scoped_location_counts"]["l1/src/abci/state.rs"] == 28, "state.rs locations")
    check(len(d["functions"]) == 57, "function count")
    check(sum(f["scoped"] for f in d["functions"]) == 46, "scoped function count")
    check(d["reconstruction_status_counts"] == {"fde_start_no_own_location": 3,
                                                "fde_start_with_own_location": 17}, "reconstruction statuses")
    check([x["site"] for x in d["dev_null_compares"]] == ["0x46ceaef", "0x46cff1f"], "/dev/null sites")
    lit = {x["text"]: x["functions"] for x in d["literals"]}
    check(lit["/CHECKPOINT_COMPLETE"] == ["0x15867a0", "0x28d1650", "0x332e0a0", "0x459a7f0"], "CHECKPOINT_COMPLETE owners")
    check(lit["/lt_hashes.json"] == ["0x32699c0", "0x3269ae0", "0x332d440"], "lt_hashes.json owners")
    check(lit["@@ linked abci state @@"] == ["0x2208e60", "0x446da60", "0x446e050"], "linked abci state owners")
    sh = load("state_hashers")
    h = sh.build(binary)
    htext = sh.render(h)
    check(hashlib.sha256(htext).hexdigest() == HASHERS_SHA256, "regenerated hashers.json hash")
    check((HERE / "hashers.json").read_bytes() == htext, "hashers.json differs from tool output")
    check(h["hasher_count"] == 29, "hasher_count")
    check(0x506CB20 not in [x["function"] for x in h["hashers"]],
          "0x506cb20 (mov [rdx+0x80],0 byte match, not a Keccak RC) must not be a hasher")
    check(h["hasher_with_first_party_location_count"] == 0, "hasher first-party count")
    check(h["edge_counts"] == {"rel32_edges": 495523, "slot_edges": 345767, "vtable_edges": 21027}, "edge counts")
    check(h["first_party_direct_hasher_caller_count"] == 108, "first-party hasher callers")
    c = next(p for p in h["paths"] if p["source"] == "0x3269ae0" and p["edge_kinds"] == ["rel32", "slot"])
    check([(x["site"], x["slot"], x["to"]) for x in c["chain"]] ==
          [(0x3269d96, 0x57700c8, 0x14f93e0)], "evm_db blake3 chain")
    c = next(p for p in h["paths"] if p["source"] == "all_scoped_db_state_functions"
             and p["edge_kinds"] == ["rel32", "slot"])
    check([(x["from"], x["site"], x["slot"], x["to"]) for x in c["chain"]] ==
          [(0x2208e60, 0x220925c, 0x57739f8, 0x394b410),
           (0x394b410, 0x394b4de, 0x57700c8, 0x14f93e0)], "state.rs blake3 chain")
    for src in ("0x332d440", "0x32699c0"):
        p = next(x for x in h["paths"] if x["source"] == src and x["edge_kinds"] == ["rel32", "slot"])
        check(p["exhausted"] and p["hit"] is None, f"{src} must not reach a hasher")
    check(h["re005_encoders"]["functions_calling_both"] == [], "RE-005 / hasher caller overlap")
    print("PASS: RE-009 packet verified (manifest, regenerated hashes, ownership + hashing facts)")


if __name__ == "__main__":
    main()
