#!/usr/bin/env python3
"""Fail-closed verifier for the RE-008 timeout/round packet."""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BINARY_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
EVIDENCE_SHA256 = "59a0302ec33323c1825295b59386cafe1f1817b0a8303ac2285f9535718b5ba7"


def fail(message):
    print(f"FAIL: {message}")
    raise SystemExit(1)


def check(condition, message):
    if not condition:
        fail(message)


def load_tool():
    spec = importlib.util.spec_from_file_location(
        "timeout_round_transition", ROOT / "tools/timeout_round_transition.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# The manifest pins every packet file except MANIFEST.sha256 itself.
PACKET_FILES = frozenset({
    "README.md", "VALIDATION.md", "bounded-disassembly.txt",
    "timeout-round-transition.json", "verify.py",
})


def check_packet():
    # The manifest loop this replaces hashed the listed files and
    # nothing else: a duplicated row passed silently, a listed file
    # replaced by a symlink was hashed through to its target, and
    # files could be added to — or deleted from — the packet unseen
    # as long as the JSON stayed intact. Enforce the admission the
    # RE-005 verifier and the node-inventory verifiers spell out.
    manifest = HERE / "MANIFEST.sha256"
    check(manifest.is_file(), "missing MANIFEST.sha256")
    listed = {}
    for line in manifest.read_text().splitlines():
        if not line.strip():
            continue
        digest, sep, name = line.partition("  ")
        check(sep == "  " and len(digest) == 64, f"malformed manifest line: {line!r}")
        check(name not in listed, f"manifest lists {name} twice")
        listed[name] = digest
    check(set(listed) == PACKET_FILES, "manifest file set differs from pinned packet files")
    present = set()
    for entry in sorted(HERE.iterdir()):
        check(not entry.is_symlink(), f"packet entry is a symlink: {entry.name}")
        if entry.is_dir():
            check(entry.name == "__pycache__" and all(
                child.name.endswith(".pyc") and not child.is_symlink()
                for child in entry.iterdir()),
                f"unexpected directory in packet: {entry.name}")
            continue
        present.add(entry.name)
    check(present - {"MANIFEST.sha256"} == set(listed), "packet contents differ from manifest")
    for name, digest in listed.items():
        path = HERE / name
        check(path.is_file() and not path.is_symlink(),
              f"manifest entry is a symlink or not a file: {name}")
        check(hashlib.sha256(path.read_bytes()).hexdigest() == digest,
              f"manifest mismatch for {name}")


def main():
    check_packet()

    binary = (ROOT / "artifacts/node/94/hl-node").read_bytes()
    check(hashlib.sha256(binary).hexdigest() == BINARY_SHA256, "binary sha256")
    tool = load_tool()
    rendered = tool.render(tool.build(binary))
    check(hashlib.sha256(rendered).hexdigest() == EVIDENCE_SHA256,
          "regenerated evidence hash")
    check((HERE / "timeout-round-transition.json").read_bytes() == rendered,
          "stored JSON differs from collector")

    evidence = json.loads(rendered)
    check(len(evidence["bounded_cfg_blocks"]) == 39, "bounded block count")
    calls = {item["name"]: item for item in evidence["calls"]}
    check(calls["direct_tc_verify"]["target"] == "0x47594f0", "direct TC verifier")
    check(calls["timeout_verify"]["target"] == "0x454aa10", "timeout verifier")
    check(calls["direct_tc_round_transition"]["target"] == "0x44b6670",
          "direct TC round call")
    check(calls["quorum_round_transition"]["target"] == "0x44b6670",
          "quorum round call")
    check(calls["tc_quorum_predicate"]["slot"] == "0x5776ae8", "TC quorum slot")

    transition = evidence["proven_transition"]
    check(transition["write_site"] == "0x44b66b8", "round write site")
    check(transition["stale_branch_site"] == "0x44b66a5", "stale branch site")
    check(transition["callers"] == ["0x44b17cf", "0x44b2629"], "round callers")

    branches = {item["case"]: item for item in evidence["branch_table"]}
    check(branches["individual timeout duplicate"]["caller_state_write_before_outcome"] is False,
          "duplicate mutation ordering")
    check(branches["individual timeout signature rejection"]["caller_state_write_before_outcome"] is False,
          "signature-rejection mutation ordering")
    check(branches["individual timeout strict quorum"]["predicate"] ==
          "2*total < 3*signed_weight", "strict quorum predicate")
    check("no separate membership rejection" in
          branches["validator key absent from stake tree"]["outcome"],
          "invalid-validator limitation")
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
