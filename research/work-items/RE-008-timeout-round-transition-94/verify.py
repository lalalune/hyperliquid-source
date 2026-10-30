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


def main():
    manifest = HERE / "MANIFEST.sha256"
    check(manifest.exists(), "missing MANIFEST.sha256")
    for line in manifest.read_text().splitlines():
        digest, name = line.split("  ", 1)
        check(hashlib.sha256((HERE / name).read_bytes()).hexdigest() == digest,
              f"manifest mismatch for {name}")

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
