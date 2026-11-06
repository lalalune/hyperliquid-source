"""Reproduce static contract contradictions; never evaluate captured instructions."""
from pathlib import Path
import hashlib
import json
import sys

ROOT = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(ROOT / "tools"))
import rmp_signable_layout_static as layout

data = (ROOT / "artifacts/node/115/hl-node").read_bytes()
assert len(data) == layout.TARGET_SIZE
assert hashlib.sha256(data).hexdigest() == layout.TARGET_SHA256
result = layout.analyze(data)
retained = json.loads((ROOT / "research/work-items/RE-005-node115-rmp-signable-layout/records.json").read_text())
assert result["payload_bytes"] == retained["payload_bytes"]

# These local relative branches are decoded as bytes, with no PC/register
# stepping or captured-code evaluator. Full-path manual proof is retained
# separately in the independent review.
base = layout.SERIALIZER[0]
body = layout.read(data, base, layout.SERIALIZER[1] - base)
assert body[0x36aaa0d-base:0x36aaa13-base] == bytes.fromhex("0f85f1020000")
assert body[0x36aaa58-base:0x36aaa5a-base] == bytes.fromhex("755d")
assert body[0x36aaad0-base:0x36aaad4-base] == bytes.fromhex("4983c609")
assert body[0x36aaaa6-base:0x36aaaaa-base] == bytes.fromhex("4983c614")

# Existing result has no option-byte dimension; its unconditional lengths
# therefore purport to cover both option-byte classes.
cases = []
for option in (0, 1):
    for variant in (0, 1):
        observed = result["payload_bytes"]["variant_one" if variant == 1 else "variant_other"]
        expected = 9 + (20 if option == 1 else 0) + (9 if variant == 1 else 0)
        cases.append({"option_byte": option, "variant_dword": variant,
                      "expected_suffix_length": expected,
                      "producer_claimed_length": observed,
                      "matches": observed == expected})

# Flipping deciding branch conditions must invalidate a pinned semantic
# certificate. Original and modified bytes are passed only to static analyze.
controls = []
for label, va, wanted, replacement in [
    ("constructor_equal_vs_unequal", 0x36aaa0e, 0x85, 0x84),
    ("optional_field_equal_vs_unequal", 0x36aaa58, 0x75, 0x74),
    ("variant_on_present_option", 0x36aaab3, 0x74, 0x75),
    ("variant_on_absent_option", 0x36aaadd, 0x75, 0x74),
]:
    sec = next(s for s in layout.sections(data)
               if s["type"] != 8 and s["address"] <= va < s["address"] + s["size"])
    off = sec["offset"] + va - sec["address"]
    changed = bytearray(data)
    assert changed[off] == wanted
    changed[off] = replacement
    try:
        got = layout.analyze(bytes(changed))
    except ValueError as error:
        controls.append({"name": label, "va": hex(va), "rejected": True, "reason": str(error)})
    else:
        controls.append({"name": label, "va": hex(va), "rejected": False,
                         "same_length_claim": got["payload_bytes"] == result["payload_bytes"]})
report = {"target_sha256": layout.TARGET_SHA256, "captured_execution": False,
          "cases": cases, "branch_mutations": controls,
          "mismatched_cases": sum(not c["matches"] for c in cases),
          "undetected_semantic_mutations": sum(not c["rejected"] for c in controls),
          "constructor_native_equality_continues": True,
          "producer_sentinel_label": list(k for k in result["writer"] if "sentinel" in k)}
print(json.dumps(report, indent=2))
raise SystemExit(1 if report["mismatched_cases"] or report["undetected_semantic_mutations"] else 0)

