#!/usr/bin/env python3
"""Verify the RE-014 packet: manifest, regenerated evidence, and pinned facts.

Run from anywhere:  python3 -I -B research/work-items/RE-014-action-dispatch-drift/verify.py
Uses explicit checks (no assert), so it is also valid under python -O. Every failure, including a
malformed or missing manifest, an entry in the packet directory that is not a regular file, or a
missing or failing tool module, prints FAIL and exits with status 1.
"""
import hashlib
import importlib.util
import json
import re
import stat
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN94_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
BIN115_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
OUTPUT_SHA256 = "fc00a6b751588761dbca7d4cbc2e887e815d912442a2a3d48ec15c802fa6a75d"
JSON_NAME = "action-dispatch-drift.json"
MANIFEST_LINE = re.compile(r"([0-9a-f]{64})  ([A-Za-z0-9._-]+)\Z")


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def check(cond, msg):
    if not cond:
        fail(msg)


def read(path):
    try:
        return path.read_bytes()
    except OSError as e:
        fail(f"cannot read {path}: {e}")


def load(name):
    try:
        spec = importlib.util.spec_from_file_location(name, ROOT / f"tools/{name}.py")
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
    except Exception as e:      # noqa: BLE001 - any import failure (missing file, missing helper) must FAIL
        fail(f"cannot load tools/{name}.py: {type(e).__name__}: {e}")
    return m


def check_manifest():
    listed = {}
    for n, line in enumerate(read(HERE / "MANIFEST.sha256").decode("utf-8", "replace").splitlines(), 1):
        m = MANIFEST_LINE.match(line)
        check(m is not None, f"MANIFEST.sha256 line {n} is malformed")
        digest, name = m.groups()
        check(name not in listed, f"MANIFEST.sha256 lists {name} twice")
        check(name != "MANIFEST.sha256", "MANIFEST.sha256 lists itself")
        listed[name] = digest
        check(hashlib.sha256(read(HERE / name)).hexdigest() == digest, f"manifest mismatch for {name}")
    entries = sorted(HERE.iterdir())
    odd = [p.name for p in entries if not stat.S_ISREG(p.lstat().st_mode)]
    check(not odd, f"packet entries {odd} are not regular files")
    present = {p.name for p in entries if p.name != "MANIFEST.sha256"}
    check(present == set(listed), f"packet files {sorted(present ^ set(listed))} not matched by MANIFEST")


def main():
    check_manifest()
    b94 = read(ROOT / "artifacts/node/94/hl-node")
    b115 = read(ROOT / "artifacts/node/115/hl-node")
    check(hashlib.sha256(b94).hexdigest() == BIN94_SHA256, "node #94 binary sha256")
    check(hashlib.sha256(b115).hexdigest() == BIN115_SHA256, "node #115 binary sha256")
    ad = load("action_dispatch_drift")
    try:
        text = ad.render(ad.build(b94, b115))
    except Exception as e:      # noqa: BLE001 - EvidenceError (fail closed) or any other error must FAIL
        fail(f"tool failed: {type(e).__name__}: {e}")
    check(hashlib.sha256(text).hexdigest() == OUTPUT_SHA256, "regenerated JSON hash")
    check(read(HERE / JSON_NAME) == text, f"{JSON_NAME} differs from tool output")
    d = json.loads(text)
    t94, t115 = d["targets"]["94"], d["targets"]["115"]
    check((t94["fde_count"], t115["fde_count"]) == (121299, 135313), "FDE counts")
    check((t94["variants"]["count"], t115["variants"]["count"]) == (88, 92), "VARIANTS counts")
    check([c["start"] for c in t94["variants"]["copies"]] == ["0x56c46e0", "0x56e8bd0", "0x5733130"], "#94 copies")
    check([c["start"] for c in t115["variants"]["copies"]] == ["0x644cc40", "0x6467f98", "0x649bac8"], "#115 copies")
    check({c["bound_text"] for c in t94["variants"]["copies"]} == {"variant index 0 <= i < 88"}, "#94 bound")
    check({c["bound_text"] for c in t115["variants"]["copies"]} == {"variant index 0 <= i < 92"}, "#115 bound")
    check(len(t94["variants"]["slots_with_ptr_shared_by_all_copies"]) == 15
          and len(t115["variants"]["slots_with_ptr_shared_by_all_copies"]) == 15, "shared VARIANTS pointers")
    check(sorted(s["function"] for s in t94["serializers"]) ==
          ["0x281e850", "0x2821000", "0x2823450", "0x2825c00", "0x334cfa0", "0x334f770", "0x3351bc0",
           "0x48e3b50", "0x48e5fa0", "0x48e8750", "0x48eaf00"], "#94 serializers")
    check(sorted(s["function"] for s in t115["serializers"]) ==
          ["0x2bc95f0", "0x2bcbbf0", "0x2bce570", "0x2bd0ef0", "0x36aef70", "0x36b1600", "0x36b3f80",
           "0x4d81e00", "0x4d84400", "0x4d86d80", "0x4d89700"], "#115 serializers")
    for t in (t94, t115):
        check(t["census"]["tables"]["serializers_equal_idiom_serializers"], "serializer census")
    check((t94["census"]["sentinel"]["occurrences"], t94["census"]["sentinel"]["before_tag_load_and_idiom"],
           t115["census"]["sentinel"]["occurrences"], t115["census"]["sentinel"]["before_tag_load_and_idiom"])
          == (12, 3, 15, 6), "sentinel census")
    check([(i["start"], i["table"]) for i in t94["execute_instances"]] ==
          [("0x2759240", "0x3ede28"), ("0x4d83050", "0x712dfc"), ("0x4d84170", "0x712f5c")], "#94 instances")
    check([(i["start"], i["table"]) for i in t115["execute_instances"]] ==
          [("0x2bdbaa0", "0x60a360"), ("0x55f99b0", "0x927b08"), ("0x55faa80", "0x927c78")], "#115 instances")
    check(t94["sentinel_other_base_instances"] == [], "#94 has no [r15] family")
    check([(i["start"], i["table"], i["tag_base"]) for i in t115["sentinel_other_base_instances"]] ==
          [("0x2bda7c0", "0x609f00", "r15"), ("0x54a2f90", "0x92671c", "r15"), ("0x54a3a00", "0x92688c", "r15")],
          "#115 [r15] family")
    check([i["unresolved_indices"] for t in (t94, t115) for i in t["execute_instances"]] == [[]] * 6,
          "unresolved arms")
    check([i["extended_decoder_indices"] for i in t115["execute_instances"]] == [[], [52], [52]],
          "extended-decoder arms")
    rel = t115["sentinel_other_base_relation"]
    check([r["arms_whose_handler_transfers_to_same_index_execute_handler"] for r in rel] == [57, 60, 60]
          and [r["arms_whose_handler_transfers_to_same_index_execute_handler_rel32_only"] for r in rel] == [54, 57, 57]
          and [r["arms_whose_handler_transfers_to_other_index_execute_handler"] for r in rel] == [[], [], []],
          "[r15] to execute handler relation")
    c94, c115 = t94["idiom_site_counts"], t115["idiom_site_counts"]
    check((c94["bias_block_occurrences"], c115["bias_block_occurrences"]) == (59, 68), "idiom occurrences")
    check((c94["cmov:cmovae"], c94["cmov:cmovb"], c115["cmov:cmovae"], c115["cmov:cmovb"]) == (51, 8, 56, 12),
          "idiom occurrences per cmov")
    check((c94["bias_block_occurrences_dispatcher_register_form"],
           c115["bias_block_occurrences_dispatcher_register_form"]) == (34, 26), "idiom occurrences, dispatcher form")
    check((c94["role:no_table"], c115["role:no_table"]) == (4, 6), "idiom sites without a jump table")
    check((c94["shape:after_bounds_check"], c115["shape:after_bounds_check"]) == (22, 24), "bounded idiom tables")
    check((c94["role:other"], c115["role:other"]) == (41, 45), "idiom tables classed other")
    de94, de115 = t94["idiom_default_elsewhere"], t115["idiom_default_elsewhere"]
    check((de94["count"], de94["cmov_counts"], de115["count"], de115["cmov_counts"])
          == (10, {"cmovb": 10}, 14, {"cmovb": 14}), "default-elsewhere sites")
    h94, h115 = t94["handler_distinctness"]["execute"], t115["handler_distinctness"]["execute"]
    check((h94["arms_with_pairwise_distinct_handlers"], h94["arms_resolved_in_all_instances"],
           h115["arms_with_pairwise_distinct_handlers"], h115["arms_resolved_in_all_instances"]) == (84, 87, 88, 91),
          "handler distinctness")
    check((t94["instance_size_spread"]["arms_with_differing_instance_sizes"],
           t115["instance_size_spread"]["arms_with_differing_instance_sizes"]) == (23, 29), "instance size spread")
    c = d["variant_join_counts"]
    check((c["common"], c["same_index"], c["shifted"], c["removed"], c["added"]) == (86, 46, 40, 2, 6), "join counts")
    check(c["shift_histogram"] == {"+1": 25, "-1": 15}, "shift histogram")
    rows = {x["name"]: x for x in d["variant_join"]}
    check([n for n, x in rows.items() if x["class"] == "removed"] ==
          ["voteAppHash", "SystemAlignedQuoteSupplyDeltaAction"], "removed names")
    check([(n, x["index_115"]) for n, x in rows.items() if x["class"] == "added"] ==
          [("validatorL1Status", 23), ("voteAbciDigest", 87), ("activateOutcomeDeployer", 88),
           ("trailingStop", 89), ("outcomeDeploy", 90), ("cDeposit2", 91)], "added names")
    check(rows["cDeposit2"]["via_115"] == ["shared_arm_tail"] * 3
          and rows["cDeposit2"]["handlers_115"] == rows["cDeposit"]["handlers_115"], "cDeposit2 shared tail")
    check(rows["multiSig"]["handlers_115"] == ["0x2bdbaa0", "0x55f99b0", "0x55faa80"]
          and rows["multiSig"]["handlers_94"][0] == "0x282ee50", "multiSig first calls")
    holds94 = {a["path"] for a in t94["anchors"] if a["holds_all_instances"]}
    holds115 = {a["path"] for a in t115["anchors"] if a["holds_all_instances"]}
    check(holds94 == {"l1/action/c_deposit.rs", "l1/action/evm_raw_tx.rs", "l1/action/vault_transfer.rs",
                      "l1/action/withdraw3.rs"}, "#94 anchors")
    check(holds115 == {"l1/action/user_outcome.rs", "l1/action/vault_transfer.rs", "l1/action/withdraw3.rs",
                       "l1/exchange/impl_outcome_deploy.rs"}, "#115 anchors")
    quals = {q["path"]: q for q in d["catalogue_paths"]}
    check({p: q["qualification"] for p, q in quals.items()} == {
        "l1/action/c_deposit.rs": "absent_path_surviving_variant",
        "l1/action/evm_raw_tx.rs": "absent_path_surviving_variant",
        "l1/action/user_outcome.rs": "added_path_existing_variant",
        "l1/exchange/impl_outcome_deploy.rs": "added_path_new_variant"}, "catalogue qualifications")
    check(quals["l1/exchange/impl_outcome_deploy.rs"]["owner_callers_outside_execute_family"] ==
          ["0x2913750", "0x50d3530", "0x50d3f40"], "impl_outcome_deploy.rs owner callers")
    x = d["re010_crosscheck"]
    check((x["cases_compared"], x["mismatched_indices"]) == (88, []), "RE-010 re-derivation")
    pr226 = "open PR #226 (head ad161cb7dde4e9e6246f831e5fba4c90c8600dee"
    check(all(pr226 in n for n in (x["unclaimed_cases_note"], x["label_counts_note"], d["contribution_note"]))
          and "inference I2" in c["arm_to_name_binding"], "framing notes (#226 overlap, I2 binding)")
    check((x["label_counts"]["wire_type_equals_serde_name"], x["label_counts"]["wire_type_differs"],
           x["label_counts"]["wire_type_differs_but_equals_rust_ident"]) == (51, 25, 20), "label counts")
    dr = d["location_drift_reach"]
    check((dr["absent115"]["path_count"], dr["absent115"]["reached"],
           dr["added115"]["path_count"], dr["added115"]["reached"]) == (24, 6, 35, 7), "drift reach counts")
    s = d["handler_size_ratios"]
    check((s["usable_pairs"], s["within_band"], s["within_band_range"]) == (84, 60, [54, 60]), "size ratio counts")
    print("PASS: RE-014 packet verified (manifest, regenerated JSON", OUTPUT_SHA256[:12] + ",",
          "VARIANTS/serializer/dispatcher/anchor facts)")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:      # noqa: BLE001 - e.g. a missing JSON field: still FAIL, never a bare traceback
        fail(f"unexpected {type(e).__name__}: {e}")
