#!/usr/bin/env python3
"""Verify the RE-009-db-code-table-94 packet.

Checks the manifest (hash + completeness against a pinned file set), the binary
digest, that the packet JSON byte-equals a fresh tool run with the pinned hash,
and the load-bearing decoded facts. Runs clean under -O (no asserts); every
failure prints one FAIL line and exits 1."""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
OUTPUT_SHA256 = "e84c625a02abde7376f07c0098799185601fe68723495b084ad997926d331f30"
MANIFEST_SELF = "MANIFEST.sha256"
# the packet is exactly these files (plus the manifest itself); a deleted or
# added file is a FAIL even if the manifest is edited to match.
PACKET_FILES = {"README.md", "db-code-table.json", "objdump-excerpts.txt", "verify.py"}
NAMES = ["Candle", "FundingLedgerUpdates", "NonFundingLedgerUpdates", "BoleInterest",
         "PortfolioSamples", "UserFills", "AssetTrades", "LegacyRewardHistory", "ExplorerUserTxs",
         "FundingHistory", "AssetCtxHistory", "OrderHistory", "UserTwapSliceFills", "TwapHistory",
         "UserPositionSamples", "UserAggregatedFills", "SpotEvents", "GovProposals", "DelegatorEvents",
         "DelegatorRewardHistory", "ValidatorBucketStats", "EvmTxs", "EvmBlockNumbers", "EvmBlocks",
         "EvmStateAccounts", "EvmStateContracts", "EvmStateStorage", "LegacyPortfolioSamples"]
TAGS = ["cA", "lu", "nf", "bi", "Ps", "uf", "aT", "rh", "et", "fH", "aH", "oh", "ts", "th",
        "up", "ua", "se", "gP", "de", "dr", "vb", "Et", "En", "Eb", "Ea", "Ec", "Es", "ps"]


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def check(cond, msg):
    if not cond:
        fail(msg)


def read_manifest():
    try:
        lines = (HERE / MANIFEST_SELF).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as e:
        fail(f"cannot read {MANIFEST_SELF}: {e}")
    listed = {}
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        digest, sep, name = line.partition("  ")
        if not sep or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest) or not name:
            fail(f"{MANIFEST_SELF} line {n} is not '<sha256>  <name>'")
        if name in listed:
            fail(f"{MANIFEST_SELF} lists {name} twice")
        listed[name] = digest
    return listed


def main():
    # 0. no subdirectories; the packet is a flat directory of files.
    for p in HERE.iterdir():
        if p.is_dir():
            fail(f"unexpected subdirectory in packet: {p.name}")

    # 1. manifest: every listed file hashes, and the manifest set equals the
    #    pinned packet file set and the files actually present.
    listed = read_manifest()
    for name, digest in listed.items():
        check((HERE / name).is_file(), f"manifest lists missing file {name}")
        got = hashlib.sha256((HERE / name).read_bytes()).hexdigest()
        check(got == digest, f"manifest mismatch for {name}")
    present = {p.name for p in HERE.iterdir() if p.is_file() and p.name != MANIFEST_SELF}
    check(set(listed) == PACKET_FILES,
          f"manifest set != pinned packet file set: "
          f"missing={sorted(PACKET_FILES - set(listed))} extra={sorted(set(listed) - PACKET_FILES)}")
    check(present == PACKET_FILES,
          f"present files != pinned packet file set: "
          f"missing={sorted(PACKET_FILES - present)} extra={sorted(present - PACKET_FILES)}")

    # 2. binary digest.
    try:
        binary = (ROOT / "artifacts/node/94/hl-node").read_bytes()
    except OSError as e:
        fail(f"cannot read the pinned binary: {e}")
    check(hashlib.sha256(binary).hexdigest() == BIN_SHA256, "binary sha256")

    # 3. regenerate the JSON and byte-compare.
    spec = importlib.util.spec_from_file_location("db_code_table", ROOT / "tools/db_code_table.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    try:
        text = m.render(m.build(binary))
    except m.EvidenceError as e:
        fail(f"tool refused the pinned binary: {e}")
    check(hashlib.sha256(text).hexdigest() == OUTPUT_SHA256, "regenerated db-code-table.json hash")
    check((HERE / "db-code-table.json").read_bytes() == text, "db-code-table.json differs from tool output")

    # 4. pinned facts.
    d = json.loads(text)
    check(d["binary_sha256"] == BIN_SHA256, "embedded binary sha256")
    check(d["elf_type"] == "ET_DYN (PIE)", "elf type")
    check(d["code_count"] == 28 and d["wrapper_count"] == 6, "code / wrapper count")
    check(d["tag_table_bases"] == ["0x56f1920", "0x572d7e0"], "tag table bases")
    check(d["name_formatters"] == ["0x35b67f0", "0x45c4a10"], "name formatters")
    check([row["tag"] for row in d["table"]] == TAGS, "28 tags")
    check([row["name"] for row in d["table"]] == NAMES, "28 names")

    # new relative to #245: names, path template + which codes reach it, bucket names
    p = d["path_build"]
    check((p["template_target"], p["template_bytes"], p["rendered_template"]) ==
          ("0x1dee9f", "04 64 68 73 2f c0 00", "dhs/{}"), "path template")
    check((p["argument_slots"], p["args_pairs"], p["arg_value_slot"]) == (1, 1, "rsp+0x7"),
          "path template arguments")
    check((p["format_fn_got"], p["format_fn"]) == ("0x576e040", "0x1344760"), "format call")
    check(p["built_for_codes"] == [21, 22, 23], "path built-for codes")
    check([row["code"] for row in d["table"] if row["path_built"]] == [21, 22, 23], "path_built rows")
    check(p["niche_when_skipped"] == "0x8000000000000000", "niche")
    check([(c["got_slot"], c.get("target_fn", c.get("import"))) for c in p["consumers"]] ==
          [("0x576ef10", "0x1402050"), ("0x576ef78", "0x14019b0"), ("0x576dfe0", "memcpy"),
           ("0x576e010", "0x54c8cb0")], "build-branch consumers")
    b = d["bucket_name_formatters"]
    check([(x["function"], x["formatter"], x["location"], x["names"]) for x in b] ==
          [("0x332eba0", "0x33dd5b0", "db/src/db_home.rs:83:13", ["Exchange", "Rpc", "EvmState"]),
           ("0x459b500", "0x45fb180", "db/src/db_home.rs:83:13", ["Exchange", "Rpc", "EvmState"])],
          "bucket-name formatters")
    check(d["bucket_names"] == {"0": "Exchange", "1": "Rpc", "2": "EvmState"}, "bucket names")
    check(d["bucket_display_fn"] == "0x1586ee0" and
          d["bucket_display_shape_candidates"] == ["0x1586ee0", "0x3818cf0"], "bucket Display (shape not unique)")

    # cross-checks with #245 (labels above; masks, home keys, gate, global, callers)
    check(d["masks"] == {"primary": "0x81ffeff", "aux": "0xe00100", "config_gate": "0x20ff01"}, "masks")
    check(len(d["home_mask_sites"]) == 12, "home mask site count")
    check(d["bucket_assignment"] == {"primary_bucket": 0, "aux_bucket": 1, "other_bucket": 2},
          "bucket assignment")
    check([row["home_bucket"] for row in d["table"]] ==
          [0] * 8 + [1] + [0] * 12 + [1, 1, 1, 2, 2, 2, 0], "home buckets")
    check(d["evm_family"] == {"base": 21, "threshold": 6}, "evm family test")
    check([row["code"] for row in d["table"] if row["is_evm_family"]] == [21, 22, 23, 24, 25, 26],
          "evm-family codes")
    g = d["config_gate"]
    check((g["got_slot"], g["global_base"], g["global_byte_offset"], g["global_byte_addr"]) ==
          ("0x576e928", "0x577b288", "0x48", "0x577b2d0"), "config-gate global")
    check((g["shift_bias"], g["shift_range"], g["shift_const"], g["shift_amount_expr"]) ==
          (246, 22, "0x20ff01", "global_byte - 10"), "config-gate immediates")
    check((g["code_lt_threshold"], g["code_le_threshold"], g["gate_sequence_hits_in_text"]) == (3, 2, 6),
          "config-gate code thresholds / sequence census")
    check(g["initializer_location_files"] == ["global_constants/src/static_config.rs:24:9"],
          "config-global initializer location")
    check(p["config_byte_suppressed_values"] == [10, 18, 19, 20, 21, 22, 23, 24, 25, 31],
          "config-byte suppressed values")
    callers = [(c["function"], c["call_site"], c["code"]) for c in d["static_callers"]]
    check(callers == [("0x3269ae0", "0x3269c5c", 24), ("0x3269ae0", "0x3269e77", 25),
                      ("0x3269ae0", "0x326a086", 26), ("0x47f1590", "0x47f2670", 23),
                      ("0x47f1590", "0x47f2682", 21), ("0x47f1590", "0x47f2697", 22)], "static callers")
    refs = d["references"]["wrappers"]
    check(all(len(r["call_rel32"]) == 1 and not (r["jmp_rel32"] or r["jcc_rel32"] or r["rip_relative"]
                                                  or r["rel8_branch"] or r["relocations"])
              and r["absolute_qword"] == 0 and r["absolute_dword"] == 0 for r in refs.values())
          and len(refs) == 6, "wrappers referenced only by one rel32 call each")
    check(all(t["file_occurrences"] == 2 and t["relative_relocs_into"] == 28 and t["code_references_into"] == 0
              for t in d["tag_blobs"]), "tag blobs")
    print("PASS: RE-009-db-code-table-94 packet verified (manifest, regenerated hash, decoded facts)")


if __name__ == "__main__":
    main()
