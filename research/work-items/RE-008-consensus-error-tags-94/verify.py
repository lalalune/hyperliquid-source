#!/usr/bin/env python3
"""Verify the RE-008 consensus error-tag packet: manifest (hashes + completeness),
regenerated evidence (hash + byte equality), the metrics block and the
load-bearing facts. Any failure, including a malformed manifest or a missing
file, prints one FAIL line and exits 1."""
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
OUTPUT_SHA256 = "98cb870229cc0c066c1112293bc5fb121b29bdde03e62ff923a54f9a4fe56cb0"
EXPECTED_METRICS = {
    "binary_wide_niche_movabs": [
        {"census_fde_count": 1, "fdes": 11471, "fdes_outside_census_count": 11470,
         "immediate": "0x8000000000000000"},
        {"census_fde_count": 3, "fdes": 13, "fdes_outside_census_count": 10, "immediate": "0x8000000000000028"},
        {"census_fde_count": 3, "fdes": 47, "fdes_outside_census_count": 44, "immediate": "0x800000000000002a"},
    ],
    "census": {
        "comparison_records": 37,
        "comparison_records_by_class": {"niche_0x00": 5, "niche_0x03": 1, "niche_0x2a": 31},
        "fdes": 7, "in_range_distinct_tags": 14,
        "in_range_records_by_dest_class": {"entry_rdi_copy": 15, "rsp": 16},
        "in_range_tag_store_addresses": 27, "in_range_tag_store_records": 31, "instructions": 5931,
        "movabs_sites_resolved": 55, "narrow_comparison_records": 0, "narrow_store_records": 0,
        "niche_0x00_store_records": 5, "niche_movabs_sites": 55, "out_of_range_niche_store_records": 2,
        "past_table_niche_store_records": 7, "raw_pattern_hits": 55,
        "raw_pattern_hits_at_instruction_starts": 55, "unresolved_site_count": 0,
    },
    "corrections": {
        "binary_variants": 42, "can1357_variants": 31, "disputed_token_occurrences": 3,
        "in_binary_not_in_can1357": 21, "in_can1357_not_in_binary": 10, "merged_lea_sites": 4,
        "merged_lea_sites_with_len_20": 4, "occurrences_spanning_two_tokens": 3,
        "strings_of_token_len_written_by_any_arm": 0,
    },
    "tag_table": {
        "copies": 3, "copies_whose_past_table_slot_leaves_fde_count": 2, "in_fde_runs": [47, 42, 42],
        "rows_agreeing_three_way": 42, "rows_whose_name_len_immediate_is_shared_by_copy": [2, 8, 8],
        "rows_with_one_shared_name_ptr": 5, "rows_with_per_copy_name_ptrs": 37, "tags": 42,
    },
    "variant_index_crosscheck": {"arms": 42, "explicit_index_calls": 11, "index_equals_tag": 11,
                                 "name_equals_table": 11},
}
MANIFEST_LINE = re.compile(r"^([0-9a-f]{64})  ([A-Za-z0-9._/-]+)$")


def fail(msg):
    print(f"FAIL: {msg}")
    sys.exit(1)


def check(cond, msg):
    if not cond:
        fail(msg)


def manifest():
    entries = {}
    for n, line in enumerate((HERE / "MANIFEST.sha256").read_text().splitlines(), 1):
        if not line.strip():
            continue
        m = MANIFEST_LINE.match(line)
        check(m is not None, f"malformed manifest line {n}: {line!r}")
        digest, name = m.groups()
        path = (HERE / name).resolve()
        check(HERE in path.parents and ".." not in Path(name).parts, f"manifest path outside packet: {name}")
        check(name not in entries, f"duplicate manifest entry {name}")
        check(path.is_file(), f"manifest file missing: {name}")
        check(hashlib.sha256(path.read_bytes()).hexdigest() == digest, f"manifest hash mismatch for {name}")
        entries[name] = digest
    on_disk = {p.relative_to(HERE).as_posix() for p in HERE.rglob("*")
               if p.name != "MANIFEST.sha256" and not p.is_dir()}
    check(on_disk == set(entries), f"manifest incomplete: {sorted(on_disk ^ set(entries))}")


def run():
    manifest()
    binary = (ROOT / "artifacts/node/94/hl-node").read_bytes()
    check(hashlib.sha256(binary).hexdigest() == BIN_SHA256, "binary sha256")

    spec = importlib.util.spec_from_file_location("cet", ROOT / "tools/consensus_error_tags.py")
    cet = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cet)
    text = cet.render(cet.build(binary))
    check(hashlib.sha256(text).hexdigest() == OUTPUT_SHA256, "regenerated JSON hash")
    check((HERE / "consensus-error-tags.json").read_bytes() == text, "JSON differs from tool output")
    d = json.loads(text)
    check(d["metrics"] == EXPECTED_METRICS, "metrics block differs from the pinned values")

    # --- tag table -------------------------------------------------------- #
    check(d["binary_sha256"] == BIN_SHA256, "embedded binary sha")
    check(d["tag_count"] == 42 and len(d["tags"]) == 42, "42 tags")
    check(d["name_table_three_way_agreement"] is True, "three-way agreement")
    for t in d["tags"]:
        check(t["name_agrees_three_way"] is True, f"tag {t['tag']} not agreed")
    expect = {
        0x00: ("Hardfork", 8), 0x01: ("SignableContentVerifySignature", 30),
        0x0c: ("BadBlockProposer", 16), 0x1a: ("ClientBlockUnexpectedCommitProof", 32),
        0x1c: ("ClientBlockMissingTx", 20), 0x1d: ("CommitProofChildQc", 18),
        0x27: ("TxInvalidBroadcasterNonce", 25), 0x28: ("MissingValidatorSetRound", 24),
        0x29: ("NetUtils", 8),
    }
    for k, (nm, ln) in expect.items():
        row = d["tags"][k]
        check(row["tag"] == f"{k:#x}" and row["variant"] == nm and row["name_len"] == ln, f"tag {k:#x} = {nm}/{ln}")
    check(d["tags"][0x13]["variant"] == "RpcPeer" and d["tags"][0x14]["variant"] == "NoClientBlocks",
          "RpcPeer/NoClientBlocks split")
    check(d["tags"][0x03]["field_keys"] == ["block_round", "last_commit_round"], "BadBlockRound fields")
    check({t["tag"] for t in d["tags"] if t["shared_name_ptr"]} == {"0x0", "0x8", "0xc", "0x1a", "0x29"},
          "five rows share one name pointer")

    # --- dispatch + bound ------------------------------------------------- #
    rule = d["dispatch_rule"]
    check(rule["identical_across_copies"] is True, "dispatch bytes identical across copies")
    check((rule["rcx_2pow63_bytes"], rule["select_bytes"], rule["tail_bytes"]) ==
          ("48b90000000000000080", "4831c14885c0b827000000480f48c1", "486304814801c8ffe0"), "dispatch bytes")
    check(rule["default_index"] == "0x27" and rule["default_index_row"] == "TxInvalidBroadcasterNonce",
          "default index 0x27")
    mons = d["formatter_monomorphs"]
    check([m["jump_table"] for m in mons] == ["0x6f9c44", "0x6f2af0", "0x3e23e8"], "jump tables")
    check([m["dispatch"]["word0"] for m in mons] == ["*rdi", "*rdi", "**rdi"], "word0 provenance")
    check(d["table_bound"]["copies_whose_past_table_slot_leaves_fde"] == ["0x244e3f0", "0x44c4480"],
          "two copies' 0x2a slot leaves FDE")
    check(mons[0]["entry_past_table"]["aliases_tags"] == ["0x29"], "copy 0x4753d60 slot 0x2a aliases 0x29")
    check(d["table_bound"]["past_table_niche_movabs_in_fde_0x47b01b0"] == ["0x47b01c9"], "0x..2a movabs site")
    x = d["variant_index_crosscheck"]
    check(all(r["index_equals_tag"] for r in x["explicit_index_calls"]), "explicit index == tag")
    check({r["container"] for r in x["explicit_index_calls"]} == {"Error"}, "explicit-index container string")

    # --- census ----------------------------------------------------------- #
    cen = {c["fde"]: c for c in d["census"]}
    check(list(cen) == ["0x47b01b0", "0x4758d70", "0x47594f0", "0x454aa10", "0x4b31e70", "0x44ab560",
                        "0x44adfa0"], "seven census FDEs")
    check(all(c["label"] == f"fde_{c['fde']}" for c in d["census"]), "neutral census labels")
    vsb = cen["0x47b01b0"]
    err = {(e["site"], e["variant_if_same_enum"]) for e in vsb["in_range_tag_stores"]}
    check(err == {("0x47b03a1", "BadBlockProposer"), ("0x47b03a1", "BadBlockQcRound"),
                  ("0x47b03a1", "BadBlockTcRound")}, "fde_0x47b01b0 shared store variants")
    check(vsb["base_immediate_histogram"] == {"low_byte_0x2a": 1}, "fde_0x47b01b0 base immediate")
    vtc = {(e["site"], e["variant_if_same_enum"]) for e in cen["0x47594f0"]["in_range_tag_stores"]}
    check(("0x4759677", "TcNoTimeout") in vtc and ("0x475972d", "TcNoTimeout") in vtc, "fde_0x47594f0 TcNoTimeout")
    psel = {e["variant_if_same_enum"] for e in cen["0x4b31e70"]["in_range_tag_stores"]}
    check(psel == {"EmptyValidators", "MissingValidatorSetRound"}, "fde_0x4b31e70 variants")

    # --- corrections ------------------------------------------------------ #
    cor = d["corrections"]
    dt = cor["merged_re008_disputed_token"]
    check(dt["is_single_variant_in_binary"] is False, "disputed token is not one variant")
    check((dt["real_token_a"]["name"], dt["real_token_a"]["tag"], dt["real_token_a"]["len"]) ==
          ("ClientBlockMissingTx", "0x1c", 20), "real token a")
    check((dt["real_token_b"]["name"], dt["real_token_b"]["tag"], dt["real_token_b"]["len"]) ==
          ("CommitProofChildQc", "0x1d", 18), "real token b")
    check(all(e["spans_two_tokens"] for e in dt["cross_token_evidence"]), "cross-token spans")
    check([e["len"] for e in dt["merged_lea_sites"]] == [20, 20, 20, 20], "merged lea sites pair with len 20")
    check("Hardfork" in cor["in_binary_not_in_can1357"], "Hardfork missing from can1357")
    check("RpcPeerNoClientBlocks" in cor["in_can1357_not_in_binary"], "can1357 fused RpcPeer")

    print("PASS: RE-008 consensus error-tag packet verified "
          "(manifest, regenerated hash + byte equality, metrics, tag table, dispatch, bound, census, corrections)")


def main():
    try:
        run()
    except SystemExit:
        raise
    except Exception as e:  # malformed input or missing files -> FAIL, not a traceback
        fail(f"{type(e).__name__}: {e}")


if __name__ == "__main__":
    main()
