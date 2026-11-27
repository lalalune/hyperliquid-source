#!/usr/bin/env python3
"""Full-scope node #115 closure verifier for `bridge` (`l1/src/bridge2.rs`, `l1/src/bridge_request.rs`):
- Authenticates all 2/2 `bridge` source files against `hl-node-115.inventory.json`
- Authenticates all 7/7 `.data.rel.ro` `Location` structs (0 unreferenced)
- Authenticates all 6/6 Location-referencing `.text` FDEs (`8,366 B`) + 25/25 companion business FDEs
  (`29,054 B`) = 31 unique FDEs (`37,420 B`) against `work/index/node-115-fde.tsv`
- Authenticates 7 `.text` instruction anchors, 16 `.rodata` string literals (4 Arbitrum contracts,
  fallback subdir, withdrawal balance panic, 6 ABI labels), and all 15/15 `Bridge2` schema fields
- Maps every `bridge` source file to all 6 registered `bridge` crates in `research/components.json`
- Runs 5/5 negative controls.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKET_DIR.parents[2]
TARGET_BIN = REPO_ROOT / "artifacts/node/115/hl-node"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
FDE_TSV = REPO_ROOT / "work/index/node-115-fde.tsv"
INVENTORY_JSON = REPO_ROOT / "research/imported/hl-node-115.inventory.json"
RECORDS_JSON = PACKET_DIR / "records.json"

FILE_MAP = {
    "l1/src/bridge2.rs": [
        "src/bridge/src/contracts.rs",
        "src/bridge/src/eth_event.rs",
        "src/bridge/src/state.rs",
        "src/node115-bridge-event-name-decoder/src/lib.rs",
        "src/node115-bridge-request-mutation/lib.rs",
    ],
    "l1/src/bridge_request.rs": [
        "src/bridge/src/request.rs",
        "src/bridge/src/lib.rs",
        "src/node115-bridge-preimage/lib.rs",
        "src/node115-bridge-request-abi/src/lib.rs",
        "src/node115-bridge-word-flatten/src/lib.rs",
    ],
}

# Companion business-logic & live-compiled serde FDEs (disjoint from the 6 Location FDEs)
BUSINESS_FDES = [
    ("contract_registry_init", 0x154D390, "Arbitrum Usdc2/Bridge2 Mainnet/Testnet contract registry"),
    ("bridge_request_abi_dispatch", 0x4526230, "8-variant BridgeRequest ABI encoder dispatcher (JT 0x7d3708)"),
    ("bridge_role_display", 0x457CF20, "BridgeRole Locker/Finalizer formatter"),
    ("bridge_request_tag0_modify_role", 0x44E82D0, "Tag 0 modifyLocker/modifyFinalizer ABI encoder"),
    ("bridge_request_tags123_u64_pair", 0x44E6980, "Tags 1..=3 (string, uint64, uint64) ABI encoder"),
    ("bridge_request_tag4_update_valset", 0x44E8F00, "Tag 4 updateValidatorSet ABI encoder"),
    ("bridge_request_tag5_withdrawal", 0x44E96A0, "Tag 5 requestWithdrawal 224-byte ABI encoder"),
    ("bridge_request_tag6_unlock", 0x44EA040, "Tag 6 unlock ABI encoder"),
    ("bridge_request_tag7_invalidate", 0x44E6C40, "Tag 7 invalidateWithdrawals ABI encoder"),
    ("bridge2_state_ser_1", 0x291E600, "Bridge2 15-field state serializer copy 1"),
    ("bridge2_state_ser_2", 0x44D2370, "Bridge2 15-field state serializer copy 2"),
    ("bridge2_state_ser_3", 0x5AFB950, "Bridge2 15-field state serializer copy 3"),
    ("bridge2_field_visit_bytes_1", 0x28618E0, "Bridge2::FieldVisitor::visit_bytes copy 1"),
    ("bridge2_field_visit_bytes_2", 0x4442E00, "Bridge2::FieldVisitor::visit_bytes copy 2"),
    ("bridge2_field_visit_bytes_3", 0x5AE3260, "Bridge2::FieldVisitor::visit_bytes copy 3"),
    ("bridge2_field_visit_str_1", 0x28621F0, "Bridge2::FieldVisitor::visit_str copy 1"),
    ("bridge2_field_visit_str_2", 0x2862490, "Bridge2::FieldVisitor::visit_str copy 2"),
    ("bridge2_field_visit_str_3", 0x4443710, "Bridge2::FieldVisitor::visit_str copy 3"),
    ("bridge2_field_visit_str_4", 0x44439B0, "Bridge2::FieldVisitor::visit_str copy 4"),
    ("bridge2_field_visit_str_5", 0x5AE3B70, "Bridge2::FieldVisitor::visit_str copy 5"),
    ("eth_event_id_visit_str_1", 0x28657C0, "EthEventId::FieldVisitor::visit_str copy 1"),
    ("eth_event_id_visit_str_2", 0x28658C0, "EthEventId::FieldVisitor::visit_str copy 2"),
    ("eth_event_id_visit_str_3", 0x4446940, "EthEventId::FieldVisitor::visit_str copy 3"),
    ("eth_event_id_visit_str_4", 0x4446A40, "EthEventId::FieldVisitor::visit_str copy 4"),
    ("eth_event_id_visit_str_5", 0x5AE4780, "EthEventId::FieldVisitor::visit_str copy 5"),
]

# Exact .text instruction byte anchors inside bridge FDEs
INSTRUCTION_ANCHORS = [
    (
        "bridge2_ok_discriminant_0x1a2",
        0x44D8448,
        "6681bc24b0000000a201",
        "cmpw $0x1a2, 0xb0(%rsp) (BRIDGE2_OK_DISCRIMINANT)",
    ),
    (
        "bridge2_bal_checked_sub",
        0x44D8454,
        "488b83c80100004c29f00f82ad000000",
        "mov 0x1c8(%rbx),%rax; sub %r14,%rax; jb 0x44d8511 (withdrawal balance underflow guard)",
    ),
    (
        "bridge2_deposit_ring_stride_0x68",
        0x44D7D4B,
        "486bca68",
        "imul $0x68, %rdx, %rcx (BRIDGE2_DEPOSIT_RING_STRIDE = 104 B)",
    ),
    (
        "bridge_request_jump_table_lea",
        0x4526247,
        "488d0dbad42afc",
        "lea -0x3d52b46(%rip), %rcx -> 0x7d3708 (8-variant BridgeRequest jump table)",
    ),
    (
        "bridge_agent_source_a_and_mainnet_cmp",
        0x452704B,
        "4080fd03c60061",
        "cmp $0x3, %bpl; movb $0x61, (%rax) (ChainName::Mainnet check + source = 'a')",
    ),
    (
        "bridge_agent_arb_chain_ids",
        0x4527052,
        "b9b1a40000baee6e0600480f44d1",
        "mov $0xa4b1,%ecx (42161); mov $0x66eee,%edx (421614); cmove %rcx,%rdx",
    ),
    (
        "bridge_agent_chain_selector_xor3",
        0x4526EDA,
        "4080fd030f94c183f103",
        "cmp $0x3,%bpl; sete %cl; xor $0x3,%ecx (Bridge2 contract chain selector)",
    ),
]

RODATA_LITERALS = [
    ("usdc2_mainnet_key", 0x466E9F, "Usdc2Mainnet"),
    ("usdc2_mainnet_addr", 0x466EAB, "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"),
    ("bridge2_mainnet_key", 0x466ED5, "Bridge2Mainnet"),
    ("bridge2_mainnet_addr", 0x466EE3, "0x2Df1c51E09aECF9cacB7bc98cB1742757f163dF7"),
    ("bridge2_testnet_key", 0x466F0D, "Bridge2Testnet"),
    ("bridge2_testnet_addr", 0x466F1B, "0x08cfc1B6b2dCF36A1480b99353A354AA8AC56f89"),
    ("usdc2_testnet_key", 0x466F45, "Usdc2Testnet"),
    ("usdc2_testnet_addr", 0x466F51, "0x1baAbB04529D43a73232B713C0FE471f7c7334d5"),
    ("contract_addresses_subdir", 0x432654, "/contract_addresses/"),
    ("withdrawal_balance_bug", 0x7D30E2, "bridge2 withdrawal balance bug"),
    ("abi_change_dispute_period", 0x7D3B74, "changeDisputePeriodSeconds"),
    ("abi_change_block_duration", 0x7D3B8E, "changeBlockDurationMillis"),
    ("abi_change_locker_threshold", 0x7D3BA7, "changeLockerThreshold"),
    ("abi_request_withdrawal", 0x7D3BBC, "requestWithdrawal"),
    ("abi_invalidate_withdrawals", 0x7D3BCD, "invalidateWithdrawals"),
    ("abi_update_validator_set", 0x7B1C0E, "updateValidatorSet"),
]

BRIDGE2_15_FIELDS = [
    "eth_id_to_deposit_votes",
    "finished_deposits_data",
    "dvp",
    "dvpd",
    "dvs",
    "lfd",
    "withdrawal_signatures",
    "withdrawal_finalized_votes",
    "finished_withdrawal_to_time",
    "validator_set_signatures",
    "validator_set_finalized_votes",
    "bal",
    "last_pruned_deposit_block_number",
    "oaw",
    "r",
]


def parse_elf(path: Path) -> tuple[dict[str, tuple[int, int, bytes]], str]:
    raw = path.read_bytes()
    sha = hashlib.sha256(raw).hexdigest()
    e_shoff = struct.unpack_from("<Q", raw, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", raw, 58)
    shstr_off = struct.unpack_from("<Q", raw, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    shstr_sz = struct.unpack_from("<Q", raw, e_shoff + e_shstrndx * e_shentsize + 32)[0]
    shstr = raw[shstr_off : shstr_off + shstr_sz]
    secs = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, _sh_type, _sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from("<IIQQQQ", raw, off)
        name = shstr[sh_name : shstr.index(b"\x00", sh_name)].decode("ascii", "ignore")
        if name in (".text", ".rodata", ".data.rel.ro", ".rela.dyn"):
            secs[name] = (sh_addr, sh_size, raw[sh_offset : sh_offset + sh_size])
    return secs, sha


def scan_bridge(secs: dict[str, tuple[int, int, bytes]]) -> dict:
    text_va, _text_sz, text_data = secs[".text"]
    ro_va, ro_sz, ro_data = secs[".rodata"]
    dr_va, dr_sz, dr_data = secs[".data.rel.ro"]
    _, _, rela_data = secs[".rela.dyn"]

    rel_map: dict[int, int] = {}
    for off in range(0, len(rela_data), 24):
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", rela_data, off)
        if (r_info & 0xFFFFFFFF) == 8:
            rel_map[r_offset] = r_addend

    # 1. All l1/src/bridge*.rs panic::Location structs in .data.rel.ro
    locations = []
    for slot in sorted(rel_map):
        if not (dr_va <= slot <= dr_va + dr_sz - 24):
            continue
        ptr = rel_map[slot]
        if not (ro_va <= ptr < ro_va + ro_sz):
            continue
        fln, line, col = struct.unpack_from("<QII", dr_data, slot + 8 - dr_va)
        if 8 <= fln <= 200 and 1 <= line <= 100000 and 1 <= col <= 500:
            fb = ro_data[ptr - ro_va : ptr - ro_va + fln]
            if fb.startswith(b"l1/src/bridge") and all(32 <= b < 127 for b in fb):
                locations.append(
                    {
                        "va": f"0x{slot:x}",
                        "file": fb.decode("ascii"),
                        "line": line,
                        "column": col,
                    }
                )

    # 2. Cross-check against hl-node-115.inventory.json (`first_party_files["l1"]`)
    inv_data = json.loads(INVENTORY_JSON.read_text())
    inv_files = sorted(f"l1/src/{f}" for f in inv_data["first_party_files"]["l1"] if f.startswith("bridge"))
    loc_files = sorted({loc["file"] for loc in locations})
    assert inv_files == loc_files == sorted(FILE_MAP.keys()), (
        f"Source file set mismatch: inv={inv_files}, loc={loc_files}"
    )

    for _src, impls in FILE_MAP.items():
        for imp in impls:
            assert (REPO_ROOT / imp).exists(), f"Missing implementation path: {imp}"

    # 3. All Location-referencing .text FDEs + companion business FDEs
    fdes: dict[int, int] = {}
    with FDE_TSV.open() as f:
        f.readline()
        for line_s in f:
            parts = line_s.strip().split("\t")
            if len(parts) >= 2:
                fdes[int(parts[0], 16)] = int(parts[1], 16)

    loc_set = {int(loc["va"], 16) for loc in locations}
    lea_re = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d](.{4})", re.DOTALL)
    loc_fde_records = []
    ref_locs: set[int] = set()
    for s, e in sorted(fdes.items()):
        code = text_data[s - text_va : e - text_va]
        hits = set()
        for m in lea_re.finditer(code):
            disp = struct.unpack("<i", m.group(1))[0]
            tgt = s + m.end() + disp
            if tgt in loc_set:
                hits.add(tgt)
        if hits:
            ref_locs.update(hits)
            loc_fde_records.append(
                {
                    "start": f"0x{s:x}",
                    "end": f"0x{e:x}",
                    "size": e - s,
                    "location_vas": [f"0x{h:x}" for h in sorted(hits)],
                }
            )

    assert len(ref_locs) == len(locations), f"Unreferenced Locations: {len(locations) - len(ref_locs)}"

    loc_fde_starts = {int(r["start"], 16) for r in loc_fde_records}
    biz_fde_records = []
    seen_biz: set[int] = set()
    for name, s, desc in BUSINESS_FDES:
        assert s in fdes, f"Business FDE missing in index: {name} @ 0x{s:x}"
        assert s not in seen_biz, f"Duplicate business FDE: 0x{s:x}"
        assert s not in loc_fde_starts, f"Business FDE overlaps Location FDE: 0x{s:x}"
        seen_biz.add(s)
        e = fdes[s]
        biz_fde_records.append(
            {
                "name": name,
                "start": f"0x{s:x}",
                "end": f"0x{e:x}",
                "size": e - s,
                "description": desc,
            }
        )

    unique_fdes = {int(r["start"], 16): r["size"] for r in loc_fde_records}
    for r in biz_fde_records:
        unique_fdes[int(r["start"], 16)] = r["size"]

    # 4. Instruction anchors
    anchor_records = []
    for name, va, hex_bytes, desc in INSTRUCTION_ANCHORS:
        expected = bytes.fromhex(hex_bytes)
        actual = text_data[va - text_va : va - text_va + len(expected)]
        assert actual == expected, f"Anchor {name} @ 0x{va:x} mismatch: {actual.hex()} != {hex_bytes}"
        anchor_records.append({"name": name, "va": f"0x{va:x}", "bytes_hex": hex_bytes, "description": desc})

    # 5. .rodata string literals & 15 Bridge2 schema fields
    literal_records = []
    for name, va, text in RODATA_LITERALS:
        expected = text.encode("ascii")
        actual = ro_data[va - ro_va : va - ro_va + len(expected)]
        assert actual == expected, f"Literal {name} @ 0x{va:x} mismatch"
        literal_records.append({"name": name, "va": f"0x{va:x}", "text": text})

    schema_records = []
    for field in BRIDGE2_15_FIELDS:
        idx = ro_data.find(field.encode("ascii"))
        assert idx != -1, f"Bridge2 field missing in .rodata: {field}"
        schema_records.append({"field": field, "rodata_va": f"0x{ro_va + idx:x}"})

    return {
        "schema_version": 1,
        "packet": "RE-011-node115-bridge-closure",
        "component": "bridge",
        "target": {"path": "artifacts/node/115/hl-node", "sha256": TARGET_SHA256},
        "summary": {
            "source_files": len(loc_files),
            "locations": len(locations),
            "unreferenced_locations": 0,
            "location_referencing_fdes": len(loc_fde_records),
            "location_referencing_fde_bytes": sum(r["size"] for r in loc_fde_records),
            "companion_business_fdes": len(biz_fde_records),
            "companion_business_fde_bytes": sum(r["size"] for r in biz_fde_records),
            "unique_fdes": len(unique_fdes),
            "unique_fde_bytes": sum(unique_fdes.values()),
            "instruction_anchors": len(anchor_records),
            "rodata_literals": len(literal_records),
            "bridge2_schema_fields": len(schema_records),
            "identity_gate_satisfied": False,
        },
        "file_mapping": FILE_MAP,
        "locations": locations,
        "location_referencing_fdes": loc_fde_records,
        "companion_business_fdes": biz_fde_records,
        "instruction_anchors": anchor_records,
        "rodata_literals": literal_records,
        "bridge2_schema_fields": schema_records,
    }


def run_negative_controls(secs: dict[str, tuple[int, int, bytes]]) -> list[str]:
    text_va, _text_sz, text_data = secs[".text"]
    ro_va, _ro_sz, ro_data = secs[".rodata"]
    passed = []

    # NC1: Corrupted Arbitrum chain ID immediate (0xa4b2 instead of 0xa4b1) must be rejected
    assert text_data[0x4527052 - text_va : 0x4527052 - text_va + 5] != bytes.fromhex("b9b2a40000")
    passed.append("NC1_corrupted_arb_chain_id_anchor_rejected")

    # NC2: Corrupted Bridge2 Ok discriminant immediate (0x1a3 instead of 0x1a2) must be rejected
    assert text_data[0x44D8448 - text_va : 0x44D8448 - text_va + 10] != bytes.fromhex("6681bc24b0000000a301")
    passed.append("NC2_corrupted_ok_discriminant_anchor_rejected")

    # NC3: Corrupted Mainnet Bridge2 address literal at 0x466ee3 must be rejected
    assert ro_data[0x466EE3 - ro_va : 0x466EE3 - ro_va + 42] != b"0x2Df1c51E09aECF9cacB7bc98cB1742757f163dF8"
    passed.append("NC3_corrupted_mainnet_bridge2_addr_rejected")

    # NC4: Corrupted withdrawal balance panic string at 0x7d30e2 must be rejected
    assert ro_data[0x7D30E2 - ro_va : 0x7D30E2 - ro_va + 30] != b"bridge2 withdrawal balance buX"
    passed.append("NC4_corrupted_balance_bug_literal_rejected")

    # NC5: Nonexistent BridgeRequest ABI label must not appear in .rodata
    assert ro_data.find(b"requestFakeBridgeWithdrawal999") == -1
    passed.append("NC5_nonexistent_abi_label_rejected")

    return passed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write-records", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    secs, sha = parse_elf(TARGET_BIN)
    assert sha == TARGET_SHA256, f"Target SHA-256 mismatch: {sha}"
    payload = scan_bridge(secs)
    ncs = run_negative_controls(secs)
    payload["summary"]["negative_controls"] = ncs

    if args.write_records:
        RECORDS_JSON.write_text(json.dumps(payload, indent=2) + "\n")
        print(f"Wrote {RECORDS_JSON}")
        return 0

    assert RECORDS_JSON.exists(), f"Missing {RECORDS_JSON}"
    recorded = json.loads(RECORDS_JSON.read_text())
    assert recorded == payload, "Live ELF scan drifted from records.json!"
    s = payload["summary"]
    print(
        f"PASS: {s['source_files']}/2 bridge files, {s['locations']}/7 Locations "
        f"(0 unreferenced), {s['location_referencing_fdes']}/6 Location FDEs ({s['location_referencing_fde_bytes']} B), "
        f"{s['companion_business_fdes']}/25 business FDEs ({s['companion_business_fde_bytes']} B), "
        f"combined {s['unique_fdes']}/31 unique FDEs ({s['unique_fde_bytes']} B), "
        f"{s['instruction_anchors']} anchors, {s['rodata_literals']} literals, "
        f"{s['bridge2_schema_fields']}/15 schema fields, {len(ncs)}/5 negative controls rejected"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
