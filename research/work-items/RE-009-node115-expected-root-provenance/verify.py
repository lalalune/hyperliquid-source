#!/usr/bin/env python3
"""Static verifier for RE-009-node115-expected-root-provenance.

Authenticates node #115 (artifacts/node/115/hl-node), checks all recorded FDEs,
instruction anchors, jump-table dispatch for action 0xdd, direct-call edges
across the single-owner 0x5a04e40 apply-block -> action -> tracker -> drain ->
comparator -> end-root-selector chain, verifies the complete 27-site .text
census of tracker offset +0x3e50, and exercises negative/corruption controls.
"""
from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET_DIR = Path(__file__).resolve().parent
RECORDS_PATH = PACKET_DIR / "records.json"

TARGET_REL = "artifacts/node/115/hl-node"
TARGET_SIZE = 105896032
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

sys.path.insert(0, str(ROOT / "tools"))
from elf_index import unwind_index  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

EXPECTED_FDES = [
    ("apply_block_slow", 0x5A04E40, 0x5A065F8),
    ("execute_block_actions_slow", 0x5483850, 0x5483F43),
    ("action_batch_driver_slow", 0x5B30F30, 0x5B3104D),
    ("action_loop_slow", 0x5863AB0, 0x586405F),
    ("action_router_slow", 0x54A3A00, 0x54A4468),
    ("abci_vote_wrapper_slow", 0x5548A80, 0x55491F2),
    ("abci_vote_handler_0xdd_slow", 0x5869400, 0x586960E),
    ("tracker_record_wrapper_slow", 0x5AFADD0, 0x5AFB3A3),
    ("tracker_insert_core_slow", 0x537AA60, 0x537B867),
    ("support_predicate_slow", 0x5373810, 0x5373AAE),
    ("recheck_caller_slow", 0x54CAE80, 0x54CB646),
    ("recheck_wrapper_slow", 0x5AFA3B0, 0x5AFA5CF),
    ("finalizer_b_slow", 0x54897E0, 0x548C8E0),
    ("tracker_drain_slow", 0x5AFA030, 0x5AFA1EE),
    ("end_root_selector_slow", 0x5A07EC0, 0x5A0871C),
]

# (va, expected_bytes_hex, fde_name, role)
EXPECTED_ANCHORS = [
    # 0x5a04e40 (apply_block slow/replay)
    (0x5A04E54, "4989f4", "apply_block_slow", "save replay context pointer in r12"),
    (0x5A04EBB, "498b8c2450040000", "apply_block_slow", "load state S = *[ctx+0x450]"),
    (0x5A04EEA, "4939fd", "apply_block_slow", "check block.round > block.prev_round"),
    (0x5A04EF3, "4c8b4130", "apply_block_slow", "load state.round [S+0x30]"),
    (0x5A04EFC, "4939f8", "apply_block_slow", "check [S+0x30] == block.prev_round"),
    (0x5A04F05, "4c8b4118", "apply_block_slow", "load [S+0x18]"),
    (0x5A04F09, "488b7920", "apply_block_slow", "load [S+0x20]"),
    (0x5A04F17, "4939f0", "apply_block_slow", "check [S+0x18] == block+0x28"),
    (0x5A04F20, "4839d7", "apply_block_slow", "check [S+0x20] == block+0x30"),
    (0x5A04F5F, "498d842450040000", "apply_block_slow", "compute &ctx.state (ctx+0x450)"),
    (0x5A04F67, "48898424e8000000", "apply_block_slow", "spill &ctx.state to [rsp+0xe8]"),
    (0x5A04FDE, "498db42450040000", "apply_block_slow", "pass &ctx.state as rsi to execute_block_actions"),
    (0x5A04FE9, "e862e8a7ff", "apply_block_slow", "call execute_block_actions_slow (0x5483850)"),
    (0x5A055A8, "488bb424e8000000", "apply_block_slow", "reload identical &ctx.state from [rsp+0xe8]"),
    (0x5A055B0, "e82b42a8ff", "apply_block_slow", "call finalizer_b_slow (0x54897e0)"),
    (0x5A05C14, "498d9c2480020000", "apply_block_slow", "load abci_digest_quorum sink ctx+0x280"),
    (0x5A05C5E, "e8bd4343ff", "apply_block_slow", "forward each row to sink before comparison"),
    (0x5A05DF6, "e8b52ddfff", "apply_block_slow", "look up row height in local history ctx+0x400"),
    (0x5A05FC6, "4c89e6", "apply_block_slow", "pass ctx to end_root_selector after comparison"),
    (0x5A05FC9, "e8f21e0000", "apply_block_slow", "call end_root_selector_slow (0x5a07ec0)"),
    # 0x5483850 (execute_block_actions_slow: H -> H+1 saturating increment + action dispatch)
    (0x5483867, "4c8b2e", "execute_block_actions_slow", "dereference S = *[ctx+0x450] into r13"),
    (0x54838D3, "498b7528", "execute_block_actions_slow", "load restored/current height H = [S+0x28]"),
    (0x54838D7, "48ffc6", "execute_block_actions_slow", "increment height H + 1"),
    (0x54838DA, "48c7c2ffffffff", "execute_block_actions_slow", "saturating fallback u64::MAX"),
    (0x54838E1, "480f45d6", "execute_block_actions_slow", "cmovne saturating H + 1"),
    (0x54838E5, "49895528", "execute_block_actions_slow", "store incremented height [S+0x28] = H + 1"),
    (0x54838F1, "49894d30", "execute_block_actions_slow", "store new round [S+0x30] = rcx"),
    (0x5483E7A, "4c896c2448", "execute_block_actions_slow", "store same S (r13) in driver arg+0x20"),
    (0x5483E87, "e8a4d06a00", "execute_block_actions_slow", "call action_batch_driver_slow (0x5b30f30)"),
    # 0x5b30f30 -> 0x5863ab0 -> 0x54a3a00 -> 0x5548a80 -> 0x5869400
    (0x5B30FCF, "488b5320", "action_batch_driver_slow", "load S from driver arg+0x20"),
    (0x5B30FE6, "4889542438", "action_batch_driver_slow", "store S into loop arg+0x18"),
    (0x5B30FF5, "e8b62ad3ff", "action_batch_driver_slow", "call action_loop_slow (0x5863ab0)"),
    (0x5863AE1, "4c8b7e18", "action_loop_slow", "load S from loop arg+0x18 into r15"),
    (0x5863E0B, "4c89fe", "action_loop_slow", "pass S in rsi to action_router_slow (arm 1)"),
    (0x5863E1C, "e8dffbc3ff", "action_loop_slow", "call action_router_slow (0x54a3a00, arm 1)"),
    (0x5863E53, "4c89fe", "action_loop_slow", "pass S in rsi to action_router_slow (arm 2)"),
    (0x5863E64, "e897fbc3ff", "action_loop_slow", "call action_router_slow (0x54a3a00, arm 2)"),
    (0x54A3A17, "4989f5", "action_router_slow", "save S in r13"),
    (0x54A3A6D, "482d86000000", "action_router_slow", "subtract action tag base 0x86"),
    (0x54A3A7C, "488d05092e48fb", "action_router_slow", "load jump table base 0x92688c"),
    (0x54A3A8A, "ffe1", "action_router_slow", "indirect dispatch to action arm"),
    (0x54A430B, "4983c708", "action_router_slow", "tag 0xdd arm: advance payload by 8"),
    (0x54A4312, "4c89ee", "action_router_slow", "pass S (r13) in rsi to abci_vote_wrapper_slow"),
    (0x54A431B, "e860470a00", "action_router_slow", "call abci_vote_wrapper_slow (0x5548a80)"),
    (0x5548A91, "4989f7", "abci_vote_wrapper_slow", "save S in r15"),
    (0x554908D, "4c89f9", "abci_vote_wrapper_slow", "pass S in rcx to abci_vote_handler_0xdd_slow"),
    (0x5549090, "e86b033200", "abci_vote_wrapper_slow", "call abci_vote_handler_0xdd_slow (0x5869400)"),
    # 0x5869400 -> 0x5afadd0 -> 0x537aa60 -> 0x5373810
    (0x5869411, "48894c2438", "abci_vote_handler_0xdd_slow", "spill S to [rsp+0x38]"),
    (0x5869451, "e8aa9606fe", "abci_vote_handler_0xdd_slow", "hash vote preimage via 0x38d2b00"),
    (0x5869461, "ff157176c700", "abci_vote_handler_0xdd_slow", "recover signer via slot 0x64e0ad8"),
    (0x58694F9, "48b8cccccccccccccc0c", "abci_vote_handler_0xdd_slow", "load height upper bound 0xccccccccccccccc"),
    (0x5869503, "4939c6", "abci_vote_handler_0xdd_slow", "compare vote height against upper bound"),
    (0x586950C, "488b542438", "abci_vote_handler_0xdd_slow", "reload S from [rsp+0x38]"),
    (0x5869511, "488db2503e0000", "abci_vote_handler_0xdd_slow", "form tracker pointer S+0x3e50"),
    (0x5869583, "e848182900", "abci_vote_handler_0xdd_slow", "call tracker_record_wrapper_slow (0x5afadd0)"),
    (0x5AFB16F, "e8ecf887ff", "tracker_record_wrapper_slow", "call tracker_insert_core_slow (0x537aa60)"),
    (0x5AFB243, "498d7660", "tracker_record_wrapper_slow", "form pending timer map tracker+0x60"),
    (0x5AFB262, "e8792f2cff", "tracker_record_wrapper_slow", "schedule pending height in tracker+0x60 (0x4dbe1e0)"),
    (0x5AFB284, "4881ea50c30000", "tracker_record_wrapper_slow", "compute prune cutoff height - 50000"),
    (0x5AFB2AE, "e8cdbc87ff", "tracker_record_wrapper_slow", "prune old heights via 0x5376f80"),
    (0x537B28F, "807b2000", "tracker_insert_core_slow", "check height entry selector [B+0x20] == 0"),
    (0x537B2B0, "e85b85ffff", "tracker_insert_core_slow", "call pre-insert support_predicate_slow (0x5373810)"),
    (0x537B370, "e89b84ffff", "tracker_insert_core_slow", "call post-insert support_predicate_slow (0x5373810)"),
    (0x537B382, "c6432000", "tracker_insert_core_slow", "false->true latch: store selector [B+0x20] = 0"),
    (0x537B398, "f30f7f4321", "tracker_insert_core_slow", "store low 16 bytes of voted digest at [B+0x21]"),
    (0x537B39D, "f30f7f4b31", "tracker_insert_core_slow", "store high 16 bytes of voted digest at [B+0x31]"),
    (0x53738FA, "e8714635fe", "support_predicate_slow", "call weighted stake gate 0x36c7f70"),
    (0x53739F9, "e8a2d05400", "support_predicate_slow", "call membership count gate 0x58c0aa0"),
    # Second slow producer on S+0x3e50: 0x54cae80 -> 0x5afa3b0 -> 0x5373e40
    (0x54CB062, "488dbd503e0000", "recheck_caller_slow", "form tracker pointer S+0x3e50 for recheck"),
    (0x54CB078, "e833f36200", "recheck_caller_slow", "call recheck_wrapper_slow (0x5afa3b0)"),
    (0x5AFA3D4, "e8679a87ff", "recheck_wrapper_slow", "call recheck core 0x5373e40"),
    (0x5AFA4CB, "e8103d2cff", "recheck_wrapper_slow", "schedule newly selected height in tracker+0x60"),
    (0x5AFA50F, "e86cca87ff", "recheck_wrapper_slow", "prune old heights via 0x5376f80"),
    # Finalizer drain on exact same S+0x3e50
    (0x54897FB, "4c8b26", "finalizer_b_slow", "dereference exact same S = *[ctx+0x450] into r12"),
    (0x548BF2D, "498db424503e0000", "finalizer_b_slow", "form tracker pointer S+0x3e50 for drain"),
    (0x548BF4B, "e8e0e06600", "finalizer_b_slow", "call tracker_drain_slow (0x5afa030)"),
    (0x5AFA044, "488d7e60", "tracker_drain_slow", "pass pending timer map tracker+0x60"),
    (0x5AFA04E, "482de8030000", "tracker_drain_slow", "compute pending-map cutoff - 1000"),
    (0x5AFA0A0, "e89b642eff", "tracker_drain_slow", "invoke timer pending-map processor 0x4de0540"),
    # End-of-block local root production AFTER comparison
    (0x5A07ED7, "488bb650040000", "end_root_selector_slow", "dereference exact same S = *[ctx+0x450]"),
    (0x5A07EDE, "4c8b7e28", "end_root_selector_slow", "read incremented height H+1 from [S+0x28]"),
    (0x5A07FCE, "e8fd5aa8ff", "end_root_selector_slow", "compute local state root via 0x548dad0"),
    (0x5A07FD3, "498dbe00040000", "end_root_selector_slow", "address local raw-root history ctx+0x400"),
    (0x5A07FE2, "4c89fe", "end_root_selector_slow", "pass height H+1 in rsi"),
    (0x5A07FE5, "e8b6bfffff", "end_root_selector_slow", "insert (H+1, local_root) into ctx+0x400 via 0x5a03fa0"),
]

EXPECTED_DIRECT_CALLS = [
    (0x5A04FE9, 0x5483850),
    (0x5483E87, 0x5B30F30),
    (0x5B30FF5, 0x5863AB0),
    (0x5863E1C, 0x54A3A00),
    (0x5863E64, 0x54A3A00),
    (0x54A431B, 0x5548A80),
    (0x5549090, 0x5869400),
    (0x5869451, 0x38D2B00),
    (0x5869583, 0x5AFADD0),
    (0x5AFB16F, 0x537AA60),
    (0x5AFB262, 0x4DBE1E0),
    (0x5AFB2AE, 0x5376F80),
    (0x537B2B0, 0x5373810),
    (0x537B370, 0x5373810),
    (0x53738FA, 0x36C7F70),
    (0x53739F9, 0x58C0AA0),
    (0x54CB078, 0x5AFA3B0),
    (0x5AFA3D4, 0x5373E40),
    (0x5AFA4CB, 0x4DBE1E0),
    (0x5AFA50F, 0x5376F80),
    (0x5A055B0, 0x54897E0),
    (0x548BF4B, 0x5AFA030),
    (0x5AFA0A0, 0x4DE0540),
    (0x5A05C5E, 0x4E3A020),
    (0x5A05DF6, 0x57F8BB0),
    (0x5A05FC9, 0x5A07EC0),
    (0x5A07FCE, 0x548DAD0),
    (0x5A07FE5, 0x5A03FA0),
]

JUMP_TABLE_BASE = 0x92688C
ACTION_TAG_BASE = 0x86
ACTION_TAG_0XDD = 0xDD
JUMP_TABLE_TARGET = 0x54A430B

# Complete .text census of little-endian 0x00003e50 (27 exact occurrences).
EXPECTED_3E50_CENSUS = [
    (0x269A60A, 0x269A1B0, 0x269AB6B, "root_capture_live"),
    (0x294FEE4, 0x294FDD0, 0x294FFDE, "producer_vote_0xdd_live"),
    (0x2AC4351, 0x2AC3A80, 0x2AC4808, "drop_normal"),
    (0x2AC47C2, 0x2AC3A80, 0x2AC4808, "drop_unwind"),
    (0x2BEEEB5, 0x2BEECD0, 0x2BEF496, "producer_recheck_live"),
    (0x2C6C77F, 0x2C6BEE0, 0x2C6C800, "serialize_live_1"),
    (0x2C6D124, 0x2C6C800, 0x2C6D273, "serialize_live_2"),
    (0x2C743C0, 0x2C71EB0, 0x2C74A69, "query_reader"),
    (0x2CA7701, 0x2CA6E30, 0x2CA7BB8, "drop_normal"),
    (0x2CA7B72, 0x2CA6E30, 0x2CA7BB8, "drop_unwind"),
    (0x2E03661, 0x2E02D90, 0x2E03B18, "drop_normal"),
    (0x2E03AD2, 0x2E02D90, 0x2E03B18, "drop_unwind"),
    (0x3C2EFD6, 0x3C2E860, 0x3C2F45B, "checkpoint_restore_memcpy"),
    (0x3D15601, 0x3D14C80, 0x3D15AAB, "drop_normal"),
    (0x3D15A75, 0x3D14C80, 0x3D15AAB, "drop_unwind"),
    (0x4E3513A, 0x4E34CE0, 0x4E3569B, "root_capture_slow"),
    (0x548161D, 0x5480950, 0x548168C, "serialize_slow_1"),
    (0x548BF31, 0x54897E0, 0x548C8E0, "consumer_drain_slow"),
    (0x548D189, 0x548CE30, 0x548D8BD, "snapshot_clone_memcpy"),
    (0x54CB065, 0x54CAE80, 0x54CB646, "producer_recheck_slow"),
    (0x55F26F0, 0x55EA030, 0x55F3D4C, "deserialize_memcpy"),
    (0x55FD740, 0x55FCDF0, 0x55FD88F, "serialize_slow_2"),
    (0x5642C31, 0x5642360, 0x56430DB, "drop_normal"),
    (0x56430A5, 0x5642360, 0x56430DB, "drop_unwind"),
    (0x5869514, 0x5869400, 0x586960E, "producer_vote_0xdd_slow"),
    (0x5A586E1, 0x5A57E10, 0x5A58B98, "drop_normal"),
    (0x5A58B52, 0x5A57E10, 0x5A58B98, "drop_unwind"),
]


def load_elf(target_path: Path, check_digest: bool = True):
    data = target_path.read_bytes()
    if check_digest:
        if len(data) != TARGET_SIZE:
            raise ValueError(f"unexpected target size {len(data)} != {TARGET_SIZE}")
        digest = hashlib.sha256(data).hexdigest()
        if digest != TARGET_SHA256:
            raise ValueError(f"unexpected target sha256 {digest}")
    sections, header = unwind_index(data)
    _, fdes = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    bounds = {(row["start"], row["end"]) for row in fdes if (row["start"], row["fde"]) in indexed}
    fde_sorted = sorted(bounds)
    fde_starts = [s for s, _ in fde_sorted]
    by_name = {sec["name"]: sec for sec in sections}
    return data, by_name, bounds, fde_sorted, fde_starts


def read_section_bytes(data: bytes, sections: dict, name: str, va: int, size: int) -> bytes:
    sec = sections[name]
    disp = va - sec["address"]
    if disp < 0 or disp + size > sec["size"]:
        raise ValueError(f"VA 0x{va:x}..0x{va+size:x} outside {name}")
    return data[sec["offset"] + disp : sec["offset"] + disp + size]


def enclosing_fde(fde_sorted, fde_starts, va: int):
    idx = bisect.bisect_right(fde_starts, va) - 1
    if idx >= 0 and fde_sorted[idx][0] <= va < fde_sorted[idx][1]:
        return fde_sorted[idx]
    return None


def verify_record_dict(data: bytes, sections: dict, bounds: set, fde_sorted, fde_starts, record: dict):
    # 1. FDEs
    fde_map = {}
    for entry in record["fdes"]:
        start = int(entry["start"], 16)
        end = int(entry["end"], 16)
        if (start, end) not in bounds:
            raise ValueError(f"FDE {entry['name']} 0x{start:x}..0x{end:x} not in indexed .eh_frame")
        fde_map[entry["name"]] = (start, end)

    # 2. Anchors
    anchor_bytes = {}
    for row in record["anchors"]:
        va = int(row["va"], 16)
        expected = bytes.fromhex(row["bytes"])
        start, end = fde_map[row["fde"]]
        if not (start <= va < va + len(expected) <= end):
            raise ValueError(f"anchor 0x{va:x} outside FDE {row['fde']}")
        actual = read_section_bytes(data, sections, ".text", va, len(expected))
        if actual != expected:
            raise ValueError(f"anchor 0x{va:x} bytes mismatch: {actual.hex()} != {expected.hex()}")
        anchor_bytes[va] = expected

    # 3. Direct call targets
    for edge in record["direct_calls"]:
        site = int(edge["call_va"], 16)
        target = int(edge["target_va"], 16)
        raw = anchor_bytes.get(site) or read_section_bytes(data, sections, ".text", site, 5)
        if len(raw) != 5 or raw[0] != 0xE8:
            raise ValueError(f"call site 0x{site:x} is not a 5-byte E8 direct call")
        rel = struct.unpack_from("<i", raw, 1)[0]
        actual_target = site + 5 + rel
        if actual_target != target:
            raise ValueError(f"call 0x{site:x} target 0x{actual_target:x} != 0x{target:x}")

    # 4. Jump table dispatch for tag 0xdd in action_router_slow (0x54a3a00)
    jt = record["jump_table_0xdd"]
    jbase = int(jt["table_base"], 16)
    idx = jt["tag"] - jt["tag_base"]
    cell = read_section_bytes(data, sections, ".rodata", jbase + idx * 4, 4)
    jtarget = jbase + struct.unpack("<i", cell)[0]
    if jtarget != int(jt["target_va"], 16):
        raise ValueError(f"jump table 0x{jbase:x}[{idx}] -> 0x{jtarget:x} != {jt['target_va']}")

    # 5. Indirect slot check for ECDSA recovery in 0x5869400
    slot_va = int(record["recovery_slot_check"]["slot_va"], 16)
    call_va = int(record["recovery_slot_check"]["call_va"], 16)
    raw_call = anchor_bytes[call_va]
    if raw_call[:2] != b"\xff\x15":
        raise ValueError(f"recovery call 0x{call_va:x} is not RIP-relative indirect call")
    actual_slot = call_va + len(raw_call) + struct.unpack_from("<i", raw_call, 2)[0]
    if actual_slot != slot_va:
        raise ValueError(f"recovery slot 0x{actual_slot:x} != 0x{slot_va:x}")

    # 6. Complete .text census of little-endian 0x00003e50
    text_sec = sections[".text"]
    text_bytes = data[text_sec["offset"] : text_sec["offset"] + text_sec["size"]]
    text_va = text_sec["address"]
    found = []
    pos = 0
    while True:
        hit = text_bytes.find(b"\x50\x3e\x00\x00", pos)
        if hit == -1:
            break
        va = text_va + hit
        fde = enclosing_fde(fde_sorted, fde_starts, va)
        found.append((va, fde[0] if fde else None, fde[1] if fde else None))
        pos = hit + 1
    expected_census = [
        (int(r["disp_va"], 16), int(r["fde_start"], 16), int(r["fde_end"], 16))
        for r in record["census_0x3e50"]
    ]
    if found != expected_census:
        raise ValueError(f".text 0x3e50 census mismatch: found {len(found)} vs expected {len(expected_census)}")

    return {
        "fdes": len(fde_map),
        "anchors": len(anchor_bytes),
        "direct_calls": len(record["direct_calls"]),
        "census_0x3e50": len(found),
    }


def build_records() -> dict:
    return {
        "target": {
            "path": TARGET_REL,
            "size": TARGET_SIZE,
            "sha256": TARGET_SHA256,
        },
        "fdes": [
            {"name": name, "start": f"0x{s:x}", "end": f"0x{e:x}"}
            for name, s, e in EXPECTED_FDES
        ],
        "anchors": [
            {"va": f"0x{va:x}", "bytes": hx, "fde": fde, "role": role}
            for va, hx, fde, role in EXPECTED_ANCHORS
        ],
        "direct_calls": [
            {"call_va": f"0x{c:x}", "target_va": f"0x{t:x}"}
            for c, t in EXPECTED_DIRECT_CALLS
        ],
        "jump_table_0xdd": {
            "table_base": f"0x{JUMP_TABLE_BASE:x}",
            "tag_base": ACTION_TAG_BASE,
            "tag": ACTION_TAG_0XDD,
            "target_va": f"0x{JUMP_TABLE_TARGET:x}",
        },
        "recovery_slot_check": {
            "call_va": "0x5869461",
            "slot_va": "0x64e0ad8",
        },
        "census_0x3e50": [
            {
                "disp_va": f"0x{va:x}",
                "fde_start": f"0x{s:x}",
                "fde_end": f"0x{e:x}",
                "class": cls,
            }
            for va, s, e, cls in EXPECTED_3E50_CENSUS
        ],
    }


def run_negative_controls(data: bytes, sections: dict, bounds: set, fde_sorted, fde_starts, record: dict) -> int:
    def clone():
        return json.loads(json.dumps(record))

    controls = []

    # 1. Altered state-offset anchor (wrong ctx+0x450 reload for finalizer)
    c1 = clone()
    for a in c1["anchors"]:
        if a["va"] == "0x5a055a8":
            a["bytes"] = "488bb424e0000000"
    controls.append(("altered_finalizer_state_reload", c1))

    # 2. Altered H -> H+1 height store offset
    c2 = clone()
    for a in c2["anchors"]:
        if a["va"] == "0x54838e5":
            a["bytes"] = "49895530"
    controls.append(("altered_height_increment_store", c2))

    # 3. Altered action 0xdd jump-table target
    c3 = clone()
    c3["jump_table_0xdd"]["target_va"] = "0x54a42f1"
    controls.append(("altered_0xdd_jump_target", c3))

    # 4. Altered direct call from 0x5869583 -> 0x5afadd0
    c4 = clone()
    for e in c4["direct_calls"]:
        if e["call_va"] == "0x5869583":
            e["target_va"] = "0x2760bc0"
    controls.append(("conflated_live_and_slow_wrapper", c4))

    # 5. Altered selector latch byte in 0x537aa60
    c5 = clone()
    for a in c5["anchors"]:
        if a["va"] == "0x537b382":
            a["bytes"] = "c6432001"
    controls.append(("inverted_selector_latch", c5))

    # 6. Altered ECDSA recovery slot
    c6 = clone()
    c6["recovery_slot_check"]["slot_va"] = "0x64e0ae0"
    controls.append(("altered_recovery_slot", c6))

    # 7. Omitted site from complete 27-site 0x3e50 census
    c7 = clone()
    c7["census_0x3e50"].pop()
    controls.append(("incomplete_0x3e50_census", c7))

    # 8. Corrupted FDE boundary
    c8 = clone()
    c8["fdes"][0]["end"] = "0x5a065f0"
    controls.append(("corrupted_fde_boundary", c8))

    for name, mutated in controls:
        try:
            verify_record_dict(data, sections, bounds, fde_sorted, fde_starts, mutated)
        except ValueError:
            continue
        raise AssertionError(f"negative control {name} unexpectedly passed")
    return len(controls)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=ROOT / TARGET_REL)
    parser.add_argument("--write", action="store_true", help="write records.json after verifying against target")
    parser.add_argument("--self-test", action="store_true", help="run all negative controls")
    args = parser.parse_args()

    data, sections, bounds, fde_sorted, fde_starts = load_elf(args.target, check_digest=True)
    record = build_records() if args.write or not RECORDS_PATH.is_file() else json.loads(RECORDS_PATH.read_text())
    stats = verify_record_dict(data, sections, bounds, fde_sorted, fde_starts, record)
    if args.write:
        RECORDS_PATH.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    rejected = run_negative_controls(data, sections, bounds, fde_sorted, fde_starts, record) if (args.self_test or True) else 0
    print(
        f"RE-009-node115-expected-root-provenance verified: "
        f"{stats['fdes']} FDEs, {stats['anchors']} anchors, "
        f"{stats['direct_calls']} direct calls, {stats['census_0x3e50']}/27 +0x3e50 census sites, "
        f"{rejected}/{rejected} negative controls rejected."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
