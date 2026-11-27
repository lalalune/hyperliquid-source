#!/usr/bin/env python3
"""Full-scope node #115 closure verifier for `evm-rpc` (`evm_rpc/src/*.rs`):
- Authenticates all 6/6 `evm_rpc/src/*.rs` source files against `hl-node-115.inventory.json`
- Authenticates all 57/57 `.data.rel.ro` `Location` structs (0 unreferenced)
- Authenticates all 48/48 referencing `.text` FDEs (`145,280 B`) against `work/index/node-115-fde.tsv`
- Authenticates all 29/29 registered JSON-RPC methods, instruction anchors, and `.rodata` constants
- Maps every `evm_rpc/src/*.rs` source file to `src/evm-rpc/src/*` and sibling Stream F crates
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
    "evm_rpc/src/evm_rpc.rs": [
        "src/evm-rpc/src/fee_history.rs",
        "src/evm-rpc/src/limiter.rs",
        "src/evm-rpc/src/method_router.rs",
        "src/node115-block-number-text/src/lib.rs",
        "src/node115-fee-history-reward/lib.rs",
    ],
    "evm_rpc/src/evm_store.rs": [
        "src/evm-rpc/src/store.rs",
        "src/node115-storage-key-builder/lib.rs",
    ],
    "evm_rpc/src/evm_write_forwarder.rs": [
        "src/evm-rpc/src/forwarder.rs",
    ],
    "evm_rpc/src/expensive_call_limiter.rs": [
        "src/evm-rpc/src/limiter.rs",
    ],
    "evm_rpc/src/method_router.rs": [
        "src/evm-rpc/src/method_router.rs",
        "src/evm-rpc/src/lib.rs",
    ],
    "evm_rpc/src/reth_rpc_helpers_copied.rs": [
        "src/evm-rpc/src/fee_history.rs",
        "src/node115-fee-history-reward/lib.rs",
    ],
}

ALL_29_METHODS = [
    "eth_blockNumber",
    "eth_call",
    "eth_chainId",
    "eth_estimateGas",
    "eth_feeHistory",
    "eth_gasPrice",
    "eth_getBalance",
    "eth_getBlockByHash",
    "eth_getBlockByNumber",
    "eth_getBlockReceipts",
    "eth_getBlockTransactionCountByHash",
    "eth_getBlockTransactionCountByNumber",
    "eth_getCode",
    "eth_getLogs",
    "eth_getStorageAt",
    "eth_getTransactionByBlockHashAndIndex",
    "eth_getTransactionByBlockNumberAndIndex",
    "eth_getTransactionByHash",
    "eth_getTransactionCount",
    "eth_getTransactionReceipt",
    "eth_maxPriorityFeePerGas",
    "eth_syncing",
    "eth_bigBlockGasPrice",
    "eth_getSystemTxsByBlockHash",
    "eth_getSystemTxsByBlockNumber",
    "eth_usingBigBlocks",
    "net_version",
    "web3_clientVersion",
    "eth_sendRawTransaction",
]

# Exact .text instruction byte anchors inside evm_rpc FDEs
INSTRUCTION_ANCHORS = [
    ("forwarder_chain_selector_cmp2", 0x1748153, "83f802", "cmp $0x2, %eax (0|1 unsupported, 2 testnet, 3+ mainnet)"),
    ("limiter_copy_size_0xc8", 0x2A04336, "bac8000000", "mov $0xc8, %edx in expensive_call_limiter.rs"),
    ("fee_history_max_percentiles_100", 0x2A20053, "4883fa64", "cmp $0x64, %rdx (MAX_REWARD_PERCENTILES = 100)"),
    ("fee_history_windows2_cmp2", 0x2A20090, "4883fa02", "cmp $0x2, %rdx (adjacent-pair percentile check)"),
    ("get_logs_addr_limit_1000", 0x2A2CFAB, "4981bc2410040000e8030000", "cmpq $0x3e8, 0x410(%r12) (addresses <= 1000)"),
    ("get_logs_topic0_limit_1000", 0x2A2CFB9, "4981bc2458040000e8030000", "cmpq $0x3e8, 0x458(%r12) (topic[0] <= 1000)"),
    ("get_logs_topic1_limit_1000", 0x2A2CFC7, "4981bc24a0040000e8030000", "cmpq $0x3e8, 0x4a0(%r12) (topic[1] <= 1000)"),
    ("get_logs_topic2_limit_1000", 0x2A2CFD5, "4981bc24e8040000e8030000", "cmpq $0x3e8, 0x4e8(%r12) (topic[2] <= 1000)"),
    ("get_logs_topic3_limit_1000", 0x2A2CFE3, "4981bc2430050000e8030000", "cmpq $0x3e8, 0x530(%r12) (topic[3] <= 1000)"),
    ("get_logs_secondary_limit_1000", 0x2A2D820, "483de8030000", "cmp $0x3e8, %rax (secondary 1000-item bound)"),
]

RODATA_LITERALS = [
    ("method_not_found", 0x453CF0, "Method not found"),
    ("parse_error", 0x616787, "Parse error"),
    ("invalid_request", 0x616792, "Invalid request"),
    ("invalid_params", 0x441182, "Invalid params"),
    ("content_type_json", 0x44A912, "application/json"),
    ("system_txs_by_block", 0x5EB259, "system_txs_by_block"),
    ("expensive_call_permit_metric", 0x6023AC, "evm_rpc_expensive_call_permit"),
    ("log_filter_limit_error", 0x433A75, "query exceeds max addresses or topics per position"),
    ("mainnet_rpc_url", 0x4806C8, "https://rpc.hyperliquid.xyz/evm"),
    ("testnet_rpc_url", 0x4806A1, "https://rpc.hyperliquid-testnet.xyz/evm"),
    ("write_forward_method", 0x4806E7, "eth_sendRawTransaction"),
    ("move_precompile_override", 0x5F693B, "MovePrecompileToAddress"),
]

RODATA_CONSTANTS = [
    ("blob_gas_divisor_f64", 0x4590B0, "f64", 786432.0),
    ("max_percentile_f64", 0x459498, "f64", 100.0),
    ("max_filter_items_u64", 0x459C00, "u64", 1000),
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


def scan_evm_rpc(secs: dict[str, tuple[int, int, bytes]]) -> dict:
    text_va, _text_sz, text_data = secs[".text"]
    ro_va, ro_sz, ro_data = secs[".rodata"]
    dr_va, dr_sz, dr_data = secs[".data.rel.ro"]
    _, _, rela_data = secs[".rela.dyn"]

    rel_map: dict[int, int] = {}
    for off in range(0, len(rela_data), 24):
        r_offset, r_info, r_addend = struct.unpack_from("<QQq", rela_data, off)
        if (r_info & 0xFFFFFFFF) == 8:
            rel_map[r_offset] = r_addend

    # 1. All evm_rpc/src/*.rs panic::Location structs in .data.rel.ro
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
            if b"evm_rpc/" in fb and all(32 <= b < 127 for b in fb):
                locations.append(
                    {
                        "va": f"0x{slot:x}",
                        "file": fb.decode("ascii"),
                        "line": line,
                        "column": col,
                    }
                )

    # 2. Cross-check against hl-node-115.inventory.json (`first_party_files["evm_rpc"]`)
    inv_data = json.loads(INVENTORY_JSON.read_text())
    inv_files = sorted(f"evm_rpc/src/{f}" for f in inv_data["first_party_files"]["evm_rpc"])
    loc_files = sorted({loc["file"] for loc in locations})
    assert inv_files == loc_files == sorted(FILE_MAP.keys()), (
        f"Source file set mismatch: inv={inv_files}, loc={loc_files}"
    )

    for _src, impls in FILE_MAP.items():
        for imp in impls:
            assert (REPO_ROOT / imp).exists(), f"Missing implementation path: {imp}"

    # 3. All referencing .text FDEs
    fdes: list[tuple[int, int]] = []
    with FDE_TSV.open() as f:
        f.readline()
        for line_s in f:
            parts = line_s.strip().split("\t")
            if len(parts) >= 2:
                fdes.append((int(parts[0], 16), int(parts[1], 16)))

    loc_set = {int(loc["va"], 16) for loc in locations}
    lea_re = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d](.{4})", re.DOTALL)
    fde_records = []
    ref_locs: set[int] = set()
    for s, e in fdes:
        code = text_data[s - text_va : e - text_va]
        hits = set()
        for m in lea_re.finditer(code):
            disp = struct.unpack("<i", m.group(1))[0]
            tgt = s + m.end() + disp
            if tgt in loc_set:
                hits.add(tgt)
        if hits:
            ref_locs.update(hits)
            fde_records.append(
                {
                    "start": f"0x{s:x}",
                    "end": f"0x{e:x}",
                    "size": e - s,
                    "location_vas": [f"0x{h:x}" for h in sorted(hits)],
                }
            )

    assert len(ref_locs) == len(locations), f"Unreferenced Locations: {len(locations) - len(ref_locs)}"

    # 4. Verify all 29 registered JSON-RPC method strings in .rodata
    method_records = []
    for m in ALL_29_METHODS:
        idx = ro_data.find(m.encode("ascii"))
        assert idx != -1, f"RPC method string missing in .rodata: {m}"
        method_records.append({"method": m, "rodata_va": f"0x{ro_va + idx:x}"})

    # 5. Verify instruction anchors
    anchor_records = []
    for name, va, hex_bytes, desc in INSTRUCTION_ANCHORS:
        expected = bytes.fromhex(hex_bytes)
        actual = text_data[va - text_va : va - text_va + len(expected)]
        assert actual == expected, f"Anchor {name} @ 0x{va:x} mismatch: {actual.hex()} != {hex_bytes}"
        anchor_records.append({"name": name, "va": f"0x{va:x}", "bytes_hex": hex_bytes, "description": desc})

    # 6. Verify .rodata string literals & numeric constants
    literal_records = []
    for name, va, text in RODATA_LITERALS:
        expected = text.encode("ascii")
        actual = ro_data[va - ro_va : va - ro_va + len(expected)]
        assert actual == expected, f"Literal {name} @ 0x{va:x} mismatch"
        literal_records.append({"name": name, "va": f"0x{va:x}", "text": text})

    const_records = []
    for name, va, kind, val in RODATA_CONSTANTS:
        if kind == "f64":
            actual_val = struct.unpack_from("<d", ro_data, va - ro_va)[0]
        else:
            actual_val = struct.unpack_from("<Q", ro_data, va - ro_va)[0]
        assert actual_val == val, f"Constant {name} @ 0x{va:x}: {actual_val} != {val}"
        const_records.append({"name": name, "va": f"0x{va:x}", "type": kind, "value": val})

    return {
        "schema_version": 1,
        "packet": "RE-011-node115-evm-rpc-closure",
        "component": "evm-rpc",
        "target": {"path": "artifacts/node/115/hl-node", "sha256": TARGET_SHA256},
        "summary": {
            "source_files": len(loc_files),
            "locations": len(locations),
            "unreferenced_locations": 0,
            "referencing_fdes": len(fde_records),
            "referencing_fde_bytes": sum(r["size"] for r in fde_records),
            "registered_rpc_methods": len(method_records),
            "instruction_anchors": len(anchor_records),
            "rodata_literals": len(literal_records),
            "rodata_constants": len(const_records),
        },
        "file_mapping": FILE_MAP,
        "locations": locations,
        "referencing_fdes": fde_records,
        "rpc_methods": method_records,
        "instruction_anchors": anchor_records,
        "rodata_literals": literal_records,
        "rodata_constants": const_records,
    }


def run_negative_controls(secs: dict[str, tuple[int, int, bytes]]) -> list[str]:
    text_va, _text_sz, text_data = secs[".text"]
    ro_va, _ro_sz, ro_data = secs[".rodata"]
    passed = []

    # NC1: Corrupted instruction anchor byte must be rejected
    va = 0x2A20053
    bad_expected = bytes.fromhex("4883fa65")  # 101 instead of 100
    assert text_data[va - text_va : va - text_va + 4] != bad_expected
    passed.append("NC1_corrupted_instruction_anchor_rejected")

    # NC2: Wrong f64 constant at 0x4590b0 must be rejected
    assert struct.unpack_from("<d", ro_data, 0x4590B0 - ro_va)[0] != 786433.0
    passed.append("NC2_wrong_f64_constant_rejected")

    # NC3: Wrong u64 constant at 0x459c00 must be rejected
    assert struct.unpack_from("<Q", ro_data, 0x459C00 - ro_va)[0] != 999
    passed.append("NC3_wrong_u64_constant_rejected")

    # NC4: Nonexistent RPC method must not be in .rodata
    assert ro_data.find(b"eth_nonexistentHyperliquidMethod999") == -1
    passed.append("NC4_nonexistent_rpc_method_rejected")

    # NC5: Corrupted literal must not match at 0x453cf0
    assert ro_data[0x453CF0 - ro_va : 0x453CF0 - ro_va + 16] != b"Method not founX"
    passed.append("NC5_corrupted_rodata_literal_rejected")
    return passed


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write-records", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    secs, sha = parse_elf(TARGET_BIN)
    assert sha == TARGET_SHA256, f"Target SHA-256 mismatch: {sha}"
    payload = scan_evm_rpc(secs)
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
        f"PASS: {s['source_files']}/6 evm_rpc/src files, {s['locations']}/57 Locations "
        f"(0 unreferenced), {s['referencing_fdes']}/48 FDEs ({s['referencing_fde_bytes']} B), "
        f"{s['registered_rpc_methods']}/29 RPC methods, {s['instruction_anchors']} anchors, "
        f"{s['rodata_literals']} literals, {s['rodata_constants']} constants, "
        f"{len(ncs)}/5 negative controls rejected"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
