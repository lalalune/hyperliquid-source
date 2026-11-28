#!/usr/bin/env python3
"""Verify 17 strictly disjoint pure first-party node #115 l1-shared and action-wire business-logic FDEs (3,426 B)."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKET_DIR.parents[2]
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
import byte_progress as bp  # noqa: E402

BINARY_PATH = REPO_ROOT / "artifacts" / "node" / "115" / "hl-node"
FDE_TSV_PATH = REPO_ROOT / "work" / "index" / "node-115-fde.tsv"
BYTE_WINDOWS_PATH = REPO_ROOT / "research" / "byte-windows.json"
WORK_ITEMS_DIR = REPO_ROOT / "research" / "work-items"
STD_LOGIC_DIR = PACKET_DIR / "std_logic"
JEM_SERDE_DIR = PACKET_DIR / "jem_serde"
RECORDS_PATH = PACKET_DIR / "records.json"
BODIES_PATH = PACKET_DIR / "bodies.bin"
LICENSES_PATH = PACKET_DIR / "licenses.json"

EXPECTED_BINARY_PATH = "artifacts/node/115/hl-node"
EXPECTED_BINARY_SIZE = 105_896_032
EXPECTED_BINARY_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

TEXT_VA = 0x1419300
TEXT_OFF = 0x1418300
RODATA_VA = 0x430400
RODATA_OFF = 0x430400
RODATA_SZ = 0x76E640
DATA_REL_RO_VA = 0x63F2BA0
DATA_REL_RO_OFF = 0x63F0BA0
DATA_REL_RO_SZ = 0xFC000

SIBLING_PACKET_TAGS = (
    "byte-match",
    "thinlto",
    "census",
    "consolidation",
    "100pct",
    "gate-closure",
    "identity",
    "compiled",
)

FORBIDDEN_SYMBOL_TOKENS = (
    "drop_in_place",
    "core::",
    "alloc::",
    "std::",
    "hashbrown",
    "serde_json",
    "rmp_serde",
    "simd_contains",
    "call_once_force",
    "write_fmt",
)

# 17 strictly disjoint pure first-party business-logic FDEs (3,426 B):
# (component, pool_kind, window_id, label, start_va, end_va, symbol_hint, anchor_kind, anchor_value)
WINDOW_SPECS: list[tuple[str, str, str, str, int, int, str, str, str]] = [
    # l1-shared (7 FDEs = 2,023 B)
    (
        "l1-shared",
        "std_logic",
        "node115-action-logic-hl-funding-cost",
        "hyperliquidity::funding_cost",
        0x38BCB80,
        0x38BCBEE,
        "e2b_hyperliquidity_funding_cost",
        "instr_hex",
        "49bafeffffffffffff7f",
    ),
    (
        "l1-shared",
        "std_logic",
        "node115-action-logic-chain-ext-config",
        "ChainExt::chain_config",
        0x46F3FC0,
        0x46F40B0,
        "e2b_chain_ext_config",
        "location",
        "l1/src/chain_ext.rs:109:29",
    ),
    (
        "l1-shared",
        "std_logic",
        "node115-action-logic-nonce-expanded-set-b",
        "nonce_set::is_expanded_set_b",
        0x421A3C0,
        0x421A51B,
        "e2b_nonce_set_expanded_set_b",
        "rodata_simd_hex",
        "2e3d94f0562703b25c83308a05046dda",
    ),
    (
        "l1-shared",
        "std_logic",
        "node115-action-logic-nonce-expanded-set-a",
        "nonce_set::is_expanded_set_a",
        0x421A520,
        0x421A67B,
        "e2b_nonce_set_expanded_set_a",
        "rodata_simd_hex",
        "010461c14e146ac35fe42271bdc1134e",
    ),
    (
        "l1-shared",
        "jem_serde",
        "node115-action-logic-nonce-set-de-json-1",
        "<NonceSet as Deserialize>::deserialize (json #1)",
        0x2923DA0,
        0x2923EE1,
        "NonceSet",
        "location",
        "l1/src/nonce_set.rs:141:13",
    ),
    (
        "l1-shared",
        "jem_serde",
        "node115-action-logic-nonce-set-de-json-2",
        "<NonceSet as Deserialize>::deserialize (json #2)",
        0x4227E90,
        0x4227FD1,
        "NonceSet",
        "location",
        "l1/src/nonce_set.rs:141:13",
    ),
    (
        "l1-shared",
        "jem_serde",
        "node115-action-logic-nonce-set-de-rmp-1",
        "<NonceSet as Deserialize>::deserialize (rmp)",
        0x4227D30,
        0x4227E81,
        "NonceSet",
        "location",
        "l1/src/nonce_set.rs:141:13",
    ),
    # action-wire (6 FDEs = 1,104 B)
    (
        "action-wire",
        "std_logic",
        "node115-action-logic-withdraw3-send-1",
        "Withdraw3Action::send_to_exchange (#1)",
        0x246CD10,
        0x246CDC8,
        "e2b_withdraw3_or_vault_transfer_send",
        "location",
        "l1/src/action/withdraw3.rs:17:22",
    ),
    (
        "action-wire",
        "std_logic",
        "node115-action-logic-withdraw3-send-2",
        "Withdraw3Action::send_to_exchange (#2)",
        0x59DA3E0,
        0x59DA498,
        "e2b_withdraw3_or_vault_transfer_send",
        "location",
        "l1/src/action/withdraw3.rs:17:22",
    ),
    (
        "action-wire",
        "std_logic",
        "node115-action-logic-withdraw3-send-3",
        "Withdraw3Action::send_to_exchange (#3)",
        0x59DA4A0,
        0x59DA558,
        "e2b_withdraw3_or_vault_transfer_send",
        "location",
        "l1/src/action/withdraw3.rs:17:22",
    ),
    (
        "action-wire",
        "std_logic",
        "node115-action-logic-vault-transfer-send-1",
        "VaultTransferAction::send_to_exchange (#1)",
        0x283C6B0,
        0x283C768,
        "e2b_withdraw3_or_vault_transfer_send",
        "location",
        "l1/src/action/vault_transfer.rs:27:18",
    ),
    (
        "action-wire",
        "std_logic",
        "node115-action-logic-vault-transfer-send-2",
        "VaultTransferAction::send_to_exchange (#2)",
        0x532F980,
        0x532FA38,
        "e2b_withdraw3_or_vault_transfer_send",
        "location",
        "l1/src/action/vault_transfer.rs:27:18",
    ),
    (
        "action-wire",
        "std_logic",
        "node115-action-logic-vault-transfer-send-3",
        "VaultTransferAction::send_to_exchange (#3)",
        0x532FA40,
        0x532FAF8,
        "e2b_withdraw3_or_vault_transfer_send",
        "location",
        "l1/src/action/vault_transfer.rs:27:18",
    ),
    # action-wire: delayed-action & enum classification methods (4 FDEs = 299 B; l1/action/* & l1/action_delayer.rs)
    (
        "action-wire",
        "std_logic",
        "node115-action-logic-action-delay-priority",
        "Action::delay_priority",
        0x36C2FA0,
        0x36C2FF1,
        "e2b_action_delay_priority",
        "rodata_jmptbl",
        "0x79ab60:92",
    ),
    (
        "action-wire",
        "std_logic",
        "node115-action-logic-action-is-not-exempt",
        "Action::is_not_exempt",
        0x36C3000,
        0x36C3028,
        "e2b_action_is_not_exempt",
        "rodata_jmptbl",
        "0x79acd0:92",
    ),
    (
        "action-wire",
        "std_logic",
        "node115-action-logic-action-is-alo-only",
        "Action::is_alo_only",
        0x36C5680,
        0x36C5711,
        "e2b_action_is_alo_only",
        "rodata_jmptbl",
        "0x79b400:92",
    ),
    (
        "action-wire",
        "std_logic",
        "node115-action-logic-batch-modify-delay-secs",
        "BatchModifyAction::delay_secs",
        0x37B9BA0,
        0x37B9BC1,
        "e2b_batch_modify_delay_secs",
        "instr_hex",
        "837e5003",
    ),
]

RODATA_STRINGS = [
    ("chain_ext_invalid_chain", 0x7DE6A6, "invalid chain"),
    ("nonce_set_de_name", 0x7C9582, "NonceSetDe"),
    ("nonce_set_invariant", 0x7C958C, "nonce invariant"),
]


def parse_elf_sections(obj: bytes) -> list[tuple[int, str, int, int, int, int, int, int]]:
    if len(obj) < 64 or obj[:4] != b"\x7fELF":
        return []
    e_shoff = struct.unpack_from("<Q", obj, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", obj, 58)
    if e_shoff == 0 or e_shnum == 0 or e_shstrndx >= e_shnum:
        return []
    shstr_off = struct.unpack_from("<Q", obj, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    out = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, _, _ = (
            struct.unpack_from("<IIQQQQIIQQ", obj, off)
        )
        end = obj.index(b"\x00", shstr_off + sh_name)
        name = obj[shstr_off + sh_name : end].decode("utf-8", "replace")
        out.append((i, name, sh_type, sh_addr, sh_offset, sh_size, sh_link, sh_info))
    return out


def extract_obj_functions(
    obj: bytes, filter_fn
) -> list[tuple[str, bytes, list[dict[str, int]]]]:
    secs = parse_elf_sections(obj)
    if not secs:
        return []
    relas_by_sec: dict[int, list[dict[str, int]]] = {}
    for s in secs:
        if s[2] == 4:  # SHT_RELA
            rs: list[dict[str, int]] = []
            for o in range(s[4], s[4] + s[5], 24):
                r_offset, r_info, r_addend = struct.unpack_from("<QQq", obj, o)
                r_kind = r_info & 0xFFFFFFFF
                rs.append(
                    {
                        "offset": int(r_offset),
                        "width": 8 if r_kind == 1 else 4,
                        "kind": int(r_kind),
                        "addend": int(r_addend),
                    }
                )
            rs.sort(key=lambda r: r["offset"])
            relas_by_sec[s[7]] = rs

    out: list[tuple[str, bytes, list[dict[str, int]]]] = []
    for idx, name, sh_type, _sh_addr, sh_offset, sh_size, _sh_link, _sh_info in secs:
        if sh_type != 1 or not name.startswith(".text.") or sh_size == 0:
            continue
        if not filter_fn(name):
            continue
        body = obj[sh_offset : sh_offset + sh_size]
        rels = [r for r in relas_by_sec.get(idx, []) if 0 <= r["offset"] < sh_size]
        out.append((name, body, rels))
    return out


def is_forbidden_symbol(sym: str) -> bool:
    if any(tok in sym for tok in FORBIDDEN_SYMBOL_TOKENS):
        return True
    if "drop_in_place" in sym:
        return True
    if not (
        "e2b_" in sym
        or ("action_logic_jem_serde" in sym and "NonceSet" in sym and "deserialize" in sym)
    ):
        return True
    return False


def compile_sources(
    jem_target_dir: Path | None = None,
) -> tuple[dict[str, list[tuple[str, bytes, list[dict[str, int]]]]], str]:
    ver = subprocess.check_output(["rustc", "+1.95.0", "--version"], text=True).strip()
    pools: dict[str, list[tuple[str, bytes, list[dict[str, int]]]]] = {
        "std_logic": [],
        "jem_serde": [],
    }

    with tempfile.TemporaryDirectory(prefix="node115_action_std_") as td:
        tmp = Path(td)
        subprocess.run(
            [
                "rustc", "+1.95.0", "--edition=2021", "--crate-name", "e2b_lib",
                "--crate-type=lib", "-C", "opt-level=3", "-C", "overflow-checks=yes",
                "-C", "lto=thin", str(STD_LOGIC_DIR / "e2b_lib.rs"),
                "-o", str(tmp / "libe2b_lib.rlib"),
            ],
            cwd=tmp,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        subprocess.run(
            [
                "rustc", "+1.95.0", "--edition=2021", "--crate-name", "action_logic_std",
                "--extern", f"e2b_lib={tmp / 'libe2b_lib.rlib'}",
                "-C", "opt-level=3", "-C", "overflow-checks=yes", "-C", "lto=thin",
                "-C", "save-temps", str(STD_LOGIC_DIR / "main.rs"),
                "-o", str(tmp / "action_logic_std"),
            ],
            cwd=tmp,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for obj_path in sorted(tmp.glob("*.rcgu.o")):
            pools["std_logic"].extend(
                extract_obj_functions(obj_path.read_bytes(), lambda n: "e2b_" in n)
            )

    tdir = jem_target_dir or Path(
        os.environ.get(
            "ACTION_LOGIC_JEM_TARGET_DIR",
            str(REPO_ROOT / "work" / "target" / "action-logic-jem-serde"),
        )
    )
    deps_dir = tdir / "release" / "deps"
    if deps_dir.exists():
        for old_o in deps_dir.glob("action_logic_jem_serde-*.o"):
            old_o.unlink()

    with tempfile.TemporaryDirectory(prefix="node115_action_jem_") as jtd:
        jroot = Path(jtd)
        (jroot / "src").mkdir(parents=True)
        for rel in ("Cargo.toml", "Cargo.lock", "src/main.rs"):
            (jroot / rel).write_bytes((JEM_SERDE_DIR / rel).read_bytes())

        env = os.environ.copy()
        env["CARGO_TARGET_DIR"] = str(tdir)
        env["CARGO_BUILD_JOBS"] = env.get("CARGO_BUILD_JOBS", "4")
        env["RUSTFLAGS"] = "-C save-temps"
        subprocess.run(
            [
                "cargo", "+1.95.0", "build", "--release", "--offline", "--locked",
                "--manifest-path", str(jroot / "Cargo.toml"),
            ],
            env=env,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    for obj_path in sorted(deps_dir.glob("action_logic_jem_serde-*.o")):
        pools["jem_serde"].extend(
            extract_obj_functions(
                obj_path.read_bytes(),
                lambda n: "action_logic_jem_serde" in n and "NonceSet" in n and "deserialize" in n,
            )
        )

    if not pools["std_logic"] or not pools["jem_serde"]:
        raise AssertionError("ThinLTO build produced empty function pool")
    return pools, ver


def load_fde_map() -> dict[int, int]:
    fdes: dict[int, int] = {}
    with FDE_TSV_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2 and parts[0].startswith("0x"):
                fdes[int(parts[0], 16)] = int(parts[1], 16)
    return fdes


def load_rela_dyn_map(binary: bytes) -> dict[int, int]:
    secs = parse_elf_sections(binary)
    rela_map: dict[int, int] = {}
    for _idx, name, _st, _addr, sh_offset, sh_size, _l, _i in secs:
        if name == ".rela.dyn":
            for o in range(sh_offset, sh_offset + sh_size, 24):
                r_offset, r_info, r_addend = struct.unpack_from("<QQq", binary, o)
                if (r_info & 0xFFFFFFFF) == 8:  # R_X86_64_RELATIVE
                    rela_map[r_offset] = r_addend
            break
    return rela_map


def verify_anchor(
    binary: bytes,
    rela_map: dict[int, int],
    start: int,
    end: int,
    anchor_kind: str,
    anchor_value: str,
) -> None:
    tbytes = binary[TEXT_OFF + (start - TEXT_VA) : TEXT_OFF + (end - TEXT_VA)]
    if anchor_kind == "instr_hex":
        needle = bytes.fromhex(anchor_value)
        if needle not in tbytes:
            raise AssertionError(f"instr_hex anchor {anchor_value!r} missing in 0x{start:x}..0x{end:x}")
        return

    if anchor_kind == "location":
        for i in range(len(tbytes) - 7):
            if tbytes[i] in (0x48, 0x4C) and tbytes[i + 1] == 0x8D and (tbytes[i + 2] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", tbytes, i + 3)[0]
                tgt = (start + i + 7) + disp
                if DATA_REL_RO_VA <= tgt < DATA_REL_RO_VA + DATA_REL_RO_SZ and tgt in rela_map:
                    file_va = rela_map[tgt]
                    if RODATA_VA <= file_va < RODATA_VA + RODATA_SZ:
                        slot_off = DATA_REL_RO_OFF + (tgt - DATA_REL_RO_VA)
                        _fp, flen, line, col = struct.unpack_from("<QQII", binary, slot_off)
                        if 0 < flen < 256:
                            ro_off = RODATA_OFF + (file_va - RODATA_VA)
                            loc_str = f"{binary[ro_off : ro_off + flen].decode('ascii', 'replace')}:{line}:{col}"
                            if loc_str == anchor_value:
                                return
        raise AssertionError(f"location anchor {anchor_value!r} not found in 0x{start:x}")

    if anchor_kind == "rodata_simd_hex":
        needle = bytes.fromhex(anchor_value)
        for i in range(len(tbytes) - 8):
            # 66 0f 74 modrm disp32 (pcmpeqb xmm, [rip+disp32])
            if tbytes[i : i + 3] == b"\x66\x0f\x74" and (tbytes[i + 3] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", tbytes, i + 4)[0]
                tgt = (start + i + 8) + disp
                if RODATA_VA <= tgt < RODATA_VA + RODATA_SZ:
                    ro_off = RODATA_OFF + (tgt - RODATA_VA)
                    if binary[ro_off : ro_off + len(needle)] == needle:
                        return
        raise AssertionError(f"rodata_simd_hex anchor {anchor_value!r} not found in 0x{start:x}")

    if anchor_kind == "rodata_jmptbl":
        va_s, count_s = anchor_value.split(":")
        jt_va = int(va_s, 16)
        count = int(count_s)
        found_ref = False
        for i in range(len(tbytes) - 7):
            if tbytes[i] in (0x48, 0x4C) and tbytes[i + 1] == 0x8D and (tbytes[i + 2] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", tbytes, i + 3)[0]
                if (start + i + 7) + disp == jt_va:
                    found_ref = True
                    break
        if not found_ref:
            raise AssertionError(f"rodata_jmptbl ref 0x{jt_va:x} not found in 0x{start:x}")
        ro_off = RODATA_OFF + (jt_va - RODATA_VA)
        for idx in range(count):
            rel = struct.unpack_from("<i", binary, ro_off + idx * 4)[0]
            dst = jt_va + rel
            if not (start <= dst < end):
                raise AssertionError(
                    f"rodata_jmptbl 0x{jt_va:x}[{idx}] -> 0x{dst:x} outside 0x{start:x}..0x{end:x}"
                )
        return

    raise AssertionError(f"unknown anchor_kind: {anchor_kind}")


def _to_int(val: object) -> int | None:
    if isinstance(val, int) and not isinstance(val, bool):
        return val
    if isinstance(val, str):
        s = val.strip()
        if s.startswith(("0x", "0X")):
            try:
                return int(s, 16)
            except ValueError:
                return None
        if s.isdigit():
            return int(s)
    return None


def _collect_json_intervals(obj: object, out: list[tuple[int, int]]) -> None:
    if isinstance(obj, dict):
        s: int | None = None
        e: int | None = None
        for sk, ek in (
            ("start", "end"),
            ("start_va", "end_va"),
            ("start_addr", "end_addr"),
            ("va_start", "va_end"),
            ("fde_start", "fde_end"),
            ("node115_start", "node115_end"),
        ):
            if sk in obj and ek in obj:
                s, e = _to_int(obj[sk]), _to_int(obj[ek])
                break
        if s is None:
            for sk, lk in (
                ("start", "size"),
                ("start_va", "size"),
                ("va", "size"),
                ("va", "len"),
                ("start", "length"),
                ("start_va", "bytes"),
                ("start_va", "size_bytes"),
                ("fde_start", "fde_size"),
            ):
                if sk in obj and lk in obj:
                    sv, lv = _to_int(obj[sk]), _to_int(obj[lk])
                    if sv is not None and lv is not None and sv >= TEXT_VA and 0 < lv < 0x1000000:
                        s, e = sv, sv + lv
                        break
        if s is not None and e is not None and s >= TEXT_VA and e > s and (e - s) < 0x1000000:
            out.append((s, e))
        for v in obj.values():
            _collect_json_intervals(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _collect_json_intervals(v, out)


def check_disjointness(windows: list[dict]) -> None:
    # 1. Internal strict disjointness
    intervals = sorted((int(w["start_va"], 16), int(w["end_va"], 16), w["id"]) for w in windows)
    for (s1, e1, id1), (s2, e2, id2) in zip(intervals, intervals[1:]):
        if s2 < e1:
            raise AssertionError(f"internal overlap: {id1} 0x{s1:x}..0x{e1:x} vs {id2} 0x{s2:x}..0x{e2:x}")

    # 2. Wave-7 consolidation-safe check against research/byte-windows.json
    bw = json.loads(BYTE_WINDOWS_PATH.read_text(encoding="utf-8"))
    for ew in bw.get("windows", []):
        bs = _to_int(ew.get("start"))
        be = _to_int(ew.get("end"))
        if bs is None or be is None:
            continue
        is_dep = "dependency" in ew
        for s, e, wid in intervals:
            if s < be and bs < e:
                if (
                    not is_dep
                    and (s, e) == (bs, be)
                    and str(ew.get("id", "")).startswith(("node115-action-logic-", "node115-fp-w"))
                ):
                    continue
                raise AssertionError(
                    f"overlap with research/byte-windows.json ({'dep' if is_dep else 'fp'}): "
                    f"{wid} 0x{s:x}..0x{e:x} vs 0x{bs:x}..0x{be:x} ({ew.get('id')})"
                )

    # 3. Exhaustive sibling compiled-byte / census packet check across all VA key spellings
    own_name = PACKET_DIR.name
    for jpath in sorted(WORK_ITEMS_DIR.glob("*/*.json")):
        pkt = jpath.parent.name
        if pkt == own_name or not any(tag in pkt for tag in SIBLING_PACKET_TAGS):
            continue
        sib_intervals: list[tuple[int, int]] = []
        _collect_json_intervals(json.loads(jpath.read_text(encoding="utf-8")), sib_intervals)
        for bs, be in sib_intervals:
            for s, e, wid in intervals:
                if s < be and bs < e:
                    if (
                        pkt.startswith("RE-001-node115-first-party-wave")
                        and pkt.endswith("-consolidation")
                        and (s, e) == (bs, be)
                    ):
                        continue
                    raise AssertionError(
                        f"overlap with sibling packet {pkt}: {wid} 0x{s:x}..0x{e:x} vs 0x{bs:x}..0x{be:x}"
                    )


def build_records_and_bodies(
    binary: bytes, fdes: dict[int, int], rela_map: dict[int, int], jem_target_dir: Path | None = None
) -> tuple[dict, bytes]:
    pools, rustc_ver = compile_sources(jem_target_dir=jem_target_dir)

    windows: list[dict] = []
    bodies = bytearray()
    by_comp: dict[str, dict[str, int]] = {}
    total_raw = 0
    raw_equal_windows = 0

    for comp, pool_kind, wid, label, start, end, sym_hint, anchor_kind, anchor_val in WINDOW_SPECS:
        size = end - start
        if fdes.get(start) != end:
            raise AssertionError(f"FDE mismatch for {wid}: 0x{start:x}..0x{end:x}")
        verify_anchor(binary, rela_map, start, end, anchor_kind, anchor_val)
        target_bytes = binary[TEXT_OFF + (start - TEXT_VA) : TEXT_OFF + (end - TEXT_VA)]

        best = None
        for sym, cbytes, rels in pools[pool_kind]:
            if len(cbytes) != size or sym_hint not in sym or is_forbidden_symbol(sym):
                continue
            try:
                cmp = bp.compare(cbytes, target_bytes, rels)
            except ValueError:
                continue
            if not cmp["relocation_qualified"]:
                continue
            raw_eq = cmp["raw_equal_bytes"]
            if best is None or raw_eq > best[3]:
                best = (sym, cbytes, rels, raw_eq, cmp)

        if best is None:
            raise AssertionError(f"No 0-diff byte_progress match for {wid} 0x{start:x}..0x{end:x} ({size} B)")

        sym, cbytes, rels, raw_eq, cmp = best
        body_off = len(bodies)
        bodies.extend(cbytes)
        total_raw += raw_eq
        if raw_eq == size:
            raw_equal_windows += 1

        cstats = by_comp.setdefault(comp, {"windows": 0, "bytes": 0, "raw_equal_bytes": 0})
        cstats["windows"] += 1
        cstats["bytes"] += size
        cstats["raw_equal_bytes"] += raw_eq

        windows.append(
            {
                "id": wid,
                "component": comp,
                "pool": pool_kind,
                "label": label,
                "start_va": f"0x{start:x}",
                "end_va": f"0x{end:x}",
                "size": size,
                "body_offset": body_off,
                "raw_equal_bytes": raw_eq,
                "raw_equal": cmp["raw_equal"],
                "relocation_bytes": cmp["relocation_bytes"],
                "non_relocation_bytes": cmp["non_relocation_bytes"],
                "relocations": rels,
                "compiled_section": sym,
                "target_sha256": hashlib.sha256(target_bytes).hexdigest(),
                "compiled_sha256": hashlib.sha256(cbytes).hexdigest(),
                "anchor_kind": anchor_kind,
                "anchor": anchor_val,
            }
        )

    rec = {
        "schema_version": 1,
        "work_item": "RE-010-node115-action-logic-byte-matches",
        "target_binary": {
            "path": EXPECTED_BINARY_PATH,
            "size": EXPECTED_BINARY_SIZE,
            "sha256": EXPECTED_BINARY_SHA256,
        },
        "toolchain": {
            "rustc_version": rustc_ver,
            "edition": "2021",
            "profile": "opt-level=3, overflow-checks=true, lto=thin",
            "jem_allocator": "tikv-jemallocator = \"=0.6.0\"",
        },
        "bodies_file": "bodies.bin",
        "bodies_sha256": hashlib.sha256(bytes(bodies)).hexdigest(),
        "rodata_strings": [
            {"name": name, "va": f"0x{va:x}", "ascii": txt}
            for name, va, txt in RODATA_STRINGS
        ],
        "summary": {
            "windows": len(windows),
            "total_bytes": len(bodies),
            "raw_equal_bytes": total_raw,
            "raw_equal_windows": raw_equal_windows,
            "relocation_qualified_windows": len(windows),
            "by_component": by_comp,
        },
        "windows": windows,
    }
    return rec, bytes(bodies)


def verify_records(
    records: dict,
    bodies: bytes,
    binary: bytes,
    fdes: dict[int, int],
    rela_map: dict[int, int],
) -> None:
    tb = records["target_binary"]
    if len(binary) != tb["size"] or tb["size"] != EXPECTED_BINARY_SIZE:
        raise AssertionError("target binary size mismatch")
    actual_sha = hashlib.sha256(binary).hexdigest()
    if actual_sha != tb["sha256"] or tb["sha256"] != EXPECTED_BINARY_SHA256:
        raise AssertionError("target binary sha256 mismatch")
    if hashlib.sha256(bodies).hexdigest() != records["bodies_sha256"]:
        raise AssertionError("bodies_sha256 mismatch")

    for rs in records["rodata_strings"]:
        va = int(rs["va"], 16)
        want = rs["ascii"].encode("ascii")
        if not (RODATA_VA <= va and va + len(want) <= RODATA_VA + RODATA_SZ):
            raise AssertionError(f"rodata string out of bounds: {rs['name']}")
        got = binary[RODATA_OFF + (va - RODATA_VA) : RODATA_OFF + (va - RODATA_VA) + len(want)]
        if got != want:
            raise AssertionError(f"rodata string mismatch for {rs['name']}: {got!r} != {want!r}")

    windows = records["windows"]
    check_disjointness(windows)

    tot_bytes = tot_raw = raw_wins = 0
    by_comp: dict[str, dict[str, int]] = {}
    for w in windows:
        start = int(w["start_va"], 16)
        end = int(w["end_va"], 16)
        size = int(w["size"])
        boff = int(w["body_offset"])
        if end - start != size or fdes.get(start) != end:
            raise AssertionError(f"FDE mismatch for {w['id']}: 0x{start:x}..0x{end:x}")
        if w["component"] not in ("l1-shared", "action-wire"):
            raise AssertionError(f"unexpected component: {w['component']}")
        if is_forbidden_symbol(w["compiled_section"]):
            raise AssertionError(f"forbidden non-first-party symbol: {w['compiled_section']}")

        verify_anchor(binary, rela_map, start, end, w["anchor_kind"], w["anchor"])

        target_bytes = binary[TEXT_OFF + (start - TEXT_VA) : TEXT_OFF + (end - TEXT_VA)]
        if hashlib.sha256(target_bytes).hexdigest() != w["target_sha256"]:
            raise AssertionError(f"target_sha256 mismatch for {w['id']}")

        cbytes = bodies[boff : boff + size]
        if len(cbytes) != size or hashlib.sha256(cbytes).hexdigest() != w["compiled_sha256"]:
            raise AssertionError(f"compiled body mismatch for {w['id']}")

        try:
            cmp = bp.compare(cbytes, target_bytes, w["relocations"])
        except ValueError as exc:
            raise AssertionError(f"byte_progress.compare rejected {w['id']}: {exc}") from exc
        if not cmp["relocation_qualified"] or cmp["non_relocation_difference_offsets"]:
            raise AssertionError(
                f"non-reloc byte diffs in {w['id']}: {cmp['non_relocation_difference_offsets'][:6]}"
            )
        if cmp["raw_equal_bytes"] != w["raw_equal_bytes"]:
            raise AssertionError(f"raw_equal_bytes mismatch for {w['id']}")

        tot_bytes += size
        tot_raw += cmp["raw_equal_bytes"]
        if cmp["raw_equal"]:
            raw_wins += 1
        cs = by_comp.setdefault(w["component"], {"windows": 0, "bytes": 0, "raw_equal_bytes": 0})
        cs["windows"] += 1
        cs["bytes"] += size
        cs["raw_equal_bytes"] += cmp["raw_equal_bytes"]

    sm = records["summary"]
    if (
        sm["windows"] != len(windows)
        or sm["total_bytes"] != tot_bytes
        or sm["raw_equal_bytes"] != tot_raw
        or sm["raw_equal_windows"] != raw_wins
        or sm["relocation_qualified_windows"] != len(windows)
        or sm["by_component"] != by_comp
    ):
        raise AssertionError("summary mismatch")


def run_negative_controls(
    records: dict,
    bodies: bytes,
    binary: bytes,
    fdes: dict[int, int],
    rela_map: dict[int, int],
) -> int:
    def mut_drop_reloc(r: dict, b: bytearray) -> None:
        # window 1 (chain_ext_config) has relocations; dropping one must fail
        r["windows"][1]["relocations"] = r["windows"][1]["relocations"][1:]

    def mut_flip_byte(r: dict, b: bytearray) -> None:
        b[0] ^= 0x01
        r["bodies_sha256"] = hashlib.sha256(bytes(b)).hexdigest()
        w0 = r["windows"][0]
        w0["compiled_sha256"] = hashlib.sha256(bytes(b[: w0["size"]])).hexdigest()

    def mut_bad_digest(r: dict, _b: bytearray) -> None:
        r["target_binary"]["sha256"] = "0" * 64

    def mut_bad_fde(r: dict, _b: bytearray) -> None:
        r["windows"][0]["end_va"] = f"0x{int(r['windows'][0]['end_va'], 16) + 1:x}"
        r["windows"][0]["size"] += 1

    def mut_overlap(r: dict, _b: bytearray) -> None:
        r["windows"].append(copy.deepcopy(r["windows"][0]))

    rejected = 0
    for name, fn in (
        ("drop_reloc", mut_drop_reloc),
        ("flip_byte", mut_flip_byte),
        ("bad_binary_digest", mut_bad_digest),
        ("bad_fde_bound", mut_bad_fde),
        ("internal_overlap", mut_overlap),
    ):
        mut_r = copy.deepcopy(records)
        mut_b = bytearray(bodies)
        fn(mut_r, mut_b)
        try:
            verify_records(mut_r, bytes(mut_b), binary, fdes, rela_map)
        except AssertionError:
            rejected += 1
        else:
            raise AssertionError(f"negative control {name!r} was NOT rejected")
    return rejected


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--generate", action="store_true", help="Compile live and write records.json + bodies.bin")
    ap.add_argument("--rebuild", action="store_true", help="Compile live and assert exact match with records.json + bodies.bin")
    ap.add_argument("--self-test", action="store_true", help="Run negative controls in addition to full verification")
    args = ap.parse_args()

    binary = BINARY_PATH.read_bytes()
    fdes = load_fde_map()
    rela_map = load_rela_dyn_map(binary)

    if args.generate:
        rec, bodies = build_records_and_bodies(binary, fdes, rela_map)
        BODIES_PATH.write_bytes(bodies)
        RECORDS_PATH.write_text(json.dumps(rec, indent=2) + "\n", encoding="utf-8")

    records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
    bodies = BODIES_PATH.read_bytes()
    verify_records(records, bodies, binary, fdes, rela_map)

    if args.rebuild:
        rebuilt_rec, rebuilt_bodies = build_records_and_bodies(binary, fdes, rela_map)
        if rebuilt_bodies != bodies:
            raise AssertionError("live ThinLTO rebuild bodies.bin differs from committed bodies.bin")
        if rebuilt_rec["summary"] != records["summary"]:
            raise AssertionError("live ThinLTO rebuild summary differs from committed records.json")
        for rw, lw in zip(records["windows"], rebuilt_rec["windows"]):
            for key in ("id", "component", "start_va", "end_va", "size", "raw_equal_bytes", "relocations", "compiled_sha256", "target_sha256"):
                if rw[key] != lw[key]:
                    raise AssertionError(f"live rebuild mismatch in {rw['id']}.{key}")

    sm = records["summary"]
    bc = sm["by_component"]
    msg = (
        f"PASS: {sm['windows']}/{sm['windows']} relocation-qualified, "
        f"{sm['total_bytes']} B ({sm['raw_equal_bytes']} raw-equal, {sm['raw_equal_windows']} 100%-raw; "
        f"l1-shared {bc['l1-shared']['windows']}w/{bc['l1-shared']['bytes']}B, "
        f"action-wire {bc['action-wire']['windows']}w/{bc['action-wire']['bytes']}B; "
        f"rebuild={args.rebuild})"
    )
    if args.self_test:
        neg = run_negative_controls(records, bodies, binary, fdes, rela_map)
        msg += f", {neg}/{neg} negative controls rejected"
    print(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
