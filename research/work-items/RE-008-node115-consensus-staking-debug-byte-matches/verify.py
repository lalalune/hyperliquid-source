#!/usr/bin/env python3
"""Live ThinLTO compiled-byte verifier for RE-008-node115-consensus-staking-debug-byte-matches."""

from __future__ import annotations

import argparse
import copy
import glob
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(REPO / "tools"))
from node115_thinlto import RUSTC, build_objects

RECORDS_PATH = HERE / "records.json"
FDE_TSV_PATH = REPO / "work" / "index" / "node-115-fde.tsv"
BYTE_WINDOWS_PATH = REPO / "research" / "byte-windows.json"
TARGET_REL = "artifacts/node/115/hl-node"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032

COMPILE_FLAGS = [
    "--edition=2021",
    "--crate-name",
    "consensus_staking_dbg",
    "-C",
    "opt-level=3",
    "-C",
    "overflow-checks=yes",
    "-C",
    "lto=thin",
    "-C",
    "save-temps",
]

# (component, label, rust_symbol_hint, start_va, expected_strings)
SPECS: list[tuple[str, str, str, int, list[str]]] = [
    # consensus: Round::fmt (5 x 293 B) + <&Round as Debug>::fmt (2 x 296 B) = 2,057 B
    ("consensus", "Round::fmt@0x27876b0", "Round", 0x27876B0, ["Round"]),
    ("consensus", "Round::fmt@0x2e2ff10", "Round", 0x2E2FF10, ["Round"]),
    ("consensus", "Round::fmt@0x564d0d0", "Round", 0x564D0D0, ["Round"]),
    ("consensus", "Round::fmt@0x5966390", "Round", 0x5966390, ["Round"]),
    ("consensus", "Round::fmt@0x5aa78c0", "Round", 0x5AA78C0, ["Round"]),
    ("consensus", "<&Round as Debug>::fmt@0x2d487c0", "&Round", 0x2D487C0, ["Round"]),
    ("consensus", "<&Round as Debug>::fmt@0x53d4fc0", "&Round", 0x53D4FC0, ["Round"]),
    # consensus: CommittedRound::fmt (293 B) + <&CommittedRound as Debug>::fmt (296 B) = 589 B
    ("consensus", "CommittedRound::fmt@0x5967b80", "CommittedRound", 0x5967B80, ["CommittedRound"]),
    ("consensus", "<&CommittedRound as Debug>::fmt@0x5941440", "&CommittedRound", 0x5941440, ["CommittedRound"]),
    # consensus: BlockHash::fmt (3 x 293 B) + <&BlockHash as Debug>::fmt (2 x 296 B) = 1,471 B
    ("consensus", "BlockHash::fmt@0x2e336d0", "BlockHash", 0x2E336D0, ["BlockHash"]),
    ("consensus", "BlockHash::fmt@0x59674b0", "BlockHash", 0x59674B0, ["BlockHash"]),
    ("consensus", "BlockHash::fmt@0x5aa9320", "BlockHash", 0x5AA9320, ["BlockHash"]),
    ("consensus", "<&BlockHash as Debug>::fmt@0x2d48690", "&BlockHash", 0x2D48690, ["BlockHash"]),
    ("consensus", "<&BlockHash as Debug>::fmt@0x59408a0", "&BlockHash", 0x59408A0, ["BlockHash"]),
    # consensus: ConsensusTxHash::fmt (3 x 293 B) + <&ConsensusTxHash as Debug>::fmt (2 x 296 B) = 1,471 B
    ("consensus", "ConsensusTxHash::fmt@0x2e39420", "ConsensusTxHash", 0x2E39420, ["ConsensusTxHash"]),
    ("consensus", "ConsensusTxHash::fmt@0x4e05de0", "ConsensusTxHash", 0x4E05DE0, ["ConsensusTxHash"]),
    ("consensus", "ConsensusTxHash::fmt@0x5aaaf60", "ConsensusTxHash", 0x5AAAF60, ["ConsensusTxHash"]),
    ("consensus", "<&ConsensusTxHash as Debug>::fmt@0x2d498f0", "&ConsensusTxHash", 0x2D498F0, ["ConsensusTxHash"]),
    ("consensus", "<&ConsensusTxHash as Debug>::fmt@0x4d99280", "&ConsensusTxHash", 0x4D99280, ["ConsensusTxHash"]),
    # consensus: Qc::fmt (456 B) + <&Qc as Debug>::fmt (459 B) = 915 B
    (
        "consensus",
        "Qc::fmt@0x59660c0",
        "Qc",
        0x59660C0,
        ["Qc", "hardfork", "round", "certified_parent_round", "committed_round", "block_hash", "signatures"],
    ),
    (
        "consensus",
        "<&Qc as Debug>::fmt@0x59406d0",
        "&Qc",
        0x59406D0,
        ["Qc", "hardfork", "round", "certified_parent_round", "committed_round", "block_hash", "signatures"],
    ),
    # consensus: Tc::fmt (256 B)
    ("consensus", "Tc::fmt@0x5966290", "Tc", 0x5966290, ["Tc", "round", "high_qc", "signatures"]),
    # consensus: <&Cert as Debug>::fmt (511 B)
    ("consensus", "<&Cert as Debug>::fmt@0x5941570", "&Cert", 0x5941570, ["Qc", "Tc", "tc", "higher_qc"]),
    # consensus: <&CommitProof as Debug>::fmt (224 B)
    ("consensus", "<&CommitProof as Debug>::fmt@0x4f0dcb0", "&CommitProof", 0x4F0DCB0, ["CommitProof", "child", "grandchild_qc"]),
    # consensus: <&ClientBlock as Debug>::fmt (221 B)
    ("consensus", "<&ClientBlock as Debug>::fmt@0x4f0dd90", "&ClientBlock", 0x4F0DD90, ["ClientBlock", "proof", "txs"]),
    # consensus: <Arc<Proof> as Debug>::fmt (227 B)
    ("consensus", "<Arc<Proof> as Debug>::fmt@0x5aa79f0", "Arc<Proof>", 0x5AA79F0, ["Proof", "signed_block", "commit_proof"]),
    # consensus: Signed::fmt (2 x 221 B = 442 B)
    ("consensus", "Signed::fmt@0x4fb5970", "Signed", 0x4FB5970, ["Signed", "signature", "content"]),
    ("consensus", "Signed::fmt@0x5aaa380", "Signed", 0x5AAA380, ["Signed", "signature", "content"]),
    # staking: NodeIp::fmt (5 x 293 B) + <&NodeIp as Debug>::fmt (2 x 296 B) = 2,057 B
    ("staking", "NodeIp::fmt@0x24b8a80", "NodeIp", 0x24B8A80, ["Ip"]),
    ("staking", "NodeIp::fmt@0x2afce10", "NodeIp", 0x2AFCE10, ["Ip"]),
    ("staking", "NodeIp::fmt@0x2cc9a70", "NodeIp", 0x2CC9A70, ["Ip"]),
    ("staking", "NodeIp::fmt@0x2e220e0", "NodeIp", 0x2E220E0, ["Ip"]),
    ("staking", "NodeIp::fmt@0x5a8b000", "NodeIp", 0x5A8B000, ["Ip"]),
    ("staking", "<&NodeIp as Debug>::fmt@0x26a0fe0", "&NodeIp", 0x26A0FE0, ["Ip"]),
    ("staking", "<&NodeIp as Debug>::fmt@0x5a2d200", "&NodeIp", 0x5A2D200, ["Ip"]),
]


def parse_elf_sections(data: bytes) -> dict[str, tuple[int, int, int]]:
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    shstr_off = struct.unpack_from("<Q", data, e_shoff + e_shstrndx * e_shentsize + 24)[0]
    sections: dict[str, tuple[int, int, int]] = {}
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        sh_name, _sh_type, _sh_flags, sh_addr, sh_offset, sh_size = struct.unpack_from(
            "<IIQQQQ", data, off
        )
        end = data.index(b"\x00", shstr_off + sh_name)
        sections[data[shstr_off + sh_name : end].decode("ascii")] = (sh_addr, sh_offset, sh_size)
    return sections


def parse_obj_sections(obj: bytes) -> dict[str, tuple[bytes, list[int]]]:
    o_shoff = struct.unpack_from("<Q", obj, 0x28)[0]
    o_shentsize, o_shnum, o_shstrndx = struct.unpack_from("<HHH", obj, 0x3A)
    o_shstr = struct.unpack_from("<Q", obj, o_shoff + o_shstrndx * o_shentsize + 24)[0]
    o_secs = []
    for i in range(o_shnum):
        off = o_shoff + i * o_shentsize
        sh_name, sh_type, _sh_flags, _sh_addr, sh_offset, sh_size, _sh_link, sh_info = (
            struct.unpack_from("<IIQQQQII", obj, off)
        )
        end = obj.index(b"\x00", o_shstr + sh_name)
        o_secs.append(
            (i, obj[o_shstr + sh_name : end].decode("utf-8", "replace"), sh_type, sh_offset, sh_size, sh_info)
        )

    relocs: dict[int, list[int]] = {}
    for _idx, _name, stype, soff, ssz, sinfo in o_secs:
        if stype == 4:  # SHT_RELA
            offs: set[int] = set()
            for p in range(soff, soff + ssz, 24):
                r_offset, r_info, _r_addend = struct.unpack_from("<QQq", obj, p)
                width = 8 if (r_info & 0xFFFFFFFF) == 1 else 4
                for k in range(width):
                    offs.add(r_offset + k)
            relocs[sinfo] = sorted(offs)

    by_name: dict[str, tuple[bytes, list[int]]] = {}
    for idx, name, stype, soff, ssz, _sinfo in o_secs:
        if stype == 1 and name.startswith(".text."):
            by_name[name] = (obj[soff : soff + ssz], relocs.get(idx, []))
    return by_name


def load_fde_map() -> dict[int, int]:
    fdes: dict[int, int] = {}
    with FDE_TSV_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2 and parts[0].startswith("0x"):
                fdes[int(parts[0], 16)] = int(parts[1], 16)
    return fdes


def compile_source(src_path: Path, flags: list[str]) -> dict[str, tuple[bytes, list[int]]]:
    return parse_obj_sections(build_objects(src_path, flags)[0])


def extract_interval(w: dict, fdes: dict[int, int]) -> tuple[int, int] | None:
    s = None
    for k in ("start", "start_va", "va_start", "fde_start", "node115_start", "va"):
        if w.get(k) is not None:
            s = w[k]
            break
    if s is None:
        return None
    si = int(s, 16) if isinstance(s, str) else int(s)
    for k in ("end", "end_va", "va_end", "fde_end", "node115_end"):
        if w.get(k) is not None:
            return (si, int(w[k], 16) if isinstance(w[k], str) else int(w[k]))
    for k in ("size", "size_bytes", "len", "byte_len", "bytes"):
        if w.get(k) is not None:
            return (si, si + int(w[k]))
    return (si, fdes[si]) if si in fdes else None


def check_disjointness(windows: list[dict], fdes: dict[int, int]) -> None:
    own: list[tuple[int, int, str]] = []
    for w in windows:
        s = int(w["start_va"], 16)
        e = int(w["end_va"], 16)
        for ps, pe, plabel in own:
            if s < pe and ps < e:
                raise AssertionError(f"internal overlap {w['label']} vs {plabel}")
        own.append((s, e, w["label"]))

    # research/byte-windows.json: forbid ANY dependency overlap and ANY partial first-party overlap;
    # allow exact (s, e) == (es, ee) non-dependency first-party consolidation (Wave 4 safe).
    bw = json.loads(BYTE_WINDOWS_PATH.read_text(encoding="utf-8"))
    for ew in bw.get("windows", []):
        iv = extract_interval(ew, fdes)
        if not iv:
            continue
        es, ee = iv
        is_dep = "dependency" in ew
        for s, e, label in own:
            if s < ee and es < e:
                if is_dep or (s, e) != (es, ee):
                    raise AssertionError(
                        f"overlap with byte-windows.json ({'dep' if is_dep else 'fp'}): "
                        f"{label} 0x{s:x}..0x{e:x} vs 0x{es:x}..0x{ee:x}"
                    )

    # Sibling byte-match / gate-closure packets: forbid ANY overlap
    checked_peers = 0
    for p in sorted(
        glob.glob(str(REPO / "research" / "work-items" / "*byte-matches*" / "records.json"))
        + glob.glob(str(REPO / "research" / "work-items" / "*gate-closure*" / "records.json"))
    ):
        if Path(p).resolve() == RECORDS_PATH.resolve():
            continue
        checked_peers += 1
        d = json.loads(Path(p).read_text(encoding="utf-8"))
        entries = d.get("windows") or d.get("records") or (d if isinstance(d, list) else [])
        for ew in entries:
            if not isinstance(ew, dict):
                continue
            iv = extract_interval(ew, fdes)
            if not iv:
                continue
            es, ee = iv
            for s, e, label in own:
                if s < ee and es < e:
                    raise AssertionError(
                        f"overlap with sibling packet {Path(p).parent.name}: "
                        f"{label} 0x{s:x}..0x{e:x} vs 0x{es:x}..0x{ee:x}"
                    )
    if checked_peers == 0:
        raise AssertionError("expected sibling byte-match packets to check")


def check_rodata_strings_in_fde(
    data115: bytes,
    sections115: dict[str, tuple[int, int, int]],
    s: int,
    e: int,
    expected: list[str],
) -> None:
    """Verify every expected ASCII string is directly targeted by a RIP-relative LEA in [s, e)."""
    text_va, text_off, _ = sections115[".text"]
    ro_va, ro_off, ro_sz = sections115[".rodata"]
    chunk = data115[text_off + (s - text_va) : text_off + (e - text_va)]
    ro_vas: set[int] = set()
    for i in range(len(chunk) - 7):
        if chunk[i] in (0x48, 0x4C) and chunk[i + 1] == 0x8D and (chunk[i + 2] & 0xC7) == 0x05:
            disp = struct.unpack_from("<i", chunk, i + 3)[0]
            va = s + i + 7 + disp
            if ro_va <= va < ro_va + ro_sz:
                ro_vas.add(va)
    for exp in expected:
        eb = exp.encode("ascii")
        if not any(
            va + len(eb) <= ro_va + ro_sz
            and data115[ro_off + (va - ro_va) : ro_off + (va - ro_va) + len(eb)] == eb
            for va in ro_vas
        ):
            raise AssertionError(f"FDE 0x{s:x}..0x{e:x} missing RIP-relative .rodata target for {exp!r}")


def build_records(
    data115: bytes,
    sections115: dict[str, tuple[int, int, int]],
    fdes: dict[int, int],
    compiled: dict[str, tuple[bytes, list[int]]],
) -> dict:
    text_va, text_off, _ = sections115[".text"]
    rustc_ver = subprocess.check_output([*RUSTC, "--version"], text=True).strip()
    src_bytes = (HERE / "main.rs").read_bytes()

    windows = []
    tot_bytes = 0
    tot_raw = 0
    comp_counts = {"consensus": [0, 0], "staking": [0, 0]}

    for comp, label, hint, start_va, exp_strs in SPECS:
        end_va = fdes[start_va]
        sz = end_va - start_va
        tbytes = data115[text_off + (start_va - text_va) : text_off + (end_va - text_va)]

        best = None
        for sec, (cbytes, ro_list) in sorted(compiled.items()):
            if len(cbytes) != sz:
                continue
            ro_set = set(ro_list)
            mism = [i for i in range(sz) if cbytes[i] != tbytes[i] and i not in ro_set]
            if not mism:
                raw_eq = sum(1 for i in range(sz) if cbytes[i] == tbytes[i])
                if best is None or raw_eq > best[0]:
                    best = (raw_eq, sec, cbytes, ro_list)
        if best is None:
            raise AssertionError(f"no 0-mismatch ThinLTO compiled symbol found for {label} (0x{start_va:x}, {sz} B)")
        raw_eq, sec, cbytes, ro_list = best

        check_rodata_strings_in_fde(data115, sections115, start_va, end_va, exp_strs)

        windows.append(
            {
                "component": comp,
                "label": label,
                "symbol_hint": hint,
                "start_va": f"0x{start_va:x}",
                "end_va": f"0x{end_va:x}",
                "size": sz,
                "target_sha256": hashlib.sha256(tbytes).hexdigest(),
                "compiled_section": sec,
                "compiled_sha256": hashlib.sha256(cbytes).hexdigest(),
                "relocation_offsets": ro_list,
                "raw_equal_bytes": raw_eq,
                "expected_rodata_strings": exp_strs,
            }
        )
        tot_bytes += sz
        tot_raw += raw_eq
        comp_counts[comp][0] += 1
        comp_counts[comp][1] += sz

    return {
        "schema_version": 1,
        "work_item": "RE-008-node115-consensus-staking-debug-byte-matches",
        "target_binary": {
            "path": TARGET_REL,
            "size": TARGET_SIZE,
            "sha256": TARGET_SHA256,
        },
        "rustc_version": rustc_ver,
        "compile_flags": COMPILE_FLAGS,
        "source_file": "main.rs",
        "source_sha256": hashlib.sha256(src_bytes).hexdigest(),
        "summary": {
            "windows": len(windows),
            "total_bytes": tot_bytes,
            "raw_equal_bytes": tot_raw,
            "consensus_windows": comp_counts["consensus"][0],
            "consensus_bytes": comp_counts["consensus"][1],
            "staking_windows": comp_counts["staking"][0],
            "staking_bytes": comp_counts["staking"][1],
        },
        "windows": windows,
    }


def verify_records(
    records: dict,
    data115: bytes,
    sections115: dict[str, tuple[int, int, int]],
    fdes: dict[int, int],
    compiled: dict[str, tuple[bytes, list[int]]],
) -> None:
    tb = records["target_binary"]
    if len(data115) != tb["size"]:
        raise AssertionError("target binary size mismatch")
    if hashlib.sha256(data115).hexdigest() != tb["sha256"]:
        raise AssertionError("target binary sha256 mismatch")

    src_bytes = (HERE / records["source_file"]).read_bytes()
    if hashlib.sha256(src_bytes).hexdigest() != records["source_sha256"]:
        raise AssertionError("source_sha256 mismatch")

    text_va, text_off, text_sz = sections115[".text"]
    windows = records["windows"]
    check_disjointness(windows, fdes)

    tot_bytes = 0
    tot_raw = 0
    comp_counts = {"consensus": [0, 0], "staking": [0, 0]}

    for w in windows:
        s = int(w["start_va"], 16)
        e = int(w["end_va"], 16)
        sz = int(w["size"])
        if e - s != sz:
            raise AssertionError(f"size math mismatch for {w['label']}")
        if fdes.get(s) != e:
            raise AssertionError(f"FDE mismatch for {w['label']}: {fdes.get(s)} != 0x{e:x}")
        if not (text_va <= s and e <= text_va + text_sz):
            raise AssertionError(f"out of .text: {w['label']}")

        tbytes = data115[text_off + (s - text_va) : text_off + (e - text_va)]
        if hashlib.sha256(tbytes).hexdigest() != w["target_sha256"]:
            raise AssertionError(f"target_sha256 mismatch for {w['label']}")

        sec = w["compiled_section"]
        if sec not in compiled:
            raise AssertionError(f"missing compiled section {sec} for {w['label']}")
        cbytes, ro_list = compiled[sec]
        if len(cbytes) != sz:
            raise AssertionError(f"compiled size mismatch for {w['label']}: {len(cbytes)} != {sz}")
        if hashlib.sha256(cbytes).hexdigest() != w["compiled_sha256"]:
            raise AssertionError(f"compiled_sha256 mismatch for {w['label']}")
        if ro_list != w["relocation_offsets"]:
            raise AssertionError(f"relocation_offsets mismatch for {w['label']}")

        ro_set = set(ro_list)
        non_reloc = [i for i in range(sz) if cbytes[i] != tbytes[i] and i not in ro_set]
        if non_reloc:
            raise AssertionError(f"non-reloc byte diffs for {w['label']}: {non_reloc[:6]}")
        raw_eq = sum(1 for i in range(sz) if cbytes[i] == tbytes[i])
        if raw_eq != w["raw_equal_bytes"]:
            raise AssertionError(f"raw_equal_bytes mismatch for {w['label']}: {raw_eq} != {w['raw_equal_bytes']}")

        check_rodata_strings_in_fde(data115, sections115, s, e, w["expected_rodata_strings"])

        tot_bytes += sz
        tot_raw += raw_eq
        comp = w["component"]
        comp_counts[comp][0] += 1
        comp_counts[comp][1] += sz

    sm = records["summary"]
    if (
        sm["windows"] != len(windows)
        or sm["total_bytes"] != tot_bytes
        or sm["raw_equal_bytes"] != tot_raw
        or sm["consensus_windows"] != comp_counts["consensus"][0]
        or sm["consensus_bytes"] != comp_counts["consensus"][1]
        or sm["staking_windows"] != comp_counts["staking"][0]
        or sm["staking_bytes"] != comp_counts["staking"][1]
    ):
        raise AssertionError("summary totals mismatch")


def run_negative_controls(
    records: dict,
    data115: bytes,
    sections115: dict[str, tuple[int, int, int]],
    fdes: dict[int, int],
    compiled: dict[str, tuple[bytes, list[int]]],
) -> int:
    def mut_drop_reloc(r: dict) -> None:
        r["windows"][0]["relocation_offsets"] = r["windows"][0]["relocation_offsets"][1:]

    def mut_bad_fde(r: dict) -> None:
        s = int(r["windows"][0]["start_va"], 16)
        sz = int(r["windows"][0]["size"]) + 1
        r["windows"][0]["end_va"] = f"0x{s + sz:x}"
        r["windows"][0]["size"] = sz

    def mut_overlap(r: dict) -> None:
        r["windows"].append(copy.deepcopy(r["windows"][0]))

    def mut_bad_sha(r: dict) -> None:
        r["windows"][0]["target_sha256"] = "0" * 64

    rejected = 0
    for name, fn in [
        ("drop_reloc", mut_drop_reloc),
        ("bad_fde", mut_bad_fde),
        ("internal_overlap", mut_overlap),
        ("bad_target_sha", mut_bad_sha),
    ]:
        mutated = copy.deepcopy(records)
        fn(mutated)
        try:
            verify_records(mutated, data115, sections115, fdes, compiled)
        except AssertionError:
            rejected += 1
        else:
            raise AssertionError(f"negative control {name} was NOT rejected")
    return rejected


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--write", action="store_true", help="regenerate records.json from live ThinLTO build")
    ap.add_argument("--self-test", action="store_true", help="also run negative controls")
    args = ap.parse_args()

    data115 = (REPO / TARGET_REL).read_bytes()
    sections115 = parse_elf_sections(data115)
    fdes = load_fde_map()
    compiled = compile_source(HERE / "main.rs", COMPILE_FLAGS)

    if args.write:
        records = build_records(data115, sections115, fdes, compiled)
        RECORDS_PATH.write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    else:
        records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))

    verify_records(records, data115, sections115, fdes, compiled)
    sm = records["summary"]
    msg = (
        f"PASS: {sm['windows']}/{sm['windows']} relocation-qualified, "
        f"{sm['total_bytes']} B ({sm['raw_equal_bytes']} raw-equal; "
        f"consensus {sm['consensus_windows']}w/{sm['consensus_bytes']}B, "
        f"staking {sm['staking_windows']}w/{sm['staking_bytes']}B)"
    )
    if args.self_test:
        neg = run_negative_controls(records, data115, sections115, fdes, compiled)
        msg += f", {neg}/{neg} negative controls rejected"
    print(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
