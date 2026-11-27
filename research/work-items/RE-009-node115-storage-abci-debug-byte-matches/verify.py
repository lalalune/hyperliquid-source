#!/usr/bin/env python3
"""Live ThinLTO compiled-byte verifier for RE-009-node115-storage-abci-debug-byte-matches."""

from __future__ import annotations

import argparse
import copy
import glob
import hashlib
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
RECORDS_PATH = HERE / "records.json"
FDE_TSV_PATH = REPO / "work" / "index" / "node-115-fde.tsv"
BYTE_WINDOWS_PATH = REPO / "research" / "byte-windows.json"


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


def parse_obj_sections(obj: bytes) -> tuple[dict[str, tuple[bytes, list[int]]], dict[int, list[int]]]:
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
        o_secs.append((i, obj[o_shstr + sh_name : end].decode("utf-8", "replace"), sh_type, sh_offset, sh_size, sh_info))

    relocs: dict[int, list[int]] = {}
    for _idx, _name, stype, soff, ssz, sinfo in o_secs:
        if stype == 4:
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
    return by_name, relocs


def load_fde_map() -> dict[int, int]:
    fdes: dict[int, int] = {}
    with FDE_TSV_PATH.open("r", encoding="utf-8") as fh:
        for line in fh:
            parts = line.strip().split("\t")
            if len(parts) >= 2 and parts[0].startswith("0x"):
                fdes[int(parts[0], 16)] = int(parts[1], 16)
    return fdes


def compile_source(src_path: Path, flags: list[str]) -> dict[str, tuple[bytes, list[int]]]:
    with tempfile.TemporaryDirectory(prefix="node115-dbg-verify-") as td:
        out_bin = Path(td) / "storage_abci_dbg"
        subprocess.run(
            ["rustc", *flags, str(src_path), "-o", str(out_bin)],
            cwd=td,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        objs = sorted(glob.glob(os.path.join(td, "storage_abci_dbg.storage_abci_dbg.*.rcgu.o")))
        if not objs:
            raise AssertionError("ThinLTO compile produced no rcgu.o object")
        by_name, _ = parse_obj_sections(Path(objs[0]).read_bytes())
        return by_name


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
    for k in ("size", "len", "byte_len", "bytes"):
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

    # byte-windows.json: forbid ANY dependency overlap and ANY partial first-party overlap;
    # allow exact (s, e) == (es, ee) first-party consolidation.
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

    # Sibling byte-match packets: forbid ANY overlap
    for p in sorted(
        glob.glob(str(REPO / "research" / "work-items" / "*byte-matches*" / "records.json"))
        + glob.glob(str(REPO / "research" / "work-items" / "*gate-closure*" / "records.json"))
    ):
        if Path(p).resolve() == RECORDS_PATH.resolve():
            continue
        d = json.loads(Path(p).read_text(encoding="utf-8"))
        for ew in d.get("windows", []):
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

        tot_bytes += sz
        tot_raw += raw_eq

    sm = records["summary"]
    if sm["windows"] != len(windows) or sm["total_bytes"] != tot_bytes or sm["raw_equal_bytes"] != tot_raw:
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
        r["windows"][0]["end_va"] = "0x25eace7"
        r["windows"][0]["size"] = 327

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
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    records = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
    data115 = (REPO / records["target_binary"]["path"]).read_bytes()
    sections115 = parse_elf_sections(data115)
    fdes = load_fde_map()
    compiled = compile_source(HERE / records["source_file"], records["compile_flags"])

    verify_records(records, data115, sections115, fdes, compiled)
    sm = records["summary"]
    msg = (
        f"PASS: {sm['windows']}/{sm['windows']} relocation-qualified, "
        f"{sm['total_bytes']} B ({sm['raw_equal_bytes']} raw-equal; "
        f"storage {sm['storage_windows']}w/{sm['storage_bytes']}B, "
        f"abci {sm['abci_windows']}w/{sm['abci_bytes']}B)"
    )
    if args.self_test:
        neg = run_negative_controls(records, data115, sections115, fdes, compiled)
        msg += f", {neg}/{neg} negative controls rejected"
    print(msg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
