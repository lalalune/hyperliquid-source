#!/usr/bin/env python3
"""Caller census for the node #115 RocksDB
rocksdb::WritableFileWriter::Sync routine.

WritableFileWriter::Sync(bool) flushes the writer's buffer and
then syncs the underlying file when there is pending data and
the file does not use direct I/O (0x6052800..0x60529ee, 494 B,
main FDE, plus a .cold FDE at 0x60527a6..0x60527fd with a 3-entry
main LSDA). The whole-.text scan finds exactly eleven direct E8
calls, 0 tail jumps, no LEA reference: rocksdb::DBImpl::
SyncClosedLogs (site 0x5ddd278), rocksdb::CompactionOutputs::
WriterSyncClose (site 0x5e1881a), rocksdb::BuildTable (site
0x5e1eed6), rocksdb::BlobLogWriter::Sync (site 0x5e261ac),
rocksdb::DBImpl::Open (sites 0x5e63cce and 0x5e650c7),
rocksdb::DBImpl::WriteToWAL (site 0x5e8a1d2),
rocksdb::CreateFile (site 0x603a9aa), rocksdb::CopyFile (site
0x603bcda), rocksdb::SyncManifest (site 0x603fb3d) and
rocksdb::PersistRocksDBOptions (site 0x60d43ff). The raw scan
finds exactly these eleven candidates, validated by decoding
forward from their enclosing FDE starts (see records.json).

Scans the whole .text of work/hl-node-115.bin for direct E8 calls, E9 tail
jumps and RIP-relative LEA references landing on the target, then
validates every candidate site by decoding forward from its enclosing FDE
start with Capstone: a site only counts when it lands on a real
instruction boundary and the decoded instruction is the expected kind with
the expected target.  This rejects false positives from immediate bytes.

Usage: python3 census.py [--out DIR]   (defaults to the packet directory)
Writes callers.tsv (validated sites) and census.json (summary).
"""
import argparse
import bisect
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
import sync115 as tool  # noqa: E402

HERE = Path(__file__).resolve().parent


def _bin_path():
    for candidate in (Path(__file__).resolve().parents[3] / "work" /
                      "hl-node-115.bin",
                      Path(__file__).resolve().parents[3] /
                      "artifacts" / "node" / "115" / "hl-node"):
        data = open(candidate, "rb").read()
        if hashlib.sha256(data).hexdigest() == tool.ARTIFACT_SHA256:
            return candidate
    raise RuntimeError("node #115 artifact not materialized")


def _load_text(bin_path):
    out = subprocess.check_output(
        ["readelf", "-SW", str(bin_path)]).decode()
    m = re.search(r"\.text\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s+"
                  r"([0-9a-f]+)", out)
    va, off, size = (int(m.group(i), 16) for i in (1, 2, 3))
    data = open(bin_path, "rb").read()
    return va, off, data[off:off + size]


def _fde_map(bin_path):
    out = subprocess.check_output(
        ["readelf", "--debug-dump=frames-interp",
         str(bin_path)]).decode()
    fdes = {}
    for line in out.splitlines():
        mm = re.search(r"FDE.*pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if mm:
            fdes[int(mm.group(1), 16)] = int(mm.group(2), 16)
    return fdes


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(HERE))
    args = parser.parse_args()
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    bin_path = _bin_path()
    text_va, _text_off, text = _load_text(bin_path)
    fdes = _fde_map(bin_path)
    starts = sorted(fdes)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False

    def fde_containing(v):
        i = bisect.bisect_right(starts, v) - 1
        if i < 0:
            return None
        s = starts[i]
        return (s, fdes[s]) if s <= v < fdes[s] else None

    def validate(site, kind):
        fde = fde_containing(site)
        if fde is None:
            return None
        start, end = fde
        o = start - text_va
        for insn in md.disasm(text[o:o + (end - start)], start):
            if insn.address == site:
                if kind == "call" and insn.mnemonic == "call":
                    return insn
                if kind == "jmp" and insn.mnemonic == "jmp":
                    return insn
                if kind == "lea" and insn.mnemonic == "lea":
                    return insn
                return None
            if insn.address > site:
                return None
        return None

    sites = []
    n = len(text)
    for opcode, kind, width in ((0xE8, "call", 5), (0xE9, "jmp", 5)):
        i = 0
        while True:
            i = text.find(bytes([opcode]), i)
            if i < 0 or i + 5 > n:
                break
            disp = struct.unpack_from("<i", text, i + 1)[0]
            site = text_va + i
            if site + width + disp == tool.START:
                if validate(site, kind) is not None:
                    sites.append((site, kind))
            i += 1
    i = 0
    while True:
        i = text.find(b"\x48\x8d", i)
        if i < 0 or i + 7 > n:
            break
        modrm = text[i + 2]
        if modrm & 0xC7 == 0x05:
            disp = struct.unpack_from("<i", text, i + 3)[0]
            site = text_va + i
            if site + 7 + disp == tool.START:
                if validate(site, "lea") is not None:
                    sites.append((site, "lea"))
        i += 1
    by_site = {s: (st, en, name, member, kind)
               for s, st, en, name, member, kind in tool.CALLERS}
    assert sorted(sites) == sorted(
        (s, kind) for s, _, _, _, _, kind in tool.CALLERS), sites
    with open(out_dir / "callers.tsv", "w") as fh:
        fh.write("target\ttarget_name\tkind\tsite\tsite_fde_start\t"
                 "site_fde_end\tinstruction\n")
        for site, kind in sorted(sites):
            st, en, name, _member, _k = by_site[site]
            fh.write(f"0x{tool.START:x}\t"
                     f"rocksdb::WritableFileWriter::Sync\t{kind}\t"
                     f"0x{site:x}\t0x{st:x}\t0x{en:x}\t"
                     f"{kind} 0x{tool.START:x}\n")
    summary = {
        "artifact_sha256": tool.ARTIFACT_SHA256,
        "targets": {
            f"0x{tool.START:x}": {
                "name": "rocksdb::WritableFileWriter::Sync",
                "calls": sum(1 for _, k in sites if k == "call"),
                "jumps": sum(1 for _, k in sites if k == "jmp"),
                "lea_refs": sum(1 for _, k in sites if k == "lea"),
            },
        },
        "validated_sites": len(sites),
    }
    with open(out_dir / "census.json", "w") as fh:
        json.dump(summary, fh, indent=1)
        fh.write("\n")
    print(f"wrote callers.tsv + census.json: {len(sites)} sites")


if __name__ == "__main__":
    main()
