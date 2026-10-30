#!/usr/bin/env python3
"""Generate the RE-013 visor lifecycle static-evidence record.

This tool is deliberately offline and stdlib-only.  It reads, but never maps
or executes, the captured visor.  Claims are limited to pinned bytes, decoded
RIP-relative references/calls, dynamic relocations, and exact FDE extents.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import struct
from pathlib import Path
from typing import Optional

from state_roots import Elf, EvidenceError, containing, fde_index, relative_relocs

EXPECTED_SHA256 = "89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31"
ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts/visor/captured/hl-visor"

# Extents come from the decoded FDE pc_begin/pc_range, not adjacency guesses.
RANGES = {
    "download-and-artifact-verification": (0x4148B0, 0x4155A2),
    "metadata-and-artifact-selection": (0x415620, 0x416CCE),
    "download-transport-adapter": (0x416CD0, 0x416E50),
    "signature-quorum-and-publication": (0x416F30, 0x41718A),
    "gpg-failure-adapter": (0x4172E0, 0x417342),
    "command-output-helper": (0x42A290, 0x42A4C2),
    "freeze-readiness-policy": (0x5B41B0, 0x5B470D),
    "child-termination": (0x5E2D70, 0x5E334E),
    "visor-child-async-state-machine": (0x5E44C0, 0x5EA1C1),
    "std-process-spawn": (0x66F280, 0x6718F9),
    "std-process-exec-fallback": (0x671900, 0x671D0D),
}

# Small instruction controls.  They make the report fail closed if any
# instruction carrying a cited observation changes.
CONTROLS = {
    0x4148EE: "4839c8400f97c5400a2e40886c240e",
    0x414AD9: "488d357a35c5ff",                 # /tmp/binary_download_
    0x414E1C: "488d35b171c5ff",                 # gpg --verify
    0x414E75: "e816540100",                     # command-output helper
    0x414E94: "4d85f60f84ec0300004c89f7",       # success/error split
    0x414EB3: "ff1557073d00807c241001",         # cleanup result test
    0x4150E3: "f30f6f8424a8000000f30f6f8c24b8000000660f748c2410020000660f74842400020000660fdbc1660fd7c881f9ffff00000f8535020000",
    0x415350: "488d3d976dc6ffbe14000000e8af09feff", # binary hash mismatch
    0x415698: "488d05d1cf3900",                 # node_metadata.json descriptor
    0x415AA9: "488d05d0cb3900",                 # visor_metadata.json descriptor
    0x416134: "488d3d9b5fc6ffbe18000000e8cbfbfdff", # skipping download
    0x41690D: "488d3daf7ec4ff",                 # index did not increase
    0x41699E: "488d35411fc5ff",                 # hardfork-version diagnostic
    0x416A9B: "488d3d25ccc4ff",                 # unexpected publisher binary
    0x41711B: "488d3d6b4fc6ffbe24000000e8e4ebfdff", # signature quorum failure
    0x5B4573: "488d3d7dacaaff",                 # freeze/readiness deferral
    0x5B45A4: "31dbeb3e84d2",                   # false return branch
    0x5B45C8: "488d35fa2bb0ff488d0d4a0e2200488d7c2428babb000000ff15fa0d23",
    0x5E62A0: "488d357f0fadff",                 # hl-node selection
    0x5E640C: "488d3573bfa7ff488d0d660c1f00488dbc2470030000488d942410010000ff15b0ef1f00",
    0x5E7627: "488d35f8fbacff",                 # hl-node restart path
    0x5E817A: "488d3d35dfa7ff",                 # restarting child
    0x5E8353: "488d35ec7ea7ff",                 # " --version"
    0x5E8CF9: "e882650800",                     # direct spawn call
    0x5E965B: "488d359b16a8ff488d0d4fd91e00488dbc2470010000488d942470030000ff1561bd1f00",
    0x5E9689: "4989879002000041c6872003000000",   # retry-state writes
    0x5E986B: "488d3defb1a7ff488db42470030000ff1588bb1f",
    0x5E3142: "448b63384489e7be09000000ff15ec45200083f8ff0f8547", # SIGKILL
    0x671049: "48833d476c1700000f8446040000488b45d04c8b4008488bb080000000488d7dac488d95f8feffff488d8dd0fcffffff151a6c170048",
    0x6710E5: "488d95f8feffff488d8dd0fcffffff151f6c170085c0745189c3",
}

RIP_REFS = {
    0x414AD9: (0x6805A, "/tmp/binary_download_"),
    0x414E1C: (0x6BFD4, "gpg --verify"),
    0x415350: (0x7C0EE, "binary hash mismatch"),
    0x416134: (0x7C0D6, "skipping binary download"),
    0x41690D: (0x5E7C3, "index did not increase"),
    0x41699E: (0x688E6, "state hardfork version"),
    0x416A9B: (0x636C7, "unexpected publisher binary"),
    0x41711B: (0x7C08D, "signature quorum verification failed"),
    0x5B4573: (0x5F1F7, "not downloading until ready after freeze"),
    0x5B45C8: (0xB71C9, "one minute passed since new binary detected"),
    0x5E62A0: (0xB7226, "hl-node"),
    0x5E640C: (0x62386, "download or verify quorum failed, keeping child running"),
    0x5E7627: (0xB7226, "hl-node"),
    0x5E817A: (0x660B6, "@@ restarting child @@"),
    0x5E8353: (0x60246, " --version"),
    0x5E965B: (0x6ACFD, "failed to spawn child, retrying"),
    0x5E986B: (0x64A61, "@@ successfully restarted child @@"),
}

DIRECT_CALLS = {
    0x414E75: 0x42A290,
    0x414EA0: 0x4172E0,
    0x5E8CF9: 0x66F280,
}

IMPORT_CALLS = {
    0x3A146E: (0x7E5F80, "unlink"),
    0x5E314E: (0x7E7740, "kill"),
    0x5E3192: (0x7E7740, "kill"),
    0x671078: (0x7E7C98, "pidfd_spawnp"),
    0x6710F3: (0x7E7D18, "posix_spawnp"),
    0x671C7F: (0x7E7D70, "execvp"),
}

DATA_RELOCS = {
    0x7B2670: (0x7C0B1, "node_metadata.json", 18),
    0x7B2680: (0x7C0C3, "visor_metadata.json", 19),
}

RELATIVE_CALL_SLOTS = {
    0x414CA9: (0x7E5E58, 0x396750, "32-byte digest helper"),
    0x414EB3: (0x7E5610, 0x3A13E0, "temporary-file cleanup helper"),
    0x41501C: (0x7E5E58, 0x396750, "32-byte digest helper"),
    0x5E62D1: (0x7E6550, 0x4148B0, "download/verification future"),
    0x5E63B6: (0x7E6558, 0x416F30, "signature-quorum/publication future"),
    0x5E75F5: (0x7E7738, 0x5E2D70, "child termination helper"),
}

DISASSEMBLY_EXPORTS = {
    "download-gpg-gate": (0x414AD9, 0x414EDF),
    "digest-mismatch-gate": (0x4150E3, 0x415366),
    "signature-quorum-publication": (0x416F30, 0x41718A),
    "freeze-readiness": (0x5B44CC, 0x5B45FA),
    "child-download-failure": (0x5E62A0, 0x5E6451),
    "child-kill-retry": (0x5E3142, 0x5E31A1),
    "child-spawn-call": (0x5E8C66, 0x5E8D1C),
    "spawn-backends": (0x671049, 0x67111E),
}


def rip_target(site: int, insn: bytes, disp_offset: int = 3, length: int = 7) -> int:
    """Decode a RIP-relative target from one bounded instruction."""
    if len(insn) < length:
        raise EvidenceError("truncated RIP-relative instruction")
    return site + length + struct.unpack_from("<i", insn, disp_offset)[0]


def direct_call_target(site: int, insn: bytes) -> int:
    if len(insn) < 5 or insn[0] != 0xE8:
        raise EvidenceError("not a complete direct call")
    return site + 5 + struct.unpack_from("<i", insn, 1)[0]


def dynamic_relocations(data: bytes) -> dict[int, tuple[str, int]]:
    """Return relocation slot -> (dynamic symbol, relocation type)."""
    if data[:6] != b"\x7fELF\x02\x01":
        raise EvidenceError("not an ELF64 little-endian file")
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    sh = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize)
          for i in range(shnum)]
    shstr = sh[shstrndx]
    names = data[shstr[4]:shstr[4] + shstr[5]]
    def name_at(i: int) -> str:
        end = names.find(b"\0", i)
        return names[i:end].decode("utf-8", "replace")
    sections = {name_at(x[0]): x for x in sh}
    dynsym = sections[".dynsym"]
    dynstr = sh[dynsym[6]]
    strings = data[dynstr[4]:dynstr[4] + dynstr[5]]
    def symbol(i: int) -> str:
        pos = dynsym[4] + i * dynsym[9]
        noff = struct.unpack_from("<I", data, pos)[0]
        end = strings.find(b"\0", noff)
        return strings[noff:end].decode("utf-8", "replace")
    out = {}
    for sec in sh:
        if sec[1] != 4:  # SHT_RELA
            continue
        for pos in range(sec[4], sec[4] + sec[5], sec[9]):
            slot, info, _addend = struct.unpack_from("<QQq", data, pos)
            out[slot] = (symbol(info >> 32), info & 0xFFFFFFFF)
    return out


def _validate(data: bytes) -> dict:
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECTED_SHA256:
        raise EvidenceError(f"binary sha256 {sha} != {EXPECTED_SHA256}")
    elf = Elf(data)
    starts, ends = fde_index(elf)
    for label, expected in RANGES.items():
        if containing(starts, ends, expected[0]) != expected:
            raise EvidenceError(f"FDE changed for {label}")
    controls = {}
    for va, expected in CONTROLS.items():
        actual = elf.read(va, len(bytes.fromhex(expected)))
        if actual.hex() != expected:
            raise EvidenceError(f"lifecycle instruction changed at {va:#x}")
        controls[hex(va)] = expected
    refs = []
    for site, (target, text) in RIP_REFS.items():
        actual = rip_target(site, elf.read(site, 7))
        if actual != target:
            raise EvidenceError(f"RIP target changed at {site:#x}")
        refs.append({"site_va": hex(site), "target_va": hex(target), "text": text,
                     "fde": [hex(x) for x in containing(starts, ends, site)]})
    calls = []
    for site, target in DIRECT_CALLS.items():
        if direct_call_target(site, elf.read(site, 5)) != target:
            raise EvidenceError(f"direct call changed at {site:#x}")
        calls.append({"site_va": hex(site), "target_va": hex(target), "kind": "direct"})
    dyn = dynamic_relocations(data)
    for site, (slot, name) in IMPORT_CALLS.items():
        insn = elf.read(site, 6)
        if insn[:2] != b"\xff\x15" or rip_target(site, insn, 2, 6) != slot:
            raise EvidenceError(f"import call changed at {site:#x}")
        if dyn.get(slot) != (name, 6):  # R_X86_64_GLOB_DAT
            raise EvidenceError(f"dynamic import changed for {name}")
        calls.append({"site_va": hex(site), "target_slot_va": hex(slot),
                      "dynamic_symbol": name, "kind": "import-indirect"})
    rel = relative_relocs(elf)
    for site, (slot, target, label) in RELATIVE_CALL_SLOTS.items():
        insn = elf.read(site, 6)
        if insn[:2] != b"\xff\x15" or rip_target(site, insn, 2, 6) != slot:
            raise EvidenceError(f"relative call slot changed at {site:#x}")
        if rel.get(slot) != target:
            raise EvidenceError(f"relative function relocation changed at {slot:#x}")
        calls.append({"site_va": hex(site), "target_slot_va": hex(slot),
                      "resolved_target_va": hex(target), "label": label,
                      "kind": "relative-relocation-indirect"})
    data_refs = []
    for slot, (target, text, length) in DATA_RELOCS.items():
        if rel.get(slot) != target or elf.read(slot + 8, 8) != struct.pack("<Q", length):
            raise EvidenceError(f"metadata descriptor changed at {slot:#x}")
        if elf.read(target, length).decode() != text:
            raise EvidenceError(f"metadata literal changed at {target:#x}")
        data_refs.append({"descriptor_va": hex(slot), "target_va": hex(target),
                          "length": length, "text": text})
    range_records = {}
    for label, (start, end) in RANGES.items():
        body = elf.read(start, end - start)
        range_records[label] = {"start_va": hex(start), "end_va": hex(end),
                                "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}
    return {"schema_version": 1, "binary_sha256": sha, "binary_bytes": len(data),
            "captured_binary_executed": False, "ranges": range_records,
            "instruction_controls": controls, "rip_data_references": refs,
            "data_relocations": data_refs, "call_edges": calls}


def generate(binary: Path, output: Path, disassembler: Optional[str] = None) -> dict:
    result = _validate(binary.read_bytes())
    output.mkdir(parents=True, exist_ok=True)
    (output / "lifecycle.json").write_text(json.dumps(result, indent=2) + "\n")
    if disassembler:
        disassembly = output / "disassembly"
        disassembly.mkdir(exist_ok=True)
        for label, (start, end) in DISASSEMBLY_EXPORTS.items():
            command = [disassembler, "-d", f"--start-address={start:#x}",
                       f"--stop-address={end:#x}", str(binary)]
            text = subprocess.run(command, check=True, text=True,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout
            text = text.replace(str(binary), "<authenticated-visor>")
            (disassembly / f"{label}.txt").write_text(text)
    return result


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, default=TARGET)
    p.add_argument("--output", type=Path, default=ROOT / "work/visor-lifecycle")
    p.add_argument("--disassembler", help="optional llvm-objdump/objdump executable")
    args = p.parse_args()
    print(json.dumps(generate(args.binary.resolve(), args.output.resolve(), args.disassembler), indent=2))


if __name__ == "__main__":
    main()
