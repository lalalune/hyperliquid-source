#!/usr/bin/env python3
"""Check the captured serializer and compare its format template with public rustc."""
import hashlib
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections
from fde_extents import eh_frame_records

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET = "x86_64-unknown-linux-gnu"
RUST = ["rustup", "run", "1.95.0", "rustc"]
OBJDUMP = os.environ.get("OBJDUMP", "objdump")


def check(condition, message):
    if not condition:
        raise ValueError(message)


def contents(data, section):
    return data[section["offset"]:section["offset"] + section["size"]]


def compiler_reference(template, native_callback):
    # Each object has one template, hence no ambiguity about its owning function.
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        matches = []
        for precision in (8, 9, 10, 11, 12):
            source, obj = work / "probe.rs", work / "probe.o"
            source.write_text('#[no_mangle] pub fn display(x: f64) -> String { format!("{x:.' +
                              str(precision) + '}") }\n')
            subprocess.run([*RUST, "--target", TARGET, "--crate-type", "lib", "-O",
                            "--emit=obj", str(source), "-o", str(obj)], check=True)
            data = obj.read_bytes()
            section, = [s for s in sections(data) if s["name"] == ".rodata.cst8"]
            relocs = subprocess.check_output([OBJDUMP, "-r", "-j", ".text.display", obj], text=True)
            check("7Display3fmt" in relocs and "format_inner" in relocs, "compiler argument/writer")
            if contents(data, section) == template:
                matches.append(precision)
        check(matches == [10], f"matching precisions: {matches}")

    libdir = subprocess.check_output([*RUST, "--target", TARGET, "--print", "target-libdir"], text=True)
    core, = Path(libdir.strip()).glob("libcore-*.rlib")
    symbols = subprocess.check_output([OBJDUMP, "-t", core], text=True)
    symbol, = re.findall(r"(?m)\bg\s+F\s+\.text\.(\S+3fmt5floatdNt\S+7Display3fmt)\s", symbols)
    sec = ".text." + symbol
    dump = subprocess.check_output([OBJDUMP, "-s", "-j", sec, core], text=True, stderr=subprocess.DEVNULL)
    words = re.findall(r"(?m)^\s*[0-9a-f]+ ((?:[0-9a-f]{8}\s+){1,4})", dump)
    reference = bytes.fromhex(" ".join(words))
    relocs = subprocess.check_output([OBJDUMP, "-r", "-j", sec, core], text=True, stderr=subprocess.DEVNULL)
    sites = re.findall(r"(?m)^([0-9a-f]+)\s+R_X86_64_PLT32\s+(\S+)", relocs)
    check([(int(p, 16), "shortest" if "shortest" in dest else "exact" if "exact" in dest else dest)
           for p, dest in sites] == [(30, "shortest"), (48, "exact")], "float Display relocations")
    normalized = bytearray(native_callback)
    for pos, _ in sites:
        off = int(pos, 16)
        normalized[off:off + 4] = bytes(4)
    check(len(reference) == 52 and normalized == reference, "complete f64 Display callback")


def main():
    data = (ROOT / "artifacts/node/115/hl-node").read_bytes()
    check(hashlib.sha256(data).hexdigest() == DIGEST, "node #115 artifact SHA-256")
    elf = sections(data)
    def read(va, size):
        s, = [s for s in elf if s["type"] != 8 and s["flags"] & 2
              and s["address"] <= va and va + size <= s["address"] + s["size"]]
        start = s["offset"] + va - s["address"]
        return data[start:start + size]

    def opcode(va, encoded):
        expected = bytes.fromhex(encoded)
        check(read(va, len(expected)) == expected, f"instruction at {va:#x}")

    def relative(va, encoded, target):
        opcode(va, encoded)
        disp = va + len(bytes.fromhex(encoded))
        check(disp + 4 + int.from_bytes(read(disp, 4), "little", signed=True) == target,
              f"relative target at {va:#x}")

    fdes = {r["start"]: r["end"] for r in eh_frame_records(data, elf)[1]}
    for start, end in ((0x2ed8270, 0x2ed83bf), (0x2ebfd30, 0x2ebfeb0),
                       (0x2edf980, 0x2edfa63), (0x44a61d0, 0x44a6312),
                       (0x1688740, 0x1688774), (0x2ebf720, 0x2ebf8ac), (0x2eac1f0, 0x2eac3a2)):
        check(fdes[start] == end, f"FDE {start:#x}")
    fields = [
        (b"delegated", 0x641d6b, 0x2ed82a7, 0x2ed82b3, 0x2ed82bb),
        (b"undelegated", 0x641d74, 0x2ed82d8, 0x2ed82e4, 0x2ed82e9),
        (b"totalPendingWithdrawal", 0x641d7f, 0x2ed8302, 0x2ed830e, 0x2ed8313),
        (b"nPendingWithdrawals", 0x641d95, 0x2ed8328, 0x2ed8334, 0x2ed833c),
    ]
    for key, va, lea, length, call in fields:
        check(read(va, len(key)) == key, str(key))
        relative(lea, "488d35", va)
        opcode(length, "ba" + len(key).to_bytes(4, "little").hex())
        relative(call, "e8", 0x2ebf720 if key == b"nPendingWithdrawals" else 0x2ebfd30)
    for va, encoded in ((0x2ed82b8, "4889d9"), (0x2ed82d4, "488d4b08"),
                        (0x2ed82fe, "488d4b10"), (0x2ed8324, "4883c318"), (0x2ed8339, "4889d9"),
                        (0x2edf98c, "f20f1007"), (0x2edf9b5, "c6043022"),
                        (0x2edf9db, "c6043022"), (0x2ebf7a7, "488b33"), (0x2ebf7be, "c604013a"),
                        (0x44a6220, "41807c06ff30"), (0x44a6236, "6641817c06fe2e30"),
                        (0x44a625f, "41813e2d302e30")):
        opcode(va, encoded)
    relative(0x2ebfdea, "e9", 0x2edf980)
    relative(0x2edf995, "ff15", 0x64e5bd8)
    relative(0x2ebf7cc, "e8", 0x2eac1f0)
    relative(0x44a61ea, "488b05", 0x64e0a78)
    relative(0x44a61f6, "488d35", 0x459898)
    relative(0x44a6207, "ff15", 0x64df6e8)
    rela, = [s for s in elf if s["name"] == ".rela.dyn"]
    targets = {off: add for off, kind, add in struct.iter_unpack("<QQq", contents(data, rela)) if kind == 8}
    check([targets[k] for k in (0x64e5bd8, 0x64e0a78, 0x64df6e8)] ==
          [0x44a61d0, 0x1688740, 0x141e3a0], "relative relocations")
    compiler_reference(read(0x459898, 8), read(0x1688740, 52))
    print("7 FDEs, 4 fields, 3 relative relocations; only 10 decimals matched across 5 probes; f64 Display 52 bytes")


if __name__ == "__main__":
    main()
