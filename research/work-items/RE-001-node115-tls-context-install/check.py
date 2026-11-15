#!/usr/bin/env python3
"""Replay three exact node115 TLS installation windows; never execute the target."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

ROOT = Path(__file__).resolve().parents[3]
TARGET = ROOT / "artifacts/node/115/hl-node"
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
FRAME = (0x15d6fd0, 0x15d8447)
# Literal instruction expectations transcribed from GNU objdump, not a decoder
# or reconstructed implementation. No relocation/operand normalization.
WINDOWS = {
    0x15d7146: bytes.fromhex(
        "49c7c6d0eeffff 644c8b3c2500000000 4d01f7 64410fb64648 "
        "83f801 0f8424010000"),
    0x15d7276: bytes.fromhex(
        "488d3593817004 4c89ff ff158a92f004 6441c6464801"),
    0x15d728c: bytes.fromhex(
        "6449833e00 0f8520010000 6449c706ffffffff "
        "488bb424a0000000 488b8424a8000000 ba01000000 b901000000 "
        "f0480fc108 4883fe01 750a 4885c9 7910 e9970d0000 "
        "4885c9 0f888e0d0000 31d2 64498b4e08 64498b7610 "
        "6449895608 6449894610 6449ff06"),
}


def executable_loads(data):
    if data[:7] != bytes.fromhex("7f454c46020101"):
        raise ValueError("expected little-endian ELF64")
    if len(data) < 64 or struct.unpack_from("<H", data, 18)[0] != 62:
        raise ValueError("expected x86-64 ELF header")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    if size < 56 or offset + size * count > len(data):
        raise ValueError("invalid program-header table")
    loads = []
    for i in range(count):
        typ, flags, off, va, _, filesz, memsz, _ = struct.unpack_from(
            "<IIQQQQQQ", data, offset + i * size)
        if typ == 1 and flags & 1:
            if filesz > memsz or off + filesz > len(data):
                raise ValueError("invalid executable PT_LOAD")
            loads.append((va, off, filesz))
    return loads


def mapped_window(data, loads, va, size):
    matches = [off + va - start for start, off, length in loads
               if start <= va and va + size <= start + length]
    if len(matches) != 1:
        raise ValueError("window must have one file-backed executable mapping")
    off = matches[0]
    value = data[off:off + size]
    if len(value) != size:
        raise ValueError("truncated window")
    return off, value


def check_windows(windows):
    if set(windows) != set(WINDOWS):
        raise ValueError("window coordinate set mismatch")
    for va, want in WINDOWS.items():
        if windows[va] != want:
            raise ValueError(f"instruction mismatch at {va:#x}")


def check_frame(text):
    ranges = [(int(a, 16), int(b, 16)) for a, b in
              re.findall(r"FDE[^\n]*pc=([0-9a-f]+)\.\.([0-9a-f]+)", text)]
    if ranges.count(FRAME) != 1:
        raise ValueError("expected one native FDE extent")
    if not all(FRAME[0] <= va and va + len(value) <= FRAME[1]
               for va, value in WINDOWS.items()):
        raise ValueError("window outside frame")


def authenticate(data):
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError("target SHA-256 mismatch")


def inspect(target=TARGET):
    data = Path(target).read_bytes()
    authenticate(data)
    loads = executable_loads(data)
    slices, records = {}, []
    for va, want in WINDOWS.items():
        off, value = mapped_window(data, loads, va, len(want))
        slices[va] = value
        records.append({"va": hex(va), "file_offset": hex(off),
                        "bytes": value.hex(), "size": len(value),
                        "sha256": hashlib.sha256(value).hexdigest()})
    check_windows(slices)
    frames = subprocess.run(["readelf", "--debug-dump=frames", str(target)],
                            check=True, capture_output=True, text=True).stdout
    check_frame(frames)
    frame_line = next(line for line in frames.splitlines()
                      if "pc=00000000015d6fd0..00000000015d8447" in line)
    return {"target_sha256": SHA256, "coordinates": "ELF virtual addresses",
            "frame": frame_line, "windows": records,
            "compared_bytes": sum(map(len, WINDOWS.values())),
            "selected_windows": len(WINDOWS), "normalization": "none",
            "target_executed": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=TARGET)
    print(json.dumps(inspect(parser.parse_args().target), indent=2))
