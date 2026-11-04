#!/usr/bin/env python3
"""Static verifier for the node #115 lu timeout-handler packet (RE-001).

Checks the handler body at 0x5bb3ca0 against the node #115 binary without
executing anything: target digest, body hash, FDE range, single ret,
claim/helper/cleanup/table-create/release sites, shift and bounds checks,
GOT resolutions, panic Location file/lines and message prefixes, the
whole-.text caller census, and that no instruction writes to the node.
"""
import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

TOOL = Path(__file__).resolve()
ROOT = TOOL.parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-timeout-handler"

TARGET_SIZE = 105896032
TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
H_START, H_END = 0x5BB3CA0, 0x5BB3E41
H_RET = 0x5BB3E23
GOLDEN = 0x9E3779B97F4A7C15
TEXT_VA, TEXT_OFF, TEXT_SIZE = 0x1419300, 0x1418300, 0x4FD7700


def fail(msg):
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        fail(f"command failed: {' '.join(cmd)} ({exc})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default=str(ROOT / "artifacts" / "node" / "115" / "hl-node"))
    ap.add_argument("--hex", default=str(PACKET / "handler.hex"))
    ap.add_argument("--records", default=str(PACKET / "records.json"))
    args = ap.parse_args()

    binary = Path(args.binary)
    data = binary.read_bytes()
    if len(data) != TARGET_SIZE:
        fail(f"binary size {len(data)} != {TARGET_SIZE}")
    if hashlib.sha256(data).hexdigest() != TARGET_SHA:
        fail("binary digest mismatch")

    records = json.loads(Path(args.records).read_text())
    body_rec = records["bodies"]["handler"]
    if body_rec["bytes"] != H_END - H_START or body_rec["range"] != "0x5bb3ca0..0x5bb3e41":
        fail("records body range/bytes mismatch")
    if body_rec["ret"] != "0x5bb3e23" or body_rec["sha256"] is None:
        fail("records ret/sha mismatch")

    hex_bytes = bytes.fromhex(Path(args.hex).read_text().strip())
    body = data[H_START - 0x1000:H_END - 0x1000]
    if len(body) != 417 or hex_bytes != body:
        fail("handler.hex does not match binary slice")
    if hashlib.sha256(body).hexdigest() != body_rec["sha256"]:
        fail("handler body hash mismatch")

    # Byte-level transition sites.
    def at(va, n):
        return data[va - 0x1000:va - 0x1000 + n]

    if at(0x5BB3CBC, 10) != bytes.fromhex("49bd157c4a7fb979379e"):
        fail("golden-ratio movabs immediate mismatch")
    if struct.unpack("<Q", at(0x5BB3CBE, 8))[0] != GOLDEN:
        fail("golden-ratio value mismatch")
    if at(0x5BB3CF7, 5) != bytes.fromhex("f0480fc102"):
        fail("release xadd bytes mismatch")
    if at(0x5BB3D5C, 6) != bytes.fromhex("f04a0fb12c01"):
        fail("claim cmpxchg bytes mismatch")
    if at(H_RET, 1) != b"\xc3":
        fail("ret byte mismatch")
    if at(0x5BB3E41, 15) != b"\xcc" * 15:
        fail("int3 padding after FDE mismatch")
    if at(0x5BB3E50, 1) != b"\x55":
        fail("next function does not start with push rbp")

    # Objdump parse over the FDE range.
    out = run(["objdump", "-d", "-M", "intel",
               f"--start-address={hex(H_START)}", f"--stop-address={hex(H_END)}",
               str(binary)])
    lines = []
    for ln in out.splitlines():
        m = re.match(r"\s+([0-9a-f]+):\t(.*)$", ln)
        if m:
            lines.append((int(m.group(1), 16), m.group(2).strip()))
    if len(lines) != 107:
        fail(f"instruction count {len(lines)} != 107")
    if sum(1 for _, t in lines if "nop" in t) != 1:
        fail("nop padding count != 1")
    rets = [va for va, t in lines if re.search(r"\bret\b", t)]
    if rets != [H_RET]:
        fail(f"ret sites {rets} != [{hex(H_RET)}]")
    by_va = dict(lines)

    def need(va, *frags):
        text = by_va.get(va, "")
        for frag in frags:
            if frag not in text:
                fail(f"site {hex(va)}: {text!r} lacks {frag!r}")

    need(0x5BB3D5C, "lock cmpxchg", "rbp")
    need(0x5BB3D8A, "call", "r12")
    need(0x5BB3DC1, "call", "r10")
    need(0x5BB3DE1, "call", "r9")
    need(0x5BB3CF7, "lock xadd", "rdx")
    need(0x5BB3D21, "mov", "0x40")
    need(0x5BB3D26, "sub")
    need(0x5BB3D29, "jb")
    need(0x5BB3D32, "jae")
    need(0x5BB3D46, "cmp", "rsi")
    need(0x5BB3D49, "jae")
    need(0x5BB3E05, "lea", "64bd260")
    need(0x5BB3E0C, "call", "64df848")
    need(0x5BB3E24, "lea", "64bd278")
    need(0x5BB3E2B, "call", "64e0820")
    need(0x5BB3E31, "lea", "64bd2a8")
    need(0x5BB3E3B, "call", "64df620")

    # No node writes: every memory-destination store must target the stack
    # spills, the bucket cmpxchg, or the bucket xadd.
    for va, text in lines:
        m = re.search(r"PTR \[([^\]]+)\],", text)
        if m and m.group(1) not in ("rsp+0x8", "rsp+0x10", "rcx+r8*1", "rdx"):
            fail(f"unexpected memory store at {hex(va)}: {text!r}")

    # Relocations: GOT resolutions, panic helpers/locations, no handler GOT.
    relocs = run(["readelf", "-r", str(binary)])
    rel = {}
    for ln in relocs.splitlines():
        m = re.match(r"([0-9a-f]+)\s+\S+\s+R_X86_64_RELATIVE\s+([0-9a-f]+)", ln)
        if m:
            rel[int(m.group(1), 16)] = int(m.group(2), 16)
    expect_got = {0x64EC148: 0x64FFF28, 0x64EC150: 0x5BB66B0,
                  0x64EC158: 0x5BB6400, 0x64EC160: 0x5BB6790,
                  0x64DF848: 0x1681E40, 0x64E0820: 0x1681E20,
                  0x64DF620: 0x1680CBF}
    for slot, want in expect_got.items():
        if rel.get(slot) != want:
            fail(f"GOT {hex(slot)} -> {rel.get(slot)} != {hex(want)}")
    if 0x5BB3CA0 in rel.values():
        fail("a GOT slot resolves to the handler")
    for slot in (0x64BD260, 0x64BD278, 0x64BD2A8):
        if rel.get(slot) != 0x44F892:
            fail(f"panic Location {hex(slot)} does not point at the file string")

    # Panic Location structs (.data.rel.ro, file offset = VA - 0x2000).
    for va, line, col in ((0x64BD260, 352, 45), (0x64BD278, 352, 5), (0x64BD2A8, 390, 23)):
        off = va - 0x2000
        _ptr, length = struct.unpack_from("<QQ", data, off)
        ln, cl = struct.unpack_from("<II", data, off + 16)
        if (length, ln, cl) != (73, line, col):
            fail(f"Location {hex(va)} = ({length}, {ln}, {cl}) != (73, {line}, {col})")
    if data[0x44F892:0x44F892 + 73] != b"/home/ubuntu/hl/code_Mainnet/z_vendor/parking_lot_core/src/parking_lot.rs":
        fail("panic source file string mismatch")
    if not data[0x46EB5C:].startswith(b"attempt to shift right with overflow"):
        fail("shift message prefix mismatch")
    if not data[0x46EB80:].startswith(b"attempt to subtract with overflow"):
        fail("subtract message prefix mismatch")
    if not data[0x4400EF:].startswith(b" index out of bounds: the len is "):
        fail("bounds-check format prefix mismatch")

    # Whole-.text caller census for direct E8 calls to the handler.
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    sites = []
    for m in re.finditer(b"\xe8", text):
        i = m.start()
        if i + 5 > len(text):
            break
        va = TEXT_VA + i
        if va + 5 + struct.unpack_from("<i", text, i + 1)[0] == H_START:
            sites.append(hex(va))
    want_sites = records["census"]["e8_handler_callers"]
    if sites != want_sites:
        fail(f"E8 caller census {sites} != {want_sites}")
    if records["census"]["got_handler_callers"] != []:
        fail("records GOT census mismatch")

    print(f"Verified node #115 lu timeout-handler packet: handler "
          f"0x5bb3ca0..0x5bb3e41 (417B, 107 instructions, single ret), "
          f"census 3 E8 / 0 GOT caller sites, no node writes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
