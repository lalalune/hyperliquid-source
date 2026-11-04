#!/usr/bin/env python3
"""Static verifier for the node #115 lu RwLock read-wait packet (RE-001).

Checks the family wait body at 0x5bb1a60 against the node #115 binary
without executing anything: target digest, body hash, FDE range, single
ret, fast-path/acquire/claim/release sites, futex numbers, golden ratio,
GOT resolutions, panic Location file/lines and message, the whole-.text
caller census (0 direct E8, 127 GOT-indirect FF 15 sites, 0
register-indirect slot loads), and the internal call census.
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
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-rwlock-read-wait"

TARGET_SIZE = 105896032
TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
W_START, W_END = 0x5BB1A60, 0x5BB210A
W_RET = 0x5BB20A2
GOLDEN = 0x9E3779B97F4A7C15
TEXT_VA, TEXT_OFF, TEXT_SIZE = 0x1419300, 0x1418300, 0x4FD7700
SELF_SLOT = 0x64E0FD8


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
    ap.add_argument("--hex", default=str(PACKET / "fde1a60.hex"))
    ap.add_argument("--records", default=str(PACKET / "records.json"))
    args = ap.parse_args()

    binary = Path(args.binary)
    data = binary.read_bytes()
    if len(data) != TARGET_SIZE:
        fail(f"binary size {len(data)} != {TARGET_SIZE}")
    if hashlib.sha256(data).hexdigest() != TARGET_SHA:
        fail("binary digest mismatch")

    records = json.loads(Path(args.records).read_text())
    body_rec = records["bodies"]["wait"]
    if body_rec["bytes"] != W_END - W_START or body_rec["range"] != "0x5bb1a60..0x5bb210a":
        fail("records body range/bytes mismatch")
    if body_rec["sha256"] != "95d9b142970398a722b871c66eb3d77a3b06ae45a55333dc5c668b3773f96aac":
        fail("records body sha mismatch")

    hexbody = bytes.fromhex(Path(args.hex).read_text().strip())
    expect = data[W_START - 0x1000:W_END - 0x1000]
    if hexbody != expect:
        fail("hex body does not match binary")
    if hashlib.sha256(hexbody).hexdigest() != body_rec["sha256"]:
        fail("hex body sha mismatch")

    out = run(["objdump", "-d", "-M", "intel",
               f"--start-address=0x{W_START:x}", f"--stop-address=0x{W_END:x}",
               str(binary)])
    instrs = []
    for line in out.splitlines():
        m = re.match(r"\s+([0-9a-f]+):\t([0-9a-f ]+)\t(.*)", line)
        if m and m.group(3).strip():
            instrs.append((int(m.group(1), 16), m.group(3).strip()))
    if len(instrs) != 426:
        fail(f"instruction count {len(instrs)} != 426")
    nops = [x for x in instrs if "nop" in x[1]]
    if len(instrs) - len(nops) != 417:
        fail("instruction count excluding nop mismatch")
    rets = [va for va, ins in instrs if ins.startswith("ret")]
    if rets != [W_RET]:
        fail(f"ret sites {rets} != [0x{W_RET:x}]")

    by_va = dict(instrs)

    def need(va, frag):
        ins = by_va.get(va, "")
        if frag not in ins:
            fail(f"site 0x{va:x}: expected {frag!r}, got {ins!r}")

    need(0x5BB1AEE, "lock cmpxchg")
    need(0x5BB1B4E, "lock cmpxchg")
    need(0x5BB1BB4, "lock cmpxchg")
    need(0x5BB1C37, "lock cmpxchg")
    for va in (0x5BB1C4F, 0x5BB1D42, 0x5BB1D85, 0x5BB1F60, 0x5BB1FCF):
        need(va, "lock xadd")
    need(0x5BB1FC3, "lock and")
    need(0x5BB1F09, "call")
    if "5bb3ca0" not in by_va[0x5BB1F09]:
        fail("handler call target mismatch")
    need(0x5BB1DD0, "mov")
    if "edi,0xca" not in by_va[0x5BB1DD0]:
        fail("untimed futex nr mismatch")
    need(0x5BB1E5C, "mov")
    if "edi,0xca" not in by_va[0x5BB1E5C]:
        fail("timed futex nr mismatch")
    if "0x9e3779b97f4a7c15" not in out.lower() and GOLDEN.to_bytes(8, "little").hex() not in out.lower():
        # golden ratio appears as movabs immediate; check the FDE dump text
        if "9e3779b97f4a7c15" not in out:
            fail("golden ratio constant missing")

    # GOT resolutions via relocations
    relocs = run(["readelf", "-r", str(binary)])
    want_rel = {
        0x64E0FD8: "5bb1a60", 0x64EC148: "64fff28", 0x64EC150: "5bb66b0",
        0x64EC158: "5bb6400", 0x64EC160: "5bb6790", 0x64EC168: "64fff20",
        0x64EC170: "5bb6070",
    }
    for slot, addend in want_rel.items():
        if not re.search(rf"00000{slot:x}\s+0+8\s+R_X86_64_RELATIVE\s+{addend}", relocs):
            fail(f"RELATIVE relocation for slot 0x{slot:x} -> 0x{addend} missing")
    if "64e06b8" not in relocs or "syscall@GLIBC_2.2.5" not in relocs:
        fail("syscall GOT resolution missing")
    if "64e1558" not in relocs or "sched_yield@GLIBC_2.2.5" not in relocs:
        fail("sched_yield GOT resolution missing")

    # Internal call census (GOT-slot comment targets on call lines)
    from collections import Counter
    c = Counter()
    for va, ins in instrs:
        m = re.search(r"# (64[0-9a-f]+)", ins)
        if "call" in ins and m:
            c[m.group(1)] += 1
    expect_calls = {"64ec150": 5, "64ec158": 1, "64ec160": 1, "64ec170": 1,
                    "64e06b8": 1, "64e1558": 1}
    for slot, n in expect_calls.items():
        if c[slot] != n:
            fail(f"internal GOT call count {slot}: {c[slot]} != {n}")
    # syscall register-indirect site: call r13 right after the untimed setup
    if by_va.get(0x5BB1DE7, "") != "call   r13":
        fail("untimed syscall register-indirect call mismatch")
    # Other direct E8 targets inside the FDE
    for va, tgt in ((0x5BB1E8B, "5c842e0"), (0x5BB1ECF, "5c84210"),
                    (0x5BB2005, "5bb5130"), (0x5BB2105, "63f0a50")):
        if tgt not in by_va.get(va, ""):
            fail(f"E8 call at 0x{va:x} target mismatch: {by_va.get(va, '')!r}")
    for slot in ("64df770", "64df848", "64e0820", "64df620"):
        if c[slot] != 1:
            fail(f"panic wrapper GOT call count {slot}: {c[slot]} != 1")

    # Panic message + Location structs (file fields read 0, resolve addends)
    msg = data[0x93FCD4:0x93FCD4 + 28]
    if msg != b"RwLock reader count overflow":
        fail(f"overflow message mismatch: {msg!r}")
    for slot, addend, ln, line, col in (
            (0x64BD230, 0x43BDAE, 67, 707, 30),
            (0x64BD260, 0x44F892, 73, 352, 45),
            (0x64BD278, 0x44F892, 73, 352, 5),
            (0x64BD290, 0x44F892, 73, 363, 23)):
        if not re.search(rf"00000{slot:x}\s+0+8\s+R_X86_64_RELATIVE\s+{addend:x}", relocs):
            fail(f"Location relocation 0x{slot:x} missing")
        off = slot - 0x2000
        ptr, length, ln_no, col_no = struct.unpack_from("<QQII", data, off)
        if ptr != 0 or length != ln or ln_no != line or col_no != col:
            fail(f"Location struct 0x{slot:x} mismatch")
        s = data[addend:addend + ln]
        if (b"raw_rwlock.rs" not in s) and (b"parking_lot.rs" not in s):
            fail(f"Location file string 0x{slot:x} mismatch: {s!r}")

    # Whole-.text caller census via byte scans
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    ff15 = 0
    i = 0
    while True:
        i = text.find(b"\xff\x15", i)
        if i < 0:
            break
        if i + 6 <= len(text):
            disp = struct.unpack_from("<i", text, i + 2)[0]
            if TEXT_VA + i + 6 + disp == SELF_SLOT:
                ff15 += 1
        i += 1
    if ff15 != 127:
        fail(f"GOT-indirect caller count {ff15} != 127")
    loads = 0
    for rex in (0x48, 0x49, 0x4C, 0x4D):
        pat = bytes([rex, 0x8B])
        j = 0
        while True:
            j = text.find(pat, j)
            if j < 0:
                break
            if j + 7 <= len(text) and (text[j + 2] & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", text, j + 3)[0]
                if TEXT_VA + j + 7 + disp == SELF_SLOT:
                    loads += 1
            j += 1
    if loads != 0:
        fail(f"register-indirect slot loads {loads} != 0")
    e8 = 0
    k = 0
    while True:
        k = text.find(b"\xe8", k)
        if k < 0:
            break
        if k + 5 <= len(text):
            rel = struct.unpack_from("<i", text, k + 1)[0]
            if TEXT_VA + k + 5 + rel == W_START:
                e8 += 1
        k += 1
    if e8 != 0:
        fail(f"direct E8 caller count {e8} != 0")

    print(f"Verified node #115 lu RwLock read-wait packet: wait "
          f"0x{W_START:x}..0x{W_END:x} ({W_END - W_START}B, "
          f"{len(instrs)} instructions, single ret), "
          f"futex wait x2, RwLock overflow panic, "
          f"0 direct callers, 127 GOT sites")


if __name__ == "__main__":
    main()
