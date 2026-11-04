#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-nextnode (packet #214).

Checks, against node #115 only (never executes the binary):
  - binary SHA-256 / size
  - the 5 claimed excerpts (hex bytes + objdump lines + strict counts)
  - exact key bytes for claims outside the excerpts
  - call targets for the census sites and key callees
  - whole-.text census for the thunk, sibling thunk and worker
    (E8/E9 byte scan + per-site disassembly targets, .rela.dyn addends)
  - FDE bounds from .eh_frame (objdump --dwarf=frames)
  - MANIFEST.sha256 coverage

Exit 0 only when every check passes.
"""

import hashlib
import re
import struct
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BIN = REPO / "artifacts" / "node" / "115" / "hl-node"
PACKET = REPO / "research" / "work-items" / "RE-001-node115-lu-nextnode"

EXPECT_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECT_SIZE = 105896032

# (name, start VA, end VA, strict mnemonics)
EXCERPTS = [
    ("thunk", 0x63AE260, 0x63AE278, 7),
    ("head", 0x63ADF71, 0x63ADF9D, 9),
    ("valid", 0x63ADFED, 0x63AE014, 11),
    ("kind", 0x63AE014, 0x63AE040, 11),
    ("tail", 0x63AE088, 0x63AE0CF, 18),
]

# Exact bytes for claims outside the excerpts: (VA, hex).
KEY_BYTES = [
    (0x63AE280, "f30f1efa"),          # thunk-B endbr64
    (0x63AE288, "41b901000000"),      # thunk-B: mov $0x1,%r9d
    (0x63AE28E, "6a01"),              # thunk-B: push $0x1
    (0x63ADF40, "4157"),              # worker: push %r15
    (0x63ADF4C, "4589cd"),            # worker: mov %r9d,%r13d (flag6 save)
    (0x63ADF9D, "4885db"),            # worker: test %rbx,%rbx (rbx==0 gate)
    (0x63ADFD1, "4c8b02"),            # worker: mov (%rdx),%r8 (bucket key)
    (0x63ADFD4, "4939c8"),            # worker: cmp %rcx,%r8
    (0x63AE130, "483b8f00010000"),    # worker: cmp 0x100(%rdi),%rcx (cache slot 0)
    (0x63AE070, "a802"),              # worker: test $0x2,%al (flag6!=0 gate bit)
    (0x63AE080, "4d85ed"),            # worker: test %r13,%r13 (arg4!=0 entry check)
    (0x63AE0D3, "4584d2"),            # worker: test %r10b,%r10b (stack7 gate)
    (0x63AE0EF, "0f854bffffff"),      # worker: jne NULL (bit13 mismatch)
    (0x63AE097, "4c8d358a1b1500"),    # worker: lea 0x64ffc28(%rip),%r14
    (0x63AE09E, "41803e00"),          # worker: cmpb $0x0,(%r14)
    (0x63AE0A4, "4131ef"),            # worker: xor %ebp,%r15d
    (0x63AE0A7, "4181e7ff0f0000"),    # worker: and $0xfff,%r15d
]

# (call site VA, expected target VA)
KEY_CALLS = [
    (0x63AE26E, 0x63ADF40),   # thunk-A -> worker
    (0x63AE290, 0x63ADF40),   # thunk-B -> worker
    (0x63AE114, 0x63D9880),   # worker thread==0 detour
    (0x63AE239, 0x63D9700),   # worker miss handler
    (0x63B1BAD, 0x63AE260),   # chain head -> thunk-A
    (0x63B1C0A, 0x63AE260),   # chain retry -> thunk-A
    (0x63B1C75, 0x63AE260),   # chain second-next -> thunk-A
    (0x63B479D, 0x63AE280),   # FDE 0x63b46e0 -> thunk-B
    (0x63AE0C0, 0x63ADB50),   # worker success path -> join
]

# Expected census: target -> (E8 sites, E9 sites)
CENSUS = {
    0x63AE260: ([0x63B1BAD, 0x63B1C0A, 0x63B1C75], []),
    0x63AE280: ([0x63B479D], []),
    0x63ADF40: ([0x63AE26E, 0x63AE290], []),
}

# Expected FDE bounds: start -> (end, size)
FDES = {
    0x63AE260: (0x63AE278, 24),
    0x63AE280: (0x63AE29A, 26),
    0x63ADF40: (0x63AE252, 786),
}

FAILURES = []


def fail(msg):
    FAILURES.append(msg)
    print(f"FAIL: {msg}")


def read_at(data, va, n, base):
    off = va - base
    return data[off:off + n]


def main():
    data = BIN.read_bytes()
    if len(data) != EXPECT_SIZE:
        fail(f"binary size {len(data)} != {EXPECT_SIZE}")
    sha = hashlib.sha256(data).hexdigest()
    if sha != EXPECT_SHA:
        fail("binary sha mismatch")
    else:
        print(f"binary sha ok ({len(data)} bytes)")

    # .text section geometry from objdump -h
    out = subprocess.run(["objdump", "-h", str(BIN)], capture_output=True,
                         text=True, check=True).stdout
    text_vma = text_off = text_size = None
    for line in out.splitlines():
        if ".text" in line:
            p = line.split()
            text_size, text_vma, text_off = int(p[2], 16), int(p[3], 16), int(p[5], 16)
    if text_vma is None:
        fail("no .text section")
        return 1
    text = data[text_off:text_off + text_size]

    def va_bytes(va, n):
        return read_at(data, va, n, 0x1000)

    # --- excerpts ---
    total_bytes = 0
    total_strict = 0
    for name, start, end, want_strict in EXCERPTS:
        raw = va_bytes(start, end - start)
        hexfile = PACKET / f"{name}.hex"
        claimed = bytes.fromhex("".join(hexfile.read_text().split()))
        if claimed != raw:
            fail(f"{name}.hex mismatch")
        total_bytes += len(raw)
        obj = subprocess.run(
            ["objdump", "-d", f"--start-address={hex(start)}",
             f"--stop-address={hex(end)}", str(BIN)],
            capture_output=True, text=True, check=True).stdout
        lines = []
        for line in obj.splitlines():
            m = re.match(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t(.*))?$", line)
            if not m:
                continue
            addr = int(m.group(1), 16)
            if not (start <= addr < end):
                continue
            byts = " ".join(m.group(2).split())
            mnem = (m.group(3) or "").strip()
            lines.append(f"{m.group(1)}:\t{byts}\t{mnem}" if mnem else f"{m.group(1)}:\t{byts}")
        saved = (PACKET / f"{name}.objdump.txt").read_text().splitlines()
        if saved != lines:
            fail(f"{name}.objdump.txt mismatch ({len(saved)} saved vs {len(lines)} regenerated)")
        strict = sum(1 for ln in lines if ln.count("\t") >= 2)
        if strict != want_strict:
            fail(f"{name} strict {strict} != {want_strict}")
        total_strict += strict
    print(f"exhibits ok: {len(EXCERPTS)} excerpts, {total_bytes} bytes, {total_strict} strict")

    # --- key bytes ---
    for va, hx in KEY_BYTES:
        got = va_bytes(va, len(bytes.fromhex(hx)))
        if got.hex() != hx:
            fail(f"key bytes at {hex(va)}: got {got.hex()} want {hx}")
    print(f"key bytes ok: {len(KEY_BYTES)} sites")

    # --- key calls ---
    for site, want in KEY_CALLS:
        b = va_bytes(site, 5)
        if b[0] != 0xE8:
            fail(f"call at {hex(site)} is not E8 (got {b[0]:#x})")
            continue
        tgt = site + 5 + struct.unpack("<i", b[1:5])[0]
        if tgt != want:
            fail(f"call at {hex(site)} targets {hex(tgt)} want {hex(want)}")
    print(f"key calls ok: {len(KEY_CALLS)} calls")

    # --- census: whole-.text E8/E9 scan (find-loop, C speed) ---
    def scan(op):
        hits = {}
        i = text.find(bytes([op]))
        while i != -1:
            va = text_vma + i
            disp = struct.unpack("<i", text[i + 1:i + 5])[0]
            tgt = va + 5 + disp
            if tgt in CENSUS:
                hits.setdefault(tgt, []).append(va)
            i = text.find(bytes([op]), i + 1)
        return hits
    e8hits = scan(0xE8)
    e9hits = scan(0xE9)
    for tgt, (want_e8, want_e9) in CENSUS.items():
        got_e8 = sorted(e8hits.get(tgt, []))
        got_e9 = sorted(e9hits.get(tgt, []))
        if got_e8 != sorted(want_e8):
            fail(f"census E8 for {hex(tgt)}: got {[hex(x) for x in got_e8]} want {[hex(x) for x in want_e8]}")
        if got_e9 != sorted(want_e9):
            fail(f"census E9 for {hex(tgt)}: got {[hex(x) for x in got_e9]} want {[hex(x) for x in want_e9]}")
    # LEA scan (48 8d with modrm rip-relative)
    lea_hits = {t: [] for t in CENSUS}
    i = 0
    while True:
        i = text.find(b"\x48\x8d", i)
        if i == -1:
            break
        if i + 7 <= len(text) and (text[i + 2] & 0xC7) == 0x05:
            disp = struct.unpack("<i", text[i + 3:i + 7])[0]
            va = text_vma + i
            if va + 7 + disp in lea_hits:
                lea_hits[va + 7 + disp].append(va)
        i += 1
    for tgt, sites in lea_hits.items():
        if sites:
            fail(f"census LEA for {hex(tgt)}: {[hex(x) for x in sites]}")
    # .rela.dyn addends
    rel = subprocess.run(["readelf", "-r", str(BIN)], capture_output=True,
                         text=True, check=True).stdout
    in_dyn = False
    rela_count = 0
    dyn_hits = []
    for line in rel.splitlines():
        if line.startswith("Relocation section '.rela.dyn'"):
            in_dyn = True
            m = re.search(r"contains (\d+) entries", line)
            rela_count = int(m.group(1)) if m else 0
            continue
        if line.startswith("Relocation section "):
            in_dyn = False
        if in_dyn:
            for tok in line.split():
                try:
                    v = int(tok, 16)
                except ValueError:
                    continue
                if v in CENSUS:
                    dyn_hits.append((line.strip()[:120], hex(v)))
    if dyn_hits:
        fail(f".rela.dyn addend hits: {dyn_hits}")
    print(f"census ok: thunk-A 3 E8, thunk-B 1 E8, worker 2 E8, 0 E9/LEA/GOT, {rela_count} rela entries")

    # --- FDE bounds ---
    frames = subprocess.run(["objdump", "--dwarf=frames", str(BIN)],
                            capture_output=True, text=True, check=True).stdout
    found = {}
    for line in frames.splitlines():
        m = re.search(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if m:
            s, e = int(m.group(1), 16), int(m.group(2), 16)
            if s in FDES:
                found[s] = (e, e - s)
    for s, (want_e, want_sz) in FDES.items():
        if found.get(s) != (want_e, want_sz):
            fail(f"FDE {hex(s)}: got {found.get(s)} want {(hex(want_e), want_sz)}")
    print("FDE bounds ok: thunk 24B, thunk-B 26B, worker 786B")

    # --- MANIFEST ---
    man = PACKET / "MANIFEST.sha256"
    entries = [ln.split() for ln in man.read_text().splitlines() if ln.strip()]
    import hashlib as _hl
    bad = 0
    for want, relpath in entries:
        p = (PACKET / relpath).resolve() if not relpath.startswith("/") else Path(relpath)
        # MANIFEST paths are relative to the packet dir; tools/tests use ../../../
        if not p.exists():
            p = PACKET / relpath
        got = _hl.sha256(p.read_bytes()).hexdigest()
        if got != want:
            bad += 1
            fail(f"MANIFEST mismatch: {relpath}")
    print(f"MANIFEST ok: {len(entries) - bad}/{len(entries)} entries")

    if FAILURES:
        print(f"verifier: {len(FAILURES)} failure(s)")
        return 1
    print("verifier: all checks passed "
          f"({len(EXCERPTS)} excerpts, {total_strict} strict, "
          f"census 3/1/2 E8 sites, MANIFEST {len(entries)} entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
