"""Checker for the RE-001-node115-bool-display-shim-143ddc0 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-node115-bool-display-shim-143ddc0/verify.py

Checks, in order: the work binary digest against the provenance entry;
MANIFEST.sha256 against every packet file; excerpt regeneration
byte-for-byte against a fresh objdump run; every excerpt instruction
byte-for-byte against the raw binary; spot instructions byte-for-byte;
the trailing int3 padding; the FDE range in frames.txt against a fresh
frame dump; the relocation evidence (the single R_X86_64_RELATIVE that
installs the routine pointer at .data.rel.ro slot 0x63f53d0, the
R_X86_64_RELATIVE that fills the .got tail slot 0x64df720 with the
callee address 0x167fa70, and the absence of any relocation inside the
routine body); the census (0 direct calls, 0 direct tail-jumps, exactly
one stored qword at file offset 0x9898, exactly one RELATIVE addend);
the semantic records; the model self-test; an INDEPENDENT raw-byte
decoder/emulator that walks the two input cases straight out of the
instruction bytes and resolves the string operands and tail target
against the live ELF image; and negative/corruption controls that must
fail on a mutated image. Prints ALL CHECKS PASSED on success, else
raises.
"""

import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

ROUTINE_START, ROUTINE_STOP = 0x143DDC0, 0x143DDF2
NEXT_FDE = 0x143DE00
WINDOWS = [("main.txt", ROUTINE_START, ROUTINE_STOP)]

SPOT_BYTES = {
    0x143DDC0: "4889f0",               # mov %rsi,%rax
    0x143DDC3: "803f00",               # cmpb $0x0,(%rdi)
    0x143DDC6: "7415",                 # je 143dddd
    0x143DDC8: "488d3509c201ff",       # lea 0x459fd8(%rip),%rsi
    0x143DDCF: "ba04000000",           # mov $0x4,%edx
    0x143DDD4: "4889c7",               # mov %rax,%rdi
    0x143DDD7: "ff254319 0a05".replace(" ", ""),  # jmp *0x64df720(%rip)
    0x143DDDD: "488d3563b403ff",       # lea 0x479247(%rip),%rsi
    0x143DDE4: "ba05000000",           # mov $0x5,%edx
    0x143DDE9: "4889c7",               # mov %rax,%rdi
    0x143DDEC: "ff252e190a05",         # jmp *0x64df720(%rip)
}

INSTALL_SLOT = 0x63F53D0       # where the routine pointer is installed
TAIL_SLOT = 0x64DF720          # .got slot both arms jump through
TAIL_TARGET = 0x167FA70        # RELATIVE addend filling the .got slot
STORED_QWORD_OFFSET = 0x9898

EXPECTED_MANIFEST = {
    "README.md", "records.json", "main.txt", "frames.txt",
    "relocations.txt", "callers.tsv", "export_excerpts.py",
    "census.py", "verify.py", "model.py",
}

LINE_RE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t(.*))?$")


def fail(message):
    raise AssertionError(message)


# --- ELF image mapping -------------------------------------------------

def seg_params(data):
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, p_flags, p_offset, p_vaddr, _pp, p_filesz,
         _pm, _pa) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1 and p_flags & 1:
            return p_offset, p_vaddr, p_filesz
    fail("no executable LOAD segment")


def sections(data):
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)

    def sh(i):
        return struct.unpack_from("<IIQQQQIIQQ", data,
                                  e_shoff + i * e_shentsize)
    strtab_off = sh(e_shstrndx)[4]

    def name(off):
        end = data.index(b"\0", strtab_off + off)
        return data[strtab_off + off:end].decode()
    out = []
    for i in range(e_shnum):
        n, t, fl, addr, off, size, lk, inf, al, ent = sh(i)
        out.append((name(n), addr, off, size))
    return out


def va_to_off(secs, va):
    for name, addr, off, size in secs:
        if addr and off and addr <= va < addr + size:
            return off + (va - addr), name
    return None, None


def vaddr_bytes(data, vaddr, length):
    p_off, p_va, _sz = seg_params(data)
    start = vaddr - p_va + p_off
    return data[start:start + length]


# --- generic structural checks ----------------------------------------

def check_digest():
    actual = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    if actual != DIGEST:
        fail("digest mismatch: %s" % actual)
    provenance = json.loads((ROOT / "provenance" / "artifacts.json").read_text())
    entries = [f for f in provenance["files"]
               if f["path"] == "artifacts/node/115/hl-node"]
    if not entries or entries[0]["sha256"] != DIGEST:
        fail("provenance entry mismatch")


def check_manifest():
    lines = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    if not lines:
        fail("empty manifest")
    seen = set()
    for line in lines:
        digest, name = line.split("  ", 1)
        seen.add(name)
        actual = hashlib.sha256((PACKET / name).read_bytes()).hexdigest()
        if actual != digest:
            fail("manifest mismatch for %s" % name)
    if seen != EXPECTED_MANIFEST:
        fail("manifest file set mismatch: %s" % sorted(seen))


def parse_excerpt(text):
    instructions = []
    for line in text.splitlines():
        match = LINE_RE.match(line)
        if not match:
            continue
        address = int(match.group(1), 16)
        raw = bytes.fromhex(match.group(2).strip())
        mnemonic = (match.group(3) or "").strip()
        if (not mnemonic and instructions
                and address == instructions[-1][0] + len(instructions[-1][1])):
            instructions[-1] = (instructions[-1][0],
                                instructions[-1][1] + raw)
        else:
            instructions.append((address, raw))
    return instructions


def check_excerpts(data):
    for name, start, stop in WINDOWS:
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        stored = (PACKET / name).read_text()
        if text != stored:
            fail("excerpt mismatch for %s" % name)
        for address, raw in parse_excerpt(stored):
            if vaddr_bytes(data, address, len(raw)) != raw:
                fail("excerpt instruction bytes differ at %#x" % address)


def check_spot(data):
    for address, hexbytes in SPOT_BYTES.items():
        want = bytes.fromhex(hexbytes)
        if vaddr_bytes(data, address, len(want)) != want:
            fail("spot byte mismatch at %#x" % address)


def check_padding(data):
    pad = vaddr_bytes(data, ROUTINE_STOP, NEXT_FDE - ROUTINE_STOP)
    if pad != b"\xcc" * len(pad):
        fail("trailing padding is not int3: %s" % pad.hex())


def check_frames():
    dump = subprocess.run(
        ["readelf", "--debug-dump=frames", "work/hl-node-115.bin"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    needed = "pc=000000000143ddc0..000000000143ddf2"
    if needed not in dump:
        fail("FDE range for the routine not found in a fresh frame dump")
    stored = (PACKET / "frames.txt").read_text()
    if needed not in stored:
        fail("frames.txt does not carry the routine FDE line")
    for line in stored.splitlines():
        line = line.strip()
        if line and line not in dump:
            fail("frames.txt line not present in a fresh dump: %s" % line)


def check_relocations():
    text = subprocess.run(["readelf", "-r", "work/hl-node-115.bin"],
                          capture_output=True, text=True,
                          check=True, cwd=ROOT).stdout
    install = [l for l in text.splitlines()
               if ("%x" % INSTALL_SLOT) in l and "RELATIVE" in l
               and l.split()[-1].lstrip("0") == "143ddc0"]
    if len(install) != 1:
        fail("expected exactly one installing RELATIVE record, got %d"
             % len(install))
    tail = [l for l in text.splitlines()
            if ("%x" % TAIL_SLOT) in l and "RELATIVE" in l
            and l.split()[-1].lstrip("0") == ("%x" % TAIL_TARGET)]
    if len(tail) != 1:
        fail("expected exactly one RELATIVE record filling the tail slot, "
             "got %d" % len(tail))
    for line in text.splitlines():
        head = line.split()
        if not head:
            continue
        try:
            off = int(head[0], 16)
        except ValueError:
            continue
        if ROUTINE_START <= off < ROUTINE_STOP:
            fail("unexpected relocation inside the routine body at %#x" % off)
    stored = (PACKET / "relocations.txt").read_text().strip().splitlines()
    if len(stored) != 2:
        fail("relocations.txt must carry exactly the two records")


def check_census(data):
    p_off, p_va, p_sz = seg_params(data)
    calls, jmps = [], []
    for off in range(p_off, p_off + p_sz - 5):
        op = data[off]
        if op not in (0xE8, 0xE9):
            continue
        rel = struct.unpack_from("<i", data, off + 1)[0]
        site = off - p_off + p_va
        if site + 5 + rel == ROUTINE_START:
            (calls if op == 0xE8 else jmps).append(site)
    if calls:
        fail("unexpected direct call sites: %s" % [hex(c) for c in calls])
    if jmps:
        fail("unexpected direct tail-jump sites: %s" % [hex(j) for j in jmps])
    qwords = [off for off in range(0, len(data) - 8, 8)
              if struct.unpack_from("<Q", data, off)[0] == ROUTINE_START]
    if qwords != [STORED_QWORD_OFFSET]:
        fail("stored-qword set mismatch: %s" % [hex(q) for q in qwords])


def check_records():
    records = json.loads((PACKET / "records.json").read_text())
    if records["routine"]["address"] != "0x143ddc0":
        fail("records routine address mismatch")
    if records["routine"]["fde"] != "0x143ddc0..0x143ddf2":
        fail("records FDE mismatch")
    if records["artifact_sha256"] != DIGEST:
        fail("records digest mismatch")
    if records["writes"] != []:
        fail("records writes must be empty")
    census = records["census"]
    if (census["direct_call_count"] != 0
            or census["direct_tail_jump_count"] != 0
            or census["relative_addends"] != 1
            or census["relative_slots"] != ["0x63f53d0"]
            or census["internal_indirect_tail_jumps"] != 2):
        fail("records census mismatch")


def check_model():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "bool_shim_model_143ddc0", PACKET / "model.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    count = module.self_test()
    if count <= 0:
        fail("model self-test ran no assertions")
    if module.TRUE_PTR != 0x459FD8 or module.FALSE_PTR != 0x479247:
        fail("model string addresses mismatch")
    if module.TRUE_LEN != 4 or module.FALSE_LEN != 5:
        fail("model lengths mismatch")
    if module.TAIL_SLOT != TAIL_SLOT:
        fail("model tail slot mismatch")
    return count


# --- independent raw-byte decoder / emulator --------------------------

def emulate_arm(data, secs, bool_byte):
    """Walk the routine's raw bytes for one input and resolve operands.

    Decodes only the instruction forms this routine uses, pulling every
    displacement and immediate straight from the bytes (nothing about
    the strings, lengths or tail target is hard-coded here). Returns a
    dict with the resolved string address, the string bytes read from
    the live image, the length immediate, and the tail-jump target
    address resolved through the .got slot.
    """
    p_off, p_va, _ = seg_params(data)

    def code(va, n):
        return data[va - p_va + p_off: va - p_va + p_off + n]

    ip = ROUTINE_START
    # mov %rsi,%rax
    if code(ip, 3) != b"\x48\x89\xf0":
        fail("decode: entry is not mov %%rsi,%%rax")
    ip += 3
    # cmpb $imm8,(%rdi)
    if code(ip, 2) != b"\x80\x3f":
        fail("decode: expected cmpb (%%rdi)")
    cmp_imm = code(ip + 2, 1)[0]
    ip += 3
    # je rel8
    if code(ip, 1) != b"\x74":
        fail("decode: expected je")
    rel8 = code(ip + 1, 1)[0]
    je_target = ip + 2 + rel8
    ip += 2
    # Select the arm exactly as the hardware would: cmpb sets ZF when
    # (bool_byte & 0xff) == cmp_imm; je takes the branch when ZF set.
    if (bool_byte & 0xFF) == cmp_imm:
        arm_ip = je_target
    else:
        arm_ip = ip  # fall through

    # lea disp32(%rip),%rsi : 48 8d 35 <disp32>
    if code(arm_ip, 3) != b"\x48\x8d\x35":
        fail("decode: arm does not begin with lea ...,%%rsi")
    disp = struct.unpack_from("<i", code(arm_ip + 3, 4), 0)[0]
    str_addr = arm_ip + 7 + disp
    arm_ip += 7
    # mov $imm32,%edx : ba <imm32>
    if code(arm_ip, 1) != b"\xba":
        fail("decode: expected mov imm32,%%edx")
    length = struct.unpack_from("<I", code(arm_ip + 1, 4), 0)[0]
    arm_ip += 5
    # mov %rax,%rdi : 48 89 c7
    if code(arm_ip, 3) != b"\x48\x89\xc7":
        fail("decode: expected mov %%rax,%%rdi")
    arm_ip += 3
    # jmp *disp32(%rip) : ff 25 <disp32>
    if code(arm_ip, 2) != b"\xff\x25":
        fail("decode: expected indirect jmp")
    jdisp = struct.unpack_from("<i", code(arm_ip + 2, 4), 0)[0]
    slot = arm_ip + 6 + jdisp
    # Resolve the tail target through the .got slot (RELATIVE addend).
    slot_off, slot_sec = va_to_off(secs, slot)
    if slot_sec != ".got":
        fail("tail slot %#x is not in .got" % slot)
    tail_target = struct.unpack_from("<Q", data, slot_off)[0]
    # The .got slot's runtime value is written by a RELATIVE record; the
    # static image holds 0, so resolve the target from the relocation.
    if tail_target == 0:
        tail_target = relative_addend_for(slot)

    str_off, str_sec = va_to_off(secs, str_addr)
    str_bytes = data[str_off:str_off + length]
    return {
        "bool_byte": bool_byte,
        "str_addr": str_addr,
        "str_section": str_sec,
        "str_bytes": str_bytes,
        "length": length,
        "tail_slot": slot,
        "tail_target": tail_target,
    }


_REL_CACHE = {}


def relative_addend_for(slot):
    if not _REL_CACHE:
        text = subprocess.run(["readelf", "-r", "work/hl-node-115.bin"],
                              capture_output=True, text=True,
                              check=True, cwd=ROOT).stdout
        for line in text.splitlines():
            if "RELATIVE" not in line:
                continue
            head = line.split()
            try:
                _REL_CACHE[int(head[0], 16)] = int(head[-1], 16)
            except (ValueError, IndexError):
                pass
    return _REL_CACHE.get(slot)


def check_emulation(data, secs):
    """Emulate both arms from the raw bytes and confirm the semantics."""
    true_arm = emulate_arm(data, secs, 0x01)
    false_arm = emulate_arm(data, secs, 0x00)

    if true_arm["str_section"] != ".rodata" or false_arm["str_section"] != ".rodata":
        fail("string operands are not both in .rodata")
    if true_arm["str_bytes"] != b"true":
        fail("non-zero arm string is %r, expected b'true'"
             % true_arm["str_bytes"])
    if false_arm["str_bytes"] != b"false":
        fail("zero arm string is %r, expected b'false'"
             % false_arm["str_bytes"])
    # The immediate length must equal the actual string length.
    if true_arm["length"] != len(b"true"):
        fail("non-zero arm length immediate %d != len('true')"
             % true_arm["length"])
    if false_arm["length"] != len(b"false"):
        fail("zero arm length immediate %d != len('false')"
             % false_arm["length"])
    # Both arms share one tail slot and one resolved target.
    if true_arm["tail_slot"] != TAIL_SLOT or false_arm["tail_slot"] != TAIL_SLOT:
        fail("tail slots differ from the recorded %#x" % TAIL_SLOT)
    if true_arm["tail_target"] != TAIL_TARGET or false_arm["tail_target"] != TAIL_TARGET:
        fail("tail target does not resolve to the recorded %#x" % TAIL_TARGET)
    # Non-canonical non-zero bytes still take the true arm (cmpb vs 0).
    if emulate_arm(data, secs, 0xFF)["str_bytes"] != b"true":
        fail("byte 0xff did not select the true arm")
    return true_arm, false_arm


def check_negative_controls(data, secs):
    """Corruptions that MUST break the emulation, proving it is not vacuous."""
    p_off, p_va, _ = seg_params(data)

    # (1) Flip the compare immediate from 0 to 1: a model that trusted the
    #     byte would now map input 0 to the "true" arm. Confirm the decoder
    #     actually reads the immediate and that flipping it flips the arm.
    mutated = bytearray(data)
    cmp_imm_off = (0x143DDC5) - p_va + p_off  # imm8 of cmpb $0x0,(%rdi)
    assert mutated[cmp_imm_off] == 0x00
    mutated[cmp_imm_off] = 0x01
    arm = emulate_arm(bytes(mutated), secs, 0x00)
    if arm["str_bytes"] != b"true":
        fail("control (1) failed: flipping the cmpb immediate did not flip "
             "the arm selected for input 0")

    # (2) Corrupt the first byte of "true" in .rodata: the string-content
    #     check must now fail (so the b'true' assertion is load-bearing).
    mutated = bytearray(data)
    true_off, _ = va_to_off(secs, 0x459FD8)
    assert data[true_off] == ord("t")
    mutated[true_off] = ord("X")
    corrupted = emulate_arm(bytes(mutated), secs, 0x01)["str_bytes"]
    if corrupted == b"true":
        fail("control (2) failed: corrupting .rodata did not change the "
             "read string")

    # (3) Corrupt the "false" length immediate from 5 to 9: the decoder
    #     must report 9 (it reads the immediate from the bytes), so the
    #     length==len("false") cross-check in check_emulation would now
    #     fail. This proves the length is read, not assumed.
    mutated = bytearray(data)
    len_off = (0x143DDE5) - p_va + p_off  # imm32 of mov $0x5,%edx (false arm)
    assert struct.unpack_from("<I", data, len_off)[0] == 5
    struct.pack_into("<I", mutated, len_off, 9)
    bad = emulate_arm(bytes(mutated), secs, 0x00)
    if bad["length"] != 9:
        fail("control (3) failed: the length immediate was not read from "
             "the bytes")
    if bad["length"] == len(b"false"):
        fail("control (3) failed: the corrupted length still equalled "
             "len('false')")


def main():
    data = BINARY.read_bytes()
    secs = sections(data)
    check_digest()
    check_manifest()
    check_excerpts(data)
    check_spot(data)
    check_padding(data)
    check_frames()
    check_relocations()
    check_census(data)
    check_records()
    model_assertions = check_model()
    true_arm, false_arm = check_emulation(data, secs)
    check_negative_controls(data, secs)
    print("ALL CHECKS PASSED "
          "(model self-test: %d assertions; emulated arms: "
          "true->%r/%d, false->%r/%d; tail target %#x)"
          % (model_assertions,
             true_arm["str_bytes"], true_arm["length"],
             false_arm["str_bytes"], false_arm["length"],
             true_arm["tail_target"]))


if __name__ == "__main__":
    sys.exit(main())
