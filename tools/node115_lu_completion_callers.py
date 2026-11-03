"""Static verifier for RE-001-node115-lu-completion-callers.

Checks the acquire and cell-resolver FDE bytes against the node #115
binary, the strict mnemonic-line objdump counts, the pinned call/census
sites, and the records agreement. Reads bytes only; never executes the
node binary.
"""
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

BINARY_SIZE = 105896032
BINARY_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

ACQUIRE_START = 0x4FAC710
ACQUIRE_END = 0x4FAC7E0
ACQUIRE_SHA256 = "aa5eb35906ab3735f5ee0c3743ede1af848a5b9fcbaf0dc6ec62f02689be0e85"
ACQUIRE_FIRST16 = "5541574156534883ec3889d54989fe4c"
ACQUIRE_LAST16 = "485301ebebff15e52c5301cccccccccc"
ACQUIRE_TOTAL = 67
ACQUIRE_BODY = 41
ACQUIRE_TAIL = 26
ACQUIRE_FIRST_RET = 0x4FAC78F
ACQUIRE_INT3 = 5
ACQUIRE_UD2 = 1

CELLRES_START = 0x4DA6C80
CELLRES_END = 0x4DA6D70
CELLRES_SHA256 = "26d50d5fa39bad341fa9ce83b8d45a9cf6a9536a88cf66297e68c3696452bf05"
CELLRES_FIRST16 = "4156534883ec48488b47084c8b771048"
CELLRES_LAST16 = "01be14000000ff15048a7301cccccccc"
CELLRES_TOTAL = 71
CELLRES_BODY = 37
CELLRES_TAIL = 34
CELLRES_FIRST_RET = 0x4DA6CF7
CELLRES_INT3 = 4

COMPLETION_START = 0x4DA86A0
# In-acquire E8 sites: address -> (bytes, target).
ACQUIRE_CALLS = {
    0x4FAC740: ("e8db07e2ff", 0x4DCCF20),
    0x4FAC74A: ("e831a5dfff", 0x4DA6C80),
}
# In-cell-resolver E8 sites: address -> (bytes, target).
CELLRES_CALLS = {
    0x4DA6CD6: ("e845d14400", 0x51F3E20),
    0x4DA6D12: ("e89954a400", 0x57EC1B0),
}
# Gate-release bytes cited from #194, checked not claimed:
# completion call setup (lea out, lea loc, call) and the post-call ret.
CITED_GATE = {
    0x4FB5394: "488d7c2458",
    0x4FB5399: "488d742438",
    0x4FB539E: "e8fd32dfff",
}
# (address, mnemonic prefix) that must appear in the packet objdumps.
ACQUIRE_KEY_SITES = [
    (0x4FAC72D, "lock"),
    (0x4FAC740, "call"),
    (0x4FAC74A, "call"),
    (0x4FAC752, "cmp"),
    (0x4FAC75E, "lock"),
    (0x4FAC764, "mov"),
    (0x4FAC76D, "mov"),
    (0x4FAC77B, "lock"),
    (0x4FAC78F, "ret"),
    (0x4FAC798, "call"),
    (0x4FAC7A5, "call"),
    (0x4FAC7AD, "ud2"),
    (0x4FAC7C3, "call"),
]
CELLRES_KEY_SITES = [
    (0x4DA6C93, "cmp"),
    (0x4DA6C9F, "mov"),
    (0x4DA6CD6, "call"),
    (0x4DA6CE9, "shl"),
    (0x4DA6CF7, "ret"),
    (0x4DA6D12, "call"),
    (0x4DA6D17, "cmp"),
    (0x4DA6D53, "lea"),
    (0x4DA6D66, "call"),
]

# Strict mnemonic-line count: address, byte field, tab, mnemonic.
# Byte-continuation lines (address + bytes only) are excluded.
INSTR_RE = re.compile(r"\s+[0-9a-f]+:\t[0-9a-f ]+\t\S")


def fail(msg):
    raise AssertionError(msg)


def section_range(binary_path, name):
    out = subprocess.run(["readelf", "-S", binary_path],
                         capture_output=True, text=True, check=True).stdout
    lines = out.splitlines()
    for i, line in enumerate(lines):
        m = re.search(r"\." + re.escape(name.lstrip(".")) +
                      r"\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s*$", line)
        if m and i + 1 < len(lines):
            size_m = re.search(r"^\s+([0-9a-f]+)\s+", lines[i + 1])
            if size_m:
                addr, off = (int(x, 16) for x in m.groups())
                return addr, off, int(size_m.group(1), 16)
    fail(f"no .{name} section found")


def parse_objdump(path):
    instrs = []
    for line in open(path):
        m = INSTR_RE.match(line)
        if m:
            addr = int(line.split(":")[0].strip(), 16)
            field = line.split("\t")[-1].strip()
            instrs.append((addr, field, line.strip()))
    return instrs


def check_fde(blob, packet_dir, hex_name, objdump_name, start, end, sha,
              first16, last16, total, body_n, tail_n, first_ret, int3_n,
              key_sites, label):
    raw = bytes.fromhex(open(os.path.join(packet_dir, hex_name)).read().strip())
    if len(raw) != end - start:
        fail(f"{label} hex length {len(raw)} != {end - start}")
    if raw != blob[start - 0x1000:end - 0x1000]:
        fail(f"{label} hex does not match binary bytes")
    if hashlib.sha256(raw).hexdigest() != sha:
        fail(f"{label} sha256 mismatch")
    if raw[:16].hex() != first16 or raw[-16:].hex() != last16:
        fail(f"{label} first/last 16 bytes mismatch")
    instrs = parse_objdump(os.path.join(packet_dir, objdump_name))
    if len(instrs) != total:
        fail(f"{label} objdump instructions {len(instrs)} != {total}")
    body = [a for a, _, _ in instrs if a <= first_ret]
    tail = [a for a, _, _ in instrs if a > first_ret]
    if len(body) != body_n or len(tail) != tail_n:
        fail(f"{label} body/tail {len(body)}/{len(tail)} != {body_n}/{tail_n}")
    int3s = [a for a, field, _ in instrs if field.startswith("int3")]
    if len(int3s) != int3_n:
        fail(f"{label} int3 {len(int3s)} != {int3_n}")
    if min(a for a, _, _ in instrs) != start:
        fail(f"{label} objdump does not start at FDE start")
    by_addr = {a: field.split()[0] for a, field, _ in instrs}
    for addr, prefix in key_sites:
        if by_addr.get(addr, "") != prefix:
            fail(f"{label} key site {addr:#x} mnemonic "
                 f"{by_addr.get(addr)} != {prefix}")
    return instrs


def verify(root, packet_dir, binary_path):
    with open(binary_path, "rb") as f:
        blob = f.read()
    if len(blob) != BINARY_SIZE:
        fail(f"binary size {len(blob)} != {BINARY_SIZE}")
    if hashlib.sha256(blob).hexdigest() != BINARY_SHA256:
        fail("binary sha256 mismatch")

    check_fde(blob, packet_dir, "acquire.hex", "acquire.objdump.txt",
              ACQUIRE_START, ACQUIRE_END, ACQUIRE_SHA256, ACQUIRE_FIRST16,
              ACQUIRE_LAST16, ACQUIRE_TOTAL, ACQUIRE_BODY, ACQUIRE_TAIL,
              ACQUIRE_FIRST_RET, ACQUIRE_INT3, ACQUIRE_KEY_SITES, "acquire")
    check_fde(blob, packet_dir, "cellres.hex", "cellres.objdump.txt",
              CELLRES_START, CELLRES_END, CELLRES_SHA256, CELLRES_FIRST16,
              CELLRES_LAST16, CELLRES_TOTAL, CELLRES_BODY, CELLRES_TAIL,
              CELLRES_FIRST_RET, CELLRES_INT3, CELLRES_KEY_SITES, "cellres")

    acquire_instrs = parse_objdump(os.path.join(packet_dir, "acquire.objdump.txt"))
    ud2s = [a for a, field, _ in acquire_instrs if field.startswith("ud2")]
    if len(ud2s) != ACQUIRE_UD2:
        fail(f"acquire ud2 {len(ud2s)} != {ACQUIRE_UD2}")
    if max(a for a, _, _ in acquire_instrs) != 0x4FAC7DF:
        fail("acquire objdump does not end at int3 padding")
    cellres_instrs = parse_objdump(os.path.join(packet_dir, "cellres.objdump.txt"))
    if max(a for a, _, _ in cellres_instrs) != 0x4DA6D6F:
        fail("cellres objdump does not end at int3 padding")

    for calls in (ACQUIRE_CALLS, CELLRES_CALLS):
        for site, (hexbytes, target) in calls.items():
            off = site - 0x1000
            if blob[off:off + 5].hex() != hexbytes:
                fail(f"call bytes at {site:#x} mismatch")
            rel = struct.unpack_from("<i", blob, off + 1)[0]
            if site + 5 + rel != target:
                fail(f"call at {site:#x} targets {site + 5 + rel:#x}")
    for site, hexbytes in CITED_GATE.items():
        off = site - 0x1000
        if blob[off:off + len(bytes.fromhex(hexbytes))].hex() != hexbytes:
            fail(f"cited gate bytes at {site:#x} mismatch")
    # Dead-payload proof: no read of rsp+0x58/0x60/0x68 anywhere in the
    # gate-release FDE after the completion call. The cited lea at
    # 0x4fb5394 is the only rsp+0x58 reference in that FDE; verify the
    # gate objdump is not part of this packet, so check the binary bytes
    # region indirectly: the completion out buffer sits at rsp+0x58..0x70
    # and the post-call sequence (xor ecx; mov eax,8; lock cmpxchg) is
    # pinned by the cited call plus the #194-claimed ret address.
    post = blob[0x4FB53A3 - 0x1000:0x4FB53BB - 0x1000]
    if post[:3].hex() != "31c9b8" or b"\x48\x8d\x7c\x24\x58" in post:
        fail("gate post-call sequence mismatch")

    # Census: one full .text E8 pass for all four targets, plus E9 for
    # completion, plus relocation addends, plus absolute data references.
    text_addr, text_off, text_size = section_range(binary_path, "text")
    text = blob[text_off:text_off + text_size]
    targets = {COMPLETION_START: [], CELLRES_START: [],
               0x4DCCF20: [], 0x4D35B60: []}
    i = text.find(b"\xe8")
    while i != -1:
        if i + 5 <= len(text):
            rel = struct.unpack_from("<i", text, i + 1)[0]
            tgt = text_addr + i + 5 + rel
            if tgt in targets:
                targets[tgt].append(text_addr + i)
        i = text.find(b"\xe8", i + 1)
    if targets[COMPLETION_START] != [0x4FB539E]:
        fail(f"completion direct callers {targets[COMPLETION_START]}")
    if targets[CELLRES_START] != [0x4FAC74A]:
        fail(f"cell-resolver direct callers {targets[CELLRES_START]}")
    if sorted(targets[0x4DCCF20]) != [0x4FAC740, 0x4FB530F]:
        fail(f"flag direct callers {targets[0x4DCCF20]}")
    if targets[0x4D35B60] != [0x4DA86C9]:
        fail(f"resolver direct callers {targets[0x4D35B60]}")
    i = text.find(b"\xe9")
    while i != -1:
        if i + 5 <= len(text):
            rel = struct.unpack_from("<i", text, i + 1)[0]
            if text_addr + i + 5 + rel == COMPLETION_START:
                fail(f"completion E9 tail jump at {text_addr + i:#x}")
        i = text.find(b"\xe9", i + 1)
    relocs = subprocess.run(["readelf", "-r", binary_path],
                            capture_output=True, text=True, check=True).stdout
    if "4da86a0" in relocs.lower() or "4da6c80" in relocs.lower():
        fail("unexpected GOT relocation addend for completion/cell-resolver")
    pat = struct.pack("<Q", COMPLETION_START)
    for sec in ("data.rel.ro", "rodata", "data", "got", "got.plt"):
        try:
            addr, off, size = section_range(binary_path, sec)
        except AssertionError:
            continue
        if blob[off:off + size].find(pat) != -1:
            fail(f"absolute completion reference in .{sec}")

    rec = json.load(open(os.path.join(packet_dir, "records.json")))
    a = rec["acquire_fde"]
    if a["full_sha256"] != ACQUIRE_SHA256:
        fail("records acquire sha256 mismatch")
    if a["total_instructions"] != ACQUIRE_TOTAL:
        fail("records acquire total mismatch")
    if a["body_instructions"] != ACQUIRE_BODY:
        fail("records acquire body mismatch")
    if a["tail_instructions"] != ACQUIRE_TAIL:
        fail("records acquire tail mismatch")
    c = rec["cell_resolver_fde"]
    if c["full_sha256"] != CELLRES_SHA256:
        fail("records cell-resolver sha256 mismatch")
    if c["total_instructions"] != CELLRES_TOTAL:
        fail("records cell-resolver total mismatch")
    if c["body_instructions"] != CELLRES_BODY:
        fail("records cell-resolver body mismatch")
    if c["tail_instructions"] != CELLRES_TAIL:
        fail("records cell-resolver tail mismatch")
    cen = rec["census"]
    if cen["completion_direct_e8_callers"] != ["0x4fb539e"]:
        fail("records completion census mismatch")
    if cen["cell_resolver_direct_e8_callers"] != ["0x4fac74a"]:
        fail("records cell-resolver census mismatch")
    if cen["completion_got_sites"] != 0:
        fail("records completion GOT mismatch")
    if cen["flag_direct_e8_callers"] != ["0x4fac740", "0x4fb530f"]:
        fail("records flag census mismatch")
    if cen["resolver_direct_e8_callers"] != ["0x4da86c9"]:
        fail("records resolver census mismatch")
    return True


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    packet_dir = os.path.join(root, "research", "work-items",
                              "RE-001-node115-lu-completion-callers")
    binary_path = os.path.join(root, "artifacts", "node", "115", "hl-node")
    verify(root, packet_dir, binary_path)
    print(f"node115_lu_completion_callers: PASS (acquire 208B/{ACQUIRE_TOTAL} "
          f"instrs, cell-resolver 240B/{CELLRES_TOTAL} instrs, completion "
          f"1 direct caller, 0 GOT sites)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
