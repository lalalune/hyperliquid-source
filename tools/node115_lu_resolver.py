"""Static verifier for RE-001-node115-lu-resolver.

Checks the resolver FDE bytes against the node #115 binary, the strict
mnemonic-line objdump counts, the pinned call/census sites, and the
records agreement. Reads bytes only; never executes the node binary.
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

RESOLVER_START = 0x4D35B60
RESOLVER_END = 0x4D35DE4
RESOLVER_SHA256 = "49457f6b0159d558b0f70375d1bdd6862c47d0d665c54c3ed2e763d65013fed7"
RESOLVER_FIRST16 = "534883ec604889fb488b06488b7e0848"
RESOLVER_LAST16 = "0000004c8943284889d84883c4605bc3"
TOTAL_INSTRS = 134
BODY_INSTRS = 106
TAIL_INSTRS = 28
NOPS = 4
FIRST_RET = 0x4D35D68
SECOND_RET = 0x4D35DE3

# In-resolver leaf-op E8 sites: address -> (bytes, target).
LEAF_CALLS = {
    0x4D35C75: ("e816ebfeff", 0x4D24790),
    0x4D35D5B: ("e830eafeff", 0x4D24790),
}
# Sole direct caller of the resolver: address -> bytes.
RESOLVER_CALLER = {0x4DA86C9: "e892d4f8ff"}
# Completion-helper resolver-call setup bytes (cited, not claimed).
COMPLETION_SPOT = {
    0x4DA86BC: "488d7c2448",
    0x4DA86C1: "488d542407",
}
# (address, mnemonic prefix) that must appear in the packet objdump.
KEY_SITES = [
    (0x4D35B7C, "mov"),
    (0x4D35BA0, "movzx"),
    (0x4D35BD0, "movzx"),
    (0x4D35C4E, "movzx"),
    (0x4D35C75, "call"),
    (0x4D35C99, "movzx"),
    (0x4D35CB0, "movzx"),
    (0x4D35CCC, "mov"),
    (0x4D35CD3, "mov"),
    (0x4D35CDB, "mov"),
    (0x4D35CF1, "and"),
    (0x4D35D20, "mov"),
    (0x4D35D69, "inc"),
    (0x4D35D80, "mov"),
    (0x4D35DC1, "mov"),
    (0x4D35D68, "ret"),
    (0x4D35DE3, "ret"),
]

# Strict mnemonic-line count: address, byte field, tab, mnemonic.
# Byte-continuation lines (address + bytes only) are excluded.
INSTR_RE = re.compile(r"\s+[0-9a-f]+:\t[0-9a-f ]+\t\S")


def fail(msg):
    raise AssertionError(msg)


def text_range(binary_path):
    out = subprocess.run(["readelf", "-S", binary_path],
                         capture_output=True, text=True, check=True).stdout
    lines = out.splitlines()
    for i, line in enumerate(lines):
        m = re.search(r"\.text\s+PROGBITS\s+([0-9a-f]+)\s+([0-9a-f]+)\s*$", line)
        if m and i + 1 < len(lines):
            size_m = re.search(r"^\s+([0-9a-f]+)\s+", lines[i + 1])
            if size_m:
                addr, off = (int(x, 16) for x in m.groups())
                return addr, off, int(size_m.group(1), 16)
    fail("no .text section found")


def parse_objdump(path):
    instrs = []
    for line in open(path):
        m = INSTR_RE.match(line)
        if m:
            addr = int(line.split(":")[0].strip(), 16)
            field = line.split("\t")[-1].strip()
            instrs.append((addr, field, line.strip()))
    return instrs


def verify(root, packet_dir, binary_path):
    with open(binary_path, "rb") as f:
        blob = f.read()
    if len(blob) != BINARY_SIZE:
        fail(f"binary size {len(blob)} != {BINARY_SIZE}")
    if hashlib.sha256(blob).hexdigest() != BINARY_SHA256:
        fail("binary sha256 mismatch")

    raw = bytes.fromhex(open(os.path.join(packet_dir, "resolver.hex")).read().strip())
    if len(raw) != RESOLVER_END - RESOLVER_START:
        fail(f"resolver hex length {len(raw)} != 644")
    if raw != blob[RESOLVER_START - 0x1000:RESOLVER_END - 0x1000]:
        fail("resolver hex does not match binary bytes")
    if hashlib.sha256(raw).hexdigest() != RESOLVER_SHA256:
        fail("resolver sha256 mismatch")
    if raw[:16].hex() != RESOLVER_FIRST16 or raw[-16:].hex() != RESOLVER_LAST16:
        fail("resolver first/last 16 bytes mismatch")

    instrs = parse_objdump(os.path.join(packet_dir, "resolver.objdump.txt"))
    if len(instrs) != TOTAL_INSTRS:
        fail(f"objdump instructions {len(instrs)} != {TOTAL_INSTRS}")
    body = [a for a, _, _ in instrs if a <= FIRST_RET]
    tail = [a for a, _, _ in instrs if a > FIRST_RET]
    if len(body) != BODY_INSTRS or len(tail) != TAIL_INSTRS:
        fail(f"body/tail {len(body)}/{len(tail)} != {BODY_INSTRS}/{TAIL_INSTRS}")
    nops = [a for a, field, _ in instrs if re.search(r"\bnop\b", field)]
    if len(nops) != NOPS:
        fail(f"nops {len(nops)} != {NOPS}")
    if min(a for a, _, _ in instrs) != RESOLVER_START:
        fail("objdump does not start at resolver start")
    if max(a for a, _, _ in instrs) != SECOND_RET:
        fail("objdump does not end at second ret")
    by_addr = {a: field.split()[0] for a, field, _ in instrs}
    for addr, prefix in KEY_SITES:
        if by_addr.get(addr, "") != prefix:
            fail(f"key site {addr:#x} mnemonic {by_addr.get(addr)} != {prefix}")

    for site, (hexbytes, target) in LEAF_CALLS.items():
        off = site - 0x1000
        if blob[off:off + 5].hex() != hexbytes:
            fail(f"leaf-op call bytes at {site:#x} mismatch")
        rel = struct.unpack_from("<i", blob, off + 1)[0]
        if site + 5 + rel != target:
            fail(f"leaf-op call at {site:#x} targets {site + 5 + rel:#x}")
    for site, hexbytes in RESOLVER_CALLER.items():
        off = site - 0x1000
        if blob[off:off + 5].hex() != hexbytes:
            fail(f"resolver caller bytes at {site:#x} mismatch")
    for site, hexbytes in COMPLETION_SPOT.items():
        off = site - 0x1000
        got = blob[off:off + len(bytes.fromhex(hexbytes))].hex()
        if got != hexbytes:
            fail(f"completion spot bytes at {site:#x} mismatch")

    # Census: full .text E8 scan for the resolver, plus GOT relocations.
    text_addr, text_off, text_size = text_range(binary_path)
    text = blob[text_off:text_off + text_size]
    hits = []
    i = text.find(b"\xe8")
    while i != -1:
        if i + 5 <= len(text):
            rel = struct.unpack_from("<i", text, i + 1)[0]
            if text_addr + i + 5 + rel == RESOLVER_START:
                hits.append(text_addr + i)
        i = text.find(b"\xe8", i + 1)
    if hits != sorted(RESOLVER_CALLER):
        fail(f"resolver direct callers {hits} != {sorted(RESOLVER_CALLER)}")
    relocs = subprocess.run(["readelf", "-r", binary_path],
                            capture_output=True, text=True, check=True).stdout
    if "4d35b60" in relocs.lower():
        fail("unexpected GOT relocation addend for resolver")

    rec = json.load(open(os.path.join(packet_dir, "records.json")))
    r = rec["resolver"]
    if r["full_sha256"] != RESOLVER_SHA256:
        fail("records resolver sha256 mismatch")
    if r["total_instructions"] != TOTAL_INSTRS:
        fail("records total instructions mismatch")
    if r["body_instructions"] != BODY_INSTRS or r["tail_instructions"] != TAIL_INSTRS:
        fail("records body/tail mismatch")
    if r["nops"] != NOPS:
        fail("records nops mismatch")
    if rec["census"]["direct_callers"] != ["0x4da86c9"]:
        fail("records census callers mismatch")
    if rec["census"]["got_sites"] != 0:
        fail("records census GOT mismatch")
    sites = {"0x4d35c75": LEAF_CALLS[0x4D35C75][0],
             "0x4d35d5b": LEAF_CALLS[0x4D35D5B][0]}
    for key, hexbytes in sites.items():
        got = None
        for k, v in rec["leaf_op_call_sites"].items():
            if k in ("rightmost_path", "levels_zero_path") and v["site"] == key:
                got = v["bytes"]
        if got != hexbytes:
            fail(f"records leaf-op call bytes for {key} mismatch")
    return True


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    packet_dir = os.path.join(root, "research", "work-items",
                              "RE-001-node115-lu-resolver")
    binary_path = os.path.join(root, "artifacts", "node", "115", "hl-node")
    verify(root, packet_dir, binary_path)
    print(f"node115_lu_resolver: PASS (resolver 644B, {TOTAL_INSTRS} instrs, "
          f"1 direct caller, 0 GOT sites)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
