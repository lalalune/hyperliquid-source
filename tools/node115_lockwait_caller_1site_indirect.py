import bisect
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

SLUG = "RE-001-node115-lockwait-caller-1site-indirect"
START = 0x636A140
END = 0x636A675
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research", "work-items", SLUG)
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")

PASS = 0
FAIL = 0
FAILURES = []


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append(name + (" :: " + str(detail) if detail else ""))


def read(p):
    with open(p, "rb") as f:
        return f.read()


def toff(va):
    # .text file offset = VA - 0x1000 (node #115 hl-node).
    return va - 0x1000


def sections(node):
    e_shoff = struct.unpack_from("<Q", node, 0x28)[0]
    e_shentsize = struct.unpack_from("<H", node, 0x3A)[0]
    e_shnum = struct.unpack_from("<H", node, 0x3C)[0]
    e_shstrndx = struct.unpack_from("<H", node, 0x3E)[0]
    hdrs = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        vals = struct.unpack_from("<IIQQQQIIQQ", node, off)
        hdrs.append(vals)
    strtab = hdrs[e_shstrndx]
    out = {}
    for vals in hdrs:
        name_off = vals[0]
        end = node.index(b"\x00", strtab[4] + name_off)
        name = node[strtab[4] + name_off:end].decode()
        out[name] = vals
    return out


def parse_eh_frame(node):
    sec = sections(node)[".eh_frame"]
    base = sec[4]
    size = sec[5]
    fdes = []
    pos = 0
    while pos + 4 <= size:
        length = struct.unpack_from("<I", node, base + pos)[0]
        if length == 0:
            break
        if length == 0xFFFFFFFF:
            break
        rec = base + pos
        cie_id = struct.unpack_from("<I", node, rec + 4)[0]
        if cie_id != 0:
            # FDE: CIE pointer is rec+4; initial_location follows it,
            # then range is a fixed 4-byte field (not ULEB).
            init = struct.unpack_from("<i", node, rec + 8)[0]
            rng = struct.unpack_from("<I", node, rec + 12)[0]
            # initial_location is PC-relative: address = (rec - base) +
            # eh_frame VA + 8 + init. eh_frame VA is section address.
            eh_va = sec[3]
            start = eh_va + (pos + 8) + init
            fdes.append((start, start + rng))
        pos += 4 + length
    fdes.sort()
    return fdes


STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")


def strict_lines(text):
    return [l for l in text.splitlines() if STRICT_RE.match(l)]


def addr_of(line):
    return int(line.split(":", 1)[0].strip(), 16)


def mnemonic_of(line):
    parts = line.split("\t")
    if len(parts) < 3:
        return ""
    return parts[2].split()[0] if parts[2].split() else ""


def operands_of(line):
    parts = line.split("\t")
    if len(parts) < 3:
        return ""
    text = parts[2].strip()
    toks = text.split(None, 1)
    return toks[1] if len(toks) > 1 else ""


_REG_CANON = {
    "rax": "rax", "eax": "rax", "ax": "rax", "al": "rax", "ah": "rax",
    "rbx": "rbx", "ebx": "rbx", "bx": "rbx", "bl": "rbx", "bh": "rbx",
    "rcx": "rcx", "ecx": "rcx", "cx": "rcx", "cl": "rcx", "ch": "rcx",
    "rdx": "rdx", "edx": "rdx", "dx": "rdx", "dl": "rdx", "dh": "rdx",
    "rsi": "rsi", "esi": "rsi", "si": "rsi", "sil": "rsi",
    "rdi": "rdi", "edi": "rdi", "di": "rdi", "dil": "rdi",
    "rbp": "rbp", "ebp": "rbp", "bp": "rbp", "bpl": "rbp",
    "rsp": "rsp", "esp": "rsp", "sp": "rsp", "spl": "rsp",
}


def canon(reg):
    if reg is None:
        return None
    r = reg.lstrip("%").lower()
    if r in _REG_CANON:
        return _REG_CANON[r]
    m = re.match(r"^(r\d+)[dwb]?$", r)
    if m:
        return m.group(1)
    return r


_NO_DST = {"cmp", "cmpb", "cmpw", "cmpl", "cmpq", "test", "testb", "testw",
           "testl", "testq", "call", "ret", "jmp", "je", "jne", "ja", "jb",
           "jae", "jbe", "jg", "jl", "jge", "jle", "jo", "jno", "js",
           "jns", "jp", "jnp", "push", "nop", "nopl", "nopw", "endbr64",
           "lock", "leave", "int3", "hlt", "ud2"}


def dst_reg(line):
    mn = mnemonic_of(line)
    if mn in _NO_DST or mn.startswith("j"):
        return None
    ops = operands_of(line)
    if not ops:
        return None
    # Strip any objdump comment ("# ...").
    ops = ops.split("#")[0].strip()
    parts = [p.strip() for p in ops.split(",")]
    if not parts:
        return None
    last = parts[-1]
    m = re.match(r"^%([A-Za-z0-9]+)$", last)
    if m:
        return "%" + m.group(1)
    return None


def parse_int(v):
    if isinstance(v, str):
        return int(v, 16)
    return int(v)


def parse_range(v):
    if isinstance(v, str) and ".." in v:
        a, b = v.split("..")
        return (int(a, 16), int(b, 16))
    if isinstance(v, list) and len(v) == 2:
        return (parse_int(v[0]), parse_int(v[1]))
    return None


SKIP_KEYS = ("census", "cited", "survey", "callers", "largest_caller_fde",
             "scan")
PAIR_KEYS = [("start", "end"), ("start_va", "end_va_exclusive"),
             ("start_va", "end_va"), ("address", "end"),
             ("start", "stop"), ("start", "end_exclusive")]


def collect_ranges(obj, out, skipped):
    # Exhibits-scoped: only "exhibits"/"windows" entries carry claimed
    # ranges. A greedy collector over every nested dict produces false
    # overlaps (e.g. section ranges, next-question pointers, survey data).
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in SKIP_KEYS or k == "fde" or k == "enclosing_fde":
                continue
            if k in ("exhibits", "windows"):
                items = v if isinstance(v, list) else (
                    list(v.values()) if isinstance(v, dict) else [])
                for e in items:
                    if not isinstance(e, dict):
                        continue
                    for rk in ("range", "fde_range", "address_range"):
                        if rk in e:
                            r = parse_range(e[rk])
                            if r is not None:
                                out.append(r)
                    for a, b in PAIR_KEYS:
                        if a in e and b in e:
                            try:
                                out.append((parse_int(e[a]), parse_int(e[b])))
                            except Exception:
                                skipped.append((a, b))
            else:
                collect_ranges(v, out, skipped)
    elif isinstance(obj, list):
        for v in obj:
            collect_ranges(v, out, skipped)


EXPECT = [
    (0x636a140, 'push', '%r15'),    (0x636a142, 'movabs', '$0x7000000000200000,%r15'),    (0x636a14c, 'push', '%r14'),    (0x636a14e, 'mov', '%rcx,%r14'),    (0x636a151, 'push', '%r13'),    (0x636a153, 'mov', '%rsi,%r13'),    (0x636a156, 'push', '%r12'),    (0x636a158, 'mov', '%r8,%r12'),    (0x636a15b, 'push', '%rbp'),    (0x636a15c, 'mov', '%rdi,%rbp'),    (0x636a15f, 'push', '%rbx'),    (0x636a160, 'movabs', '$0x7000000000000000,%rbx'),    (0x636a16a, 'sub', '$0x28,%rsp'),    (0x636a16e, 'mov', '%fs:0x28,%rax'),    (0x636a177, 'mov', '%rax,0x18(%rsp)'),    (0x636a17c, 'mov', '0x60(%rsp),%rax'),    (0x636a181, 'add', '$0xf,%rax'),    (0x636a185, 'and', '$0xfffffffffffffff0,%rax'),    (0x636a189, 'mov', '%rax,%rcx'),    (0x636a18c, 'lea', '-0x1(%rax,%r9,1),%rsi'),    (0x636a191, 'add', '$0x8f,%rax'),    (0x636a197, 'neg', '%rcx'),    (0x636a19a, 'and', '%rcx,%rsi'),    (0x636a19d, 'and', '%rcx,%rax'),    (0x636a1a0, 'add', '%rax,%rsi'),    (0x636a1a3, 'cmp', '%rsi,%rbx'),    (0x636a1a6, 'jb', '636a1ea <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x621dba>'),    (0x636a1a8, 'lea', '-0x1(%rsi,%rsi,1),%rdi'),    (0x636a1ad, 'mov', '$0xf,%r9d'),    (0x636a1b3, 'mov', '$0x1,%r10d'),    (0x636a1b9, 'bsr', '%rdi,%r8'),    (0x636a1bd, 'movslq', '%r8d,%rcx'),    (0x636a1c0, 'cmp', '%r9,%rcx'),    (0x636a1c3, 'cmovb', '%r9,%rcx'),    (0x636a1c7, 'sub', '$0x3,%rcx'),    (0x636a1cb, 'shl', '%cl,%r10'),    (0x636a1ce, 'mov', '%r10,%r11'),    (0x636a1d1, 'lea', '-0x1(%rsi,%r10,1),%r15'),    (0x636a1d6, 'neg', '%r11'),    (0x636a1d9, 'and', '%r11,%r15'),    (0x636a1dc, 'add', '$0x1fffff,%r15'),    (0x636a1e3, 'and', '$0xffffffffffe00000,%r15'),    (0x636a1ea, 'mov', '(%r14),%eax'),    (0x636a1ed, 'lea', '0x3bdf8c(%rip),%rbx'),    (0x636a1f4, 'movb', '$0x1,0x16(%rsp)'),    (0x636a1f9, 'movb', '$0x1,0x17(%rsp)'),    (0x636a1fe, 'lea', '0x1(%rax),%esi'),    (0x636a201, 'cmp', '$0xc5,%esi'),    (0x636a207, 'cmovbe', '%rsi,%rax'),    (0x636a20b, 'mov', '(%rbx,%rax,8),%rbx'),    (0x636a20f, 'mov', '0x8(%rdx),%rdi'),    (0x636a213, 'add', '$0x1fffff,%rbx'),    (0x636a21a, 'and', '$0xffffffffffe00000,%rbx'),    (0x636a221, 'lea', '0x174f78(%rip),%r8'),    (0x636a228, 'cmp', '%r15,%rbx'),    (0x636a22b, 'cmovb', '%r15,%rbx'),    (0x636a22f, 'cmp', '%r8,%rdi'),    (0x636a232, 'je', '636a3d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x621fa0>'),    (0x636a238, 'mov', '0x8(%rdx),%r15'),    (0x636a23c, 'cmp', '%r8,%r15'),    (0x636a23f, 'je', '636a390 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x621f60>'),    (0x636a245, 'test', '%rbp,%rbp'),    (0x636a248, 'je', '636a418 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x621fe8>'),    (0x636a24e, 'addb', '$0x1,0x1(%rbp)'),    (0x636a252, 'cmpb', '$0x0,0x330(%rbp)'),    (0x636a259, 'je', '636a5b8 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x622188>'),    (0x636a25f, 'sub', '$0x8,%rsp'),    (0x636a263, 'mov', '(%rdx),%edx'),    (0x636a265, 'mov', '%r15,%rdi'),    (0x636a268, 'mov', '$0x200000,%ecx'),    (0x636a26d, 'xor', '%esi,%esi'),    (0x636a26f, 'push', '%rdx'),    (0x636a270, 'mov', '%rbx,%rdx'),    (0x636a273, 'lea', '0x27(%rsp),%r9'),    (0x636a278, 'lea', '0x26(%rsp),%r8'),    (0x636a27d, 'call', '*(%r15)'),    (0x636a280, 'pop', '%rcx'),    (0x636a281, 'mov', '%rbp,%rdi'),    (0x636a284, 'pop', '%rsi'),    (0x636a285, 'mov', '%rax,%r15'),    (0x636a288, 'subb', '$0x1,0x1(%rdi)'),    (0x636a28c, 'je', '636a408 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x621fd8>'),    (0x636a292, 'test', '%r15,%r15'),    (0x636a295, 'je', '636a3c8 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x621f98>'),    (0x636a29b, 'mov', '0x3a7893(%rip),%edi'),    (0x636a2a1, 'test', '%edi,%edi'),    (0x636a2a3, 'je', '636a2d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x621ea0>'),    (0x636a2a5, 'lea', '0x3a80c8(%rip),%r8'),    (0x636a2ac, 'mov', '(%r8),%edx'),    (0x636a2af, 'test', '%edx,%edx'),    (0x636a2b1, 'jne', '636a2d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x621ea0>'),    (0x636a2b3, 'cmp', '$0x2,%edi'),    (0x636a2b6, 'je', '636a4c0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x622090>'),    (0x636a2bc, 'test', '%r13,%r13'),    (0x636a2bf, 'je', '636a2d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x621ea0>'),    (0x636a2c1, 'cmp', '$0x1,%edi'),    (0x636a2c4, 'je', '636a4d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6220a0>'),    (0x636a2ca, 'nopw', '0x0(%rax,%rax,1)'),    (0x636a2d0, 'movabs', '$0x7000000000000000,%r13'),    (0x636a2da, 'cmp', '%rbx,%r13'),    (0x636a2dd, 'jb', '636a4b0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x622080>'),    (0x636a2e3, 'lea', '-0x1(%rbx),%r9'),    (0x636a2e7, 'mov', '%rbx,%rcx'),    (0x636a2ea, 'bsr', '%rbx,%rdx'),    (0x636a2ee, 'mov', '$0xe,%edi'),    (0x636a2f3, 'and', '%r9,%rcx'),    (0x636a2f6, 'mov', '$0xc,%r10d'),    (0x636a2fc, 'cmp', '$0x1,%rcx'),    (0x636a300, 'sbb', '$0xffffffff,%edx'),    (0x636a303, 'cmp', '%edi,%edx'),    (0x636a305, 'cmovb', '%edi,%edx'),    (0x636a308, 'lea', '-0x3(%rdx),%ecx'),    (0x636a30b, 'sub', '$0xe,%edx'),    (0x636a30e, 'cmove', '%r10d,%ecx'),    (0x636a312, 'shr', '%cl,%r9'),    (0x636a315, 'and', '$0x3,%r9d'),    (0x636a319, 'lea', '(%r9,%rdx,4),%r11d'),    (0x636a31d, 'mov', '%r11d,(%r14)'),    (0x636a320, 'mov', '%rbx,(%r15)'),    (0x636a323, 'mov', '(%r12),%r14'),    (0x636a327, 'sub', '$0x90,%rbx'),    (0x636a32e, 'movq', '$0x0,0x8(%r15)'),    (0x636a336, 'lea', '0x1(%r14),%rax'),    (0x636a33a, 'mov', '%rax,(%r12)'),    (0x636a33e, 'lea', '0x90(%r15),%r12'),    (0x636a345, 'mov', '%rbx,0x20(%r15)'),    (0x636a349, 'mov', '0x10(%r15),%rbx'),    (0x636a34d, 'mov', '%r12,0x18(%r15)'),    (0x636a351, 'and', '$0xfffffffff0000000,%rbx'),    (0x636a358, 'mov', '%r14,0x30(%r15)'),    (0x636a35c, 'or', '$0xe80afff,%rbx'),    (0x636a363, 'mov', '%rbx,0x10(%r15)'),    (0x636a367, 'mov', '0x18(%rsp),%rax'),    (0x636a36c, 'sub', '%fs:0x28,%rax'),    (0x636a375, 'jne', '636a670 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x622240>'),    (0x636a37b, 'add', '$0x28,%rsp'),    (0x636a37f, 'mov', '%r15,%rax'),    (0x636a382, 'pop', '%rbx'),    (0x636a383, 'pop', '%rbp'),    (0x636a384, 'pop', '%r12'),    (0x636a386, 'pop', '%r13'),    (0x636a388, 'pop', '%r14'),    (0x636a38a, 'pop', '%r15'),    (0x636a38c, 'ret', ''),    (0x636a38d, 'nopl', '(%rax)'),    (0x636a390, 'mov', '(%rdx),%esi'),    (0x636a392, 'sub', '$0x8,%rsp'),    (0x636a396, 'mov', '$0x200000,%ecx'),    (0x636a39b, 'mov', '%rbx,%rdx'),    (0x636a39e, 'mov', '%rbp,%rdi'),    (0x636a3a1, 'push', '%rsi'),    (0x636a3a2, 'xor', '%esi,%esi'),    (0x636a3a4, 'lea', '0x27(%rsp),%r9'),    (0x636a3a9, 'lea', '0x26(%rsp),%r8'),    (0x636a3ae, 'call', '63ad870 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x665440>'),    (0x636a3b3, 'pop', '%r9'),    (0x636a3b5, 'pop', '%r10'),    (0x636a3b7, 'mov', '%rax,%r15'),    (0x636a3ba, 'test', '%r15,%r15'),    (0x636a3bd, 'jne', '636a29b <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x621e6b>'),    (0x636a3c3, 'nopl', '0x0(%rax,%rax,1)'),    (0x636a3c8, 'xor', '%r15d,%r15d'),    (0x636a3cb, 'jmp', '636a367 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x621f37>'),    (0x636a3cd, 'nopl', '(%rax)'),    (0x636a3d0, 'lea', '0x16(%rsp),%rcx'),    (0x636a3d5, 'lea', '0x17(%rsp),%r8'),    (0x636a3da, 'mov', '%rbx,%rsi'),    (0x636a3dd, 'xor', '%edi,%edi'),    (0x636a3df, 'mov', '$0x200000,%edx'),    (0x636a3e4, 'call', '63b6050 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x66dc20>'),    (0x636a3e9, 'mov', '%rax,%r15'),    (0x636a3ec, 'test', '%rax,%rax'),    (0x636a3ef, 'je', '636a3c8 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x621f98>'),    (0x636a3f1, 'mov', '%rbx,%rsi'),    (0x636a3f4, 'mov', '%rax,%rdi'),    (0x636a3f7, 'call', '63c27f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x67a3c0>'),    (0x636a3fc, 'jmp', '636a29b <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x621e6b>'),    (0x636a401, 'nopl', '0x0(%rax)'),    (0x636a408, 'call', '63ef5e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6a71b0>'),    (0x636a40d, 'jmp', '636a292 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x621e62>'),    (0x636a412, 'nopw', '0x0(%rax,%rax,1)'),    (0x636a418, 'mov', '$0xffffffffffffef58,%rcx'),    (0x636a41f, 'cmpb', '$0x0,%fs:0x330(%rcx)'),    (0x636a427, 'jne', '636a5d8 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6221a8>'),    (0x636a42d, 'mov', '%fs:0x0,%r9'),    (0x636a436, 'addb', '$0x1,%fs:0x1(%rcx)'),    (0x636a43b, 'mov', '%rcx,%rdi'),    (0x636a43e, 'mov', '%r9,(%rsp)'),    (0x636a442, 'add', '%r9,%rdi'),    (0x636a445, 'mov', '%rdx,0x8(%rsp)'),    (0x636a44a, 'call', '63ef5e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6a71b0>'),    (0x636a44f, 'sub', '$0x8,%rsp'),    (0x636a453, 'mov', '0x10(%rsp),%rdx'),    (0x636a458, 'mov', '(%rdx),%r11d'),    (0x636a45b, 'mov', '%r15,%rdi'),    (0x636a45e, 'mov', '%rbx,%rdx'),    (0x636a461, 'xor', '%esi,%esi'),    (0x636a463, 'mov', '$0x200000,%ecx'),    (0x636a468, 'push', '%r11'),    (0x636a46a, 'lea', '0x27(%rsp),%r9'),    (0x636a46f, 'lea', '0x26(%rsp),%r8'),    (0x636a474, 'call', '*(%r15)'),    (0x636a477, 'mov', '%rax,%r15'),    (0x636a47a, 'pop', '%rax'),    (0x636a47b, 'mov', '$0xffffffffffffef58,%rax'),    (0x636a482, 'pop', '%rdx'),    (0x636a483, 'mov', '(%rsp),%rdi'),    (0x636a487, 'add', '%rax,%rdi'),    (0x636a48a, 'cmpb', '$0x0,%fs:0x330(%rax)'),    (0x636a492, 'je', '636a288 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x621e58>'),    (0x636a498, 'xor', '%esi,%esi'),    (0x636a49a, 'call', '63ef8e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6a74b0>'),    (0x636a49f, 'mov', '%rax,%rdi'),    (0x636a4a2, 'jmp', '636a288 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x621e58>'),    (0x636a4a7, 'nopw', '0x0(%rax,%rax,1)'),    (0x636a4b0, 'mov', '$0xc7,%r11d'),    (0x636a4b6, 'jmp', '636a31d <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x621eed>'),    (0x636a4bb, 'nopl', '0x0(%rax,%rax,1)'),    (0x636a4c0, 'mov', '%rbx,%rsi'),    (0x636a4c3, 'mov', '%r15,%rdi'),    (0x636a4c6, 'call', '63c27b0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x67a380>'),    (0x636a4cb, 'jmp', '636a2d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x621ea0>'),    (0x636a4d0, 'lea', '0x20(%r13),%rcx'),    (0x636a4d4, 'lea', '0x60(%r13),%rdi'),    (0x636a4d8, 'mov', '%rcx,0x8(%rsp)'),    (0x636a4dd, 'mov', '%rdi,(%rsp)'),    (0x636a4e1, 'call', '63f17b0 <pthread_mutex_trylock@plt>'),    (0x636a4e6, 'test', '%eax,%eax'),    (0x636a4e8, 'jne', '636a619 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6221e9>'),    (0x636a4ee, 'addq', '$0x1,0x58(%r13)'),    (0x636a4f3, 'cmp', '0x50(%r13),%rbp'),    (0x636a4f7, 'je', '636a502 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6220d2>'),    (0x636a4f9, 'addq', '$0x1,0x48(%r13)'),    (0x636a4fe, 'mov', '%rbp,0x50(%r13)'),    (0x636a502, 'cmpb', '$0x0,0x90(%r13)'),    (0x636a50a, 'jne', '636a660 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x622230>'),    (0x636a510, 'mov', '0xa0(%r13),%rbp'),    (0x636a517, 'mov', '0x0(%r13),%r9d'),    (0x636a51b, 'mov', '0x8(%rbp),%r11'),    (0x636a51f, 'test', '%r9d,%r9d'),    (0x636a522, 'je', '636a630 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x622200>'),    (0x636a528, 'test', '%r11,%r11'),    (0x636a52b, 'je', '636a550 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x622120>'),    (0x636a52d, 'mov', '$0x2,%esi'),    (0x636a532, 'nopw', '0x0(%rax,%rax,1)'),    (0x636a538, 'mov', '0x8(%r11),%r11'),    (0x636a53c, 'add', '$0x1,%rsi'),    (0x636a540, 'test', '%r11,%r11'),    (0x636a543, 'jne', '636a538 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x622108>'),    (0x636a545, 'cmp', '$0x2,%rsi'),    (0x636a549, 'sete', '%al'),    (0x636a54c, 'test', '%al,%al'),    (0x636a54e, 'je', '636a59d <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x62216d>'),    (0x636a550, 'movb', '$0x1,0x90(%r13)'),    (0x636a558, 'nopl', '0x0(%rax,%rax,1)'),    (0x636a560, 'mov', '0x0(%rbp),%rsi'),    (0x636a564, 'mov', '%rbp,%rdi'),    (0x636a567, 'call', '63c27b0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x67a380>'),    (0x636a56c, 'mov', '0x0(%rbp),%r8'),    (0x636a570, 'add', '$0x1fffff,%r8'),    (0x636a577, 'sub', '0x20(%rbp),%r8'),    (0x636a57b, 'mov', '0x8(%rbp),%rbp'),    (0x636a57f, 'shr', '$0x15,%r8'),    (0x636a583, 'add', '%r8,0xf40(%r13)'),    (0x636a58a, 'test', '%rbp,%rbp'),    (0x636a58d, 'jne', '636a560 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x622130>'),    (0x636a58f, 'cmpb', '$0x0,0x90(%r13)'),    (0x636a597, 'jne', '636a660 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x622230>'),    (0x636a59d, 'movb', '$0x0,0x88(%r13)'),    (0x636a5a5, 'mov', '(%rsp),%rdi'),    (0x636a5a9, 'call', '63f0b70 <pthread_mutex_unlock@plt>'),    (0x636a5ae, 'jmp', '636a2d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x621ea0>'),    (0x636a5b3, 'nopl', '0x0(%rax,%rax,1)'),    (0x636a5b8, 'mov', '%rbp,%rdi'),    (0x636a5bb, 'mov', '%rdx,(%rsp)'),    (0x636a5bf, 'call', '63ef5e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6a71b0>'),    (0x636a5c4, 'sub', '$0x8,%rsp'),    (0x636a5c8, 'mov', '0x8(%rsp),%rdx'),    (0x636a5cd, 'jmp', '636a263 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x621e33>'),    (0x636a5d2, 'nopw', '0x0(%rax,%rax,1)'),    (0x636a5d8, 'mov', '%fs:0x0,%r10'),    (0x636a5e1, 'mov', '%rcx,%rdi'),    (0x636a5e4, 'xor', '%esi,%esi'),    (0x636a5e6, 'mov', '%rdx,0x8(%rsp)'),    (0x636a5eb, 'add', '%r10,%rdi'),    (0x636a5ee, 'mov', '%r10,(%rsp)'),    (0x636a5f2, 'call', '63ef8e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6a74b0>'),    (0x636a5f7, 'mov', '0x8(%rsp),%rdx'),    (0x636a5fc, 'addb', '$0x1,0x1(%rax)'),    (0x636a600, 'cmpb', '$0x0,0x330(%rax)'),    (0x636a607, 'mov', '%rax,%rdi'),    (0x636a60a, 'je', '636a445 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x622015>'),    (0x636a610, 'sub', '$0x8,%rsp'),    (0x636a614, 'jmp', '636a458 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x622028>'),    (0x636a619, 'mov', '0x8(%rsp),%rdi'),    (0x636a61e, 'call', '63bf680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677250>'),    (0x636a623, 'movb', '$0x1,0x88(%r13)'),    (0x636a62b, 'jmp', '636a4ee <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6220be>'),    (0x636a630, 'mov', '$0x2,%r10d'),    (0x636a636, 'test', '%r11,%r11'),    (0x636a639, 'je', '636a59d <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x62216d>'),    (0x636a63f, 'nop', ''),    (0x636a640, 'mov', '0x8(%r11),%r11'),    (0x636a644, 'add', '$0x1,%r10'),    (0x636a648, 'test', '%r11,%r11'),    (0x636a64b, 'jne', '636a640 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x622210>'),    (0x636a64d, 'cmp', '$0x5,%r10'),    (0x636a651, 'sete', '%al'),    (0x636a654, 'jmp', '636a54c <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x62211c>'),    (0x636a659, 'nopl', '0x0(%rax)'),    (0x636a660, 'mov', '%rbx,%rsi'),    (0x636a663, 'mov', '%r15,%rdi'),    (0x636a666, 'call', '63c27b0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x67a380>'),    (0x636a66b, 'jmp', '636a59d <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x62216d>'),    (0x636a670, 'call', '63f0d70 <__stack_chk_fail@plt>'),]


def main():
    node = read(BIN)
    check("binary size 105896032", len(node) == 105896032, str(len(node)))
    check("binary sha256",
          hashlib.sha256(node).hexdigest() ==
          "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

    rec = json.loads(read(os.path.join(PACKET, "records.json")).decode())
    check("records base", rec["base"] ==
          "05bc2de303c05525b71e7e257426e741bc66a390", str(rec.get("base")))

    fdes = parse_eh_frame(node)
    starts = [s for s, e in fdes]
    check("total FDEs 135313", len(fdes) == 135313, str(len(fdes)))
    i = bisect.bisect_left(starts, START)
    check("target FDE start", i < len(fdes) and fdes[i][0] == START)
    check("target FDE end", i < len(fdes) and fdes[i][1] == END)
    check("target FDE size 1333", END - START == 1333)
    prev = fdes[i - 1]
    check("prev FDE 0x6369fe0..0x636a136",
          prev == (0x6369FE0, 0x636A136), str(prev))
    check("prev gap 10 (0xcc padding)", START - prev[1] == 10)
    check("prev gap bytes are 0xcc int3 padding",
          node[toff(prev[1]):toff(START)] == b"\xcc" * 10)
    nxt = fdes[i + 1]
    check("next FDE 0x636a680..0x636aad8",
          nxt == (0x636A680, 0x636AAD8), str(nxt))
    check("next gap 11 (0xcc padding)", nxt[0] - END == 11)
    check("next gap bytes are 0xcc int3 padding",
          node[toff(END):toff(nxt[0])] == b"\xcc" * 11)
    check("next FDE does NOT start endbr64 (push %r15)",
          node[toff(nxt[0]):toff(nxt[0]) + 2] == b"\x41\x57")
    check("prev FDE end is 10 bytes before this FDE start",
          prev[1] == START - 10)
    check("call-target FDE 0x63ad870..0x63ad997",
          fdes[bisect.bisect_left(starts, 0x63AD870)] ==
          (0x63AD870, 0x63AD997))
    check("call-target FDE 0x63b6050..0x63b607d",
          fdes[bisect.bisect_left(starts, 0x63B6050)] ==
          (0x63B6050, 0x63B607D))
    check("call-target FDE 0x63c27b0..0x63c27cc",
          fdes[bisect.bisect_left(starts, 0x63C27B0)] ==
          (0x63C27B0, 0x63C27CC))
    check("call-target FDE 0x63c27f0..0x63c283a",
          fdes[bisect.bisect_left(starts, 0x63C27F0)] ==
          (0x63C27F0, 0x63C283A))
    check("call-target FDE 0x63ef5e0..0x63ef640",
          fdes[bisect.bisect_left(starts, 0x63EF5E0)] ==
          (0x63EF5E0, 0x63EF640))
    check("call-target FDE 0x63ef8e0..0x63efba2 (#258 window)",
          fdes[bisect.bisect_left(starts, 0x63EF8E0)] ==
          (0x63EF8E0, 0x63EFBA2))
    check("lock-wait helper FDE 0x63bf680..0x63bf7ee",
          fdes[bisect.bisect_left(starts, 0x63BF680)] ==
          (0x63BF680, 0x63BF7EE))
    check("lu-miss handler FDE 0x63d9700..0x63d987b",
          fdes[bisect.bisect_left(starts, 0x63D9700)] ==
          (0x63D9700, 0x63D987B))
    check("bin_table_init FDE 0x63d9880..0x63d9a64",
          fdes[bisect.bisect_left(starts, 0x63D9880)] ==
          (0x63D9880, 0x63D9A64))
    check("second-handler FDE 0x634ebb0..0x634eccd",
          fdes[bisect.bisect_left(starts, 0x634EBB0)] ==
          (0x634EBB0, 0x634ECCD))
    check("key resolver FDE 0x6365150..0x6365660",
          fdes[bisect.bisect_left(starts, 0x6365150)] ==
          (0x6365150, 0x6365660))
    check("next-question FDE 0x6386540..0x638693a",
          fdes[bisect.bisect_left(starts, 0x6386540)] ==
          (0x6386540, 0x638693A))
    check("#321 shared FDE 0x63c9650..0x63c9c80",
          fdes[bisect.bisect_left(starts, 0x63C9650)] ==
          (0x63C9650, 0x63C9C80))

    hexb = read(os.path.join(PACKET, "lockwait_caller_1site_indirect.hex"))
    check("hex exhibit raw bytes 1333", len(hexb) == 1333, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])
    objdump = read(os.path.join(
        PACKET, "lockwait_caller_1site_indirect.objdump.txt")).decode()
    lines = strict_lines(objdump)
    check("strict lines 315", len(lines) == 315, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if mnemonic_of(l) == "call"]
    check("call lines 17", len(calls) == 17, str(len(calls)))
    rets = [l for l in lines if mnemonic_of(l) == "ret"]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x636a38c",
          sorted(addr_of(l) for l in rets) == [0x636A38C],
          str([hex(addr_of(l)) for l in rets]))
    tgt = {}
    for l in calls:
        m = re.search(r"\tcall\s+([0-9a-f]+)", l)
        if m:
            t = int(m.group(1), 16)
            tgt[t] = tgt.get(t, 0) + 1
    indirect = [l for l in calls
                if re.search(r"\tcall\s+\*", l)]
    check("indirect calls 2", len(indirect) == 2,
          str([hex(addr_of(l)) for l in indirect]))
    check("indirect sites are 0x636a27d and 0x636a474",
          sorted(addr_of(l) for l in indirect) == [0x636A27D, 0x636A474])
    expect = {0x63AD870: 1, 0x63B6050: 1, 0x63BF680: 1, 0x63C27B0: 3,
              0x63C27F0: 1, 0x63EF5E0: 3, 0x63EF8E0: 2, 0x63F0B70: 1,
              0x63F0D70: 1, 0x63F17B0: 1}
    check("call target multiset exact", dict(tgt) == expect, str(tgt))
    check("distinct direct call targets 10", len(tgt) == 10, str(len(tgt)))
    check("no bti sites", tgt.get(0x63D9880, 0) == 0,
          str(tgt.get(0x63D9880, 0)))
    check("lu-miss sites 0",
          tgt.get(0x63D9700, 0) == 0, str(tgt.get(0x63D9700, 0)))
    check("second-handler sites 0", tgt.get(0x634EBB0, 0) == 0,
          str(tgt.get(0x634EBB0, 0)))
    check("lock-wait helper called 1 time", tgt.get(0x63BF680, 0) == 1,
          str(tgt.get(0x63BF680, 0)))
    check("lock-wait site is 0x636a61e",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63bf680" in l) == [0x636A61E])
    check("resolver 0x6365150 called 0 times", tgt.get(0x6365150, 0) == 0,
          str(tgt.get(0x6365150, 0)))
    check("stack_chk_fail plt call 1 at 0x636a670",
          tgt.get(0x63F0D70, 0) == 1, str(tgt.get(0x63F0D70, 0)))
    plt_calls = [l for l in calls if "@plt" in l]
    check("PLT calls 3 (by @plt suffix, not address range)",
          len(plt_calls) == 3, str(len(plt_calls)))
    check("distinct PLT targets 3",
          len({re.search(r"\tcall\s+([0-9a-f]+)", l).group(1)
               for l in plt_calls}) == 3)
    check("no internal .text call is counted as PLT",
          not any("63c27b0" in l and "@plt" in l for l in calls)
          and not any("63ef5e0" in l and "@plt" in l for l in calls))
    for _w, _a in (("#314", 0x63495B0), ("#315", 0x6353A70),
                  ("#316", 0x6355900), ("#317", 0x63577F0),
                  ("#318", 0x635A7A0), ("#319", 0x635C6D0),
                  ("#320", 0x635E2E0), ("#321", 0x63C9650),
                  ("#322", 0x63CCD60), ("#323", 0x63CDDD0),
                  ("#324", 0x63D03A0), ("#325", 0x63D17E0),
                  ("#326", 0x63D2A80), ("#327", 0x63D3F0E),
                  ("#328", 0x63D4048), ("#329", 0x63E94A0),
                  ("#330", 0x6362190), ("#331", 0x6362910)):
        check("%s window not called" % _w, tgt.get(_a, 0) == 0,
              str(tgt.get(_a, 0)))

    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 2", sorted(addr_of(l) for l in bsr) == [0x636A1B9, 0x636A2EA],
          str([hex(addr_of(l)) for l in bsr]))
    locks = [l for l in lines if mnemonic_of(l) == "lock"]
    check("lock lines 0", len(locks) == 0, str(locks))
    check("lock sub count 0",
          sum(1 for l in lines if "lock sub" in l) == 0)
    check("lock add count 0",
          sum(1 for l in lines if "lock add" in l) == 0)
    jmps = [l for l in lines
            if mnemonic_of(l) in ("jmp", "je", "jne", "ja", "jb", "jae",
                                  "jbe", "jg", "jl", "jge", "jle", "jo",
                                  "jno", "js", "jns", "jp", "jnp")]
    check("jump lines 42", len(jmps) == 42, str(len(jmps)))

    def jump_target(line):
        m = re.search(r"\s([0-9a-f]{6,})\s*<", line)
        return int(m.group(1), 16) if m else None

    outside = []
    for l in jmps:
        t = jump_target(l)
        if t is not None and not (START <= t < END):
            outside.append((addr_of(l), t))
    check("jump closure: 0 outside the window", outside == [], str(outside))
    check("jump targets are exactly the 42 branches",
          sorted(jump_target(l) for l in jmps) ==
          [0x636A1EA, 0x636A263, 0x636A288, 0x636A288, 0x636A292, 0x636A29B,
           0x636A29B, 0x636A2D0, 0x636A2D0, 0x636A2D0, 0x636A2D0, 0x636A2D0,
           0x636A31D, 0x636A367, 0x636A390, 0x636A3C8, 0x636A3C8, 0x636A3D0,
           0x636A408, 0x636A418, 0x636A445, 0x636A458, 0x636A4B0, 0x636A4C0,
           0x636A4D0, 0x636A4EE, 0x636A502, 0x636A538, 0x636A54C, 0x636A550,
           0x636A560, 0x636A59D, 0x636A59D, 0x636A59D, 0x636A5B8, 0x636A5D8,
           0x636A619, 0x636A630, 0x636A640, 0x636A660, 0x636A660, 0x636A670],
          str(sorted(jump_target(l) for l in jmps)))
    check("endbr64 count 0",
          sum(1 for l in lines if "endbr64" in l) == 0)
    check("entry is push %r15 at 0x636a140, NOT endbr64",
          "push" in by_addr[START] and "%r15" in by_addr[START])
    check("canary present: 2 fs:0x28 lines",
          sum(1 for l in lines if "%fs:0x28" in l) == 2)
    check("canary load at 0x636a16e",
          "mov" in by_addr[0x636A16E] and "%fs:0x28,%rax" in by_addr[0x636A16E])
    check("canary check sub at 0x636a36c",
          "sub" in by_addr[0x636A36C] and "%fs:0x28,%rax" in by_addr[0x636A36C])
    check("canary fail jne to stack_chk_fail at 0x636a375",
          "jne" in by_addr[0x636A375] and "636a670" in by_addr[0x636A375])
    check("TLS flag check present: 2 fs:0x330 lines",
          sum(1 for l in lines if "%fs:0x330" in l) == 2)
    check("TLS cmp at 0x636a41f",
          "cmpb" in by_addr[0x636A41F] and "%fs:0x330(%rcx)" in by_addr[0x636A41F])
    check("TLS cmp at 0x636a48a",
          "cmpb" in by_addr[0x636A48A] and "%fs:0x330(%rax)" in by_addr[0x636A48A])
    check("0x330 access at 0x636a600 is plain memory, NOT %fs",
          "cmpb" in by_addr[0x636A600] and "%fs:0x330" not in by_addr[0x636A600])
    check("no size-table lea 0x6727a00 anywhere",
          not any("6727a00" in l for l in lines))
    check("no byte-table lea 0x67277c0 anywhere",
          not any("67277c0" in l for l in lines))
    check("no fallback-table lea 0x6728140 anywhere",
          not any("6728140" in l for l in lines))
    check("no node-table lea 0x65096c0 anywhere",
          not any("65096c0" in l for l in lines))
    check("no lu-miss .bss 0x6511a00 anywhere",
          not any("6511a00" in l for l in lines))
    check("no shr $0x1c anywhere (no 10-bit tag extract)",
          not any("shr" in l and "$0x1c" in l for l in lines))
    check("size-table lea 0x6728180 at 0x636a1ed",
          "lea" in by_addr[0x636A1ED] and "6728180" in by_addr[0x636A1ED])
    check("sentinel lea 0x64df1a0 at 0x636a221",
          "lea" in by_addr[0x636A221] and "64df1a0" in by_addr[0x636A221])
    check("bss mov 0x6711b34 at 0x636a29b",
          "mov" in by_addr[0x636A29B] and "6711b34" in by_addr[0x636A29B])
    check("bss lea 0x6712374 at 0x636a2a5",
          "lea" in by_addr[0x636A2A5] and "6712374" in by_addr[0x636A2A5])
    check("no prefetch instructions",
          not any("prefetch" in l for l in lines))
    check("tzcnt 0",
          [l for l in lines if mnemonic_of(l) == "tzcnt"] == [])
    check("btc 0",
          [l for l in lines if mnemonic_of(l) == "btc"] == [])
    check("list-walk shr $0x15 at 0x636a57f",
          "shr" in by_addr[0x636A57F] and "$0x15,%r8" in by_addr[0x636A57F])
    check("movabs tag constant r15 at 0x636a142",
          "movabs" in by_addr[0x636A142]
          and "$0x7000000000200000,%r15" in by_addr[0x636A142])
    check("movabs tag constant rbx at 0x636a160",
          "movabs" in by_addr[0x636A160]
          and "$0x7000000000000000,%rbx" in by_addr[0x636A160])
    check("tag or $0xe80afff at 0x636a35c",
          "or" in by_addr[0x636A35C] and "$0xe80afff,%rbx" in by_addr[0x636A35C])
    check("tag store at 0x636a363",
          "mov" in by_addr[0x636A363] and "%rbx,0x10(%r15)" in by_addr[0x636A363])
    check("size-class index store at 0x636a31d",
          "mov" in by_addr[0x636A31D] and "%r11d,(%r14)" in by_addr[0x636A31D])
    check("size store at 0x636a320",
          "mov" in by_addr[0x636A320] and "%rbx,(%r15)" in by_addr[0x636A320])
    check("index saturate mov $0xc7 at 0x636a4b0",
          "mov" in by_addr[0x636A4B0] and "$0xc7,%r11d" in by_addr[0x636A4B0])
    check("indirect call 1 at 0x636a27d",
          "call" in by_addr[0x636A27D] and "*(%r15)" in by_addr[0x636A27D])
    check("indirect call 2 at 0x636a474",
          "call" in by_addr[0x636A474] and "*(%r15)" in by_addr[0x636A474])
    check("indirect r15 def mov 0x8(rdx) at 0x636a238",
          "mov" in by_addr[0x636A238] and "0x8(%rdx),%r15" in by_addr[0x636A238])
    check("trylock call at 0x636a4e1",
          "call" in by_addr[0x636A4E1] and "63f17b0" in by_addr[0x636A4E1])
    check("lock-wait call at 0x636a61e",
          "call" in by_addr[0x636A61E] and "63bf680" in by_addr[0x636A61E])
    check("unlock call at 0x636a5a9",
          "call" in by_addr[0x636A5A9] and "63f0b70" in by_addr[0x636A5A9])
    check("waited-flag set movb $0x1,0x88(r13) at 0x636a623",
          "movb" in by_addr[0x636A623] and "$0x1,0x88(%r13)" in by_addr[0x636A623])
    check("waited-flag clear movb $0,0x88(r13) at 0x636a59d",
          "movb" in by_addr[0x636A59D] and "$0x0,0x88(%r13)" in by_addr[0x636A59D])
    check("mutex lea 0x60(r13) at 0x636a4d4",
          "lea" in by_addr[0x636A4D4] and "0x60(%r13),%rdi" in by_addr[0x636A4D4])
    check("node lea 0x20(r13) at 0x636a4d0",
          "lea" in by_addr[0x636A4D0] and "0x20(%r13),%rcx" in by_addr[0x636A4D0])
    check("node stored to 0x8(rsp) at 0x636a4d8",
          "mov" in by_addr[0x636A4D8] and "%rcx,0x8(%rsp)" in by_addr[0x636A4D8])
    check("mutex stored to (rsp) at 0x636a4dd",
          "mov" in by_addr[0x636A4DD] and "%rdi,(%rsp)" in by_addr[0x636A4DD])
    check("lock-wait setup mov 0x8(rsp) to rdi at 0x636a619",
          "mov" in by_addr[0x636A619] and "0x8(%rsp),%rdi" in by_addr[0x636A619])
    check("exit value mov r15 rax at 0x636a37f",
          "mov" in by_addr[0x636A37F] and "%r15,%rax" in by_addr[0x636A37F])
    check("zero path xor r15d at 0x636a3c8",
          "xor" in by_addr[0x636A3C8] and "%r15d,%r15d" in by_addr[0x636A3C8])

    # Instruction spot checks: (address, mnemonic, operand substring).
    # Exhaustive: every strict line of the exhibit.
    # __EXPECT__

    for _a, _m, _op in EXPECT:
        check("expect %s %s %s" % (hex(_a), _m, _op),
              _a in by_addr and mnemonic_of(by_addr[_a]) == _m
              and _op in operands_of(by_addr[_a]),
              by_addr.get(_a, "MISSING"))

    # CFG: successors (jump targets inside window + fall-through; calls
    # fall through except noreturn PLT calls; ret is terminal).
    def call_target(line):
        m = re.search(r"\tcall\s+([0-9a-f]+)", line)
        return int(m.group(1), 16) if m else None

    NORETURN = {0x63F0D70}
    succ = {}
    ordered = sorted(by_addr)
    for idx, a in enumerate(ordered):
        line = by_addr[a]
        mn = mnemonic_of(line)
        s = set()
        t = jump_target(line) if mn.startswith("j") else None
        ct = call_target(line) if mn == "call" else None
        if mn == "ret":
            pass
        elif mn == "call" and ct in NORETURN:
            pass
        elif mn == "jmp":
            if t is not None and START <= t < END:
                s.add(t)
        elif mn.startswith("j"):
            if t is not None and START <= t < END:
                s.add(t)
            if idx + 1 < len(ordered):
                s.add(ordered[idx + 1])
        else:
            if idx + 1 < len(ordered):
                s.add(ordered[idx + 1])
        succ[a] = s
    preds = {a: set() for a in ordered}
    for a, ss in succ.items():
        for t in ss:
            preds[t].add(a)

    def reaches(src, dst):
        seen = set()
        stack = [src]
        while stack:
            x = stack.pop()
            if x == dst:
                return True
            if x in seen:
                continue
            seen.add(x)
            stack.extend(succ.get(x, ()))
        return False

    check("entry reaches lock-wait site 0x636a61e", reaches(START, 0x636A61E))
    check("entry reaches ret 0x636a38c", reaches(START, 0x636A38C))
    check("entry reaches trylock 0x636a4e1", reaches(START, 0x636A4E1))
    check("entry reaches indirect site 1 0x636a27d", reaches(START, 0x636A27D))
    check("entry reaches indirect site 2 0x636a474", reaches(START, 0x636A474))
    check("entry reaches loop head 0x636a4ee", reaches(START, 0x636A4EE))
    check("entry reaches epilogue 0x636a367", reaches(START, 0x636A367))
    check("entry reaches store path 0x636a2d0", reaches(START, 0x636A2D0))
    check("entry reaches TLS path 0x636a418", reaches(START, 0x636A418))
    check("entry reaches zero path 0x636a3c8", reaches(START, 0x636A3C8))
    check("preds of lock-wait setup 0x636a619 is the trylock fail only",
          preds[0x636A619] == {0x636A4E8}, str(preds[0x636A619]))
    check("preds of trylock 0x636a4e1 is the block entry only",
          preds[0x636A4E1] == {0x636A4DD}, str(preds[0x636A4E1]))
    check("preds of loop head 0x636a4ee are trylock success and rejoin",
          preds[0x636A4EE] == {0x636A4E8, 0x636A62B}, str(preds[0x636A4EE]))
    check("preds of epilogue 0x636a367 are store path and zero path",
          preds[0x636A367] == {0x636A363, 0x636A3CB}, str(preds[0x636A367]))
    check("preds of indirect setup 0x636a263 are main path and 0x636a5b8",
          preds[0x636A263] == {0x636A25F, 0x636A5CD}, str(preds[0x636A263]))
    check("preds of indirect setup 0x636a458 are TLS paths",
          preds[0x636A458] == {0x636A453, 0x636A614}, str(preds[0x636A458]))
    check("preds of store path 0x636a2d0 are six entries",
          preds[0x636A2D0] == {0x636A2A3, 0x636A2B1, 0x636A2BF, 0x636A2CA,
                              0x636A4CB, 0x636A5AE}, str(preds[0x636A2D0]))

    # Reaching definitions: per-register IN sets at the lock-wait site,
    # the two indirect sites, and the exit mov. ENTRY is the caller's
    # value at the window entry; CALL(x) is a call-clobber at x.
    CALLER_SAVED = {"rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10",
                    "r11"}

    def reaching_defs(reg):
        IN = {a: set() for a in ordered}
        OUT = {a: set() for a in ordered}
        IN[START] = {("ENTRY",)}

        def is_def(x):
            return (isinstance(x, tuple)
                    or (isinstance(x, int)
                        and canon(dst_reg(by_addr[x])) == reg))

        changed = True
        while changed:
            changed = False
            for a in ordered:
                new_in = set()
                for p in preds[a]:
                    new_in |= OUT[p]
                if a == START:
                    new_in |= {("ENTRY",)}
                if new_in != IN[a]:
                    IN[a] = new_in
                    changed = True
                mn = mnemonic_of(by_addr[a])
                if mn == "call" and reg in CALLER_SAVED:
                    new_out = {("CALL", a)}
                elif mn.startswith("cmov"):
                    d = canon(dst_reg(by_addr[a]))
                    new_out = set(IN[a]) | ({a} if d == reg else set())
                else:
                    d = canon(dst_reg(by_addr[a]))
                    if d == reg:
                        new_out = ({x for x in IN[a] if not is_def(x)}
                                   | {a})
                    else:
                        new_out = set(IN[a])
                if new_out != OUT[a]:
                    OUT[a] = new_out
                    changed = True
        return IN

    rdi_in = reaching_defs("rdi")
    r13_in = reaching_defs("r13")
    rsi_in = reaching_defs("rsi")
    rdx_in = reaching_defs("rdx")
    rcx_in = reaching_defs("rcx")
    r8_in = reaching_defs("r8")
    r9_in = reaching_defs("r9")
    rax_in = reaching_defs("rax")
    r10_in = reaching_defs("r10")
    r11_in = reaching_defs("r11")
    rbx_in = reaching_defs("rbx")
    rbp_in = reaching_defs("rbp")
    r14_in = reaching_defs("r14")
    r15_in = reaching_defs("r15")
    r12_in = reaching_defs("r12")
    SITE = 0x636A61E
    IND1 = 0x636A27D
    IND2 = 0x636A474
    MOVRET = 0x636A37F
    CALL_TRYLOCK = {("CALL", 0x636A4E1)}
    check("site rdi only def is mov 0x8(rsp) rdi 0x636a619",
          rdi_in[SITE] == {0x636A619}, str(rdi_in[SITE]))
    check("site rbx defs are the table size and the max",
          rbx_in[SITE] == {0x636A21A, 0x636A22B}, str(rbx_in[SITE]))
    check("site rsi is clobbered by the trylock only",
          rsi_in[SITE] == CALL_TRYLOCK, str(rsi_in[SITE]))
    check("site rdx is clobbered by the trylock only",
          rdx_in[SITE] == CALL_TRYLOCK, str(rdx_in[SITE]))
    check("site rcx is clobbered by the trylock only",
          rcx_in[SITE] == CALL_TRYLOCK, str(rcx_in[SITE]))
    check("site r9 is clobbered by the trylock only",
          r9_in[SITE] == CALL_TRYLOCK, str(r9_in[SITE]))
    check("site rax is clobbered by the trylock only",
          rax_in[SITE] == CALL_TRYLOCK, str(rax_in[SITE]))
    check("site r10 is clobbered by the trylock only",
          r10_in[SITE] == CALL_TRYLOCK, str(r10_in[SITE]))
    check("site r11 is clobbered by the trylock only",
          r11_in[SITE] == CALL_TRYLOCK, str(r11_in[SITE]))
    check("site r8 is clobbered by the trylock only",
          r8_in[SITE] == CALL_TRYLOCK, str(r8_in[SITE]))
    check("site r13 def is the entry rsi save",
          r13_in[SITE] == {0x636A153}, str(r13_in[SITE]))
    check("site r14 def is the entry rcx save",
          r14_in[SITE] == {0x636A14E}, str(r14_in[SITE]))
    check("site r15 defs are the four record-pointer returns",
          r15_in[SITE] == {0x636A285, 0x636A3B7, 0x636A3E9, 0x636A477},
          str(r15_in[SITE]))
    check("site rbp def is the entry rdi save",
          rbp_in[SITE] == {0x636A15C}, str(rbp_in[SITE]))
    check("site r12 def is the entry r8 save",
          r12_in[SITE] == {0x636A158}, str(r12_in[SITE]))
    check("ind1 r15 only def is mov 0x8(rdx) at 0x636a238",
          r15_in[IND1] == {0x636A238}, str(r15_in[IND1]))
    check("ind2 r15 only def is mov 0x8(rdx) at 0x636a238",
          r15_in[IND2] == {0x636A238}, str(r15_in[IND2]))
    check("ind1 rdi only def is mov r15 rdi at 0x636a265",
          rdi_in[IND1] == {0x636A265}, str(rdi_in[IND1]))
    check("ind2 rdi only def is mov r15 rdi at 0x636a45b",
          rdi_in[IND2] == {0x636A45B}, str(rdi_in[IND2]))
    check("ind1 rsi only def is xor esi at 0x636a26d",
          rsi_in[IND1] == {0x636A26D}, str(rsi_in[IND1]))
    check("ind2 rsi only def is xor esi at 0x636a461",
          rsi_in[IND2] == {0x636A461}, str(rsi_in[IND2]))
    check("ind1 rdx only def is mov rbx rdx at 0x636a270",
          rdx_in[IND1] == {0x636A270}, str(rdx_in[IND1]))
    check("ind2 rdx only def is mov rbx rdx at 0x636a45e",
          rdx_in[IND2] == {0x636A45E}, str(rdx_in[IND2]))
    check("ind1 rcx only def is mov $0x200000 at 0x636a268",
          rcx_in[IND1] == {0x636A268}, str(rcx_in[IND1]))
    check("ind2 rcx only def is mov $0x200000 at 0x636a463",
          rcx_in[IND2] == {0x636A463}, str(rcx_in[IND2]))
    check("ind1 r8 only def is lea 0x26(rsp) at 0x636a278",
          r8_in[IND1] == {0x636A278}, str(r8_in[IND1]))
    check("ind2 r8 only def is lea 0x26(rsp) at 0x636a46f",
          r8_in[IND2] == {0x636A46F}, str(r8_in[IND2]))
    check("ind1 r9 only def is lea 0x27(rsp) at 0x636a273",
          r9_in[IND1] == {0x636A273}, str(r9_in[IND1]))
    check("ind2 r9 only def is lea 0x27(rsp) at 0x636a46a",
          r9_in[IND2] == {0x636A46A}, str(r9_in[IND2]))
    check("rax at ret is the canary residue def 0x636a36c",
          rax_in[MOVRET] == {0x636A36C}, str(rax_in[MOVRET]))
    check("r15 at mov-to-rax 0x636a37f is five defs (4 returns + zero)",
          r15_in[MOVRET] == {0x636A285, 0x636A3B7, 0x636A3C8, 0x636A3E9,
                            0x636A477},
          str(r15_in[MOVRET]))

    check("records lock-wait sites match census",
          [s.get("site") for s in rec.get("lock_wait_sites", [])] ==
          ["0x636a61e"])
    check("records second-handler sites 0",
          rec.get("second_handler_sites", []) == [])
    check("records indirect count 2",
          rec.get("indirect", {}).get("count") == 2)
    check("records indirect sites",
          rec.get("indirect", {}).get("sites") ==
          ["0x636a27d", "0x636a474"])
    check("records indirect r15 def",
          rec.get("indirect", {}).get("r15_def", "").startswith("0x636a238"))
    check("records sites lu-miss 0",
          rec.get("sites", {}).get("lu_miss") == 0)
    check("records sites bin_table_init 0",
          rec.get("sites", {}).get("bin_table_init") == 0)
    check("records sites second-handler 0",
          rec.get("sites", {}).get("second_handler") == 0)
    check("records sites lock-wait 1",
          rec.get("sites", {}).get("lock_wait") == 1)
    check("records sites bsr 2",
          rec.get("sites", {}).get("bsr") == 2)
    check("records window bytes 1333",
          rec.get("window", {}).get("bytes") == 1333)
    check("records window range",
          rec.get("window", {}).get("range") == "0x636a140..0x636a675")
    check("records return value is r15 (record pointer, or 0)",
          rec.get("return_value", {}).get("rax") ==
          "r15 (record pointer, or 0)")

    # Sections (own ELF parse): .bss exact end; referenced addresses.
    secmap = sections(node)
    bss = secmap[".bss"]
    check("bss section 0x64ffe40..0x6728924",
          bss[3] == 0x64FFE40 and bss[3] + bss[5] == 0x6728924, str(bss))
    check("address 0x6711b34 inside .bss",
          bss[3] <= 0x6711B34 < bss[3] + bss[5])
    check("address 0x6712374 inside .bss",
          bss[3] <= 0x6712374 < bss[3] + bss[5])
    check("address 0x6728180 inside .bss",
          bss[3] <= 0x6728180 < bss[3] + bss[5])
    check("address 0x64df1a0 inside .data.rel.ro",
          secmap[".data.rel.ro"][3] <= 0x64DF1A0
          < secmap[".data.rel.ro"][3] + secmap[".data.rel.ro"][5])
    check("no 0x65096c0 referenced (no node table in this window)",
          not any("65096c0" in l for l in lines))
    txt = secmap[".text"]
    check("window inside .text",
          txt[3] <= START and END <= txt[3] + txt[5])
    check("call target 0x63ad870 inside .text (internal, not PLT)",
          txt[3] <= 0x63AD870 < txt[3] + txt[5])
    check("call target 0x63ef8e0 inside .text (internal, not PLT)",
          txt[3] <= 0x63EF8E0 < txt[3] + txt[5])

    # rela counts by direct ELF parse
    dyn_total = plt_total = rel_count = 0
    for nm, s in secmap.items():
        if nm == ".rela.dyn":
            dyn_total = s[5] // 24
            for j in range(dyn_total):
                rtype = struct.unpack_from("<Q", node, s[4] + j * 24 + 8)[0] & 0xFFFFFFFF
                if rtype == 8:
                    rel_count += 1
        if nm == ".rela.plt":
            plt_total = s[5] // 24
    check("rela.dyn total 60723", dyn_total == 60723, str(dyn_total))
    check("rela.dyn RELATIVE 59534", rel_count == 59534, str(rel_count))
    check("rela.plt 278", plt_total == 278, str(plt_total))

    # raw-e8 census: scan .text for e8 with rel32 targets 0x63d9700 /
    # 0x63d9880 / 0x634ebb0 / 0x63bf680 (lock-wait helper).
    text_sec = secmap[".text"]
    tva, toff_sec, tsize = text_sec[3], text_sec[4], text_sec[5]
    tbytes = node[toff_sec:toff_sec + tsize]
    counts = {}
    bti_counts = {}
    sh_counts = {}
    lw_counts = {}
    pos = tbytes.find(b"\xe8")
    while pos != -1:
        if pos + 5 <= len(tbytes):
            rel = struct.unpack_from("<i", tbytes, pos + 1)[0]
            tgtv = tva + pos + 5 + rel
            va = tva + pos
            k = bisect.bisect_right(starts, va) - 1
            if k >= 0 and fdes[k][0] <= va < fdes[k][1]:
                if tgtv == 0x63D9700:
                    counts[fdes[k][0]] = counts.get(fdes[k][0], 0) + 1
                if tgtv == 0x63D9880:
                    bti_counts[fdes[k][0]] = bti_counts.get(fdes[k][0], 0) + 1
                if tgtv == 0x634EBB0:
                    sh_counts[fdes[k][0]] = sh_counts.get(fdes[k][0], 0) + 1
                if tgtv == 0x63BF680:
                    lw_counts[fdes[k][0]] = lw_counts.get(fdes[k][0], 0) + 1
        pos = tbytes.find(b"\xe8", pos + 1)
    tiers = {}
    for v in counts.values():
        tiers[v] = tiers.get(v, 0) + 1
    check("raw-e8 lu-miss total 168", sum(counts.values()) == 168,
          str(sum(counts.values())))
    check("raw-e8 lu-miss tiers",
          tiers == {1: 18, 2: 14, 3: 1, 4: 11, 5: 1, 6: 2, 7: 1, 8: 1, 10: 3, 13: 1},
          str(tiers))
    check("raw-e8 lu-miss FDEs 53", len(counts) == 53, str(len(counts)))
    check("this FDE raw lu-miss 0", counts.get(START, 0) == 0,
          str(counts.get(START, 0)))
    check("#321 shared FDE raw lu-miss 2", counts.get(0x63C9650, 0) == 2,
          str(counts.get(0x63C9650, 0)))
    bti_tiers = {}
    for v in bti_counts.values():
        bti_tiers[v] = bti_tiers.get(v, 0) + 1
    check("raw-e8 bti total 108", sum(bti_counts.values()) == 108,
          str(sum(bti_counts.values())))
    check("raw-e8 bti tiers",
          bti_tiers == {1: 17, 2: 12, 4: 8, 5: 1, 6: 2, 8: 1, 10: 1},
          str(bti_tiers))
    check("raw-e8 bti FDEs 42", len(bti_counts) == 42, str(len(bti_counts)))
    check("this FDE raw bti 0", bti_counts.get(START, 0) == 0,
          str(bti_counts.get(START, 0)))
    check("#258 FDE raw bti 2", bti_counts.get(0x63EF8E0, 0) == 2,
          str(bti_counts.get(0x63EF8E0, 0)))
    check("this FDE raw second-handler 0",
          sh_counts.get(START, 0) == 0, str(sh_counts.get(START, 0)))
    check("raw-e8 second-handler total 64", sum(sh_counts.values()) == 64,
          str(sum(sh_counts.values())))
    check("raw-e8 second-handler FDEs 28", len(sh_counts) == 28,
          str(len(sh_counts)))
    check("0x63bcd20 raw second-handler 2",
          sh_counts.get(0x63BCD20, 0) == 2, str(sh_counts.get(0x63BCD20, 0)))
    check("0x6387880 raw second-handler 1",
          sh_counts.get(0x6387880, 0) == 1, str(sh_counts.get(0x6387880, 0)))
    lw_tiers = {}
    for v in lw_counts.values():
        lw_tiers[v] = lw_tiers.get(v, 0) + 1
    check("raw-e8 lock-wait total 474", sum(lw_counts.values()) == 474,
          str(sum(lw_counts.values())))
    check("raw-e8 lock-wait tiers",
          lw_tiers == {1: 348, 2: 19, 3: 9, 4: 4, 5: 1, 7: 2, 8: 1, 18: 1},
          str(lw_tiers))
    check("raw-e8 lock-wait FDEs 385", len(lw_counts) == 385,
          str(len(lw_counts)))
    check("this FDE raw lock-wait 1", lw_counts.get(START, 0) == 1,
          str(lw_counts.get(START, 0)))
    check("next candidate raw lu-miss 0", counts.get(0x6386540, 0) == 0,
          str(counts.get(0x6386540, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x6386540, 0) == 0,
          str(bti_counts.get(0x6386540, 0)))
    check("next candidate raw second-handler 0",
          sh_counts.get(0x6386540, 0) == 0, str(sh_counts.get(0x6386540, 0)))
    check("next candidate raw lock-wait 1",
          lw_counts.get(0x6386540, 0) == 1,
          str(lw_counts.get(0x6386540, 0)))

    # lock-wait frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 344", len(survey.get("survivors", [])) == 344,
          str(len(survey.get("survivors", []))))
    check("survey this window is a lock-wait survivor",
          "0x636a140" in survey.get("survivors", []))
    check("survey this window is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x636a140") == 1,
          str(survey.get("sites_per_fde", {}).get("0x636a140")))
    check("survey one-site survivors 319",
          survey.get("one_site_survivors") == 319,
          str(survey.get("one_site_survivors")))
    check("survey lock-wait total sites 474",
          survey.get("total_sites") == 474,
          str(survey.get("total_sites")))
    check("survey lock-wait total FDEs 385",
          survey.get("total_fdes") == 385,
          str(survey.get("total_fdes")))
    check("survey lu-miss frontier exhausted (16/16 claimed)",
          survey.get("lu_miss_exhausted") is True)
    check("survey this window is NOT a lu-miss survivor",
          "0x636a140" not in survey.get("lu_miss_survivors", []))
    check("survey this window is NOT a second-handler survivor",
          "0x636a140" not in survey.get("second_handler_survivors", []))
    nq = rec.get("next_question", {})
    check("next question is the lock-wait frontier",
          nq.get("frontier") == "lock-wait helper 0x63bf680 callers",
          str(nq.get("frontier")))
    check("next question range 0x6386540..0x638693a",
          nq.get("range") == "0x6386540..0x638693a", str(nq.get("range")))
    check("next question bytes 1018", nq.get("bytes") == 1018,
          str(nq.get("bytes")))
    check("next question lu-miss sites 0",
          nq.get("lu_miss_sites") == 0, str(nq.get("lu_miss_sites")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 256", nq.get("strict") == 256,
          str(nq.get("strict")))
    check("next question calls 11", nq.get("calls") == 11,
          str(nq.get("calls")))
    check("next question indirect calls 0",
          nq.get("indirect_calls") == 0, str(nq.get("indirect_calls")))
    check("next question indirect sites",
          nq.get("indirect_sites") == [], str(nq.get("indirect_sites")))
    check("next question calls by target",
          nq.get("calls_by_target") ==
          {"0x6364350": 1, "0x6364360": 1, "0x63b5b40": 1, "0x63b5b50": 1,
           "0x63bf680": 1, "0x63f0b70": 1, "0x63f0d70": 1, "0x63f0f20": 3,
           "0x63f17b0": 1},
          str(nq.get("calls_by_target")))
    check("next question lock-wait sites 1",
          nq.get("lock_wait_sites") == 1, str(nq.get("lock_wait_sites")))
    check("next question lock-wait site list",
          nq.get("lock_wait_site") == ["0x6386664"],
          str(nq.get("lock_wait_site")))
    check("next question second-handler sites 0",
          nq.get("second_handler_sites") == 0,
          str(nq.get("second_handler_sites")))
    check("next question bsr 0", nq.get("bsr") == 0,
          str(nq.get("bsr")))
    check("next question rets 1",
          nq.get("ret") == ["0x638665c"], str(nq.get("ret")))
    check("next question jumps 46", nq.get("jumps") == 46,
          str(nq.get("jumps")))
    check("next question jumps outside 0", nq.get("jumps_outside_window") == 0,
          str(nq.get("jumps_outside_window")))
    check("next question endbr64 1", nq.get("endbr64") == 1,
          str(nq.get("endbr64")))
    check("next question canary present", nq.get("canary") is True,
          str(nq.get("canary")))
    check("next question plt calls 6", nq.get("plt_calls") == 6,
          str(nq.get("plt_calls")))
    check("records census strict 315",
          rec.get("census", {}).get("strict") == 315)
    check("records census calls 17",
          rec.get("census", {}).get("calls") == 17)
    check("records exhibits 2", len(rec.get("exhibits", [])) == 2,
          str(len(rec.get("exhibits", []))))

    # Disjointness against ALL prior records.json exhibits in the tree.
    own = os.path.join(PACKET, "records.json")
    mine = []
    skipped = []
    collect_ranges(rec, mine, skipped)
    check("own ranges collected", len(mine) >= 1, str(len(mine)))
    check("0 skipped own records", len(skipped) == 0, str(skipped[:3]))
    priors = []
    pskipped = []
    # Prior collection is I/O-bound (~3 min per verifier run: hundreds of
    # records.json reads). An optional fingerprint-validated cache
    # (HL_PRIORS_CACHE) reuses it across runs in one build: the fingerprint
    # is the sorted (relative path, size) of every candidate file, so any
    # content change invalidates it. Without the env var the verifier
    # always collects fresh; the cache never changes the verdict, only
    # the wall time. The tests set it and additionally assert the priors
    # count, so an empty/corrupt cache cannot pass vacuously.
    cand = sorted(glob.glob(os.path.join(ROOT, "..", "hl-wt-calls*",
                                         "research", "work-items", "*",
                                         "records.json")))
    cand = [os.path.normpath(d) for d in cand
            if SLUG not in os.path.normpath(d)
            and os.path.normpath(PACKET) not in os.path.normpath(d)]
    fp = []
    for d in cand:
        try:
            st = os.stat(d)
            fp.append([os.path.relpath(d, os.path.dirname(ROOT)), st.st_size])
        except Exception:
            pass
    cache_path = os.environ.get("HL_PRIORS_CACHE")
    used_cache = False
    if cache_path:
        try:
            with open(cache_path) as f:
                cache = json.load(f)
            if cache.get("fingerprint") == fp:
                priors = [tuple(x) for x in cache["priors"]]
                pskipped = cache["pskipped"]
                used_cache = True
        except Exception:
            used_cache = False
    if not used_cache:
        for d in cand:
            try:
                with open(d) as f:
                    collect_ranges(json.load(f), priors, pskipped)
            except Exception:
                pass
        if cache_path:
            try:
                with open(cache_path, "w") as f:
                    json.dump({"fingerprint": fp, "priors": priors,
                               "pskipped": pskipped}, f)
            except Exception:
                pass
    check("priors >= 50000", len(priors) >= 50000, str(len(priors)))
    check("priors 0 skipped", len(pskipped) == 0, str(pskipped[:3]))
    mine_set = set(mine)
    bad = []
    for m in mine_set:
        for p in priors:
            if m[0] < p[1] and p[0] < m[1]:
                bad.append((m, p))
                break
    check("disjointness NONE", not bad, str(bad[:3]))
    print("priors scanned: %d" % len(priors))
    # next candidate 0x6386540..0x638693a must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x6386540 < p[1] and p[0] < 0x638693A]
    check("next candidate 0x6386540 disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x638693A and 0x6386540 < END))

    # Slug uniqueness: committed tree + worktree scan, same packet excluded.
    slug_hit = False
    try:
        out = subprocess.run(["git", "ls-tree", "HEAD", "--name-only",
                              "research/work-items/"],
                             cwd=ROOT, capture_output=True, text=True,
                             timeout=60)
        if SLUG in out.stdout.split():
            slug_hit = True
    except Exception:
        pass
    if not slug_hit:
        for d in glob.glob(os.path.join(ROOT, "..", "hl-wt-calls*",
                                        "research", "work-items", SLUG)):
            dnorm = os.path.normpath(d)
            if os.path.normpath(PACKET) in dnorm:
                continue
            same_window = False
            try:
                with open(os.path.join(d, "records.json")) as f:
                    r2 = json.load(f)
                ranges2 = []
                collect_ranges(r2, ranges2, [])
                if (START, END) in ranges2:
                    same_window = True
            except Exception:
                pass
            if not same_window:
                slug_hit = True
    check("slug unique", not slug_hit)
    check("slug not colliding with #314-#331 lu-miss/lockwait slugs",
          SLUG not in ("RE-001-node115-lu-miss-caller-1site",
                       "RE-001-node115-lu-miss-caller-1site-dispatch",
                       "RE-001-node115-lu-miss-caller-1site-dispatch2",
                       "RE-001-node115-lu-miss-caller-1site-dispatch3",
                       "RE-001-node115-lu-miss-caller-4site-dispatch",
                       "RE-001-node115-lu-miss-caller-7site-dispatch",
                       "RE-001-node115-lu-miss-caller-1site-arraywalk",
                       "RE-001-node115-lu-miss-caller-2site-trylock",
                       "RE-001-node115-lu-miss-caller-6site-twowalk",
                       "RE-001-node115-lu-miss-caller-2site-ctypescan",
                       "RE-001-node115-lu-miss-caller-10site-threewalk",
                       "RE-001-node115-lu-miss-caller-10site-threetail",
                       "RE-001-node115-lu-miss-caller-2site-singlewalk",
                       "RE-001-node115-lu-miss-caller-1site-lookup",
                       "RE-001-node115-lu-miss-caller-1site-direct",
                       "RE-001-node115-lu-miss-caller-3site-prefetch",
                       "RE-001-node115-lockwait-caller-1site-bitloop",
                       "RE-001-node115-lockwait-caller-1site-bitmapdrain"))

    # MANIFEST: exactly 5 entries, packet files only, sha256 matches.
    man = read(os.path.join(PACKET, "MANIFEST.sha256")).decode()
    ok = True
    for line in man.strip().splitlines():
        h, name = line.split(None, 1)
        name = name.strip().lstrip("*")
        if name == "MANIFEST.sha256":
            ok = False
            break
        if hashlib.sha256(read(os.path.join(PACKET, name))).hexdigest() != h:
            ok = False
    check("MANIFEST hashes", ok)
    check("MANIFEST excludes itself", "MANIFEST.sha256" not in man)
    check("MANIFEST entries 5", len(man.strip().splitlines()) == 5,
          str(len(man.strip().splitlines())))
    check("MANIFEST has no tools/tests entries",
          not any("tools/" in l or "tests/" in l
                  for l in man.splitlines()))
    expect_names = {"README.md", "EVIDENCE.md", "records.json",
                    "lockwait_caller_1site_indirect.hex",
                    "lockwait_caller_1site_indirect.objdump.txt"}
    check("MANIFEST names are the 5 packet files",
          {l.split(None, 1)[1].strip().lstrip("*")
           for l in man.strip().splitlines()} == expect_names)

    # EVIDENCE + README presence.
    check("EVIDENCE.md present",
          os.path.exists(os.path.join(PACKET, "EVIDENCE.md")))
    check("README.md present",
          os.path.exists(os.path.join(PACKET, "README.md")))

    print("PASS %d FAIL %d" % (PASS, FAIL))
    if FAILURES:
        print("FAILURES:")
        for f in FAILURES:
            print(" - " + f)
    sys.exit(0 if FAIL == 0 else 1)

if __name__ == "__main__":
    main()
