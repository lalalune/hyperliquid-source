import bisect
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

SLUG = "RE-001-node115-lockwait-caller-1site-duffs"
START = 0x635f780
END = 0x635fb47
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
    (0x635f780, 'push', '%r15'),    (0x635f782, 'push', '%r14'),    (0x635f784, 'push', '%r13'),
    (0x635f786, 'push', '%r12'),    (0x635f788, 'push', '%rbp'),    (0x635f789, 'push', '%rbx'),
    (0x635f78a, 'sub', '$0x138,%rsp'),    (0x635f791, 'mov', '%fs:0x28,%rax'),    (0x635f79a, 'mov', '%rax,0x128(%rsp)'),
    (0x635f7a2, 'lea', '0x1a047f(%rip),%rax        # 64ffc28 <__register_atfork@plt+0x10e098>'),    (0x635f7a9, 'cmpb', '$0x0,(%rax)'),    (0x635f7ac, 'je', '635f7e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6173b0>'),
    (0x635f7ae, 'mov', '0x128(%rsp),%rax'),    (0x635f7b6, 'sub', '%fs:0x28,%rax'),    (0x635f7bf, 'jne', '635fb42 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617712>'),
    (0x635f7c5, 'add', '$0x138,%rsp'),    (0x635f7cc, 'pop', '%rbx'),    (0x635f7cd, 'pop', '%rbp'),
    (0x635f7ce, 'pop', '%r12'),    (0x635f7d0, 'pop', '%r13'),    (0x635f7d2, 'pop', '%r14'),
    (0x635f7d4, 'pop', '%r15'),    (0x635f7d6, 'ret', ''),    (0x635f7d7, 'nopw', '0x0(%rax,%rax,1)'),
    (0x635f7e0, 'movl', '$0x0,0x1c(%rsp)'),    (0x635f7e8, 'mov', '(%rsi),%r13d'),    (0x635f7eb, 'mov', '%rdi,%r12'),
    (0x635f7ee, 'call', '634eba0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x606770>'),    (0x635f7f3, 'mov', '%eax,0x4(%rsp)'),    (0x635f7f7, 'test', '%eax,%eax'),
    (0x635f7f9, 'je', '635f7ae <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61737e>'),    (0x635f7fb, 'lea', '0x1a9ebe(%rip),%r8        # 65096c0 <__register_atfork@plt+0x117b30>'),    (0x635f802, 'xor', '%ebx,%ebx'),
    (0x635f804, 'lea', '0x1c(%rsp),%rbp'),    (0x635f809, 'and', '$0x3,%eax'),    (0x635f80c, 'je', '635f952 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617522>'),
    (0x635f812, 'cmp', '$0x1,%eax'),    (0x635f815, 'je', '635f8e6 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6174b6>'),    (0x635f81b, 'cmp', '$0x2,%eax'),
    (0x635f81e, 'je', '635f884 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617454>'),    (0x635f820, 'test', '%r13d,%r13d'),    (0x635f823, 'je', '635f87b <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61744b>'),
    (0x635f825, 'mov', '(%r8),%r15'),    (0x635f828, 'test', '%r15,%r15'),    (0x635f82b, 'je', '635f87b <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61744b>'),
    (0x635f82d, 'lea', '0x20(%rsp),%rbx'),    (0x635f832, 'mov', '%rbp,%rcx'),    (0x635f835, 'mov', '%r12,%rdi'),
    (0x635f838, 'mov', '%r8,0x8(%rsp)'),    (0x635f83d, 'lea', '0x29e8(%r15),%rsi'),    (0x635f844, 'mov', '%rbx,%rdx'),
    (0x635f847, 'call', '635f6a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617270>'),    (0x635f84c, 'mov', '%rbp,%rcx'),    (0x635f84f, 'mov', '%rbx,%rdx'),
    (0x635f852, 'mov', '%r12,%rdi'),    (0x635f855, 'lea', '0x75d8(%r15),%rsi'),    (0x635f85c, 'call', '635f6a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617270>'),
    (0x635f861, 'mov', '%rbp,%rcx'),    (0x635f864, 'mov', '%rbx,%rdx'),    (0x635f867, 'mov', '%r12,%rdi'),
    (0x635f86a, 'lea', '0xc1c8(%r15),%rsi'),    (0x635f871, 'call', '635f6a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617270>'),    (0x635f876, 'mov', '0x8(%rsp),%r8'),
    (0x635f87b, 'mov', '$0x1,%ebx'),    (0x635f880, 'add', '$0x8,%r8'),    (0x635f884, 'cmp', '%ebx,%r13d'),
    (0x635f887, 'je', '635f8df <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6174af>'),    (0x635f889, 'mov', '(%r8),%r15'),    (0x635f88c, 'test', '%r15,%r15'),
    (0x635f88f, 'je', '635f8df <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6174af>'),    (0x635f891, 'lea', '0x20(%rsp),%r14'),    (0x635f896, 'mov', '%rbp,%rcx'),
    (0x635f899, 'mov', '%r12,%rdi'),    (0x635f89c, 'mov', '%r8,0x8(%rsp)'),    (0x635f8a1, 'lea', '0x29e8(%r15),%rsi'),
    (0x635f8a8, 'mov', '%r14,%rdx'),    (0x635f8ab, 'call', '635f6a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617270>'),    (0x635f8b0, 'mov', '%rbp,%rcx'),
    (0x635f8b3, 'mov', '%r14,%rdx'),    (0x635f8b6, 'mov', '%r12,%rdi'),    (0x635f8b9, 'lea', '0x75d8(%r15),%rsi'),
    (0x635f8c0, 'call', '635f6a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617270>'),    (0x635f8c5, 'mov', '%rbp,%rcx'),    (0x635f8c8, 'mov', '%r14,%rdx'),
    (0x635f8cb, 'mov', '%r12,%rdi'),    (0x635f8ce, 'lea', '0xc1c8(%r15),%rsi'),    (0x635f8d5, 'call', '635f6a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617270>'),
    (0x635f8da, 'mov', '0x8(%rsp),%r8'),    (0x635f8df, 'add', '$0x1,%ebx'),    (0x635f8e2, 'add', '$0x8,%r8'),
    (0x635f8e6, 'cmp', '%ebx,%r13d'),    (0x635f8e9, 'je', '635f941 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617511>'),    (0x635f8eb, 'mov', '(%r8),%r15'),
    (0x635f8ee, 'test', '%r15,%r15'),    (0x635f8f1, 'je', '635f941 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617511>'),    (0x635f8f3, 'lea', '0x20(%rsp),%r14'),
    (0x635f8f8, 'mov', '%rbp,%rcx'),    (0x635f8fb, 'mov', '%r12,%rdi'),    (0x635f8fe, 'mov', '%r8,0x8(%rsp)'),
    (0x635f903, 'lea', '0x29e8(%r15),%rsi'),    (0x635f90a, 'mov', '%r14,%rdx'),    (0x635f90d, 'call', '635f6a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617270>'),
    (0x635f912, 'mov', '%rbp,%rcx'),    (0x635f915, 'mov', '%r14,%rdx'),    (0x635f918, 'mov', '%r12,%rdi'),
    (0x635f91b, 'lea', '0x75d8(%r15),%rsi'),    (0x635f922, 'call', '635f6a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617270>'),    (0x635f927, 'mov', '%rbp,%rcx'),
    (0x635f92a, 'mov', '%r14,%rdx'),    (0x635f92d, 'mov', '%r12,%rdi'),    (0x635f930, 'lea', '0xc1c8(%r15),%rsi'),
    (0x635f937, 'call', '635f6a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617270>'),    (0x635f93c, 'mov', '0x8(%rsp),%r8'),    (0x635f941, 'add', '$0x1,%ebx'),
    (0x635f944, 'add', '$0x8,%r8'),    (0x635f948, 'cmp', '%ebx,0x4(%rsp)'),    (0x635f94c, 'je', '635fad7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6176a7>'),
    (0x635f952, 'cmp', '%ebx,%r13d'),    (0x635f955, 'je', '635f9ad <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61757d>'),    (0x635f957, 'mov', '(%r8),%r14'),
    (0x635f95a, 'test', '%r14,%r14'),    (0x635f95d, 'je', '635f9ad <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61757d>'),    (0x635f95f, 'lea', '0x20(%rsp),%r15'),
    (0x635f964, 'mov', '%rbp,%rcx'),    (0x635f967, 'mov', '%r12,%rdi'),    (0x635f96a, 'mov', '%r8,0x8(%rsp)'),
    (0x635f96f, 'lea', '0x29e8(%r14),%rsi'),    (0x635f976, 'mov', '%r15,%rdx'),    (0x635f979, 'call', '635f6a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617270>'),
    (0x635f97e, 'mov', '%rbp,%rcx'),    (0x635f981, 'mov', '%r15,%rdx'),    (0x635f984, 'mov', '%r12,%rdi'),
    (0x635f987, 'lea', '0x75d8(%r14),%rsi'),    (0x635f98e, 'call', '635f6a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617270>'),    (0x635f993, 'mov', '%rbp,%rcx'),
    (0x635f996, 'mov', '%r15,%rdx'),    (0x635f999, 'mov', '%r12,%rdi'),    (0x635f99c, 'lea', '0xc1c8(%r14),%rsi'),
    (0x635f9a3, 'call', '635f6a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617270>'),    (0x635f9a8, 'mov', '0x8(%rsp),%r8'),    (0x635f9ad, 'lea', '0x1(%rbx),%r14d'),
    (0x635f9b1, 'lea', '0x8(%r8),%r15'),    (0x635f9b5, 'cmp', '%r14d,%r13d'),    (0x635f9b8, 'je', '635fa0d <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6175dd>'),
    (0x635f9ba, 'mov', '0x8(%r8),%rbx'),    (0x635f9be, 'test', '%rbx,%rbx'),    (0x635f9c1, 'je', '635fa0d <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6175dd>'),
    (0x635f9c3, 'lea', '0x20(%rsp),%rdx'),    (0x635f9c8, 'lea', '0x29e8(%rbx),%rsi'),    (0x635f9cf, 'mov', '%rbp,%rcx'),
    (0x635f9d2, 'mov', '%r12,%rdi'),    (0x635f9d5, 'mov', '%rdx,0x8(%rsp)'),    (0x635f9da, 'call', '635f6a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617270>'),
    (0x635f9df, 'mov', '0x8(%rsp),%rdx'),    (0x635f9e4, 'mov', '%rbp,%rcx'),    (0x635f9e7, 'mov', '%r12,%rdi'),
    (0x635f9ea, 'lea', '0x75d8(%rbx),%rsi'),    (0x635f9f1, 'call', '635f6a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617270>'),    (0x635f9f6, 'mov', '0x8(%rsp),%rdx'),
    (0x635f9fb, 'mov', '%rbp,%rcx'),    (0x635f9fe, 'mov', '%r12,%rdi'),    (0x635fa01, 'lea', '0xc1c8(%rbx),%rsi'),
    (0x635fa08, 'call', '635f6a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617270>'),    (0x635fa0d, 'lea', '0x1(%r14),%ecx'),    (0x635fa11, 'cmp', '%ecx,%r13d'),
    (0x635fa14, 'je', '635fa69 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617639>'),    (0x635fa16, 'mov', '0x8(%r15),%rbx'),    (0x635fa1a, 'test', '%rbx,%rbx'),
    (0x635fa1d, 'je', '635fa69 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617639>'),    (0x635fa1f, 'lea', '0x20(%rsp),%rdx'),    (0x635fa24, 'lea', '0x29e8(%rbx),%rsi'),
    (0x635fa2b, 'mov', '%rbp,%rcx'),    (0x635fa2e, 'mov', '%r12,%rdi'),    (0x635fa31, 'mov', '%rdx,0x8(%rsp)'),
    (0x635fa36, 'call', '635f6a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617270>'),    (0x635fa3b, 'mov', '0x8(%rsp),%rdx'),    (0x635fa40, 'mov', '%rbp,%rcx'),
    (0x635fa43, 'mov', '%r12,%rdi'),    (0x635fa46, 'lea', '0x75d8(%rbx),%rsi'),    (0x635fa4d, 'call', '635f6a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617270>'),
    (0x635fa52, 'mov', '0x8(%rsp),%rdx'),    (0x635fa57, 'mov', '%rbp,%rcx'),    (0x635fa5a, 'mov', '%r12,%rdi'),
    (0x635fa5d, 'lea', '0xc1c8(%rbx),%rsi'),    (0x635fa64, 'call', '635f6a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617270>'),    (0x635fa69, 'lea', '0x2(%r14),%esi'),
    (0x635fa6d, 'cmp', '%esi,%r13d'),    (0x635fa70, 'je', '635fac5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617695>'),    (0x635fa72, 'mov', '0x10(%r15),%rbx'),
    (0x635fa76, 'test', '%rbx,%rbx'),    (0x635fa79, 'je', '635fac5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617695>'),    (0x635fa7b, 'lea', '0x20(%rsp),%rdx'),
    (0x635fa80, 'lea', '0x29e8(%rbx),%rsi'),    (0x635fa87, 'mov', '%rbp,%rcx'),    (0x635fa8a, 'mov', '%r12,%rdi'),
    (0x635fa8d, 'mov', '%rdx,0x8(%rsp)'),    (0x635fa92, 'call', '635f6a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617270>'),    (0x635fa97, 'mov', '0x8(%rsp),%rdx'),
    (0x635fa9c, 'mov', '%rbp,%rcx'),    (0x635fa9f, 'mov', '%r12,%rdi'),    (0x635faa2, 'lea', '0x75d8(%rbx),%rsi'),
    (0x635faa9, 'call', '635f6a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617270>'),    (0x635faae, 'mov', '0x8(%rsp),%rdx'),    (0x635fab3, 'mov', '%rbp,%rcx'),
    (0x635fab6, 'mov', '%r12,%rdi'),    (0x635fab9, 'lea', '0xc1c8(%rbx),%rsi'),    (0x635fac0, 'call', '635f6a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617270>'),
    (0x635fac5, 'lea', '0x3(%r14),%ebx'),    (0x635fac9, 'lea', '0x18(%r15),%r8'),    (0x635facd, 'cmp', '%ebx,0x4(%rsp)'),
    (0x635fad1, 'jne', '635f952 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x617522>'),    (0x635fad7, 'mov', '0x1c(%rsp),%edi'),    (0x635fadb, 'test', '%edi,%edi'),
    (0x635fadd, 'je', '635f7ae <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61737e>'),    (0x635fae3, 'lea', '0x20(%rsp),%rbp'),    (0x635fae8, 'lea', '0x0(%rbp,%rdi,8),%r13'),
    (0x635faed, 'jmp', '635fb1e <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6176ee>'),    (0x635faef, 'nop', ''),    (0x635faf0, 'addq', '$0x1,0x38(%r14)'),
    (0x635faf5, 'cmp', '0x30(%r14),%r12'),    (0x635faf9, 'je', '635fb04 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6176d4>'),    (0x635fafb, 'addq', '$0x1,0x28(%r14)'),
    (0x635fb00, 'mov', '%r12,0x30(%r14)'),    (0x635fb04, 'movb', '$0x0,0x68(%rdi)'),    (0x635fb08, 'add', '$0x8,%rbp'),
    (0x635fb0c, 'add', '$0x40,%rdi'),    (0x635fb10, 'call', '63f0b70 <pthread_mutex_unlock@plt>'),    (0x635fb15, 'cmp', '%rbp,%r13'),
    (0x635fb18, 'je', '635f7ae <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61737e>'),    (0x635fb1e, 'mov', '0x0(%rbp),%r14'),    (0x635fb22, 'lea', '0x40(%r14),%rdi'),
    (0x635fb26, 'call', '63f17b0 <pthread_mutex_trylock@plt>'),    (0x635fb2b, 'mov', '%r14,%rdi'),    (0x635fb2e, 'test', '%eax,%eax'),
    (0x635fb30, 'je', '635faf0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6176c0>'),    (0x635fb32, 'call', '63bf680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677250>'),    (0x635fb37, 'movb', '$0x1,0x68(%r14)'),
    (0x635fb3c, 'mov', '0x0(%rbp),%rdi'),    (0x635fb40, 'jmp', '635faf0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6176c0>'),    (0x635fb42, 'call', '63f0d70 <__stack_chk_fail@plt>'),
]


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
    check("target FDE size 967", END - START == 967)
    prev = fdes[i - 1]
    check("prev FDE 0x635f6a0..0x635f77c",
          prev == (0x635F6A0, 0x635F77C), str(prev))
    check("prev gap 4 (0xcc padding)", START - prev[1] == 4)
    check("prev gap bytes are 0xcc int3 padding",
          node[toff(prev[1]):toff(START)] == b"\xcc" * 4)
    nxt = fdes[i + 1]
    check("next FDE 0x635fb50..0x635fcf2",
          nxt == (0x635FB50, 0x635FCF2), str(nxt))
    check("next gap 9 (0xcc padding)", nxt[0] - END == 9)
    check("next gap bytes are 0xcc int3 padding",
          node[toff(END):toff(nxt[0])] == b"\xcc" * 9)
    check("next FDE starts push %r15, not endbr64",
          node[toff(nxt[0]):toff(nxt[0]) + 2] == b"\x41\x57"
          and node[toff(nxt[0]):toff(nxt[0]) + 4] != b"\xf3\x0f\x1e\xfa")
    check("prev FDE end is 4 bytes before this FDE start",
          prev[1] == START - 4)
    check("call-target FDE 0x634eba0..0x634ebab",
          fdes[bisect.bisect_left(starts, 0x634EBA0)] ==
          (0x634EBA0, 0x634EBAB))
    check("count FDE is 11 bytes, starts endbr64, is not the handler",
          node[toff(0x634EBA0):toff(0x634EBA0) + 4] == b"\xf3\x0f\x1e\xfa"
          and fdes[bisect.bisect_left(starts, 0x634EBA0)][1] -
          fdes[bisect.bisect_left(starts, 0x634EBA0)][0] == 11)
    check("call-target FDE 0x635f6a0..0x635f77c",
          fdes[bisect.bisect_left(starts, 0x635F6A0)] ==
          (0x635F6A0, 0x635F77C))
    check("next-candidate callee FDE 0x6360ed0..0x636116d",
          fdes[bisect.bisect_left(starts, 0x6360ED0)] ==
          (0x6360ED0, 0x636116D))
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
    check("next-question FDE 0x6386110..0x63864b9",
          fdes[bisect.bisect_left(starts, 0x6386110)] ==
          (0x6386110, 0x63864B9))
    check("#321 shared FDE 0x63c9650..0x63c9c80",
          fdes[bisect.bisect_left(starts, 0x63C9650)] ==
          (0x63C9650, 0x63C9C80))

    hexb = read(os.path.join(PACKET, "lockwait_caller_1site_duffs.hex"))
    check("hex exhibit raw bytes 967", len(hexb) == 967, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])
    objdump = read(os.path.join(
        PACKET, "lockwait_caller_1site_duffs.objdump.txt")).decode()
    lines = strict_lines(objdump)
    check("strict lines 240", len(lines) == 240, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if mnemonic_of(l) == "call"]
    check("call lines 26", len(calls) == 26, str(len(calls)))
    rets = [l for l in lines if mnemonic_of(l) == "ret"]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x635f7d6",
          sorted(addr_of(l) for l in rets) == [0x635F7D6],
          str([hex(addr_of(l)) for l in rets]))
    tgt = {}
    for l in calls:
        m = re.search(r"\tcall\s+([0-9a-f]+)", l)
        if m:
            t = int(m.group(1), 16)
            tgt[t] = tgt.get(t, 0) + 1
    indirect = [l for l in calls
                if re.search(r"\tcall\s+\*", l)]
    check("indirect calls 0", len(indirect) == 0,
          str([hex(addr_of(l)) for l in indirect]))
    expect = {0x634EBA0: 1, 0x635F6A0: 21, 0x63BF680: 1, 0x63F0B70: 1,
              0x63F0D70: 1, 0x63F17B0: 1}
    check("call target multiset exact", dict(tgt) == expect, str(tgt))
    check("distinct direct call targets 6", len(tgt) == 6, str(len(tgt)))
    check("no bti sites", tgt.get(0x63D9880, 0) == 0,
          str(tgt.get(0x63D9880, 0)))
    check("lu-miss sites 0",
          tgt.get(0x63D9700, 0) == 0, str(tgt.get(0x63D9700, 0)))
    check("second-handler sites 0", tgt.get(0x634EBB0, 0) == 0,
          str(tgt.get(0x634EBB0, 0)))
    check("lock-wait helper called 1 time", tgt.get(0x63BF680, 0) == 1,
          str(tgt.get(0x63BF680, 0)))
    check("lock-wait site is 0x635fb32",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63bf680" in l) == [0x635FB32])
    check("resolver 0x6365150 called 0 times", tgt.get(0x6365150, 0) == 0,
          str(tgt.get(0x6365150, 0)))
    check("stack_chk_fail plt call 1 at 0x635fb42",
          tgt.get(0x63F0D70, 0) == 1, str(tgt.get(0x63F0D70, 0)))
    check("trylock plt call 1 at 0x635fb26",
          tgt.get(0x63F17B0, 0) == 1, str(tgt.get(0x63F17B0, 0)))
    check("unlock plt call 1 at 0x635fb10",
          tgt.get(0x63F0B70, 0) == 1, str(tgt.get(0x63F0B70, 0)))
    check("count call 0x634eba0 1 at 0x635f7ee",
          tgt.get(0x634EBA0, 0) == 1, str(tgt.get(0x634EBA0, 0)))
    check("callee 0x635f6a0 called 21 times at the exact sites",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "635f6a0" in l) ==
          [0x635F847, 0x635F85C, 0x635F871, 0x635F8AB, 0x635F8C0, 0x635F8D5,
           0x635F90D, 0x635F922, 0x635F937, 0x635F979, 0x635F98E, 0x635F9A3,
           0x635F9DA, 0x635F9F1, 0x635FA08, 0x635FA36, 0x635FA4D, 0x635FA64,
           0x635FA92, 0x635FAA9, 0x635FAC0])
    plt_calls = [l for l in calls if "@plt" in l]
    check("PLT calls 3 (by @plt suffix, not address range)",
          len(plt_calls) == 3, str(len(plt_calls)))
    check("distinct PLT targets 3",
          len({re.search(r"\tcall\s+([0-9a-f]+)", l).group(1)
               for l in plt_calls}) == 3)
    check("no internal .text call is counted as PLT",
          not any("635f6a0" in l and "@plt" in l for l in calls)
          and not any("634eba0" in l and "@plt" in l for l in calls))
    for _w, _a in (("#314", 0x63495B0), ("#315", 0x6353A70),
                  ("#316", 0x6355900), ("#317", 0x63577F0),
                  ("#318", 0x635A7A0), ("#319", 0x635C6D0),
                  ("#320", 0x635E2E0), ("#321", 0x63C9650),
                  ("#322", 0x63CCD60), ("#323", 0x63CDDD0),
                  ("#324", 0x63D03A0), ("#325", 0x63D17E0),
                  ("#326", 0x63D2A80), ("#327", 0x63D3F0E),
                  ("#328", 0x63D4048), ("#329", 0x63E94A0),
                  ("#330", 0x6362190), ("#331", 0x6362910),
                  ("#332", 0x636A140), ("#333", 0x6386540)):
        check("%s window not called" % _w, tgt.get(_a, 0) == 0,
              str(tgt.get(_a, 0)))

    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", len(bsr) == 0, str([hex(addr_of(l)) for l in bsr]))
    check("shr 0 (no shift anywhere; remainder uses AND)",
          [l for l in lines if mnemonic_of(l) == "shr"] == [])
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
    check("jump lines 28", len(jmps) == 28, str(len(jmps)))

    def jump_target(line):
        m = re.search(r"\s([0-9a-f]{6,})\s*<", line)
        return int(m.group(1), 16) if m else None

    outside = []
    for l in jmps:
        t = jump_target(l)
        if t is not None and not (START <= t < END):
            outside.append((addr_of(l), t))
    check("jump closure: 0 outside the window", outside == [], str(outside))
    check("jump targets are exactly the 28 branches",
          sorted(jump_target(l) for l in jmps) ==
          [0x635F7AE, 0x635F7AE, 0x635F7AE, 0x635F7E0, 0x635F87B, 0x635F87B,
           0x635F884, 0x635F8DF, 0x635F8DF, 0x635F8E6, 0x635F941, 0x635F941,
           0x635F952, 0x635F952, 0x635F9AD, 0x635F9AD, 0x635FA0D, 0x635FA0D,
           0x635FA69, 0x635FA69, 0x635FAC5, 0x635FAC5, 0x635FAD7, 0x635FAF0,
           0x635FAF0, 0x635FB04, 0x635FB1E, 0x635FB42],
          str(sorted(jump_target(l) for l in jmps)))
    check("endbr64 count 0",
          sum(1 for l in lines if "endbr64" in l) == 0)
    check("entry is push %r15 at 0x635f780 (no endbr64)",
          "push" in by_addr[START] and "%r15" in by_addr[START])
    check("canary present: 2 fs:0x28 lines",
          sum(1 for l in lines if "%fs:0x28" in l) == 2)
    check("canary load at 0x635f791",
          "mov" in by_addr[0x635F791] and "%fs:0x28,%rax" in by_addr[0x635F791])
    check("canary save to 0x128(rsp) at 0x635f79a",
          "mov" in by_addr[0x635F79A] and "%rax,0x128(%rsp)" in by_addr[0x635F79A])
    check("canary check sub at 0x635f7b6",
          "sub" in by_addr[0x635F7B6] and "%fs:0x28,%rax" in by_addr[0x635F7B6])
    check("canary fail jne to stack_chk_fail at 0x635f7bf",
          "jne" in by_addr[0x635F7BF] and "635fb42" in by_addr[0x635F7BF])
    check("TLS flag check absent: 0 fs:0x330 lines",
          sum(1 for l in lines if "%fs:0x330" in l) == 0)
    check("no size-table lea 0x6727a00 anywhere",
          not any("6727a00" in l for l in lines))
    check("no byte-table lea 0x67277c0 anywhere",
          not any("67277c0" in l for l in lines))
    check("no fallback-table lea 0x6728140 anywhere",
          not any("6728140" in l for l in lines))
    check("no lu-miss .bss 0x6511a00 anywhere",
          not any("6511a00" in l for l in lines))
    check("no shr $0x1c anywhere (no 10-bit tag extract)",
          not any("shr" in l and "$0x1c" in l for l in lines))
    check("no prefetch instructions",
          not any("prefetch" in l for l in lines))
    check("tzcnt 0",
          [l for l in lines if mnemonic_of(l) == "tzcnt"] == [])
    check("btc 0",
          [l for l in lines if mnemonic_of(l) == "btc"] == [])
    check("entry-gate lea 0x64ffc28 at 0x635f7a2",
          "lea" in by_addr[0x635F7A2] and "64ffc28" in by_addr[0x635F7A2])
    check("entry-gate cmpb $0x0,(%rax) at 0x635f7a9",
          "cmpb" in by_addr[0x635F7A9] and "$0x0,(%rax)" in by_addr[0x635F7A9])
    check("entry-gate je 0x635f7e0 at 0x635f7ac",
          "je" in by_addr[0x635F7AC] and "635f7e0" in by_addr[0x635F7AC])
    check("count init movl $0x0,0x1c(rsp) at 0x635f7e0",
          "movl" in by_addr[0x635F7E0] and "$0x0,0x1c(%rsp)" in by_addr[0x635F7E0])
    check("exclusion index mov (%rsi),%r13d at 0x635f7e8",
          "mov" in by_addr[0x635F7E8] and "(%rsi),%r13d" in by_addr[0x635F7E8])
    check("owner save mov %rdi,%r12 at 0x635f7eb",
          "mov" in by_addr[0x635F7EB] and "%rdi,%r12" in by_addr[0x635F7EB])
    check("count call at 0x635f7ee",
          "call" in by_addr[0x635F7EE] and "634eba0" in by_addr[0x635F7EE])
    check("count store mov %eax,0x4(rsp) at 0x635f7f3",
          "mov" in by_addr[0x635F7F3] and "%eax,0x4(%rsp)" in by_addr[0x635F7F3])
    check("N==0 je epilogue at 0x635f7f9",
          "je" in by_addr[0x635F7F9] and "635f7ae" in by_addr[0x635F7F9])
    check("runtime-table lea 0x65096c0 at 0x635f7fb",
          "lea" in by_addr[0x635F7FB] and "65096c0" in by_addr[0x635F7FB])
    check("count-addr lea 0x1c(rsp) at 0x635f804",
          "lea" in by_addr[0x635F804] and "0x1c(%rsp),%rbp" in by_addr[0x635F804])
    check("remainder and $0x3,%eax at 0x635f809",
          "and" in by_addr[0x635F809] and "$0x3,%eax" in by_addr[0x635F809])
    check("dispatch je D 0x635f952 at 0x635f80c",
          "je" in by_addr[0x635F80C] and "635f952" in by_addr[0x635F80C])
    check("dispatch je C 0x635f8e6 at 0x635f815",
          "je" in by_addr[0x635F815] and "635f8e6" in by_addr[0x635F815])
    check("dispatch je B 0x635f884 at 0x635f81e",
          "je" in by_addr[0x635F81E] and "635f884" in by_addr[0x635F81E])
    check("exclusion test %r13d,%r13d at 0x635f820",
          "test" in by_addr[0x635F820] and "%r13d,%r13d" in by_addr[0x635F820])
    check("exclusion cmp %ebx,%r13d at 0x635f884",
          "cmp" in by_addr[0x635F884] and "%ebx,%r13d" in by_addr[0x635F884])
    check("exclusion cmp %ebx,%r13d at 0x635f8e6",
          "cmp" in by_addr[0x635F8E6] and "%ebx,%r13d" in by_addr[0x635F8E6])
    check("exclusion cmp %ebx,%r13d at 0x635f952",
          "cmp" in by_addr[0x635F952] and "%ebx,%r13d" in by_addr[0x635F952])
    check("sub-node lea +0x29e8 at 0x635f83d",
          "lea" in by_addr[0x635F83D] and "0x29e8(%r15),%rsi" in by_addr[0x635F83D])
    check("sub-node lea +0x75d8 at 0x635f855",
          "lea" in by_addr[0x635F855] and "0x75d8(%r15),%rsi" in by_addr[0x635F855])
    check("sub-node lea +0xc1c8 at 0x635f86a",
          "lea" in by_addr[0x635F86A] and "0xc1c8(%r15),%rsi" in by_addr[0x635F86A])
    check("D-loop ebx+=4 lea at 0x635fac5",
          "lea" in by_addr[0x635FAC5] and "0x3(%r14),%ebx" in by_addr[0x635FAC5])
    check("D-loop r8+=0x20 lea at 0x635fac9",
          "lea" in by_addr[0x635FAC9] and "0x18(%r15),%r8" in by_addr[0x635FAC9])
    check("D-loop back jne 0x635f952 at 0x635fad1",
          "jne" in by_addr[0x635FAD1] and "635f952" in by_addr[0x635FAD1])
    check("C-exit je drain 0x635fad7 at 0x635f94c",
          "je" in by_addr[0x635F94C] and "635fad7" in by_addr[0x635F94C])
    check("drain count mov 0x1c(rsp),%edi at 0x635fad7",
          "mov" in by_addr[0x635FAD7] and "0x1c(%rsp),%edi" in by_addr[0x635FAD7])
    check("empty-queue je epilogue at 0x635fadd",
          "je" in by_addr[0x635FADD] and "635f7ae" in by_addr[0x635FADD])
    check("drain base lea 0x20(rsp) at 0x635fae3",
          "lea" in by_addr[0x635FAE3] and "0x20(%rsp),%rbp" in by_addr[0x635FAE3])
    check("drain end lea at 0x635fae8",
          "lea" in by_addr[0x635FAE8] and "0x0(%rbp,%rdi,8),%r13" in by_addr[0x635FAE8])
    check("drain jmp tail head at 0x635faed",
          "jmp" in by_addr[0x635FAED] and "635fb1e" in by_addr[0x635FAED])
    check("tail node load mov 0x0(%rbp),%r14 at 0x635fb1e",
          "mov" in by_addr[0x635FB1E] and "0x0(%rbp),%r14" in by_addr[0x635FB1E])
    check("tail mutex lea 0x40(%r14) at 0x635fb22",
          "lea" in by_addr[0x635FB22] and "0x40(%r14),%rdi" in by_addr[0x635FB22])
    check("trylock call at 0x635fb26",
          "call" in by_addr[0x635FB26] and "63f17b0" in by_addr[0x635FB26])
    check("lock-wait setup mov %r14,%rdi at 0x635fb2b",
          "mov" in by_addr[0x635FB2B] and "%r14,%rdi" in by_addr[0x635FB2B])
    check("trylock-success je rejoin at 0x635fb30",
          "je" in by_addr[0x635FB30] and "635faf0" in by_addr[0x635FB30])
    check("lock-wait call at 0x635fb32",
          "call" in by_addr[0x635FB32] and "63bf680" in by_addr[0x635FB32])
    check("waited-flag set movb $0x1,0x68(%r14) at 0x635fb37",
          "movb" in by_addr[0x635FB37] and "$0x1,0x68(%r14)" in by_addr[0x635FB37])
    check("node reload mov 0x0(%rbp),%rdi at 0x635fb3c",
          "mov" in by_addr[0x635FB3C] and "0x0(%rbp),%rdi" in by_addr[0x635FB3C])
    check("lock-wait jmp rejoin at 0x635fb40",
          "jmp" in by_addr[0x635FB40] and "635faf0" in by_addr[0x635FB40])
    check("acquired addq $0x1,0x38(%r14) at 0x635faf0",
          "addq" in by_addr[0x635FAF0] and "$0x1,0x38(%r14)" in by_addr[0x635FAF0])
    check("owner cmp 0x30(%r14),%r12 at 0x635faf5",
          "cmp" in by_addr[0x635FAF5] and "0x30(%r14),%r12" in by_addr[0x635FAF5])
    check("owner-count addq $0x1,0x28(%r14) at 0x635fafb",
          "addq" in by_addr[0x635FAFB] and "$0x1,0x28(%r14)" in by_addr[0x635FAFB])
    check("owner store mov %r12,0x30(%r14) at 0x635fb00",
          "mov" in by_addr[0x635FB00] and "%r12,0x30(%r14)" in by_addr[0x635FB00])
    check("waited-flag clear movb $0x0,0x68(%rdi) at 0x635fb04",
          "movb" in by_addr[0x635FB04] and "$0x0,0x68(%rdi)" in by_addr[0x635FB04])
    check("drain advance add $0x8,%rbp at 0x635fb08",
          "add" in by_addr[0x635FB08] and "$0x8,%rbp" in by_addr[0x635FB08])
    check("unlock-arg add $0x40,%rdi at 0x635fb0c",
          "add" in by_addr[0x635FB0C] and "$0x40,%rdi" in by_addr[0x635FB0C])
    check("unlock call at 0x635fb10",
          "call" in by_addr[0x635FB10] and "63f0b70" in by_addr[0x635FB10])
    check("drain-end cmp %rbp,%r13 at 0x635fb15",
          "cmp" in by_addr[0x635FB15] and "%rbp,%r13" in by_addr[0x635FB15])
    check("drain-done je epilogue at 0x635fb18",
          "je" in by_addr[0x635FB18] and "635f7ae" in by_addr[0x635FB18])

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

    check("entry reaches lock-wait site 0x635fb32", reaches(START, 0x635FB32))
    check("entry reaches ret 0x635f7d6", reaches(START, 0x635F7D6))
    check("entry reaches trylock 0x635fb26", reaches(START, 0x635FB26))
    check("entry reaches epilogue 0x635f7ae", reaches(START, 0x635F7AE))
    check("entry reaches gate 0x635f7e0", reaches(START, 0x635F7E0))
    check("entry reaches count call 0x635f7ee", reaches(START, 0x635F7EE))
    check("entry reaches A-block 0x635f820", reaches(START, 0x635F820))
    check("entry reaches B-block 0x635f884", reaches(START, 0x635F884))
    check("entry reaches C-block 0x635f8e6", reaches(START, 0x635F8E6))
    check("entry reaches D-loop 0x635f952", reaches(START, 0x635F952))
    check("entry reaches drain 0x635fad7", reaches(START, 0x635FAD7))
    check("entry reaches tail loop 0x635fb1e", reaches(START, 0x635FB1E))
    check("preds of lock-wait site 0x635fb32 is trylock fail only",
          preds[0x635FB32] == {0x635FB30}, str(preds[0x635FB32]))
    check("preds of trylock 0x635fb26 is the setup only",
          preds[0x635FB26] == {0x635FB22}, str(preds[0x635FB26]))
    check("preds of rejoin 0x635faf0 are trylock success, lock-wait path, "
          "and padding nop",
          preds[0x635FAF0] == {0x635FAEF, 0x635FB30, 0x635FB40},
          str(preds[0x635FAF0]))
    check("preds of ret 0x635f7d6 is the final pop",
          preds[0x635F7D6] == {0x635F7D4}, str(preds[0x635F7D6]))
    check("preds of tail head 0x635fb1e are drain entry and loop-back",
          preds[0x635FB1E] == {0x635FAED, 0x635FB18}, str(preds[0x635FB1E]))
    check("preds of D head 0x635f952 are dispatch, C fall-through, loop-back",
          preds[0x635F952] == {0x635F80C, 0x635F94C, 0x635FAD1},
          str(preds[0x635F952]))
    check("preds of drain 0x635fad7 are C-exit and D-exit",
          preds[0x635FAD7] == {0x635F94C, 0x635FAD1}, str(preds[0x635FAD7]))
    check("preds of gate 0x635f7e0 are gate je and ret padding",
          preds[0x635F7E0] == {0x635F7AC, 0x635F7D7}, str(preds[0x635F7E0]))
    check("preds of epilogue 0x635f7ae are gate-closed, N==0, empty queue, "
          "drain done",
          preds[0x635F7AE] == {0x635F7AC, 0x635F7F9, 0x635FADD, 0x635FB18},
          str(preds[0x635F7AE]))
    check("preds of A-block 0x635f820 is the dispatch fall-through",
          preds[0x635F820] == {0x635F81E}, str(preds[0x635F820]))
    check("preds of B-block 0x635f884 are dispatch je and A fall-through",
          preds[0x635F884] == {0x635F81E, 0x635F880}, str(preds[0x635F884]))
    check("preds of C-block 0x635f8e6 are dispatch je and B fall-through",
          preds[0x635F8E6] == {0x635F815, 0x635F8E2}, str(preds[0x635F8E6]))

    # Reaching definitions: per-register IN sets at the lock-wait site
    # and the ret. ENTRY is the caller's value at the window entry;
    # CALL(x) is a call-clobber at x.
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
    SITE = 0x635FB32
    RET = 0x635F7D6
    CALL_TRYLOCK = {("CALL", 0x635FB26)}
    check("site rdi only def is mov %r14,%rdi 0x635fb2b",
          rdi_in[SITE] == {0x635FB2B}, str(rdi_in[SITE]))
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
    check("site rbx defs are the C-block and D-block index steps",
          rbx_in[SITE] == {0x635F941, 0x635FAC5}, str(rbx_in[SITE]))
    check("site rbp defs are drain base and +8 advance",
          rbp_in[SITE] == {0x635FAE3, 0x635FB08}, str(rbp_in[SITE]))
    check("site r12 def is the entry rdi save",
          r12_in[SITE] == {0x635F7EB}, str(r12_in[SITE]))
    check("site r13 def is the drain end-pointer lea",
          r13_in[SITE] == {0x635FAE8}, str(r13_in[SITE]))
    check("site r14 def is the tail node load",
          r14_in[SITE] == {0x635FB1E}, str(r14_in[SITE]))
    check("site r15 defs are entry plus the three remainder loads and the "
          "D-block table step",
          r15_in[SITE] == {("ENTRY",), 0x635F825, 0x635F889, 0x635F8EB,
                           0x635F9B1},
          str(r15_in[SITE]))
    check("rax at ret is the canary residue def 0x635f7b6",
          rax_in[RET] == {0x635F7B6}, str(rax_in[RET]))

    check("records lock-wait sites match census",
          [s.get("site") for s in rec.get("lock_wait_sites", [])] ==
          ["0x635fb32"])
    check("records second-handler sites 0",
          rec.get("second_handler_sites", []) == [])
    check("records sites lu-miss 0",
          rec.get("sites", {}).get("lu_miss") == 0)
    check("records sites bin_table_init 0",
          rec.get("sites", {}).get("bin_table_init") == 0)
    check("records sites second-handler 0",
          rec.get("sites", {}).get("second_handler") == 0)
    check("records sites lock-wait 1",
          rec.get("sites", {}).get("lock_wait") == 1)
    check("records sites bsr 0",
          rec.get("sites", {}).get("bsr") == 0)
    check("records window bytes 967",
          rec.get("window", {}).get("bytes") == 967)
    check("records window range",
          rec.get("window", {}).get("range") == "0x635f780..0x635fb47")
    check("records return value is 0 (canary residue, void return)",
          rec.get("return_value", {}).get("rax") ==
          "0 (canary residue, void return)")
    check("records entry gate address 0x64ffc28",
          rec.get("entry_gate", {}).get("address") == "0x64ffc28")
    check("records entry gate file byte 0x01",
          rec.get("entry_gate", {}).get("file_byte") == "0x01")
    check("records count call target 0x634eba0",
          rec.get("count_call", {}).get("target") == "0x634eba0")
    check("records callee FDE 0x635f6a0..0x635f77c",
          rec.get("callee", {}).get("fde") == "0x635f6a0..0x635f77c")
    check("records duffs dispatch mentions N&3",
          "N&3" in rec.get("duffs", {}).get("dispatch", ""))

    # Sections (own ELF parse): .bss exact end; referenced addresses.
    secmap = sections(node)
    bss = secmap[".bss"]
    check("bss section 0x64ffe40..0x6728924",
          bss[3] == 0x64FFE40 and bss[3] + bss[5] == 0x6728924, str(bss))
    for _a in (0x65096B0, 0x65096C0):
        check("address %s inside .bss" % hex(_a),
              bss[3] <= _a < bss[3] + bss[5])
    check("address 0x64ffc28 inside .data",
          secmap[".data"][3] <= 0x64FFC28
          < secmap[".data"][3] + secmap[".data"][5])
    check("file byte at 0x64ffc28 is 0x01 (gate closed at load)",
          node[0x64FFC28 - 0x3000] == 0x01)
    txt = secmap[".text"]
    check("window inside .text",
          txt[3] <= START and END <= txt[3] + txt[5])
    check("call target 0x635f6a0 inside .text (internal, not PLT)",
          txt[3] <= 0x635F6A0 < txt[3] + txt[5])
    check("call target 0x634eba0 inside .text (internal, not PLT)",
          txt[3] <= 0x634EBA0 < txt[3] + txt[5])

    # rela counts by direct ELF parse
    dyn_total = plt_total = rel_count = 0
    gate_relocs = 0
    runtime_table_relocs = 0
    for nm, s in secmap.items():
        if nm == ".rela.dyn":
            dyn_total = s[5] // 24
            for j in range(dyn_total):
                off, info, add = struct.unpack_from(
                    "<QQq", node, s[4] + j * 24)
                rtype = info & 0xFFFFFFFF
                if rtype == 8:
                    rel_count += 1
                if off == 0x64FFC28:
                    gate_relocs += 1
                if 0x65096C0 <= off < 0x6509EC0:
                    runtime_table_relocs += 1
        if nm == ".rela.plt":
            plt_total = s[5] // 24
    check("rela.dyn total 60723", dyn_total == 60723, str(dyn_total))
    check("rela.dyn RELATIVE 59534", rel_count == 59534, str(rel_count))
    check("rela.plt 278", plt_total == 278, str(plt_total))
    check("no rela lands at the entry-gate byte 0x64ffc28",
          gate_relocs == 0, str(gate_relocs))
    check("no rela lands in the runtime table 0x65096c0..0x6509ec0",
          runtime_table_relocs == 0, str(runtime_table_relocs))

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
    check("next candidate raw lu-miss 0", counts.get(0x6386110, 0) == 0,
          str(counts.get(0x6386110, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x6386110, 0) == 0,
          str(bti_counts.get(0x6386110, 0)))
    check("next candidate raw second-handler 0",
          sh_counts.get(0x6386110, 0) == 0, str(sh_counts.get(0x6386110, 0)))
    check("next candidate raw lock-wait 1",
          lw_counts.get(0x6386110, 0) == 1,
          str(lw_counts.get(0x6386110, 0)))

    # lock-wait frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 344", len(survey.get("survivors", [])) == 344,
          str(len(survey.get("survivors", []))))
    check("survey this window is a lock-wait survivor",
          "0x635f780" in survey.get("survivors", []))
    check("survey this window is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x635f780") == 1,
          str(survey.get("sites_per_fde", {}).get("0x635f780")))
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
          "0x635f780" not in survey.get("lu_miss_survivors", []))
    check("survey this window is NOT a second-handler survivor",
          "0x635f780" not in survey.get("second_handler_survivors", []))
    check("survey next candidate is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x6386110") == 1,
          str(survey.get("sites_per_fde", {}).get("0x6386110")))
    nq = rec.get("next_question", {})
    check("next question is the lock-wait frontier",
          nq.get("frontier") == "lock-wait helper 0x63bf680 callers",
          str(nq.get("frontier")))
    check("next question range 0x6386110..0x63864b9",
          nq.get("range") == "0x6386110..0x63864b9", str(nq.get("range")))
    check("next question bytes 937", nq.get("bytes") == 937,
          str(nq.get("bytes")))
    check("next question lu-miss sites 0",
          nq.get("lu_miss_sites") == 0, str(nq.get("lu_miss_sites")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 258", nq.get("strict") == 258,
          str(nq.get("strict")))
    check("next question calls 23", nq.get("calls") == 23,
          str(nq.get("calls")))
    check("next question indirect calls 0",
          nq.get("indirect_calls") == 0, str(nq.get("indirect_calls")))
    check("next question indirect sites",
          nq.get("indirect_sites") == [], str(nq.get("indirect_sites")))
    check("next question calls by target",
          nq.get("calls_by_target") ==
          {"0x6360ed0": 16, "0x63bf680": 1, "0x63f0b70": 4,
           "0x63f0d70": 1, "0x63f17b0": 1},
          str(nq.get("calls_by_target")))
    check("next question lock-wait sites 1",
          nq.get("lock_wait_sites") == 1, str(nq.get("lock_wait_sites")))
    check("next question lock-wait site list",
          nq.get("lock_wait_site") == ["0x6386474"],
          str(nq.get("lock_wait_site")))
    check("next question second-handler sites 0",
          nq.get("second_handler_sites") == 0,
          str(nq.get("second_handler_sites")))
    check("next question bsr 0", nq.get("bsr") == 0,
          str(nq.get("bsr")))
    check("next question rets 1",
          nq.get("ret") == ["0x6386465"], str(nq.get("ret")))
    check("next question jumps 43", nq.get("jumps") == 43,
          str(nq.get("jumps")))
    check("next question jumps outside 0", nq.get("jumps_outside_window") == 0,
          str(nq.get("jumps_outside_window")))
    check("next question endbr64 0", nq.get("endbr64") == 0,
          str(nq.get("endbr64")))
    check("next question canary present", nq.get("canary") is True,
          str(nq.get("canary")))
    check("next question plt calls 6", nq.get("plt_calls") == 6,
          str(nq.get("plt_calls")))
    check("records census strict 240",
          rec.get("census", {}).get("strict") == 240)
    check("records census calls 26",
          rec.get("census", {}).get("calls") == 26)
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
    # next candidate 0x6386110..0x63864b9 must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x6386110 < p[1] and p[0] < 0x63864B9]
    check("next candidate 0x6386110 disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x63864B9 and 0x6386110 < END))

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
    check("slug not colliding with #314-#333 lu-miss/lockwait slugs",
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
                       "RE-001-node115-lockwait-caller-1site-bitmapdrain",
                       "RE-001-node115-lockwait-caller-1site-indirect",
                       "RE-001-node115-lockwait-caller-1site-strcmp"))

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
                    "lockwait_caller_1site_duffs.hex",
                    "lockwait_caller_1site_duffs.objdump.txt"}
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
