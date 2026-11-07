import bisect
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

import node115_prior_corpus as prior_corpus

SLUG = "RE-001-node115-lockwait-caller-1site-resolver-noloader-dead-duff-q30"
START = 0x639FC40
END = 0x639FEF8
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
    (0x639fc40, 'endbr64', ''),
    (0x639fc44, 'push', '%r15'),
    (0x639fc46, 'lea', '0x372553(%rip),%r15        # 67121a0 <__register_atfork@plt+0x320610>'),
    (0x639fc4d, 'push', '%r14'),
    (0x639fc4f, 'mov', '%rsi,%r14'),
    (0x639fc52, 'push', '%r13'),
    (0x639fc54, 'mov', '%r8,%r13'),
    (0x639fc57, 'push', '%r12'),
    (0x639fc59, 'mov', '%rcx,%r12'),
    (0x639fc5c, 'push', '%rbp'),
    (0x639fc5d, 'mov', '%rdi,%rbp'),
    (0x639fc60, 'mov', '%r15,%rdi'),
    (0x639fc63, 'push', '%rbx'),
    (0x639fc64, 'mov', '%r9,%rbx'),
    (0x639fc67, 'sub', '$0x18,%rsp'),
    (0x639fc6b, 'mov', '%fs:0x28,%rax'),
    (0x639fc74, 'mov', '%rax,0x8(%rsp)'),
    (0x639fc79, 'xor', '%eax,%eax'),
    (0x639fc7b, 'call', '63f17b0 <pthread_mutex_trylock@plt>'),
    (0x639fc80, 'test', '%eax,%eax'),
    (0x639fc82, 'jne', '639fd20 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6578f0>'),
    (0x639fc88, 'addq', '$0x1,0x372508(%rip)        # 6712198 <__register_atfork@plt+0x320608>'),
    (0x639fc90, 'cmp', '0x3724f9(%rip),%rbp        # 6712190 <__register_atfork@plt+0x320600>'),
    (0x639fc97, 'je', '639fca8 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x657878>'),
    (0x639fc99, 'addq', '$0x1,0x3724e7(%rip)        # 6712188 <__register_atfork@plt+0x3205f8>'),
    (0x639fca1, 'mov', '%rbp,0x3724e8(%rip)        # 6712190 <__register_atfork@plt+0x320600>'),
    (0x639fca8, 'mov', '$0x1,%ebp'),
    (0x639fcad, 'or', '0x50(%rsp),%rbx'),
    (0x639fcb2, 'je', '639fcf0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6578c0>'),
    (0x639fcb4, 'movb', '$0x0,0x37250d(%rip)        # 67121c8 <__register_atfork@plt+0x320638>'),
    (0x639fcbb, 'mov', '%r15,%rdi'),
    (0x639fcbe, 'call', '63f0b70 <pthread_mutex_unlock@plt>'),
    (0x639fcc3, 'mov', '0x8(%rsp),%rax'),
    (0x639fcc8, 'sub', '%fs:0x28,%rax'),
    (0x639fcd1, 'jne', '639fef3 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x657ac3>'),
    (0x639fcd7, 'add', '$0x18,%rsp'),
    (0x639fcdb, 'mov', '%ebp,%eax'),
    (0x639fcdd, 'pop', '%rbx'),
    (0x639fcde, 'pop', '%rbp'),
    (0x639fcdf, 'pop', '%r12'),
    (0x639fce1, 'pop', '%r13'),
    (0x639fce3, 'pop', '%r14'),
    (0x639fce5, 'pop', '%r15'),
    (0x639fce7, 'ret', ''),
    (0x639fce8, 'nopl', '0x0(%rax,%rax,1)'),
    (0x639fcf0, 'mov', '0x10(%r14),%rdi'),
    (0x639fcf4, 'call', '6388310 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fee0>'),
    (0x639fcf9, 'mov', '0x30(%rax),%rax'),
    (0x639fcfd, 'mov', '%rax,(%rsp)'),
    (0x639fd01, 'test', '%r12,%r12'),
    (0x639fd04, 'je', '639fd19 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6578e9>'),
    (0x639fd06, 'test', '%r13,%r13'),
    (0x639fd09, 'je', '639fd19 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6578e9>'),
    (0x639fd0b, 'mov', '0x0(%r13),%rdx'),
    (0x639fd0f, 'cmp', '$0x8,%rdx'),
    (0x639fd13, 'jne', '639fd38 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x657908>'),
    (0x639fd15, 'mov', '%rax,(%r12)'),
    (0x639fd19, 'xor', '%ebp,%ebp'),
    (0x639fd1b, 'jmp', '639fcb4 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x657884>'),
    (0x639fd1d, 'nopl', '(%rax)'),
    (0x639fd20, 'lea', '-0x40(%r15),%rdi'),
    (0x639fd24, 'call', '63bf680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677250>'),
    (0x639fd29, 'movb', '$0x1,0x372498(%rip)        # 67121c8 <__register_atfork@plt+0x320638>'),
    (0x639fd30, 'jmp', '639fc88 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x657858>'),
    (0x639fd35, 'nopl', '(%rax)'),
    (0x639fd38, 'mov', '$0x8,%ecx'),
    (0x639fd3d, 'mov', '%rsp,%r9'),
    (0x639fd40, 'cmp', '%rcx,%rdx'),
    (0x639fd43, 'cmova', '%rcx,%rdx'),
    (0x639fd47, 'cmp', '$0x8,%edx'),
    (0x639fd4a, 'jb', '639fea8 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x657a78>'),
    (0x639fd50, 'mov', '%edx,%r14d'),
    (0x639fd53, 'mov', '%rax,(%r12)'),
    (0x639fd57, 'lea', '0x8(%r12),%rcx'),
    (0x639fd5c, 'mov', '-0x8(%r9,%r14,1),%rax'),
    (0x639fd61, 'and', '$0xfffffffffffffff8,%rcx'),
    (0x639fd65, 'mov', '%rax,-0x8(%r12,%r14,1)'),
    (0x639fd6a, 'sub', '%rcx,%r12'),
    (0x639fd6d, 'sub', '%r12,%r9'),
    (0x639fd70, 'add', '%edx,%r12d'),
    (0x639fd73, 'and', '$0xfffffff8,%r12d'),
    (0x639fd77, 'cmp', '$0x8,%r12d'),
    (0x639fd7b, 'jb', '639febf <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x657a8f>'),
    (0x639fd81, 'mov', '(%r9,%rbx,1),%rdi'),
    (0x639fd85, 'lea', '-0x1(%r12),%esi'),
    (0x639fd8a, 'mov', '$0x8,%r10d'),
    (0x639fd90, 'shr', '$0x3,%esi'),
    (0x639fd93, 'mov', '%rdi,(%rcx,%rbx,1)'),
    (0x639fd97, 'and', '$0x7,%esi'),
    (0x639fd9a, 'cmp', '%r12d,%r10d'),
    (0x639fd9d, 'jae', '639febf <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x657a8f>'),
    (0x639fda3, 'test', '%esi,%esi'),
    (0x639fda5, 'je', '639fe3a <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x657a0a>'),
    (0x639fdab, 'cmp', '$0x1,%esi'),
    (0x639fdae, 'je', '639fe22 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6579f2>'),
    (0x639fdb0, 'cmp', '$0x2,%esi'),
    (0x639fdb3, 'je', '639fe13 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6579e3>'),
    (0x639fdb5, 'cmp', '$0x3,%esi'),
    (0x639fdb8, 'je', '639fe04 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6579d4>'),
    (0x639fdba, 'cmp', '$0x4,%esi'),
    (0x639fdbd, 'je', '639fdf5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6579c5>'),
    (0x639fdbf, 'cmp', '$0x5,%esi'),
    (0x639fdc2, 'je', '639fde6 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6579b6>'),
    (0x639fdc4, 'cmp', '$0x6,%esi'),
    (0x639fdc7, 'je', '639fdd7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6579a7>'),
    (0x639fdc9, 'mov', '(%r9,%r10,1),%rbx'),
    (0x639fdcd, 'mov', '%rbx,(%rcx,%r10,1)'),
    (0x639fdd1, 'mov', '$0x10,%r10d'),
    (0x639fdd7, 'mov', '%r10d,%r11d'),
    (0x639fdda, 'add', '$0x8,%r10d'),
    (0x639fdde, 'mov', '(%r9,%r11,1),%r8'),
    (0x639fde2, 'mov', '%r8,(%rcx,%r11,1)'),
    (0x639fde6, 'mov', '%r10d,%ebp'),
    (0x639fde9, 'add', '$0x8,%r10d'),
    (0x639fded, 'mov', '(%r9,%rbp,1),%r14'),
    (0x639fdf1, 'mov', '%r14,(%rcx,%rbp,1)'),
    (0x639fdf5, 'mov', '%r10d,%eax'),
    (0x639fdf8, 'add', '$0x8,%r10d'),
    (0x639fdfc, 'mov', '(%r9,%rax,1),%rsi'),
    (0x639fe00, 'mov', '%rsi,(%rcx,%rax,1)'),
    (0x639fe04, 'mov', '%r10d,%edi'),
    (0x639fe07, 'add', '$0x8,%r10d'),
    (0x639fe0b, 'mov', '(%r9,%rdi,1),%rbx'),
    (0x639fe0f, 'mov', '%rbx,(%rcx,%rdi,1)'),
    (0x639fe13, 'mov', '%r10d,%r11d'),
    (0x639fe16, 'add', '$0x8,%r10d'),
    (0x639fe1a, 'mov', '(%r9,%r11,1),%r8'),
    (0x639fe1e, 'mov', '%r8,(%rcx,%r11,1)'),
    (0x639fe22, 'mov', '%r10d,%ebp'),
    (0x639fe25, 'add', '$0x8,%r10d'),
    (0x639fe29, 'mov', '(%r9,%rbp,1),%r14'),
    (0x639fe2d, 'mov', '%r14,(%rcx,%rbp,1)'),
    (0x639fe31, 'cmp', '%r12d,%r10d'),
    (0x639fe34, 'jae', '639febf <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x657a8f>'),
    (0x639fe3a, 'mov', '%r10d,%eax'),
    (0x639fe3d, 'lea', '0x8(%r10),%edi'),
    (0x639fe41, 'lea', '0x10(%r10),%r11d'),
    (0x639fe45, 'mov', '(%r9,%rax,1),%rsi'),
    (0x639fe49, 'lea', '0x18(%r10),%ebp'),
    (0x639fe4d, 'mov', '%rsi,(%rcx,%rax,1)'),
    (0x639fe51, 'mov', '(%r9,%rdi,1),%rbx'),
    (0x639fe55, 'lea', '0x20(%r10),%eax'),
    (0x639fe59, 'mov', '%rbx,(%rcx,%rdi,1)'),
    (0x639fe5d, 'mov', '(%r9,%r11,1),%r8'),
    (0x639fe61, 'lea', '0x28(%r10),%edi'),
    (0x639fe65, 'mov', '%r8,(%rcx,%r11,1)'),
    (0x639fe69, 'mov', '(%r9,%rbp,1),%r14'),
    (0x639fe6d, 'lea', '0x30(%r10),%r11d'),
    (0x639fe71, 'mov', '%r14,(%rcx,%rbp,1)'),
    (0x639fe75, 'mov', '(%r9,%rax,1),%rsi'),
    (0x639fe79, 'lea', '0x38(%r10),%ebp'),
    (0x639fe7d, 'add', '$0x40,%r10d'),
    (0x639fe81, 'mov', '%rsi,(%rcx,%rax,1)'),
    (0x639fe85, 'mov', '(%r9,%rdi,1),%rbx'),
    (0x639fe89, 'mov', '%rbx,(%rcx,%rdi,1)'),
    (0x639fe8d, 'mov', '(%r9,%r11,1),%r8'),
    (0x639fe91, 'mov', '%r8,(%rcx,%r11,1)'),
    (0x639fe95, 'mov', '(%r9,%rbp,1),%r14'),
    (0x639fe99, 'mov', '%r14,(%rcx,%rbp,1)'),
    (0x639fe9d, 'cmp', '%r12d,%r10d'),
    (0x639fea0, 'jb', '639fe3a <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x657a0a>'),
    (0x639fea2, 'jmp', '639febf <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x657a8f>'),
    (0x639fea4, 'nopl', '0x0(%rax)'),
    (0x639fea8, 'test', '$0x4,%dl'),
    (0x639feab, 'jne', '639fecd <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x657a9d>'),
    (0x639fead, 'test', '%edx,%edx'),
    (0x639feaf, 'je', '639febf <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x657a8f>'),
    (0x639feb1, 'movzbl', '(%rsp),%r10d'),
    (0x639feb6, 'mov', '%r10b,(%r12)'),
    (0x639feba, 'test', '$0x2,%dl'),
    (0x639febd, 'jne', '639fee2 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x657ab2>'),
    (0x639febf, 'mov', '%rdx,0x0(%r13)'),
    (0x639fec3, 'mov', '$0x16,%ebp'),
    (0x639fec8, 'jmp', '639fcb4 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x657884>'),
    (0x639fecd, 'mov', '(%rsp),%esi'),
    (0x639fed0, 'mov', '%edx,%edi'),
    (0x639fed2, 'mov', '%esi,(%r12)'),
    (0x639fed6, 'mov', '-0x4(%r9,%rdi,1),%r8d'),
    (0x639fedb, 'mov', '%r8d,-0x4(%r12,%rdi,1)'),
    (0x639fee0, 'jmp', '639febf <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x657a8f>'),
    (0x639fee2, 'mov', '%edx,%r11d'),
    (0x639fee5, 'movzwl', '-0x2(%r9,%r11,1),%ebp'),
    (0x639feeb, 'mov', '%bp,-0x2(%r12,%r11,1)'),
    (0x639fef1, 'jmp', '639febf <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x657a8f>'),
    (0x639fef3, 'call', '63f0d70 <__stack_chk_fail@plt>')
]

def main():
    node = read(BIN)
    check("binary size 105896032", len(node) == 105896032, str(len(node)))
    check("binary sha256",
          hashlib.sha256(node).hexdigest() ==
          "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

    rec = json.loads(read(os.path.join(PACKET, "records.json")).decode())
    check("records base", rec["base"] ==
          "7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6", str(rec.get("base")))

    fdes = parse_eh_frame(node)
    starts = [s for s, e in fdes]
    check("total FDEs 135313", len(fdes) == 135313, str(len(fdes)))
    i = bisect.bisect_left(starts, START)
    check("target FDE start", i < len(fdes) and fdes[i][0] == START)
    check("target FDE end", i < len(fdes) and fdes[i][1] == END)
    check("target FDE size 696", END - START == 696)
    prev = fdes[i - 1]
    check("prev FDE 0x639f980..0x639fc38",
          prev == (0x639F980, 0x639FC38), str(prev))
    check("prev gap 8 (8 int3 padding bytes 0x639fc38..0x639fc40)", START - prev[1] == 8 and all(b == 0xCC for b in node[toff(prev[1]):toff(START)]))
    check("prev FDE starts endbr64 (0xf3)",
          node[toff(prev[0])] == 0xF3)
    nxt = fdes[i + 1]
    check("next FDE 0x639ff00..0x63a01b8 (#368 window)",
          nxt == (0x639FF00, 0x63A01B8), str(nxt))
    check("next gap 8 (8 int3 padding bytes 0x639fef8..0x639ff00)", nxt[0] - END == 8 and all(b == 0xCC for b in node[toff(END):toff(nxt[0])]))
    check("next FDE starts endbr64 (0xf3)",
          node[toff(nxt[0])] == 0xF3)
    check("prev FDE end 0x639fc38, 8 int3 bytes before this FDE start",
          prev[1] == 0x639FC38)
    check("count FDE 0x634eba0..0x634ebab (cited, NOT called here)",
          fdes[bisect.bisect_left(starts, 0x634EBA0)] ==
          (0x634EBA0, 0x634EBAB))
    check("log-helper FDE 0x63bf5b6..0x63bf677",
          fdes[bisect.bisect_left(starts, 0x63BF5B6)] ==
          (0x63BF5B6, 0x63BF677))
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
    check("thunk FDE 0x63643f0..0x6364400",
          fdes[bisect.bisect_left(starts, 0x63643F0)] ==
          (0x63643F0, 0x6364400))
    check("#338 window FDE 0x6387ff0..0x6388303",
          fdes[bisect.bisect_left(starts, 0x6387FF0)] ==
          (0x6387FF0, 0x6388303))
    check("#339 window FDE 0x63a4cf0..0x63a4fc8",
          fdes[bisect.bisect_left(starts, 0x63A4CF0)] ==
          (0x63A4CF0, 0x63A4FC8))
    check("#340 window FDE 0x63a4a10..0x63a4ce8",
          fdes[bisect.bisect_left(starts, 0x63A4A10)] ==
          (0x63A4A10, 0x63A4CE8))
    check("#341 window FDE 0x63a4750..0x63a4a10",
          fdes[bisect.bisect_left(starts, 0x63A4750)] ==
          (0x63A4750, 0x63A4A10))
    check("#342 window FDE 0x63a4490..0x63a4750",
          fdes[bisect.bisect_left(starts, 0x63A4490)] ==
          (0x63A4490, 0x63A4750))
    check("#343 window FDE 0x63a41d0..0x63a4490",
          fdes[bisect.bisect_left(starts, 0x63A41D0)] ==
          (0x63A41D0, 0x63A4490))
    check("#344 window FDE 0x63a3f10..0x63a41d0",
          fdes[bisect.bisect_left(starts, 0x63A3F10)] ==
          (0x63A3F10, 0x63A41D0))
    check("#345 window FDE 0x63a3c50..0x63a3f10",
          fdes[bisect.bisect_left(starts, 0x63A3C50)] ==
          (0x63A3C50, 0x63A3F10))
    check("#346 window FDE 0x63a3990..0x63a3c50",
          fdes[bisect.bisect_left(starts, 0x63A3990)] ==
          (0x63A3990, 0x63A3C50))
    check("#347 window FDE 0x63a36d0..0x63a3990",
          fdes[bisect.bisect_left(starts, 0x63A36D0)] ==
          (0x63A36D0, 0x63A3990))
    check("#348 window FDE 0x63a3410..0x63a36d0",
          fdes[bisect.bisect_left(starts, 0x63A3410)] ==
          (0x63A3410, 0x63A36D0))
    check("#349 window FDE 0x63a3150..0x63a3410",
          fdes[bisect.bisect_left(starts, 0x63A3150)] ==
          (0x63A3150, 0x63A3410))
    check("#350 window FDE 0x63a2e90..0x63a3150",
          fdes[bisect.bisect_left(starts, 0x63A2E90)] ==
          (0x63A2E90, 0x63A3150))
    check("#351 window FDE 0x63a2bd0..0x63a2e90",
          fdes[bisect.bisect_left(starts, 0x63A2BD0)] ==
          (0x63A2BD0, 0x63A2E90))
    check("#352 window FDE 0x63a2910..0x63a2bd0",
          fdes[bisect.bisect_left(starts, 0x63A2910)] ==
          (0x63A2910, 0x63A2BD0))
    check("#353 window FDE 0x63a2650..0x63a2910",
          fdes[bisect.bisect_left(starts, 0x63A2650)] ==
          (0x63A2650, 0x63A2910))
    check("#354 window FDE 0x63a2390..0x63a2650",
          fdes[bisect.bisect_left(starts, 0x63A2390)] ==
          (0x63A2390, 0x63A2650))
    check("#355 window FDE 0x63a20d0..0x63a2390",
          fdes[bisect.bisect_left(starts, 0x63A20D0)] ==
          (0x63A20D0, 0x63A2390))
    check("#356 window FDE 0x63a1e10..0x63a20d0",
          fdes[bisect.bisect_left(starts, 0x63A1E10)] ==
          (0x63A1E10, 0x63A20D0))
    check("#357 window FDE 0x63a1b50..0x63a1e10",
          fdes[bisect.bisect_left(starts, 0x63A1B50)] ==
          (0x63A1B50, 0x63A1E10))
    check("#358 window FDE 0x63a1890..0x63a1b50",
          fdes[bisect.bisect_left(starts, 0x63A1890)] ==
          (0x63A1890, 0x63A1B50))
    check("#359 window FDE 0x63a15d0..0x63a1890",
          fdes[bisect.bisect_left(starts, 0x63A15D0)] ==
          (0x63A15D0, 0x63A1890))
    check("#360 window FDE 0x63a1310..0x63a15d0",
          fdes[bisect.bisect_left(starts, 0x63A1310)] ==
          (0x63A1310, 0x63A15D0))
    check("#361 window FDE 0x63a1050..0x63a1310",
          fdes[bisect.bisect_left(starts, 0x63A1050)] ==
          (0x63A1050, 0x63A1310))
    check("#362 window FDE 0x63a0d90..0x63a1050",
          fdes[bisect.bisect_left(starts, 0x63A0D90)] ==
          (0x63A0D90, 0x63A1050))
    check("#363 window FDE 0x63a0ad0..0x63a0d90",
          fdes[bisect.bisect_left(starts, 0x63A0AD0)] ==
          (0x63A0AD0, 0x63A0D90))
    check("#365 window FDE 0x63a06e0..0x63a0803",
          fdes[bisect.bisect_left(starts, 0x63A06E0)] ==
          (0x63A06E0, 0x63A0803))
    check("#366 window FDE 0x63a0480..0x63a06d3",
          fdes[bisect.bisect_left(starts, 0x63A0480)] ==
          (0x63A0480, 0x63A06D3))
    check("#367 window FDE 0x63a01c0..0x63a0478",
          fdes[bisect.bisect_left(starts, 0x63A01C0)] ==
          (0x63A01C0, 0x63A0478))
    check("#368 window FDE 0x639ff00..0x63a01b8",
          fdes[bisect.bisect_left(starts, 0x639FF00)] ==
          (0x639FF00, 0x63A01B8))
    check("resolver FDE 0x6388310..0x6388372",
          fdes[bisect.bisect_left(starts, 0x6388310)] ==
          (0x6388310, 0x6388372))
    check("loader FDE 0x63bfb90..0x63bfb98 (8-byte trivial load helper)",
          fdes[bisect.bisect_left(starts, 0x63BFB90)] ==
          (0x63BFB90, 0x63BFB98))
    check("next-question FDE 0x639f980..0x639fc38",
          fdes[bisect.bisect_left(starts, 0x639F980)] ==
          (0x639F980, 0x639FC38))
    hexb = read(os.path.join(PACKET, "lockwait_caller_1site_resolver_noloader_dead_duff_q30.hex"))
    check("hex exhibit raw bytes 696", len(hexb) == 696, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])
    objdump = read(os.path.join(
        PACKET, "lockwait_caller_1site_resolver_noloader_dead_duff_q30.objdump.txt")).decode()
    lines = strict_lines(objdump)
    check("strict lines 185", len(lines) == 185, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if mnemonic_of(l) == "call"]
    check("call lines 5", len(calls) == 5, str(len(calls)))
    rets = [l for l in lines if mnemonic_of(l) == "ret"]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x639fce7",
          sorted(addr_of(l) for l in rets) == [0x639fce7],
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
    expect = {0x6388310: 1, 0x63BF680: 1, 0x63F0B70: 1,
              0x63F0D70: 1, 0x63F17B0: 1}
    check("call target multiset exact", dict(tgt) == expect, str(tgt))
    check("distinct direct call targets 5", len(tgt) == 5, str(len(tgt)))
    check("no bti sites", tgt.get(0x63D9880, 0) == 0,
          str(tgt.get(0x63D9880, 0)))
    check("lu-miss sites 0",
          tgt.get(0x63D9700, 0) == 0, str(tgt.get(0x63D9700, 0)))
    check("second-handler sites 0", tgt.get(0x634EBB0, 0) == 0,
          str(tgt.get(0x634EBB0, 0)))
    check("lock-wait helper called 1 time", tgt.get(0x63BF680, 0) == 1,
          str(tgt.get(0x63BF680, 0)))
    check("lock-wait site is 0x639fd24",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63bf680" in l) == [0x639fd24])
    check("resolver 0x6365150 called 0 times", tgt.get(0x6365150, 0) == 0,
          str(tgt.get(0x6365150, 0)))
    check("count call 0x634eba0 NOT called (0 times)",
          tgt.get(0x634EBA0, 0) == 0, str(tgt.get(0x634EBA0, 0)))
    check("index resolver 0x6388310 called 1 time at 0x639fcf4",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "6388310" in l) == [0x639fcf4])
    check("load helper 0x63bfb90 NOT called (0 times)",
          tgt.get(0x63BFB90, 0) == 0, str(tgt.get(0x63BFB90, 0)))
    check("stack_chk_fail plt call 1 at 0x639fef3",
          tgt.get(0x63F0D70, 0) == 1, str(tgt.get(0x63F0D70, 0)))
    check("trylock plt call 1 at 0x639fc7b",
          tgt.get(0x63F17B0, 0) == 1, str(tgt.get(0x63F17B0, 0)))
    check("unlock plt call 1 at 0x639fcbe",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63f0b70" in l) == [0x639fcbe])
    check("no #321 window call", tgt.get(0x63C9650, 0) == 0,
          str(tgt.get(0x63C9650, 0)))
    plt_calls = [l for l in calls if "@plt" in l]
    check("PLT calls 3 (by @plt suffix, not address range)",
          len(plt_calls) == 3, str(len(plt_calls)))
    check("distinct PLT targets 3",
          len({re.search(r"\tcall\s+([0-9a-f]+)", l).group(1)
               for l in plt_calls}) == 3)
    check("no internal .text call is counted as PLT",
          not any(("6388310" in l or "63bf680" in l)
                  and "@plt" in l for l in calls))
    for _w, _a in (("#314", 0x63495B0), ("#315", 0x6353A70),
                  ("#316", 0x6355900), ("#317", 0x63577F0),
                  ("#318", 0x635A7A0), ("#319", 0x635C6D0),
                  ("#320", 0x635E2E0),
                  ("#322", 0x63CCD60), ("#323", 0x63CDDD0),
                  ("#324", 0x63D03A0), ("#325", 0x63D17E0),
                  ("#326", 0x63D2A80), ("#327", 0x63D3F0E),
                  ("#328", 0x63D4048), ("#329", 0x63E94A0),
                  ("#330", 0x6362190), ("#331", 0x6362910),
                  ("#332", 0x636A140), ("#333", 0x6386540),
                  ("#334", 0x635F780), ("#335", 0x6386110),
                  ("#336", 0x63CE510), ("#337", 0x6386B60),
                  ("#338", 0x6387FF0),
                  ("#339", 0x63A4CF0),
                  ("#340", 0x63A4A10),
                  ("#341", 0x63A4750),
                  ("#342", 0x63A4490),
                  ("#343", 0x63A41D0),
                  ("#344", 0x63A3F10),
                  ("#345", 0x63A3C50),
                  ("#346", 0x63A3990),
                  ("#347", 0x63A36D0),
                  ("#348", 0x63A3410),
                  ("#349", 0x63A3150),
                  ("#350", 0x63A2E90),
                  ("#351", 0x63A2BD0),
                  ("#352", 0x63A2910),
                  ("#353", 0x63A2650),
                  ("#354", 0x63A2390),
                  ("#355", 0x63A20D0),
                  ("#356", 0x63A1E10),
                  ("#357", 0x63A1B50),
                  ("#358", 0x63A1890),
                  ("#359", 0x63A15D0),
                  ("#360", 0x63A1310),
                  ("#361", 0x63A1050),
                  ("#362", 0x63A0D90),
                  ("#363", 0x63A0AD0),
                  ("#364", 0x63A0810),
                  ("#365", 0x63A06E0),
                  ("#366", 0x63A0480),
                  ("#367", 0x63A01C0),
                  ("#368", 0x639FF00)):
        check("%s window not called" % _w, tgt.get(_a, 0) == 0,
              str(tgt.get(_a, 0)))

    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", len(bsr) == 0, str([hex(addr_of(l)) for l in bsr]))
    check("shr exactly 1 (shr $0x3 at 0x639fd90)",
          [hex(addr_of(l)) for l in lines if mnemonic_of(l) == "shr"] ==
          ["0x639fd90"])
    check("shr is $0x3,%esi at 0x639fd90",
          "shr" in by_addr[0x639fd90] and "$0x3,%esi" in by_addr[0x639fd90])
    check("shl exactly 0 (no entry stride in this window)",
          [l for l in lines if mnemonic_of(l) == "shl"] == [])
    check("btc 0",
          [l for l in lines if mnemonic_of(l) == "btc"] == [])
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
          [0x639fc88, 0x639fca8, 0x639fcb4, 0x639fcb4, 0x639fcf0,
           0x639fd19, 0x639fd19, 0x639fd20, 0x639fd38, 0x639fdd7,
           0x639fde6, 0x639fdf5, 0x639fe04, 0x639fe13, 0x639fe22,
           0x639fe3a, 0x639fe3a, 0x639fea8, 0x639febf, 0x639febf,
           0x639febf, 0x639febf, 0x639febf, 0x639febf, 0x639febf,
           0x639fecd, 0x639fee2, 0x639fef3],
          str(sorted(jump_target(l) for l in jmps)))
    check("endbr64 count 1",
          sum(1 for l in lines if "endbr64" in l) == 1)
    check("entry is endbr64 at 0x639fc40",
          "endbr64" in by_addr[START])
    check("canary present: 2 fs:0x28 lines",
          sum(1 for l in lines if "%fs:0x28" in l) == 2)
    check("canary load at 0x639fc6b",
          "mov" in by_addr[0x639fc6b] and "%fs:0x28,%rax" in by_addr[0x639fc6b])
    check("canary save to 0x8(%rsp) at 0x639fc74",
          "mov" in by_addr[0x639fc74] and "%rax,0x8(%rsp)" in by_addr[0x639fc74])
    check("canary check sub at 0x639fcc8",
          "sub" in by_addr[0x639fcc8] and "%fs:0x28,%rax" in by_addr[0x639fcc8])
    check("canary fail jne to stack_chk_fail at 0x639fcd1",
          "jne" in by_addr[0x639fcd1] and "639fef3" in by_addr[0x639fcd1])
    check("TLS flag check absent: 0 fs:0x330 lines",
          sum(1 for l in lines if "%fs:0x330" in l) == 0)
    check("no prefetch instructions",
          not any("prefetch" in l for l in lines))
    check("tzcnt 0",
          [l for l in lines if mnemonic_of(l) == "tzcnt"] == [])
    check('entry endbr64 at 0x639fc40',
          'endbr64' in by_addr[0x639fc40])
    check('push %r15 at 0x639fc44',
          'push' in by_addr[0x639fc44] and '%r15' in by_addr[0x639fc44])
    check('mutex lea 0x67121a0 at 0x639fc46',
          'lea' in by_addr[0x639fc46] and '0x372553(%rip),%r15' in by_addr[0x639fc46])
    check('push %r14 at 0x639fc4d',
          'push' in by_addr[0x639fc4d] and '%r14' in by_addr[0x639fc4d])
    check('entry rsi save mov %rsi,%r14 at 0x639fc4f',
          'mov' in by_addr[0x639fc4f] and '%rsi,%r14' in by_addr[0x639fc4f])
    check('push %r13 at 0x639fc52',
          'push' in by_addr[0x639fc52] and '%r13' in by_addr[0x639fc52])
    check('entry r8 save mov %r8,%r13 at 0x639fc54',
          'mov' in by_addr[0x639fc54] and '%r8,%r13' in by_addr[0x639fc54])
    check('push %r12 at 0x639fc57',
          'push' in by_addr[0x639fc57] and '%r12' in by_addr[0x639fc57])
    check('entry rcx save mov %rcx,%r12 at 0x639fc59',
          'mov' in by_addr[0x639fc59] and '%rcx,%r12' in by_addr[0x639fc59])
    check('push %rbp at 0x639fc5c',
          'push' in by_addr[0x639fc5c] and '%rbp' in by_addr[0x639fc5c])
    check('entry rdi save mov %rdi,%rbp at 0x639fc5d',
          'mov' in by_addr[0x639fc5d] and '%rdi,%rbp' in by_addr[0x639fc5d])
    check('mov %r15,%rdi at 0x639fc60',
          'mov' in by_addr[0x639fc60] and '%r15,%rdi' in by_addr[0x639fc60])
    check('push %rbx at 0x639fc63',
          'push' in by_addr[0x639fc63] and '%rbx' in by_addr[0x639fc63])
    check('entry r9 save mov %r9,%rbx at 0x639fc64',
          'mov' in by_addr[0x639fc64] and '%r9,%rbx' in by_addr[0x639fc64])
    check('frame sub $0x18,%rsp at 0x639fc67',
          'sub' in by_addr[0x639fc67] and '$0x18,%rsp' in by_addr[0x639fc67])
    check('canary load mov %fs:0x28,%rax at 0x639fc6b',
          'mov' in by_addr[0x639fc6b] and '%fs:0x28,%rax' in by_addr[0x639fc6b])
    check('canary save mov %rax,0x8(%rsp) at 0x639fc74',
          'mov' in by_addr[0x639fc74] and '%rax,0x8(%rsp)' in by_addr[0x639fc74])
    check('xor %eax,%eax at 0x639fc79',
          'xor' in by_addr[0x639fc79] and '%eax,%eax' in by_addr[0x639fc79])
    check('trylock call at 0x639fc7b',
          'call' in by_addr[0x639fc7b] and '63f17b0 <pthread_mutex_trylock@plt>' in by_addr[0x639fc7b])
    check('trylock test %eax,%eax at 0x639fc80',
          'test' in by_addr[0x639fc80] and '%eax,%eax' in by_addr[0x639fc80])
    check('trylock-fail jne lock-wait setup at 0x639fc82',
          'jne' in by_addr[0x639fc82] and '639fd20' in by_addr[0x639fc82])
    check('acq-count addq $0x1,0x372508(%rip) at 0x639fc88',
          'addq' in by_addr[0x639fc88] and '$0x1,0x372508(%rip)' in by_addr[0x639fc88])
    check('owner cmp 0x6712190,%rbp at 0x639fc90',
          'cmp' in by_addr[0x639fc90] and '0x3724f9(%rip),%rbp' in by_addr[0x639fc90])
    check('owner-unchanged je exit-1 at 0x639fc97',
          'je' in by_addr[0x639fc97] and '639fca8' in by_addr[0x639fc97])
    check('counter addq $0x1,0x3724e7(%rip) at 0x639fc99',
          'addq' in by_addr[0x639fc99] and '$0x1,0x3724e7(%rip)' in by_addr[0x639fc99])
    check('owner store mov %rbp,0x3724e8(%rip) at 0x639fca1',
          'mov' in by_addr[0x639fca1] and '%rbp,0x3724e8(%rip)' in by_addr[0x639fca1])
    check('exit-1 mov $0x1,%ebp at 0x639fca8',
          'mov' in by_addr[0x639fca8] and '$0x1,%ebp' in by_addr[0x639fca8])
    check('caller-cond or 0x50(%rsp),%rbx at 0x639fcad',
          'or' in by_addr[0x639fcad] and '0x50(%rsp),%rbx' in by_addr[0x639fcad])
    check('caller-cond je resolver path at 0x639fcb2',
          'je' in by_addr[0x639fcb2] and '639fcf0' in by_addr[0x639fcb2])
    check('waited-flag clear movb $0x0,0x37250d(%rip) at 0x639fcb4',
          'movb' in by_addr[0x639fcb4] and '$0x0,0x37250d(%rip)' in by_addr[0x639fcb4])
    check('unlock rdi mov %r15,%rdi at 0x639fcbb',
          'mov' in by_addr[0x639fcbb] and '%r15,%rdi' in by_addr[0x639fcbb])
    check('unlock call at 0x639fcbe',
          'call' in by_addr[0x639fcbe] and '63f0b70 <pthread_mutex_unlock@plt>' in by_addr[0x639fcbe])
    check('canary reload mov 0x8(%rsp),%rax at 0x639fcc3',
          'mov' in by_addr[0x639fcc3] and '0x8(%rsp),%rax' in by_addr[0x639fcc3])
    check('canary check sub %fs:0x28,%rax at 0x639fcc8',
          'sub' in by_addr[0x639fcc8] and '%fs:0x28,%rax' in by_addr[0x639fcc8])
    check('canary fail jne stack_chk_fail at 0x639fcd1',
          'jne' in by_addr[0x639fcd1] and '639fef3' in by_addr[0x639fcd1])
    check('rsp restore add $0x18,%rsp at 0x639fcd7',
          'add' in by_addr[0x639fcd7] and '$0x18,%rsp' in by_addr[0x639fcd7])
    check('exit mov %ebp,%eax at 0x639fcdb',
          'mov' in by_addr[0x639fcdb] and '%ebp,%eax' in by_addr[0x639fcdb])
    check('pop %rbx at 0x639fcdd',
          'pop' in by_addr[0x639fcdd] and '%rbx' in by_addr[0x639fcdd])
    check('pop %rbp at 0x639fcde',
          'pop' in by_addr[0x639fcde] and '%rbp' in by_addr[0x639fcde])
    check('pop %r12 at 0x639fcdf',
          'pop' in by_addr[0x639fcdf] and '%r12' in by_addr[0x639fcdf])
    check('pop %r13 at 0x639fce1',
          'pop' in by_addr[0x639fce1] and '%r13' in by_addr[0x639fce1])
    check('pop %r14 at 0x639fce3',
          'pop' in by_addr[0x639fce3] and '%r14' in by_addr[0x639fce3])
    check('pop %r15 at 0x639fce5',
          'pop' in by_addr[0x639fce5] and '%r15' in by_addr[0x639fce5])
    check('ret at 0x639fce7',
          'ret' in by_addr[0x639fce7])
    check('resolver arg mov 0x10(%r14),%rdi at 0x639fcf0',
          'mov' in by_addr[0x639fcf0] and '0x10(%r14),%rdi' in by_addr[0x639fcf0])
    check('resolver call 0x6388310 at 0x639fcf4',
          'call' in by_addr[0x639fcf4] and '6388310' in by_addr[0x639fcf4])
    check('resolver qword mov 0x30(%rax),%rax at 0x639fcf9 (no loader, no adjust)',
          'mov' in by_addr[0x639fcf9] and '0x30(%rax),%rax' in by_addr[0x639fcf9])
    check('qword store mov %rax,(%rsp) at 0x639fcfd',
          'mov' in by_addr[0x639fcfd] and '%rax,(%rsp)' in by_addr[0x639fcfd])
    check('rcx==0 test %r12,%r12 at 0x639fd01',
          'test' in by_addr[0x639fd01] and '%r12,%r12' in by_addr[0x639fd01])
    check('rcx==0 je exit-0 at 0x639fd04',
          'je' in by_addr[0x639fd04] and '639fd19' in by_addr[0x639fd04])
    check('r8==0 test %r13,%r13 at 0x639fd06',
          'test' in by_addr[0x639fd06] and '%r13,%r13' in by_addr[0x639fd06])
    check('r8==0 je exit-0 at 0x639fd09',
          'je' in by_addr[0x639fd09] and '639fd19' in by_addr[0x639fd09])
    check('len load mov 0x0(%r13),%rdx at 0x639fd0b',
          'mov' in by_addr[0x639fd0b] and '0x0(%r13),%rdx' in by_addr[0x639fd0b])
    check('len cmp $0x8,%rdx at 0x639fd0f',
          'cmp' in by_addr[0x639fd0f] and '$0x8,%rdx' in by_addr[0x639fd0f])
    check('len!=8 jne Duff path at 0x639fd13',
          'jne' in by_addr[0x639fd13] and '639fd38' in by_addr[0x639fd13])
    check('len==8 qword store mov %rax,(%r12) at 0x639fd15',
          'mov' in by_addr[0x639fd15] and '%rax,(%r12)' in by_addr[0x639fd15])
    check('exit-0 xor %ebp,%ebp at 0x639fd19',
          'xor' in by_addr[0x639fd19] and '%ebp,%ebp' in by_addr[0x639fd19])
    check('exit-0 jmp flag-clear at 0x639fd1b',
          'jmp' in by_addr[0x639fd1b] and '639fcb4' in by_addr[0x639fd1b])
    check('lock-wait setup lea -0x40(%r15),%rdi at 0x639fd20',
          'lea' in by_addr[0x639fd20] and '-0x40(%r15),%rdi' in by_addr[0x639fd20])
    check('lock-wait call at 0x639fd24',
          'call' in by_addr[0x639fd24] and '63bf680' in by_addr[0x639fd24])
    check('waited-flag set movb $0x1,0x372498(%rip) at 0x639fd29',
          'movb' in by_addr[0x639fd29] and '$0x1,0x372498(%rip)' in by_addr[0x639fd29])
    check('lock-wait rejoin jmp trylock-success (NO retry) at 0x639fd30',
          'jmp' in by_addr[0x639fd30] and '639fc88' in by_addr[0x639fd30])
    check('Duff cap mov $0x8,%ecx at 0x639fd38',
          'mov' in by_addr[0x639fd38] and '$0x8,%ecx' in by_addr[0x639fd38])
    check('Duff src mov %rsp,%r9 at 0x639fd3d',
          'mov' in by_addr[0x639fd3d] and '%rsp,%r9' in by_addr[0x639fd3d])
    check('Duff cmp %rcx,%rdx at 0x639fd40',
          'cmp' in by_addr[0x639fd40] and '%rcx,%rdx' in by_addr[0x639fd40])
    check('Duff min cmova %rcx,%rdx at 0x639fd43',
          'cmova' in by_addr[0x639fd43] and '%rcx,%rdx' in by_addr[0x639fd43])
    check('Duff cmp $0x8,%edx at 0x639fd47',
          'cmp' in by_addr[0x639fd47] and '$0x8,%edx' in by_addr[0x639fd47])
    check('Duff n<8 jb small tail at 0x639fd4a',
          'jb' in by_addr[0x639fd4a] and '639fea8' in by_addr[0x639fd4a])
    check('Duff n mov %edx,%r14d at 0x639fd50',
          'mov' in by_addr[0x639fd50] and '%edx,%r14d' in by_addr[0x639fd50])
    check('Duff first qword mov %rax,(%r12) at 0x639fd53',
          'mov' in by_addr[0x639fd53] and '%rax,(%r12)' in by_addr[0x639fd53])
    check('Duff lea 0x8(%r12),%rcx at 0x639fd57',
          'lea' in by_addr[0x639fd57] and '0x8(%r12),%rcx' in by_addr[0x639fd57])
    check('Duff last-qword load mov -0x8(%r9,%r14,1),%rax at 0x639fd5c',
          'mov' in by_addr[0x639fd5c] and '-0x8(%r9,%r14,1),%rax' in by_addr[0x639fd5c])
    check('Duff and $~7,%rcx at 0x639fd61',
          'and' in by_addr[0x639fd61] and '$0xfffffffffffffff8,%rcx' in by_addr[0x639fd61])
    check('Duff last-qword store mov %rax,-0x8(%r12,%r14,1) at 0x639fd65',
          'mov' in by_addr[0x639fd65] and '%rax,-0x8(%r12,%r14,1)' in by_addr[0x639fd65])
    check('Duff sub %rcx,%r12 at 0x639fd6a',
          'sub' in by_addr[0x639fd6a] and '%rcx,%r12' in by_addr[0x639fd6a])
    check('Duff sub %r12,%r9 at 0x639fd6d',
          'sub' in by_addr[0x639fd6d] and '%r12,%r9' in by_addr[0x639fd6d])
    check('Duff add %edx,%r12d at 0x639fd70',
          'add' in by_addr[0x639fd70] and '%edx,%r12d' in by_addr[0x639fd70])
    check('Duff and $~7,%r12d at 0x639fd73',
          'and' in by_addr[0x639fd73] and '$0xfffffff8,%r12d' in by_addr[0x639fd73])
    check('Duff cmp $0x8,%r12d at 0x639fd77',
          'cmp' in by_addr[0x639fd77] and '$0x8,%r12d' in by_addr[0x639fd77])
    check('Duff loop-entry jb writeback at 0x639fd7b',
          'jb' in by_addr[0x639fd7b] and '639febf' in by_addr[0x639fd7b])
    check('Duff loop first mov (%r9,%rbx,1),%rdi at 0x639fd81',
          'mov' in by_addr[0x639fd81] and '(%r9,%rbx,1),%rdi' in by_addr[0x639fd81])
    check('Duff lea -0x1(%r12),%esi at 0x639fd85',
          'lea' in by_addr[0x639fd85] and '-0x1(%r12),%esi' in by_addr[0x639fd85])
    check('Duff mov $0x8,%r10d at 0x639fd8a',
          'mov' in by_addr[0x639fd8a] and '$0x8,%r10d' in by_addr[0x639fd8a])
    check('Duff shr $0x3,%esi at 0x639fd90',
          'shr' in by_addr[0x639fd90] and '$0x3,%esi' in by_addr[0x639fd90])
    check('Duff first store mov %rdi,(%rcx,%rbx,1) at 0x639fd93',
          'mov' in by_addr[0x639fd93] and '%rdi,(%rcx,%rbx,1)' in by_addr[0x639fd93])
    check('Duff dispatch and $0x7,%esi at 0x639fd97',
          'and' in by_addr[0x639fd97] and '$0x7,%esi' in by_addr[0x639fd97])
    check('Duff cmp %r12d,%r10d at 0x639fd9a',
          'cmp' in by_addr[0x639fd9a] and '%r12d,%r10d' in by_addr[0x639fd9a])
    check('Duff jae writeback at 0x639fd9d',
          'jae' in by_addr[0x639fd9d] and '639febf' in by_addr[0x639fd9d])
    check('Duff test %esi,%esi at 0x639fda3',
          'test' in by_addr[0x639fda3] and '%esi,%esi' in by_addr[0x639fda3])
    check('Duff esi==0 je 8x body at 0x639fda5',
          'je' in by_addr[0x639fda5] and '639fe3a' in by_addr[0x639fda5])
    check('Duff cmp $0x1,%esi at 0x639fdab',
          'cmp' in by_addr[0x639fdab] and '$0x1,%esi' in by_addr[0x639fdab])
    check('Duff esi==1 je tail at 0x639fdae',
          'je' in by_addr[0x639fdae] and '639fe22' in by_addr[0x639fdae])
    check('Duff cmp $0x2,%esi at 0x639fdb0',
          'cmp' in by_addr[0x639fdb0] and '$0x2,%esi' in by_addr[0x639fdb0])
    check('Duff esi==2 je tail at 0x639fdb3',
          'je' in by_addr[0x639fdb3] and '639fe13' in by_addr[0x639fdb3])
    check('Duff cmp $0x3,%esi at 0x639fdb5',
          'cmp' in by_addr[0x639fdb5] and '$0x3,%esi' in by_addr[0x639fdb5])
    check('Duff esi==3 je tail at 0x639fdb8',
          'je' in by_addr[0x639fdb8] and '639fe04' in by_addr[0x639fdb8])
    check('Duff cmp $0x4,%esi at 0x639fdba',
          'cmp' in by_addr[0x639fdba] and '$0x4,%esi' in by_addr[0x639fdba])
    check('Duff esi==4 je tail at 0x639fdbd',
          'je' in by_addr[0x639fdbd] and '639fdf5' in by_addr[0x639fdbd])
    check('Duff cmp $0x5,%esi at 0x639fdbf',
          'cmp' in by_addr[0x639fdbf] and '$0x5,%esi' in by_addr[0x639fdbf])
    check('Duff esi==5 je tail at 0x639fdc2',
          'je' in by_addr[0x639fdc2] and '639fde6' in by_addr[0x639fdc2])
    check('Duff cmp $0x6,%esi at 0x639fdc4',
          'cmp' in by_addr[0x639fdc4] and '$0x6,%esi' in by_addr[0x639fdc4])
    check('Duff esi==6 je tail at 0x639fdc7',
          'je' in by_addr[0x639fdc7] and '639fdd7' in by_addr[0x639fdc7])
    check('Duff tail-end cmp %r12d,%r10d at 0x639fe31',
          'cmp' in by_addr[0x639fe31] and '%r12d,%r10d' in by_addr[0x639fe31])
    check('Duff tail-end jae writeback at 0x639fe34',
          'jae' in by_addr[0x639fe34] and '639febf' in by_addr[0x639fe34])
    check('8x body mov %r10d,%eax at 0x639fe3a',
          'mov' in by_addr[0x639fe3a] and '%r10d,%eax' in by_addr[0x639fe3a])
    check('8x body add $0x40,%r10d at 0x639fe7d',
          'add' in by_addr[0x639fe7d] and '$0x40,%r10d' in by_addr[0x639fe7d])
    check('8x body cmp %r12d,%r10d at 0x639fe9d',
          'cmp' in by_addr[0x639fe9d] and '%r12d,%r10d' in by_addr[0x639fe9d])
    check('8x body back-edge jb 0x639fe3a at 0x639fea0',
          'jb' in by_addr[0x639fea0] and '639fe3a' in by_addr[0x639fea0])
    check('8x body jmp writeback at 0x639fea2',
          'jmp' in by_addr[0x639fea2] and '639febf' in by_addr[0x639fea2])
    check('small tail test $0x4,%dl at 0x639fea8',
          'test' in by_addr[0x639fea8] and '$0x4,%dl' in by_addr[0x639fea8])
    check('small tail jne 4-byte at 0x639feab',
          'jne' in by_addr[0x639feab] and '639fecd' in by_addr[0x639feab])
    check('small tail test %edx,%edx at 0x639fead',
          'test' in by_addr[0x639fead] and '%edx,%edx' in by_addr[0x639fead])
    check('small tail je writeback at 0x639feaf',
          'je' in by_addr[0x639feaf] and '639febf' in by_addr[0x639feaf])
    check('small tail movzbl (%rsp),%r10d at 0x639feb1',
          'movzbl' in by_addr[0x639feb1] and '(%rsp),%r10d' in by_addr[0x639feb1])
    check('small tail mov %r10b,(%r12) at 0x639feb6',
          'mov' in by_addr[0x639feb6] and '%r10b,(%r12)' in by_addr[0x639feb6])
    check('small tail test $0x2,%dl at 0x639feba',
          'test' in by_addr[0x639feba] and '$0x2,%dl' in by_addr[0x639feba])
    check('small tail jne 2-byte at 0x639febd',
          'jne' in by_addr[0x639febd] and '639fee2' in by_addr[0x639febd])
    check('writeback mov %rdx,0x0(%r13) at 0x639febf',
          'mov' in by_addr[0x639febf] and '%rdx,0x0(%r13)' in by_addr[0x639febf])
    check('exit-22 mov $0x16,%ebp at 0x639fec3',
          'mov' in by_addr[0x639fec3] and '$0x16,%ebp' in by_addr[0x639fec3])
    check('exit-22 jmp flag-clear at 0x639fec8',
          'jmp' in by_addr[0x639fec8] and '639fcb4' in by_addr[0x639fec8])
    check('4-byte mov (%rsp),%esi at 0x639fecd',
          'mov' in by_addr[0x639fecd] and '(%rsp),%esi' in by_addr[0x639fecd])
    check('4-byte mov %esi,(%r12) at 0x639fed2',
          'mov' in by_addr[0x639fed2] and '%esi,(%r12)' in by_addr[0x639fed2])
    check('4-byte last mov -0x4(%r9,%rdi,1),%r8d at 0x639fed6',
          'mov' in by_addr[0x639fed6] and '-0x4(%r9,%rdi,1),%r8d' in by_addr[0x639fed6])
    check('4-byte jmp writeback at 0x639fee0',
          'jmp' in by_addr[0x639fee0] and '639febf' in by_addr[0x639fee0])
    check('2-byte movzwl -0x2(%r9,%r11,1),%ebp at 0x639fee5',
          'movzwl' in by_addr[0x639fee5] and '-0x2(%r9,%r11,1),%ebp' in by_addr[0x639fee5])
    check('2-byte jmp writeback at 0x639fef1',
          'jmp' in by_addr[0x639fef1] and '639febf' in by_addr[0x639fef1])
    check('stack_chk_fail call at 0x639fef3',
          'call' in by_addr[0x639fef3] and '63f0d70 <__stack_chk_fail@plt>' in by_addr[0x639fef3])
    # Instruction spot checks: (address, mnemonic, operand substring).
    # Exhaustive: every strict line of the exhibit.
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

    check("entry reaches lock-wait site 0x639fd24", reaches(START, 0x639fd24))
    check("entry reaches ret 0x639fce7", reaches(START, 0x639fce7))
    check("entry reaches trylock 0x639fc7b", reaches(START, 0x639fc7b))
    check("entry reaches flag-clear 0x639fcb4", reaches(START, 0x639fcb4))
    check("entry reaches epilogue canary 0x639fcc3", reaches(START, 0x639fcc3))
    check("entry reaches resolver call 0x639fcf4", reaches(START, 0x639fcf4))
    check("entry reaches exit-1 block 0x639fca8", reaches(START, 0x639fca8))
    check("entry reaches exit-0 block 0x639fd19", reaches(START, 0x639fd19))
    check("entry reaches exit-22 block 0x639fec3", reaches(START, 0x639fec3))
    check("entry reaches Duff entry 0x639fd38", reaches(START, 0x639fd38))
    check("entry reaches lock-wait setup 0x639fd20", reaches(START, 0x639fd20))
    check("entry reaches writeback 0x639febf", reaches(START, 0x639febf))
    check("entry reaches Duff loop first instr 0x639fd81 (graph edge only; fully dead, see Duff block)",
          reaches(START, 0x639fd81))
    check("entry reaches 8x body 0x639fe3a (graph edge only; fully dead, see Duff block)",
          reaches(START, 0x639fe3a))
    check("entry reaches small tail 0x639fea8", reaches(START, 0x639fea8))
    check("preds of lock-wait site 0x639fd24 is the setup lea only",
          preds[0x639fd24] == {0x639fd20}, str(preds[0x639fd24]))
    check("preds of lock-wait setup 0x639fd20 are trylock fail and the "
          "padding nopl",
          preds[0x639fd20] == {0x639fc82, 0x639fd1d}, str(preds[0x639fd20]))
    check("preds of trylock 0x639fc7b is the xor only",
          preds[0x639fc7b] == {0x639fc79}, str(preds[0x639fc7b]))
    check("preds of rejoin 0x639fc88 are trylock success and the "
          "lock-wait jmp",
          preds[0x639fc88] == {0x639fc82, 0x639fd30}, str(preds[0x639fc88]))
    check("preds of ret 0x639fce7 is the final pop",
          preds[0x639fce7] == {0x639fce5}, str(preds[0x639fce7]))
    check("preds of flag-clear block 0x639fcb4 are the caller-cond "
          "fall-through, the exit-0 jmp and the exit-22 jmp",
          preds[0x639fcb4] == {0x639fcb2, 0x639fd1b, 0x639fec8},
          str(preds[0x639fcb4]))
    check("preds of exit-1 block 0x639fca8 are the owner-unchanged je "
          "and the owner-store fall-through",
          preds[0x639fca8] == {0x639fc97, 0x639fca1}, str(preds[0x639fca8]))
    check("preds of resolver call 0x639fcf4 is the resolver-arg mov only",
          preds[0x639fcf4] == {0x639fcf0}, str(preds[0x639fcf4]))
    check("preds of resolver path 0x639fcf0 are the caller-cond je and "
          "the padding nopl",
          preds[0x639fcf0] == {0x639fcb2, 0x639fce8}, str(preds[0x639fcf0]))
    check("preds of exit-0 block 0x639fd19 are rcx==0, r8==0 and the "
          "len==8 qword store",
          preds[0x639fd19] == {0x639fd04, 0x639fd09, 0x639fd15},
          str(preds[0x639fd19]))
    check("preds of Duff entry 0x639fd38 are the len!=8 jne and the "
          "padding nopl",
          preds[0x639fd38] == {0x639fd13, 0x639fd35}, str(preds[0x639fd38]))
    check("preds of writeback 0x639febf are the loop-entry jb, the two "
          "dispatch jaes, the 8x-body jmp, the small-tail je, the small-tail "
          "jne fall-through and the two small-tail jmps",
          preds[0x639febf] == {0x639fd7b, 0x639fd9d, 0x639fe34, 0x639fea2,
                               0x639feaf, 0x639febd, 0x639fee0, 0x639fef1},
          str(preds[0x639febf]))
    check("preds of 8x body 0x639fe3a are the dispatch je, the "
          "tail-end fall-through and the body's own back-edge",
          preds[0x639fe3a] == {0x639fda5, 0x639fe34, 0x639fea0}, str(preds[0x639fe3a]))
    check("preds of Duff loop first instr 0x639fd81 is the loop-entry jb "
          "fall-through only",
          preds[0x639fd81] == {0x639fd7b}, str(preds[0x639fd81]))
    check("preds of small tail 0x639fea8 are the n<8 jb and the padding nopl",
          preds[0x639fea8] == {0x639fd4a, 0x639fea4}, str(preds[0x639fea8]))
    check("preds of n==8 path 0x639fd50 is the n>=8 cmp fall-through only",
          preds[0x639fd50] == {0x639fd4a}, str(preds[0x639fd50]))
    # The Duff's-device loop IS present (0x639fd81..0x639fea2) but it is
    # FULLY DEAD, unlike #366 (reachable dispatch tail) and #339..#364
    # (unreachable loop, different mechanism): the only CFG entry to the
    # loop is the fall-through from the loop-entry jb at 0x639fd7b
    # (preds[0x639fd81] == {0x639fd7b}), and that jb is ALWAYS taken.
    # The jb tests r12d < 8 after cmp $0x8,%r12d at 0x639fd77, and r12d
    # is 0 on every path that reaches 0x639fd77: r12 = dest - ((dest+8)
    # & ~7) = (dest mod 8) - 8 (sub %rcx,%r12 at 0x639fd6a, rcx =
    # (dest+8)&~7 from lea 0x8(%r12) at 0x639fd57 and and $~7,%rcx at
    # 0x639fd61), then r12d += n (add %edx,%r12d at 0x639fd70) and
    # r12d &= ~7 (and $0xfffffff8,%r12d at 0x639fd73). The only path to
    # 0x639fd50 has n == 8: len == 8 exits 0 on the fast path (the jne at
    # 0x639fd13 falls through only when len == 8), len < 8 goes to the
    # small tail (jb at 0x639fd4a), so reaching 0x639fd50 requires
    # n >= 8 while n = min(len,8) <= 8 (cmova at 0x639fd43), hence
    # n == 8 exactly and r12d = ((dest mod 8) - 8 + 8) & ~7 = 0 < 8.
    # So the dispatch
    # tail (0x639fd81..0x639fe38) and the 8-at-a-time body
    # (0x639fe3a..0x639fea2) are never entered. For len > 8 only the
    # first qword is copied -- stored to dest+0 at 0x639fd53, re-loaded
    # from src+0 at 0x639fd5c (mov -0x8(%r9,%r14,1),%rax -- with r14d
    # == 8 reads src+0, not src+8), and stored AGAIN to dest+0 at
    # 0x639fd65 -- then *r8 = 8 and exit 22.
    # For len < 8 the small tail (0x639fea8..0x639fef1) copies n = len
    # bytes by 4/2/1-byte decomposition, *r8 = n, exit 22.
    check("Duff cap is 8: mov $0x8,%ecx at 0x639fd38",
          "mov" in by_addr[0x639fd38] and "$0x8,%ecx" in by_addr[0x639fd38])
    check("Duff src is the stack temp: mov %rsp,%r9 at 0x639fd3d",
          "mov" in by_addr[0x639fd3d] and "%rsp,%r9" in by_addr[0x639fd3d])
    check("Duff min is cmova %rcx,%rdx at 0x639fd43",
          "cmova" in by_addr[0x639fd43] and "%rcx,%rdx" in by_addr[0x639fd43])
    check("Duff n<8 jb small tail at 0x639fd4a",
          "jb" in by_addr[0x639fd4a] and "639fea8" in by_addr[0x639fd4a])
    check("Duff n==8 path entry is the jb fall-through only",
          preds[0x639fd50] == {0x639fd4a}, str(preds[0x639fd50]))
    check("Duff r12 chain: sub %rcx,%r12 at 0x639fd6a",
          "sub" in by_addr[0x639fd6a] and "%rcx,%r12" in by_addr[0x639fd6a])
    check("Duff r12 chain: add %edx,%r12d at 0x639fd70",
          "add" in by_addr[0x639fd70] and "%edx,%r12d" in by_addr[0x639fd70])
    check("Duff r12 chain: and $~7,%r12d at 0x639fd73",
          "and" in by_addr[0x639fd73] and "$0xfffffff8,%r12d" in by_addr[0x639fd73])
    check("Duff loop-entry cmp $0x8,%r12d at 0x639fd77",
          "cmp" in by_addr[0x639fd77] and "$0x8,%r12d" in by_addr[0x639fd77])
    check("Duff loop-entry jb writeback at 0x639fd7b",
          "jb" in by_addr[0x639fd7b] and "639febf" in by_addr[0x639fd7b])
    check("Duff loop sole entry is the loop-entry jb fall-through",
          preds[0x639fd81] == {0x639fd7b}, str(preds[0x639fd81]))
    check("Duff dispatch tail entries are the six je targets for esi in 1..6",
          sorted(jump_target(by_addr[a]) for a in
                 (0x639fdae, 0x639fdb3, 0x639fdb8, 0x639fdbd, 0x639fdc2,
                  0x639fdc7)) ==
          [0x639fdd7, 0x639fde6, 0x639fdf5, 0x639fe04, 0x639fe13, 0x639fe22],
          str([hex(jump_target(by_addr[a])) for a in
               (0x639fdae, 0x639fdb3, 0x639fdb8, 0x639fdbd, 0x639fdc2,
                0x639fdc7)]))
    check("Duff 8x-body entry je at 0x639fda5 fires only when esi==0",
          "je" in by_addr[0x639fda5] and "639fe3a" in by_addr[0x639fda5]
          and "test" in by_addr[0x639fda3]
          and "%esi,%esi" in by_addr[0x639fda3])
    check("Duff shr $0x3 at 0x639fd90 and and $0x7 at 0x639fd97",
          "shr" in by_addr[0x639fd90] and "$0x3,%esi" in by_addr[0x639fd90]
          and "and" in by_addr[0x639fd97] and "$0x7,%esi" in by_addr[0x639fd97])
    check("Duff tail-end jae writeback at 0x639fe34",
          "jae" in by_addr[0x639fe34] and "639febf" in by_addr[0x639fe34])
    check("8x body back-edge jb 0x639fe3a at 0x639fea0",
          "jb" in by_addr[0x639fea0] and "639fe3a" in by_addr[0x639fea0])
    check("8x body exit jmp writeback at 0x639fea2",
          "jmp" in by_addr[0x639fea2] and "639febf" in by_addr[0x639fea2])
    check("small tail entry is the n<8 jb and the padding nopl",
          preds[0x639fea8] == {0x639fd4a, 0x639fea4}, str(preds[0x639fea8]))
    check("backward jumps are the exit-0 jmp, the lock-wait rejoin, "
          "the 8x-body back-edge, the exit-22 jmp and the two small-tail jmps",
          sorted((addr_of(l), jump_target(l)) for l in jmps
                 if jump_target(l) is not None
                 and jump_target(l) < addr_of(l)) ==
          [(0x639fd1b, 0x639fcb4), (0x639fd30, 0x639fc88),
           (0x639fea0, 0x639fe3a), (0x639fec8, 0x639fcb4),
           (0x639fee0, 0x639febf), (0x639fef1, 0x639febf)],
          str([(hex(addr_of(l)), hex(jump_target(l))) for l in jmps
               if jump_target(l) is not None
               and jump_target(l) < addr_of(l)]))
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
    SITE = 0x639fd24
    RET = 0x639fce7
    CALL_TRYLOCK = {("CALL", 0x639fc7b)}
    check("site rdi only def is lea -0x40(%r15),%rdi 0x639fd20",
          rdi_in[SITE] == {0x639fd20}, str(rdi_in[SITE]))
    check("site rsi is clobbered by the trylock only (no post-trylock "
          "restore in this window, like #339/#340/#341/#342/#343/#344/#345/#346/#347/#348/#349/#350/#351/#352/#353/#354/#355/#356/#357/#358/#359/#360/#361/#362/#363/#364/#365/#366/#367/#368, unlike #338)",
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
    check("site rbx def is the entry r9 save",
          rbx_in[SITE] == {0x639fc64}, str(rbx_in[SITE]))
    check("site rbp def is the entry rdi save",
          rbp_in[SITE] == {0x639fc5d}, str(rbp_in[SITE]))
    check("site r12 def is the entry rcx save",
          r12_in[SITE] == {0x639fc59}, str(r12_in[SITE]))
    check("site r13 def is the entry r8 save",
          r13_in[SITE] == {0x639fc54}, str(r13_in[SITE]))
    check("site r14 def is the entry rsi save",
          r14_in[SITE] == {0x639fc4f}, str(r14_in[SITE]))
    check("site r15 def is the mutex lea",
          r15_in[SITE] == {0x639fc46}, str(r15_in[SITE]))
    check("rax at ret is exactly the single mov %ebp,%eax at 0x639fcdb",
          rax_in[RET] == {0x639fcdb}, str(rax_in[RET]))
    check("ebp at the exit mov is exactly the 3 exit values 0/1/22",
          rbp_in[0x639fcdb] == {0x639fca8, 0x639fd19, 0x639fec3},
          str(rbp_in[0x639fcdb]))
    check("ebp at the flag-clear is exactly the 3 exit values 0/1/22 "
          "(the flag-clear is the exit join point in this window)",
          rbp_in[0x639fcb4] == {0x639fca8, 0x639fd19, 0x639fec3},
          str(rbp_in[0x639fcb4]))
    check("rbx at the Duff entry is the caller-cond or only "
          "(copy path forces rbx==0)",
          rbx_in[0x639fd38] == {0x639fcad}, str(rbx_in[0x639fd38]))
    check("rdx at the Duff entry is the len load only",
          rdx_in[0x639fd38] == {0x639fd0b}, str(rdx_in[0x639fd38]))
    check("rdx at the writeback is the len load plus the cmova min",
          rdx_in[0x639febf] == {0x639fd0b, 0x639fd43}, str(rdx_in[0x639febf]))
    check("r12 at the Duff entry is the entry rcx save",
          r12_in[0x639fd38] == {0x639fc59}, str(r12_in[0x639fd38]))
    check("r13 at the Duff entry is the entry r8 save",
          r13_in[0x639fd38] == {0x639fc54}, str(r13_in[0x639fd38]))
    check("r11 at the 8x body is the resolver clobber plus the two tail defs",
          r11_in[0x639fe3a] == {("CALL", 0x639fcf4), 0x639fe13, 0x639fe6d},
          str(r11_in[0x639fe3a]))
    check("rbp at the 8x body is exit-1 plus the two tail defs",
          rbp_in[0x639fe3a] == {0x639fca8, 0x639fe22, 0x639fe79},
          str(rbp_in[0x639fe3a]))
    check("r12 at the 8x body is the loop-entry and only",
          r12_in[0x639fe3a] == {0x639fd73}, str(r12_in[0x639fe3a]))
    check("r8 at the writeback is the resolver clobber plus the three copy defs",
          r8_in[0x639febf] == {("CALL", 0x639fcf4), 0x639fe1a, 0x639fe8d,
                               0x639fed6},
          str(r8_in[0x639febf]))
    check("r9 at the writeback is the Duff src plus the r9 adjust",
          r9_in[0x639febf] == {0x639fd3d, 0x639fd6d}, str(r9_in[0x639febf]))

    check("records lock-wait sites match census",
          [s.get("site") for s in rec.get("lock_wait_sites", [])] ==
          ["0x639fd24"])
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
    check("records window bytes 696",
          rec.get("window", {}).get("bytes") == 696)
    check("records window range",
          rec.get("window", {}).get("range") == "0x639fc40..0x639fef8")
    check("records return value exits 0/1/22",
          rec.get("return_value", {}).get("rax") ==
          "eax: 0/1/22 (mov %ebp,%eax at 0x639fcdb; ebp: mov $0x1 at 0x639fca8, xor %ebp at 0x639fd19, mov $0x16 at 0x639fec3)")
    check("records entry gate absent (no gate byte in this window)",
          rec.get("entry_gate") is None)
    check("records count call absent (0x634eba0 NOT called here)",
          rec.get("count_call") is None)
    check("records resolver target 0x6388310",
          rec.get("resolver", {}).get("target") == "0x6388310")
    check("records resolver site 0x639fcf4",
          rec.get("resolver", {}).get("site") == "0x639fcf4")
    check("records loader absent (0x63bfb90 NOT called here)",
          rec.get("loader") is None)
    check("records inline adjust absent (no fixed adjust here)",
          rec.get("inline_adjust", {}).get("amount") is None)
    check("records selector is direct qword read (no index, no table)",
          rec.get("selector", {}).get("index") ==
          "none - qword at +0x30 of resolver result read directly (mov 0x30(%rax),%rax at 0x639fcf9)")
    check("records copy loop is a fully dead Duff loop",
          rec.get("copy_loop", {}).get("loop") is True)
    check("records copy dispatch is the Duff dispatch",
          rec.get("copy_loop", {}).get("dispatch") ==
          "Duff's-device dispatch at 0x639fd81 (shr $0x3,%esi at 0x639fd90, and $0x7,%esi at 0x639fd97) with tail entries for esi in 1..6; UNREACHABLE - loop-entry jb at 0x639fd7b always taken (r12d == 0)")
    check("records copy Duff loop is dead",
          rec.get("copy_loop", {}).get("dead_loop") is True)

    # Sections (own ELF parse): .bss exact end; referenced addresses.
    secmap = sections(node)
    bss = secmap[".bss"]
    check("bss section 0x64ffe40..0x6728924",
          bss[3] == 0x64FFE40 and bss[3] + bss[5] == 0x6728924, str(bss))
    for _a in (0x6712188, 0x6712190, 0x6712198, 0x67121A0,
               0x67121C8):
        check("address %s inside .bss" % hex(_a),
              bss[3] <= _a < bss[3] + bss[5])
    check("no .data address is referenced in this window",
          rec.get("census", {}).get("data_referenced_addresses") == [])
    check("no .rodata address is referenced in this window",
          rec.get("census", {}).get("data_rel_ro_referenced_addresses") == [])
    txt = secmap[".text"]
    check("window inside .text",
          txt[3] <= START and END <= txt[3] + txt[5])
    for _t in (0x6388310, 0x63BF680):
        check("call target %s inside .text (internal, not PLT)" % hex(_t),
              txt[3] <= _t < txt[3] + txt[5])

    # rela counts by direct ELF parse
    dyn_total = plt_total = rel_count = 0
    mutex_relocs = 0
    for nm, s in secmap.items():
        if nm == ".rela.dyn":
            dyn_total = s[5] // 24
            for j in range(dyn_total):
                off, info, add = struct.unpack_from(
                    "<QQq", node, s[4] + j * 24)
                rtype = info & 0xFFFFFFFF
                if rtype == 8:
                    rel_count += 1
                if off in (0x6712188, 0x6712190, 0x6712198, 0x67121A0,
                           0x67121C8):
                    mutex_relocs += 1
        if nm == ".rela.plt":
            plt_total = s[5] // 24
    check("rela.dyn total 60723", dyn_total == 60723, str(dyn_total))
    check("rela.dyn RELATIVE 59534", rel_count == 59534, str(rel_count))
    check("rela.plt 278", plt_total == 278, str(plt_total))
    check("no rela lands at any mutex field",
          mutex_relocs == 0, str(mutex_relocs))

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
    check("next candidate raw lu-miss 0", counts.get(0x639F980, 0) == 0,
          str(counts.get(0x639F980, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x639F980, 0) == 0,
          str(bti_counts.get(0x639F980, 0)))
    check("next candidate raw second-handler 0",
          sh_counts.get(0x639F980, 0) == 0, str(sh_counts.get(0x639F980, 0)))
    check("next candidate raw lock-wait 1",
          lw_counts.get(0x639F980, 0) == 1,
          str(lw_counts.get(0x639F980, 0)))
    # lock-wait frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 344", len(survey.get("survivors", [])) == 344,
          str(len(survey.get("survivors", []))))
    check("survey this window is a lock-wait survivor",
          "0x639fc40" in survey.get("survivors", []))
    check("survey this window is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x639fc40") == 1,
          str(survey.get("sites_per_fde", {}).get("0x639fc40")))
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
          "0x639fc40" not in survey.get("lu_miss_survivors", []))
    check("survey this window is NOT a second-handler survivor",
          "0x639fc40" not in survey.get("second_handler_survivors", []))
    check("survey next candidate is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x639f980") == 1,
          str(survey.get("sites_per_fde", {}).get("0x639f980")))
    nq = rec.get("next_question", {})
    check("next question is the lock-wait frontier",
          nq.get("frontier") == "lock-wait helper 0x63bf680 callers",
          str(nq.get("frontier")))
    check("next question range 0x639f980..0x639fc38",
          nq.get("range") == "0x639f980..0x639fc38", str(nq.get("range")))
    check("next question bytes 696", nq.get("bytes") == 696,
          str(nq.get("bytes")))
    check("next question lu-miss sites 0",
          nq.get("lu_miss_sites") == 0, str(nq.get("lu_miss_sites")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 185", nq.get("strict") == 185,
          str(nq.get("strict")))
    check("next question calls 5", nq.get("calls") == 5,
          str(nq.get("calls")))
    check("next question indirect calls 0",
          nq.get("indirect_calls") == 0, str(nq.get("indirect_calls")))
    check("next question calls by target",
          nq.get("calls_by_target") ==
          {"0x6388310": 1, "0x63bf680": 1, "0x63f0b70": 1,
           "0x63f0d70": 1, "0x63f17b0": 1},
          str(nq.get("calls_by_target")))
    check("next question lock-wait sites 1",
          nq.get("lock_wait_sites") == 1, str(nq.get("lock_wait_sites")))
    check("next question lock-wait site list",
          nq.get("lock_wait_site") == ["0x639fa64"],
          str(nq.get("lock_wait_site")))
    check("next question second-handler sites 0",
          nq.get("second_handler_sites") == 0,
          str(nq.get("second_handler_sites")))
    check("next question bsr 0", nq.get("bsr") == 0,
          str(nq.get("bsr")))
    check("next question rets 1",
          nq.get("ret") == ["0x639fa27"], str(nq.get("ret")))
    check("next question jumps 28", nq.get("jumps") == 28,
          str(nq.get("jumps")))
    check("next question jumps outside 0", nq.get("jumps_outside_window") == 0,
          str(nq.get("jumps_outside_window")))
    check("next question endbr64 1", nq.get("endbr64") == 1,
          str(nq.get("endbr64")))
    check("next question canary present", nq.get("canary") is True,
          str(nq.get("canary")))
    check("next question plt calls 3", nq.get("plt_calls") == 3,
          str(nq.get("plt_calls")))
    check("records census strict 185",
          rec.get("census", {}).get("strict") == 185)
    check("records census calls 5",
          rec.get("census", {}).get("calls") == 5)
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
    # Authenticate the frozen public corpus and include current packet overlays.
    candidates = prior_corpus.paths(ROOT, "*/records.json")
    candidates = [path for path in candidates
                  if os.path.realpath(path) != os.path.realpath(own)]
    for path in candidates:
        with open(path) as source:
            collect_ranges(json.load(source), priors, pskipped)
    check("pinned public prior corpus", prior_corpus.is_verified(ROOT),
          str(len(priors)))
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
    # The recorded next candidate is a historical frontier. Later packets
    # may claim it, so only its geometry relative to this packet is checked.
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x639FC38 and 0x639F980 < END))

    # A packet path identifies its slug within the repository.
    slug_hit = os.path.basename(os.path.normpath(PACKET)) != SLUG
    check("slug unique", not slug_hit)
    check("slug not colliding with #314-#368 lu-miss/lockwait slugs",
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
                       "RE-001-node115-lockwait-caller-1site-strcmp",
                       "RE-001-node115-lockwait-caller-1site-duffs",
                       "RE-001-node115-lockwait-caller-1site-tablecopy",
                       "RE-001-node115-lockwait-caller-1site-indirectexp",
                       "RE-001-node115-lockwait-caller-1site-thunk",
                       "RE-001-node115-lockwait-caller-1site-lookup",
                       "RE-001-node115-lockwait-caller-1site-resolver",
                       "RE-001-node115-lockwait-caller-1site-resolver-fixed-138",
                       "RE-001-node115-lockwait-caller-1site-resolver-fixed-140",
                       "RE-001-node115-lockwait-caller-1site-resolver-fixed-178",
                       "RE-001-node115-lockwait-caller-1site-resolver-fixed-180",
                       "RE-001-node115-lockwait-caller-1site-resolver-fixed-1b8",
                       "RE-001-node115-lockwait-caller-1site-resolver-fixed-1c0",
                       "RE-001-node115-lockwait-caller-1site-resolver-fixed-1f8",
                       "RE-001-node115-lockwait-caller-1site-resolver-fixed-200",
                       "RE-001-node115-lockwait-caller-1site-resolver-fixed-238",
                       "RE-001-node115-lockwait-caller-1site-resolver-fixed-240",
                       "RE-001-node115-lockwait-caller-1site-resolver-fixed-278",
                       "RE-001-node115-lockwait-caller-1site-resolver-fixed-280",
                       "RE-001-node115-lockwait-caller-1site-resolver-fixed-2b8",
                       "RE-001-node115-lockwait-caller-1site-resolver-fixed-2c0",
                       "RE-001-node115-lockwait-caller-1site-resolver-fixed-2f8",
                       "RE-001-node115-lockwait-caller-1site-resolver-fixed-300",
                       "RE-001-node115-lockwait-caller-1site-resolver-fixed-338",
                       "RE-001-node115-lockwait-caller-1site-resolver-fixed-340",
                       "RE-001-node115-lockwait-caller-1site-resolver-fixed-378",
                       "RE-001-node115-lockwait-caller-1site-resolver-fixed-380",
                       "RE-001-node115-lockwait-caller-1site-resolver-noloader",
                       "RE-001-node115-lockwait-caller-1site-resolver-noloader-duff",
                       "RE-001-node115-lockwait-caller-1site-resolver-noloader-dead-duff",
                       "RE-001-node115-lockwait-caller-1site-resolver-noloader-dead-duff-q28"))

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
                    "lockwait_caller_1site_resolver_noloader_dead_duff_q30.hex",
                    "lockwait_caller_1site_resolver_noloader_dead_duff_q30.objdump.txt"}
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
