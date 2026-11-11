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

SLUG = "RE-001-node115-lockwait-caller-1site-resolver-fixed-2f8"
START = 0x63A15D0
END = 0x63A1890
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
    (0x63a15d0, 'endbr64', ''),
    (0x63a15d4, 'push', '%r15'),
    (0x63a15d6, 'lea', '0x370bc3(%rip),%r15        # 67121a0 <__register_atfork@plt+0x320610>'),
    (0x63a15dd, 'push', '%r14'),
    (0x63a15df, 'mov', '%rsi,%r14'),
    (0x63a15e2, 'push', '%r13'),
    (0x63a15e4, 'mov', '%r8,%r13'),
    (0x63a15e7, 'push', '%r12'),
    (0x63a15e9, 'mov', '%rcx,%r12'),
    (0x63a15ec, 'push', '%rbp'),
    (0x63a15ed, 'mov', '%rdi,%rbp'),
    (0x63a15f0, 'mov', '%r15,%rdi'),
    (0x63a15f3, 'push', '%rbx'),
    (0x63a15f4, 'mov', '%r9,%rbx'),
    (0x63a15f7, 'sub', '$0x18,%rsp'),
    (0x63a15fb, 'mov', '%fs:0x28,%rax'),
    (0x63a1604, 'mov', '%rax,0x8(%rsp)'),
    (0x63a1609, 'xor', '%eax,%eax'),
    (0x63a160b, 'call', '63f17b0 <pthread_mutex_trylock@plt>'),
    (0x63a1610, 'test', '%eax,%eax'),
    (0x63a1612, 'jne', '63a16c0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659290>'),
    (0x63a1618, 'addq', '$0x1,0x370b78(%rip)        # 6712198 <__register_atfork@plt+0x320608>'),
    (0x63a1620, 'cmp', '0x370b69(%rip),%rbp        # 6712190 <__register_atfork@plt+0x320600>'),
    (0x63a1627, 'je', '63a1638 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659208>'),
    (0x63a1629, 'addq', '$0x1,0x370b57(%rip)        # 6712188 <__register_atfork@plt+0x3205f8>'),
    (0x63a1631, 'mov', '%rbp,0x370b58(%rip)        # 6712190 <__register_atfork@plt+0x320600>'),
    (0x63a1638, 'mov', '$0x1,%ebp'),
    (0x63a163d, 'or', '0x50(%rsp),%rbx'),
    (0x63a1642, 'je', '63a1680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659250>'),
    (0x63a1644, 'movb', '$0x0,0x370b7d(%rip)        # 67121c8 <__register_atfork@plt+0x320638>'),
    (0x63a164b, 'mov', '%r15,%rdi'),
    (0x63a164e, 'call', '63f0b70 <pthread_mutex_unlock@plt>'),
    (0x63a1653, 'mov', '0x8(%rsp),%rax'),
    (0x63a1658, 'sub', '%fs:0x28,%rax'),
    (0x63a1661, 'jne', '63a188b <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65945b>'),
    (0x63a1667, 'add', '$0x18,%rsp'),
    (0x63a166b, 'mov', '%ebp,%eax'),
    (0x63a166d, 'pop', '%rbx'),
    (0x63a166e, 'pop', '%rbp'),
    (0x63a166f, 'pop', '%r12'),
    (0x63a1671, 'pop', '%r13'),
    (0x63a1673, 'pop', '%r14'),
    (0x63a1675, 'pop', '%r15'),
    (0x63a1677, 'ret', ''),
    (0x63a1678, 'nopl', '0x0(%rax,%rax,1)'),
    (0x63a1680, 'mov', '0x10(%r14),%rdi'),
    (0x63a1684, 'call', '6388310 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fee0>'),
    (0x63a1689, 'mov', '0x50(%rax),%rdi'),
    (0x63a168d, 'add', '$0x2f8,%rdi'),
    (0x63a1694, 'call', '63bfb90 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677760>'),
    (0x63a1699, 'mov', '%rax,(%rsp)'),
    (0x63a169d, 'test', '%r12,%r12'),
    (0x63a16a0, 'je', '63a16b5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659285>'),
    (0x63a16a2, 'test', '%r13,%r13'),
    (0x63a16a5, 'je', '63a16b5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659285>'),
    (0x63a16a7, 'mov', '0x0(%r13),%rdx'),
    (0x63a16ab, 'cmp', '$0x8,%rdx'),
    (0x63a16af, 'jne', '63a16d8 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6592a8>'),
    (0x63a16b1, 'mov', '%rax,(%r12)'),
    (0x63a16b5, 'xor', '%ebp,%ebp'),
    (0x63a16b7, 'jmp', '63a1644 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659214>'),
    (0x63a16b9, 'nopl', '0x0(%rax)'),
    (0x63a16c0, 'lea', '-0x40(%r15),%rdi'),
    (0x63a16c4, 'call', '63bf680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677250>'),
    (0x63a16c9, 'movb', '$0x1,0x370af8(%rip)        # 67121c8 <__register_atfork@plt+0x320638>'),
    (0x63a16d0, 'jmp', '63a1618 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6591e8>'),
    (0x63a16d5, 'nopl', '(%rax)'),
    (0x63a16d8, 'mov', '$0x8,%ecx'),
    (0x63a16dd, 'mov', '%rsp,%r9'),
    (0x63a16e0, 'cmp', '%rcx,%rdx'),
    (0x63a16e3, 'cmova', '%rcx,%rdx'),
    (0x63a16e7, 'cmp', '$0x8,%edx'),
    (0x63a16ea, 'jb', '63a1840 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659410>'),
    (0x63a16f0, 'mov', '%edx,%ebp'),
    (0x63a16f2, 'mov', '%rax,(%r12)'),
    (0x63a16f6, 'lea', '0x8(%r12),%rcx'),
    (0x63a16fb, 'mov', '-0x8(%r9,%rbp,1),%r14'),
    (0x63a1700, 'and', '$0xfffffffffffffff8,%rcx'),
    (0x63a1704, 'mov', '%r14,-0x8(%r12,%rbp,1)'),
    (0x63a1709, 'sub', '%rcx,%r12'),
    (0x63a170c, 'sub', '%r12,%r9'),
    (0x63a170f, 'add', '%edx,%r12d'),
    (0x63a1712, 'and', '$0xfffffff8,%r12d'),
    (0x63a1716, 'cmp', '$0x8,%r12d'),
    (0x63a171a, 'jb', '63a1857 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659427>'),
    (0x63a1720, 'mov', '(%r9,%rbx,1),%rax'),
    (0x63a1724, 'lea', '-0x1(%r12),%esi'),
    (0x63a1729, 'mov', '$0x8,%edi'),
    (0x63a172e, 'shr', '$0x3,%esi'),
    (0x63a1731, 'mov', '%rax,(%rcx,%rbx,1)'),
    (0x63a1735, 'and', '$0x7,%esi'),
    (0x63a1738, 'cmp', '%r12d,%edi'),
    (0x63a173b, 'jae', '63a1857 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659427>'),
    (0x63a1741, 'test', '%esi,%esi'),
    (0x63a1743, 'je', '63a17d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6593a0>'),
    (0x63a1749, 'cmp', '$0x1,%esi'),
    (0x63a174c, 'je', '63a17b9 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659389>'),
    (0x63a174e, 'cmp', '$0x2,%esi'),
    (0x63a1751, 'je', '63a17ab <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65937b>'),
    (0x63a1753, 'cmp', '$0x3,%esi'),
    (0x63a1756, 'je', '63a179e <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65936e>'),
    (0x63a1758, 'cmp', '$0x4,%esi'),
    (0x63a175b, 'je', '63a1790 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659360>'),
    (0x63a175d, 'cmp', '$0x5,%esi'),
    (0x63a1760, 'je', '63a1782 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659352>'),
    (0x63a1762, 'cmp', '$0x6,%esi'),
    (0x63a1765, 'je', '63a1774 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659344>'),
    (0x63a1767, 'mov', '(%r9,%rdi,1),%rbx'),
    (0x63a176b, 'mov', '%rbx,(%rcx,%rdi,1)'),
    (0x63a176f, 'mov', '$0x10,%edi'),
    (0x63a1774, 'mov', '%edi,%r10d'),
    (0x63a1777, 'add', '$0x8,%edi'),
    (0x63a177a, 'mov', '(%r9,%r10,1),%r8'),
    (0x63a177e, 'mov', '%r8,(%rcx,%r10,1)'),
    (0x63a1782, 'mov', '%edi,%r11d'),
    (0x63a1785, 'add', '$0x8,%edi'),
    (0x63a1788, 'mov', '(%r9,%r11,1),%rbp'),
    (0x63a178c, 'mov', '%rbp,(%rcx,%r11,1)'),
    (0x63a1790, 'mov', '%edi,%r14d'),
    (0x63a1793, 'add', '$0x8,%edi'),
    (0x63a1796, 'mov', '(%r9,%r14,1),%rsi'),
    (0x63a179a, 'mov', '%rsi,(%rcx,%r14,1)'),
    (0x63a179e, 'mov', '%edi,%eax'),
    (0x63a17a0, 'add', '$0x8,%edi'),
    (0x63a17a3, 'mov', '(%r9,%rax,1),%rbx'),
    (0x63a17a7, 'mov', '%rbx,(%rcx,%rax,1)'),
    (0x63a17ab, 'mov', '%edi,%r10d'),
    (0x63a17ae, 'add', '$0x8,%edi'),
    (0x63a17b1, 'mov', '(%r9,%r10,1),%r8'),
    (0x63a17b5, 'mov', '%r8,(%rcx,%r10,1)'),
    (0x63a17b9, 'mov', '%edi,%r11d'),
    (0x63a17bc, 'add', '$0x8,%edi'),
    (0x63a17bf, 'mov', '(%r9,%r11,1),%rbp'),
    (0x63a17c3, 'mov', '%rbp,(%rcx,%r11,1)'),
    (0x63a17c7, 'cmp', '%r12d,%edi'),
    (0x63a17ca, 'jae', '63a1857 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659427>'),
    (0x63a17d0, 'mov', '%edi,%r14d'),
    (0x63a17d3, 'lea', '0x8(%rdi),%eax'),
    (0x63a17d6, 'lea', '0x10(%rdi),%r10d'),
    (0x63a17da, 'mov', '(%r9,%r14,1),%rsi'),
    (0x63a17de, 'lea', '0x18(%rdi),%r11d'),
    (0x63a17e2, 'mov', '%rsi,(%rcx,%r14,1)'),
    (0x63a17e6, 'mov', '(%r9,%rax,1),%rbx'),
    (0x63a17ea, 'lea', '0x20(%rdi),%r14d'),
    (0x63a17ee, 'mov', '%rbx,(%rcx,%rax,1)'),
    (0x63a17f2, 'mov', '(%r9,%r10,1),%r8'),
    (0x63a17f6, 'lea', '0x28(%rdi),%eax'),
    (0x63a17f9, 'mov', '%r8,(%rcx,%r10,1)'),
    (0x63a17fd, 'mov', '(%r9,%r11,1),%rbp'),
    (0x63a1801, 'lea', '0x30(%rdi),%r10d'),
    (0x63a1805, 'mov', '%rbp,(%rcx,%r11,1)'),
    (0x63a1809, 'mov', '(%r9,%r14,1),%rsi'),
    (0x63a180d, 'lea', '0x38(%rdi),%r11d'),
    (0x63a1811, 'add', '$0x40,%edi'),
    (0x63a1814, 'mov', '%rsi,(%rcx,%r14,1)'),
    (0x63a1818, 'mov', '(%r9,%rax,1),%rbx'),
    (0x63a181c, 'mov', '%rbx,(%rcx,%rax,1)'),
    (0x63a1820, 'mov', '(%r9,%r10,1),%r8'),
    (0x63a1824, 'mov', '%r8,(%rcx,%r10,1)'),
    (0x63a1828, 'mov', '(%r9,%r11,1),%rbp'),
    (0x63a182c, 'mov', '%rbp,(%rcx,%r11,1)'),
    (0x63a1830, 'cmp', '%r12d,%edi'),
    (0x63a1833, 'jb', '63a17d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6593a0>'),
    (0x63a1835, 'jmp', '63a1857 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659427>'),
    (0x63a1837, 'nopw', '0x0(%rax,%rax,1)'),
    (0x63a1840, 'test', '$0x4,%dl'),
    (0x63a1843, 'jne', '63a1865 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659435>'),
    (0x63a1845, 'test', '%edx,%edx'),
    (0x63a1847, 'je', '63a1857 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659427>'),
    (0x63a1849, 'movzbl', '(%rsp),%r8d'),
    (0x63a184e, 'mov', '%r8b,(%r12)'),
    (0x63a1852, 'test', '$0x2,%dl'),
    (0x63a1855, 'jne', '63a187a <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65944a>'),
    (0x63a1857, 'mov', '%rdx,0x0(%r13)'),
    (0x63a185b, 'mov', '$0x16,%ebp'),
    (0x63a1860, 'jmp', '63a1644 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659214>'),
    (0x63a1865, 'mov', '(%rsp),%eax'),
    (0x63a1868, 'mov', '%edx,%esi'),
    (0x63a186a, 'mov', '%eax,(%r12)'),
    (0x63a186e, 'mov', '-0x4(%r9,%rsi,1),%edi'),
    (0x63a1873, 'mov', '%edi,-0x4(%r12,%rsi,1)'),
    (0x63a1878, 'jmp', '63a1857 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659427>'),
    (0x63a187a, 'mov', '%edx,%r10d'),
    (0x63a187d, 'movzwl', '-0x2(%r9,%r10,1),%r11d'),
    (0x63a1883, 'mov', '%r11w,-0x2(%r12,%r10,1)'),
    (0x63a1889, 'jmp', '63a1857 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659427>'),
    (0x63a188b, 'call', '63f0d70 <__stack_chk_fail@plt>')
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
    check("target FDE size 704", END - START == 704)
    prev = fdes[i - 1]
    check("prev FDE 0x63a1310..0x63a15d0",
          prev == (0x63A1310, 0x63A15D0), str(prev))
    check("prev gap 0 (contiguous, no padding)", START - prev[1] == 0)
    check("prev FDE starts endbr64 (0xf3)",
          node[toff(prev[0])] == 0xF3)
    nxt = fdes[i + 1]
    check("next FDE 0x63a1890..0x63a1b50 (#358 window)",
          nxt == (0x63A1890, 0x63A1B50), str(nxt))
    check("next gap 0 (contiguous, no padding)", nxt[0] - END == 0)
    check("next FDE starts endbr64 (0xf3)",
          node[toff(nxt[0])] == 0xF3)
    check("prev FDE end is this FDE start (gap 0)",
          prev[1] == START)
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
    check("resolver FDE 0x6388310..0x6388372",
          fdes[bisect.bisect_left(starts, 0x6388310)] ==
          (0x6388310, 0x6388372))
    check("loader FDE 0x63bfb90..0x63bfb98 (8-byte trivial load helper)",
          fdes[bisect.bisect_left(starts, 0x63BFB90)] ==
          (0x63BFB90, 0x63BFB98))
    check("next-question FDE 0x63a1310..0x63a15d0",
          fdes[bisect.bisect_left(starts, 0x63A1310)] ==
          (0x63A1310, 0x63A15D0))
    hexb = read(os.path.join(PACKET, "lockwait_caller_1site_resolver_fixed_2f8.hex"))
    check("hex exhibit raw bytes 704", len(hexb) == 704, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])
    objdump = read(os.path.join(
        PACKET, "lockwait_caller_1site_resolver_fixed_2f8.objdump.txt")).decode()
    lines = strict_lines(objdump)
    check("strict lines 187", len(lines) == 187, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if mnemonic_of(l) == "call"]
    check("call lines 6", len(calls) == 6, str(len(calls)))
    rets = [l for l in lines if mnemonic_of(l) == "ret"]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x63a1677",
          sorted(addr_of(l) for l in rets) == [0x63A1677],
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
    expect = {0x6388310: 1, 0x63BF680: 1, 0x63BFB90: 1, 0x63F0B70: 1,
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
    check("lock-wait site is 0x63a16c4",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63bf680" in l) == [0x63A16C4])
    check("resolver 0x6365150 called 0 times", tgt.get(0x6365150, 0) == 0,
          str(tgt.get(0x6365150, 0)))
    check("count call 0x634eba0 NOT called (0 times)",
          tgt.get(0x634EBA0, 0) == 0, str(tgt.get(0x634EBA0, 0)))
    check("index resolver 0x6388310 called 1 time at 0x63a1684",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "6388310" in l) == [0x63A1684])
    check("load helper 0x63bfb90 called 1 time at 0x63a1694",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63bfb90" in l) == [0x63A1694])
    check("stack_chk_fail plt call 1 at 0x63a188b",
          tgt.get(0x63F0D70, 0) == 1, str(tgt.get(0x63F0D70, 0)))
    check("trylock plt call 1 at 0x63a160b",
          tgt.get(0x63F17B0, 0) == 1, str(tgt.get(0x63F17B0, 0)))
    check("unlock plt call 1 at 0x63a164e",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63f0b70" in l) == [0x63A164E])
    check("no #321 window call", tgt.get(0x63C9650, 0) == 0,
          str(tgt.get(0x63C9650, 0)))
    plt_calls = [l for l in calls if "@plt" in l]
    check("PLT calls 3 (by @plt suffix, not address range)",
          len(plt_calls) == 3, str(len(plt_calls)))
    check("distinct PLT targets 3",
          len({re.search(r"\tcall\s+([0-9a-f]+)", l).group(1)
               for l in plt_calls}) == 3)
    check("no internal .text call is counted as PLT",
          not any(("6388310" in l or "63bfb90" in l or "63bf680" in l)
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
                  ("#358", 0x63A1890)):
        check("%s window not called" % _w, tgt.get(_a, 0) == 0,
              str(tgt.get(_a, 0)))

    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", len(bsr) == 0, str([hex(addr_of(l)) for l in bsr]))
    check("shr exactly 1 at 0x63a172e",
          sorted(addr_of(l) for l in lines
                 if mnemonic_of(l) == "shr") ==
          [0x63A172E])
    check("shr at 0x63a172e is $0x3 (copy remainder)",
          "$0x3,%esi" in operands_of(by_addr[0x63A172E]))
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
          [0x63A1618, 0x63A1638, 0x63A1644, 0x63A1644, 0x63A1680, 0x63A16B5, 0x63A16B5, 0x63A16C0, 0x63A16D8, 0x63A1774, 0x63A1782, 0x63A1790, 0x63A179E, 0x63A17AB, 0x63A17B9, 0x63A17D0, 0x63A17D0, 0x63A1840, 0x63A1857, 0x63A1857, 0x63A1857, 0x63A1857, 0x63A1857, 0x63A1857, 0x63A1857, 0x63A1865, 0x63A187A, 0x63A188B],
          str(sorted(jump_target(l) for l in jmps)))
    check("endbr64 count 1",
          sum(1 for l in lines if "endbr64" in l) == 1)
    check("entry is endbr64 at 0x63a15d0",
          "endbr64" in by_addr[START])
    check("canary present: 2 fs:0x28 lines",
          sum(1 for l in lines if "%fs:0x28" in l) == 2)
    check("canary load at 0x63a15fb",
          "mov" in by_addr[0x63A15FB] and "%fs:0x28,%rax" in by_addr[0x63A15FB])
    check("canary save to 0x8(%rsp) at 0x63a1604",
          "mov" in by_addr[0x63A1604] and "%rax,0x8(%rsp)" in by_addr[0x63A1604])
    check("canary check sub at 0x63a1658",
          "sub" in by_addr[0x63A1658] and "%fs:0x28,%rax" in by_addr[0x63A1658])
    check("canary fail jne to stack_chk_fail at 0x63a1661",
          "jne" in by_addr[0x63A1661] and "63a188b" in by_addr[0x63A1661])
    check("TLS flag check absent: 0 fs:0x330 lines",
          sum(1 for l in lines if "%fs:0x330" in l) == 0)
    check("no prefetch instructions",
          not any("prefetch" in l for l in lines))
    check("tzcnt 0",
          [l for l in lines if mnemonic_of(l) == "tzcnt"] == [])
    check('entry endbr64 at 0x63a15d0',
          'endbr64' in by_addr[0x63A15D0])
    check('push %r15 at 0x63a15d4',
          'push' in by_addr[0x63A15D4] and '%r15' in by_addr[0x63A15D4])
    check('mutex lea 0x67121a0 at 0x63a15d6',
          'lea' in by_addr[0x63A15D6] and '0x370bc3(%rip),%r15' in by_addr[0x63A15D6])
    check('entry rsi save mov %rsi,%r14 at 0x63a15df',
          'mov' in by_addr[0x63A15DF] and '%rsi,%r14' in by_addr[0x63A15DF])
    check('entry r8 save mov %r8,%r13 at 0x63a15e4',
          'mov' in by_addr[0x63A15E4] and '%r8,%r13' in by_addr[0x63A15E4])
    check('entry rcx save mov %rcx,%r12 at 0x63a15e9',
          'mov' in by_addr[0x63A15E9] and '%rcx,%r12' in by_addr[0x63A15E9])
    check('entry rdi save mov %rdi,%rbp at 0x63a15ed',
          'mov' in by_addr[0x63A15ED] and '%rdi,%rbp' in by_addr[0x63A15ED])
    check('entry r9 save mov %r9,%rbx at 0x63a15f4',
          'mov' in by_addr[0x63A15F4] and '%r9,%rbx' in by_addr[0x63A15F4])
    check('frame sub $0x18,%rsp at 0x63a15f7',
          'sub' in by_addr[0x63A15F7] and '$0x18,%rsp' in by_addr[0x63A15F7])
    check('canary load mov %fs:0x28,%rax at 0x63a15fb',
          'mov' in by_addr[0x63A15FB] and '%fs:0x28,%rax' in by_addr[0x63A15FB])
    check('canary save mov %rax,0x8(%rsp) at 0x63a1604',
          'mov' in by_addr[0x63A1604] and '%rax,0x8(%rsp)' in by_addr[0x63A1604])
    check('xor %eax,%eax before trylock at 0x63a1609',
          'xor' in by_addr[0x63A1609] and '%eax,%eax' in by_addr[0x63A1609])
    check('trylock call at 0x63a160b',
          'call' in by_addr[0x63A160B] and '63f17b0 <pthread_mutex_trylock@plt>' in by_addr[0x63A160B])
    check('trylock test %eax,%eax at 0x63a1610',
          'test' in by_addr[0x63A1610] and '%eax,%eax' in by_addr[0x63A1610])
    check('trylock-fail jne lock-wait setup at 0x63a1612',
          'jne' in by_addr[0x63A1612] and '63a16c0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659290>' in by_addr[0x63A1612])
    check('acq-count addq $0x1,0x370b78(%rip) at 0x63a1618',
          'addq' in by_addr[0x63A1618] and '$0x1,0x370b78(%rip)' in by_addr[0x63A1618])
    check('owner cmp 0x6712190,%rbp at 0x63a1620',
          'cmp' in by_addr[0x63A1620] and '0x370b69(%rip),%rbp' in by_addr[0x63A1620])
    check('owner-unchanged je exit-1 mov at 0x63a1627',
          'je' in by_addr[0x63A1627] and '63a1638 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659208>' in by_addr[0x63A1627])
    check('counter addq $0x1,0x370b57(%rip) at 0x63a1629',
          'addq' in by_addr[0x63A1629] and '$0x1,0x370b57(%rip)' in by_addr[0x63A1629])
    check('owner store mov %rbp,0x370b58(%rip) at 0x63a1631',
          'mov' in by_addr[0x63A1631] and '%rbp,0x370b58(%rip)' in by_addr[0x63A1631])
    check('exit-1 mov $0x1,%ebp at 0x63a1638',
          'mov' in by_addr[0x63A1638] and '$0x1,%ebp' in by_addr[0x63A1638])
    check('caller-cond or 0x50(%rsp),%rbx at 0x63a163d',
          'or' in by_addr[0x63A163D] and '0x50(%rsp),%rbx' in by_addr[0x63A163D])
    check('caller-cond je lookup path at 0x63a1642',
          'je' in by_addr[0x63A1642] and '63a1680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659250>' in by_addr[0x63A1642])
    check('waited-flag clear movb $0x0,0x370b7d(%rip) at 0x63a1644',
          'movb' in by_addr[0x63A1644] and '$0x0,0x370b7d(%rip)' in by_addr[0x63A1644])
    check('unlock rdi mov %r15,%rdi at 0x63a164b',
          'mov' in by_addr[0x63A164B] and '%r15,%rdi' in by_addr[0x63A164B])
    check('unlock call at 0x63a164e',
          'call' in by_addr[0x63A164E] and '63f0b70 <pthread_mutex_unlock@plt>' in by_addr[0x63A164E])
    check('canary reload mov 0x8(%rsp),%rax at 0x63a1653',
          'mov' in by_addr[0x63A1653] and '0x8(%rsp),%rax' in by_addr[0x63A1653])
    check('canary check sub %fs:0x28,%rax at 0x63a1658',
          'sub' in by_addr[0x63A1658] and '%fs:0x28,%rax' in by_addr[0x63A1658])
    check('canary fail jne stack_chk_fail at 0x63a1661',
          'jne' in by_addr[0x63A1661] and '63a188b <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65945b>' in by_addr[0x63A1661])
    check('rsp restore add $0x18,%rsp at 0x63a1667',
          'add' in by_addr[0x63A1667] and '$0x18,%rsp' in by_addr[0x63A1667])
    check('exit mov %ebp,%eax at 0x63a166b',
          'mov' in by_addr[0x63A166B] and '%ebp,%eax' in by_addr[0x63A166B])
    check('ret at 0x63a1677',
          'ret' in by_addr[0x63A1677])
    check('resolver arg mov 0x10(%r14),%rdi at 0x63a1680',
          'mov' in by_addr[0x63A1680] and '0x10(%r14),%rdi' in by_addr[0x63A1680])
    check('resolver call 0x6388310 at 0x63a1684',
          'call' in by_addr[0x63A1684] and '6388310 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fee0>' in by_addr[0x63A1684])
    check('table base mov 0x50(%rax),%rdi at 0x63a1689',
          'mov' in by_addr[0x63A1689] and '0x50(%rax),%rdi' in by_addr[0x63A1689])
    check('inline adjust add $0x2f8,%rdi at 0x63a168d',
          'add' in by_addr[0x63A168D] and '$0x2f8,%rdi' in by_addr[0x63A168D])
    check('loader call 0x63bfb90 at 0x63a1694',
          'call' in by_addr[0x63A1694] and '63bfb90 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677760>' in by_addr[0x63A1694])
    check('resolved value store mov %rax,(%rsp) at 0x63a1699',
          'mov' in by_addr[0x63A1699] and '%rax,(%rsp)' in by_addr[0x63A1699])
    check('rcx==0 test %r12,%r12 at 0x63a169d',
          'test' in by_addr[0x63A169D] and '%r12,%r12' in by_addr[0x63A169D])
    check('rcx==0 je exit-0 at 0x63a16a0',
          'je' in by_addr[0x63A16A0] and '63a16b5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659285>' in by_addr[0x63A16A0])
    check('r8==0 test %r13,%r13 at 0x63a16a2',
          'test' in by_addr[0x63A16A2] and '%r13,%r13' in by_addr[0x63A16A2])
    check('r8==0 je exit-0 at 0x63a16a5',
          'je' in by_addr[0x63A16A5] and '63a16b5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659285>' in by_addr[0x63A16A5])
    check('len load mov 0x0(%r13),%rdx at 0x63a16a7',
          'mov' in by_addr[0x63A16A7] and '0x0(%r13),%rdx' in by_addr[0x63A16A7])
    check('len cmp $0x8,%rdx at 0x63a16ab',
          'cmp' in by_addr[0x63A16AB] and '$0x8,%rdx' in by_addr[0x63A16AB])
    check('len!=8 jne copy dispatch at 0x63a16af',
          'jne' in by_addr[0x63A16AF] and '63a16d8 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6592a8>' in by_addr[0x63A16AF])
    check('len==8 store mov %rax,(%r12) at 0x63a16b1',
          'mov' in by_addr[0x63A16B1] and '%rax,(%r12)' in by_addr[0x63A16B1])
    check('exit-0 xor %ebp,%ebp at 0x63a16b5',
          'xor' in by_addr[0x63A16B5] and '%ebp,%ebp' in by_addr[0x63A16B5])
    check('exit-0 jmp flag-clear at 0x63a16b7',
          'jmp' in by_addr[0x63A16B7] and '63a1644 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659214>' in by_addr[0x63A16B7])
    check('lock-wait setup lea -0x40(%r15),%rdi at 0x63a16c0',
          'lea' in by_addr[0x63A16C0] and '-0x40(%r15),%rdi' in by_addr[0x63A16C0])
    check('lock-wait call at 0x63a16c4',
          'call' in by_addr[0x63A16C4] and '63bf680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677250>' in by_addr[0x63A16C4])
    check('waited-flag set movb $0x1,0x370af8(%rip) at 0x63a16c9',
          'movb' in by_addr[0x63A16C9] and '$0x1,0x370af8(%rip)' in by_addr[0x63A16C9])
    check('lock-wait rejoin jmp trylock-success (NO retry) at 0x63a16d0',
          'jmp' in by_addr[0x63A16D0] and '63a1618 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6591e8>' in by_addr[0x63A16D0])
    check('copy mov $0x8,%ecx at 0x63a16d8',
          'mov' in by_addr[0x63A16D8] and '$0x8,%ecx' in by_addr[0x63A16D8])
    check('copy src mov %rsp,%r9 at 0x63a16dd',
          'mov' in by_addr[0x63A16DD] and '%rsp,%r9' in by_addr[0x63A16DD])
    check('copy cmp %rcx,%rdx at 0x63a16e0',
          'cmp' in by_addr[0x63A16E0] and '%rcx,%rdx' in by_addr[0x63A16E0])
    check('copy min cmova %rcx,%rdx at 0x63a16e3',
          'cmova' in by_addr[0x63A16E3] and '%rcx,%rdx' in by_addr[0x63A16E3])
    check('copy cmp $0x8,%edx at 0x63a16e7',
          'cmp' in by_addr[0x63A16E7] and '$0x8,%edx' in by_addr[0x63A16E7])
    check('copy len<8 jb remainder at 0x63a16ea',
          'jb' in by_addr[0x63A16EA] and '63a1840 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659410>' in by_addr[0x63A16EA])
    check('copy mov %edx,%ebp at 0x63a16f0',
          'mov' in by_addr[0x63A16F0] and '%edx,%ebp' in by_addr[0x63A16F0])
    check('copy first qword store mov %rax,(%r12) at 0x63a16f2',
          'mov' in by_addr[0x63A16F2] and '%rax,(%r12)' in by_addr[0x63A16F2])
    check('copy dest lea 0x8(%r12),%rcx at 0x63a16f6',
          'lea' in by_addr[0x63A16F6] and '0x8(%r12),%rcx' in by_addr[0x63A16F6])
    check('copy last qword load mov -0x8(%r9,%rbp,1),%r14 at 0x63a16fb',
          'mov' in by_addr[0x63A16FB] and '-0x8(%r9,%rbp,1),%r14' in by_addr[0x63A16FB])
    check('copy align and $0xfffffffffffffff8,%rcx at 0x63a1700',
          'and' in by_addr[0x63A1700] and '$0xfffffffffffffff8,%rcx' in by_addr[0x63A1700])
    check('copy last qword store mov %r14,-0x8(%r12,%rbp,1) at 0x63a1704',
          'mov' in by_addr[0x63A1704] and '%r14,-0x8(%r12,%rbp,1)' in by_addr[0x63A1704])
    check('copy sub %rcx,%r12 at 0x63a1709',
          'sub' in by_addr[0x63A1709] and '%rcx,%r12' in by_addr[0x63A1709])
    check('copy sub %r12,%r9 at 0x63a170c',
          'sub' in by_addr[0x63A170C] and '%r12,%r9' in by_addr[0x63A170C])
    check('copy add %edx,%r12d at 0x63a170f',
          'add' in by_addr[0x63A170F] and '%edx,%r12d' in by_addr[0x63A170F])
    check('copy and $0xfffffff8,%r12d at 0x63a1712',
          'and' in by_addr[0x63A1712] and '$0xfffffff8,%r12d' in by_addr[0x63A1712])
    check('loop-guard cmp $0x8,%r12d at 0x63a1716',
          'cmp' in by_addr[0x63A1716] and '$0x8,%r12d' in by_addr[0x63A1716])
    check('loop-guard jb writeback at 0x63a171a',
          'jb' in by_addr[0x63A171A] and '63a1857 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659427>' in by_addr[0x63A171A])
    check('duffs loop head mov (%r9,%rbx,1),%rax at 0x63a1720',
          'mov' in by_addr[0x63A1720] and '(%r9,%rbx,1),%rax' in by_addr[0x63A1720])
    check('dispatch lea -0x1(%r12),%esi at 0x63a1724',
          'lea' in by_addr[0x63A1724] and '-0x1(%r12),%esi' in by_addr[0x63A1724])
    check('dispatch mov $0x8,%edi at 0x63a1729',
          'mov' in by_addr[0x63A1729] and '$0x8,%edi' in by_addr[0x63A1729])
    check('dispatch shr $0x3,%esi at 0x63a172e',
          'shr' in by_addr[0x63A172E] and '$0x3,%esi' in by_addr[0x63A172E])
    check('duffs first store mov %rax,(%rcx,%rbx,1) at 0x63a1731',
          'mov' in by_addr[0x63A1731] and '%rax,(%rcx,%rbx,1)' in by_addr[0x63A1731])
    check('dispatch and $0x7,%esi at 0x63a1735',
          'and' in by_addr[0x63A1735] and '$0x7,%esi' in by_addr[0x63A1735])
    check('dispatch cmp %r12d,%edi at 0x63a1738',
          'cmp' in by_addr[0x63A1738] and '%r12d,%edi' in by_addr[0x63A1738])
    check('dispatch jae writeback at 0x63a173b',
          'jae' in by_addr[0x63A173B] and '63a1857 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659427>' in by_addr[0x63A173B])
    check('dispatch test %esi,%esi at 0x63a1741',
          'test' in by_addr[0x63A1741] and '%esi,%esi' in by_addr[0x63A1741])
    check('dispatch je D-block (esi==0) at 0x63a1743',
          'je' in by_addr[0x63A1743] and '63a17d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6593a0>' in by_addr[0x63A1743])
    check('dispatch cmp $0x1,%esi at 0x63a1749',
          'cmp' in by_addr[0x63A1749] and '$0x1,%esi' in by_addr[0x63A1749])
    check('dispatch je 0x63a17b9 (esi==1) at 0x63a174c',
          'je' in by_addr[0x63A174C] and '63a17b9 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659389>' in by_addr[0x63A174C])
    check('dispatch cmp $0x2,%esi at 0x63a174e',
          'cmp' in by_addr[0x63A174E] and '$0x2,%esi' in by_addr[0x63A174E])
    check('dispatch je 0x63a17ab (esi==2) at 0x63a1751',
          'je' in by_addr[0x63A1751] and '63a17ab <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65937b>' in by_addr[0x63A1751])
    check('dispatch cmp $0x3,%esi at 0x63a1753',
          'cmp' in by_addr[0x63A1753] and '$0x3,%esi' in by_addr[0x63A1753])
    check('dispatch je 0x63a179e (esi==3) at 0x63a1756',
          'je' in by_addr[0x63A1756] and '63a179e <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65936e>' in by_addr[0x63A1756])
    check('dispatch cmp $0x4,%esi at 0x63a1758',
          'cmp' in by_addr[0x63A1758] and '$0x4,%esi' in by_addr[0x63A1758])
    check('dispatch je 0x63a1790 (esi==4) at 0x63a175b',
          'je' in by_addr[0x63A175B] and '63a1790 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659360>' in by_addr[0x63A175B])
    check('dispatch cmp $0x5,%esi at 0x63a175d',
          'cmp' in by_addr[0x63A175D] and '$0x5,%esi' in by_addr[0x63A175D])
    check('dispatch je 0x63a1782 (esi==5) at 0x63a1760',
          'je' in by_addr[0x63A1760] and '63a1782 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659352>' in by_addr[0x63A1760])
    check('dispatch cmp $0x6,%esi at 0x63a1762',
          'cmp' in by_addr[0x63A1762] and '$0x6,%esi' in by_addr[0x63A1762])
    check('dispatch je 0x63a1774 (esi==6) at 0x63a1765',
          'je' in by_addr[0x63A1765] and '63a1774 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659344>' in by_addr[0x63A1765])
    check('D-block mov %edi,%r14d at 0x63a17d0',
          'mov' in by_addr[0x63A17D0] and '%edi,%r14d' in by_addr[0x63A17D0])
    check('D-block add $0x40,%edi at 0x63a1811',
          'add' in by_addr[0x63A1811] and '$0x40,%edi' in by_addr[0x63A1811])
    check('D-block cmp %r12d,%edi at 0x63a1830',
          'cmp' in by_addr[0x63A1830] and '%r12d,%edi' in by_addr[0x63A1830])
    check('D-block jb D-block at 0x63a1833',
          'jb' in by_addr[0x63A1833] and '63a17d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6593a0>' in by_addr[0x63A1833])
    check('D-block exit jmp writeback at 0x63a1835',
          'jmp' in by_addr[0x63A1835] and '63a1857 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659427>' in by_addr[0x63A1835])
    check('remainder test $0x4,%dl at 0x63a1840',
          'test' in by_addr[0x63A1840] and '$0x4,%dl' in by_addr[0x63A1840])
    check('remainder 4-byte jne 0x63a1865 at 0x63a1843',
          'jne' in by_addr[0x63A1843] and '63a1865 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659435>' in by_addr[0x63A1843])
    check('remainder test %edx,%edx at 0x63a1845',
          'test' in by_addr[0x63A1845] and '%edx,%edx' in by_addr[0x63A1845])
    check('remainder len==0 je writeback at 0x63a1847',
          'je' in by_addr[0x63A1847] and '63a1857 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659427>' in by_addr[0x63A1847])
    check('remainder 1-byte movzbl (%rsp),%r8d at 0x63a1849',
          'movzbl' in by_addr[0x63A1849] and '(%rsp),%r8d' in by_addr[0x63A1849])
    check('remainder 1-byte store mov %r8b,(%r12) at 0x63a184e',
          'mov' in by_addr[0x63A184E] and '%r8b,(%r12)' in by_addr[0x63A184E])
    check('remainder test $0x2,%dl at 0x63a1852',
          'test' in by_addr[0x63A1852] and '$0x2,%dl' in by_addr[0x63A1852])
    check('remainder 2-byte jne 0x63a187a at 0x63a1855',
          'jne' in by_addr[0x63A1855] and '63a187a <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65944a>' in by_addr[0x63A1855])
    check('writeback mov %rdx,0x0(%r13) at 0x63a1857',
          'mov' in by_addr[0x63A1857] and '%rdx,0x0(%r13)' in by_addr[0x63A1857])
    check('exit-22 mov $0x16,%ebp at 0x63a185b',
          'mov' in by_addr[0x63A185B] and '$0x16,%ebp' in by_addr[0x63A185B])
    check('exit-22 jmp flag-clear at 0x63a1860',
          'jmp' in by_addr[0x63A1860] and '63a1644 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659214>' in by_addr[0x63A1860])
    check('4-byte copy mov (%rsp),%eax at 0x63a1865',
          'mov' in by_addr[0x63A1865] and '(%rsp),%eax' in by_addr[0x63A1865])
    check('4-byte copy store mov %eax,(%r12) at 0x63a186a',
          'mov' in by_addr[0x63A186A] and '%eax,(%r12)' in by_addr[0x63A186A])
    check('4-byte copy tail mov -0x4(%r9,%rsi,1),%edi at 0x63a186e',
          'mov' in by_addr[0x63A186E] and '-0x4(%r9,%rsi,1),%edi' in by_addr[0x63A186E])
    check('4-byte copy tail store mov %edi,-0x4(%r12,%rsi,1) at 0x63a1873',
          'mov' in by_addr[0x63A1873] and '%edi,-0x4(%r12,%rsi,1)' in by_addr[0x63A1873])
    check('4-byte copy jmp writeback at 0x63a1878',
          'jmp' in by_addr[0x63A1878] and '63a1857 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659427>' in by_addr[0x63A1878])
    check('2-byte copy mov %edx,%r10d at 0x63a187a',
          'mov' in by_addr[0x63A187A] and '%edx,%r10d' in by_addr[0x63A187A])
    check('2-byte copy movzwl -0x2(%r9,%r10,1),%r11d at 0x63a187d',
          'movzwl' in by_addr[0x63A187D] and '-0x2(%r9,%r10,1),%r11d' in by_addr[0x63A187D])
    check('2-byte copy store mov %r11w,-0x2(%r12,%r10,1) at 0x63a1883',
          'mov' in by_addr[0x63A1883] and '%r11w,-0x2(%r12,%r10,1)' in by_addr[0x63A1883])
    check('2-byte copy jmp writeback at 0x63a1889',
          'jmp' in by_addr[0x63A1889] and '63a1857 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x659427>' in by_addr[0x63A1889])
    check('stack_chk_fail call at 0x63a188b',
          'call' in by_addr[0x63A188B] and '63f0d70 <__stack_chk_fail@plt>' in by_addr[0x63A188B])
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

    check("entry reaches lock-wait site 0x63a16c4", reaches(START, 0x63A16C4))
    check("entry reaches ret 0x63a1677", reaches(START, 0x63A1677))
    check("entry reaches trylock 0x63a160b", reaches(START, 0x63A160B))
    check("entry reaches epilogue canary 0x63a1653", reaches(START, 0x63A1653))
    check("entry reaches resolver call 0x63a1684", reaches(START, 0x63A1684))
    check("entry reaches loader call 0x63a1694", reaches(START, 0x63A1694))
    check("entry reaches exit-1 block 0x63a1638", reaches(START, 0x63A1638))
    check("entry reaches exit-0 block 0x63a16b5", reaches(START, 0x63A16B5))
    check("entry reaches exit-22 block 0x63a185b", reaches(START, 0x63A185B))
    check("entry reaches copy dispatch 0x63a16d8", reaches(START, 0x63A16D8))
    check("entry reaches remainder entry 0x63a1840", reaches(START, 0x63A1840))
    check("entry reaches writeback 0x63a1857", reaches(START, 0x63A1857))
    check("entry reaches Duff's loop head 0x63a1720 in the CFG only "
          "(guard analysis below shows it is never entered)",
          reaches(START, 0x63A1720))
    check("entry reaches D-block 0x63a17d0 in the CFG only",
          reaches(START, 0x63A17D0))
    check("preds of lock-wait site 0x63a16c4 is the setup lea only",
          preds[0x63A16C4] == {0x63A16C0}, str(preds[0x63A16C4]))
    check("preds of lock-wait setup 0x63a16c0 are trylock fail and the "
          "padding nopl",
          preds[0x63A16C0] == {0x63A1612, 0x63A16B9}, str(preds[0x63A16C0]))
    check("preds of trylock 0x63a160b is the xor only",
          preds[0x63A160B] == {0x63A1609}, str(preds[0x63A160B]))
    check("preds of rejoin 0x63a1618 are trylock success and the "
          "lock-wait jmp",
          preds[0x63A1618] == {0x63A1612, 0x63A16D0}, str(preds[0x63A1618]))
    check("preds of ret 0x63a1677 is the final pop",
          preds[0x63A1677] == {0x63A1675}, str(preds[0x63A1677]))
    check("preds of epilogue canary 0x63a1653 is the unlock only",
          preds[0x63A1653] == {0x63A164E}, str(preds[0x63A1653]))
    check("preds of flag-clear block 0x63a1644 are caller-cond, exit-0 "
          "and exit-22",
          preds[0x63A1644] == {0x63A1642, 0x63A16B7, 0x63A1860},
          str(preds[0x63A1644]))
    check("preds of exit-0 block 0x63a16b5 are rcx==0, r8==0 and the "
          "len==8 store",
          preds[0x63A16B5] == {0x63A16A0, 0x63A16A5, 0x63A16B1},
          str(preds[0x63A16B5]))
    check("preds of exit-22 block 0x63a185b is the writeback only",
          preds[0x63A185B] == {0x63A1857}, str(preds[0x63A185B]))
    check("preds of writeback 0x63a1857 are the 8 copy exits",
          preds[0x63A1857] == {0x63A171A, 0x63A173B, 0x63A17CA, 0x63A1835,
                               0x63A1847, 0x63A1855, 0x63A1878, 0x63A1889},
          str(preds[0x63A1857]))
    check("preds of Duff's loop head 0x63a1720 is the loop guard only",
          preds[0x63A1720] == {0x63A171A}, str(preds[0x63A1720]))
    check("preds of D-block 0x63a17d0 are dispatch esi==0, the jae "
          "fall-through and the loop-back",
          preds[0x63A17D0] == {0x63A1743, 0x63A17CA, 0x63A1833},
          str(preds[0x63A17D0]))
    check("preds of copy dispatch 0x63a16d8 are len!=8 jne and the "
          "padding nopl",
          preds[0x63A16D8] == {0x63A16AF, 0x63A16D5}, str(preds[0x63A16D8]))
    check("preds of resolver call 0x63a1684 is the lookup path only",
          preds[0x63A1684] == {0x63A1680}, str(preds[0x63A1684]))
    check("preds of lookup path 0x63a1680 are caller-cond je and the "
          "padding nopl",
          preds[0x63A1680] == {0x63A1642, 0x63A1678}, str(preds[0x63A1680]))
    # The Duff's-device loop is present but dead: the guard computes
    # r12d = ((dest - ((dest+8) & ~7)) + 8) & ~7, which is 0 for every
    # destination alignment, so the jb at 0x63a171a is always taken.
    # Emulate the prologue arithmetic for all 8 alignments.
    def _guard_r12d(dest_mod_8):
        r12 = dest_mod_8 - 8
        return ((r12 + 8) & 0xFFFFFFFF) & ~7
    check("Duff's loop guard r12d is 0 for every dest alignment "
          "(loop dead)",
          all(_guard_r12d(k) == 0 for k in range(8)),
          str([_guard_r12d(k) for k in range(8)]))
    check("loop-guard jb at 0x63a171a targets the writeback",
          "jb" in by_addr[0x63A171A] and "63a1857" in by_addr[0x63A171A])
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
    SITE = 0x63A16C4
    RET = 0x63A1677
    CALL_TRYLOCK = {("CALL", 0x63A160B)}
    check("site rdi only def is lea -0x40(%r15),%rdi 0x63a16c0",
          rdi_in[SITE] == {0x63A16C0}, str(rdi_in[SITE]))
    check("site rsi is clobbered by the trylock only (no post-trylock "
          "restore in this window, like #339/#340/#341/#342/#343/#344/#345/#346/#347/#348/#349/#350/#351/#352/#353/#354/#355/#356/#357/#358, unlike #338)",
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
          rbx_in[SITE] == {0x63A15F4}, str(rbx_in[SITE]))
    check("site rbp def is the entry rdi save",
          rbp_in[SITE] == {0x63A15ED}, str(rbp_in[SITE]))
    check("site r12 def is the entry rcx save",
          r12_in[SITE] == {0x63A15E9}, str(r12_in[SITE]))
    check("site r13 def is the entry r8 save",
          r13_in[SITE] == {0x63A15E4}, str(r13_in[SITE]))
    check("site r14 def is the entry rsi save",
          r14_in[SITE] == {0x63A15DF}, str(r14_in[SITE]))
    check("site r15 def is the mutex lea",
          r15_in[SITE] == {0x63A15D6}, str(r15_in[SITE]))
    check("rax at ret is the exit-value mov 0x63a166b",
          rax_in[RET] == {0x63A166B}, str(rax_in[RET]))
    check("ebp reaching defs at the flag-clear are the 3 exit values",
          rbp_in[0x63A1644] == {0x63A1638, 0x63A16B5, 0x63A185B},
          str(rbp_in[0x63A1644]))

    check("records lock-wait sites match census",
          [s.get("site") for s in rec.get("lock_wait_sites", [])] ==
          ["0x63a16c4"])
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
    check("records window bytes 704",
          rec.get("window", {}).get("bytes") == 704)
    check("records window range",
          rec.get("window", {}).get("range") == "0x63a15d0..0x63a1890")
    check("records return value exits 0/1/22",
          rec.get("return_value", {}).get("rax") ==
          "ebp: 0/1/22 (mov %ebp,%eax at 0x63a166b)")
    check("records entry gate absent (no gate byte in this window)",
          rec.get("entry_gate") is None)
    check("records count call absent (0x634eba0 NOT called here)",
          rec.get("count_call") is None)
    check("records resolver target 0x6388310",
          rec.get("resolver", {}).get("target") == "0x6388310")
    check("records resolver site 0x63a1684",
          rec.get("resolver", {}).get("site") == "0x63a1684")
    check("records loader target 0x63bfb90",
          rec.get("loader", {}).get("target") == "0x63bfb90")
    check("records loader site 0x63a1694",
          rec.get("loader", {}).get("site") == "0x63a1694")
    check("records inline adjust 0x2f8 at 0x63a168d",
          rec.get("inline_adjust", {}).get("amount") == "0x2f8"
          and rec.get("inline_adjust", {}).get("site") == "0x63a168d")
    check("records selector index is fixed +0x2f8 (no index register)",
          rec.get("selector", {}).get("index") ==
          "fixed +0x2f8 (no index register)")
    check("records copy dispatch is (len-1)>>3 & 7",
          rec.get("copy_loop", {}).get("dispatch") == "(len-1)>>3 & 7")
    check("records copy is 8-at-a-time",
          rec.get("copy_loop", {}).get("width") == 8)
    check("records copy loop is marked dead",
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
    for _t in (0x6388310, 0x63BF680, 0x63BFB90):
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
    check("next candidate raw lu-miss 0", counts.get(0x63A1310, 0) == 0,
          str(counts.get(0x63A1310, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x63A1310, 0) == 0,
          str(bti_counts.get(0x63A1310, 0)))
    check("next candidate raw second-handler 0",
          sh_counts.get(0x63A1310, 0) == 0, str(sh_counts.get(0x63A1310, 0)))
    check("next candidate raw lock-wait 1",
          lw_counts.get(0x63A1310, 0) == 1,
          str(lw_counts.get(0x63A1310, 0)))
    # lock-wait frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 344", len(survey.get("survivors", [])) == 344,
          str(len(survey.get("survivors", []))))
    check("survey this window is a lock-wait survivor",
          "0x63a15d0" in survey.get("survivors", []))
    check("survey this window is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x63a15d0") == 1,
          str(survey.get("sites_per_fde", {}).get("0x63a15d0")))
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
          "0x63a15d0" not in survey.get("lu_miss_survivors", []))
    check("survey this window is NOT a second-handler survivor",
          "0x63a15d0" not in survey.get("second_handler_survivors", []))
    check("survey next candidate is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x63a1310") == 1,
          str(survey.get("sites_per_fde", {}).get("0x63a1310")))
    nq = rec.get("next_question", {})
    check("next question is the lock-wait frontier",
          nq.get("frontier") == "lock-wait helper 0x63bf680 callers",
          str(nq.get("frontier")))
    check("next question range 0x63a1310..0x63a15d0",
          nq.get("range") == "0x63a1310..0x63a15d0", str(nq.get("range")))
    check("next question bytes 704", nq.get("bytes") == 704,
          str(nq.get("bytes")))
    check("next question lu-miss sites 0",
          nq.get("lu_miss_sites") == 0, str(nq.get("lu_miss_sites")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 187", nq.get("strict") == 187,
          str(nq.get("strict")))
    check("next question calls 6", nq.get("calls") == 6,
          str(nq.get("calls")))
    check("next question indirect calls 0",
          nq.get("indirect_calls") == 0, str(nq.get("indirect_calls")))
    check("next question calls by target",
          nq.get("calls_by_target") ==
          {"0x6388310": 1, "0x63bf680": 1, "0x63bfb90": 1,
           "0x63f0b70": 1, "0x63f0d70": 1, "0x63f17b0": 1},
          str(nq.get("calls_by_target")))
    check("next question lock-wait sites 1",
          nq.get("lock_wait_sites") == 1, str(nq.get("lock_wait_sites")))
    check("next question lock-wait site list",
          nq.get("lock_wait_site") == ["0x63a1404"],
          str(nq.get("lock_wait_site")))
    check("next question second-handler sites 0",
          nq.get("second_handler_sites") == 0,
          str(nq.get("second_handler_sites")))
    check("next question bsr 0", nq.get("bsr") == 0,
          str(nq.get("bsr")))
    check("next question rets 1",
          nq.get("ret") == ["0x63a13b7"], str(nq.get("ret")))
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
    check("records census strict 187",
          rec.get("census", {}).get("strict") == 187)
    check("records census calls 6",
          rec.get("census", {}).get("calls") == 6)
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
    # Reuse the authenticated frozen corpus and current repository overlays.
    candidates = prior_corpus.paths(ROOT)
    candidates = [path for path in candidates
                  if os.path.realpath(path) != os.path.realpath(own)]
    for path in candidates:
        with open(path) as source:
            collect_ranges(json.load(source), priors, pskipped)
    check("pinned public prior corpus", prior_corpus.is_verified(ROOT))
    check("prior claimed ranges present", bool(priors))
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
    # The recorded next candidate is a historical research lead. Other
    # packets can claim it later without invalidating this packet's evidence.
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x63A15D0 and 0x63A1310 < END))

    # A packet path identifies its slug within the repository.
    slug_hit = os.path.basename(os.path.normpath(PACKET)) != SLUG
    check("slug unique", not slug_hit)
    check("slug not colliding with #314-#358 lu-miss/lockwait slugs",
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
                       "RE-001-node115-lockwait-caller-1site-resolver-fixed-2c0"))

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
                    "lockwait_caller_1site_resolver_fixed_2f8.hex",
                    "lockwait_caller_1site_resolver_fixed_2f8.objdump.txt"}
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
