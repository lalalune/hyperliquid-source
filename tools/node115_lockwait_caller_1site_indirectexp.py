import bisect
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

SLUG = "RE-001-node115-lockwait-caller-1site-indirectexp"
START = 0x63ce510
END = 0x63ce8b8
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
    (0x63ce510, 'endbr64', ''),    (0x63ce514, 'push', '%r15'),    (0x63ce516, 'push', '%r14'),
    (0x63ce518, 'mov', '%r8d,%r14d'),    (0x63ce51b, 'push', '%r13'),    (0x63ce51d, 'mov', '%rdx,%r13'),
    (0x63ce520, 'push', '%r12'),    (0x63ce522, 'mov', '%rdi,%r12'),    (0x63ce525, 'push', '%rbp'),
    (0x63ce526, 'mov', '%rsi,%rbp'),    (0x63ce529, 'mov', '%rcx,%rsi'),    (0x63ce52c, 'push', '%rbx'),
    (0x63ce52d, 'sub', '$0x98,%rsp'),    (0x63ce534, 'mov', '%fs:0x28,%rax'),    (0x63ce53d, 'mov', '%rax,0x88(%rsp)'),
    (0x63ce545, 'xor', '%eax,%eax'),    (0x63ce547, 'lea', '0x40(%rsp),%r15'),    (0x63ce54c, 'lea', '0x18(%rsp),%rbx'),
    (0x63ce551, 'mov', '%rbx,%r8'),    (0x63ce554, 'lea', '0x10(%rsp),%rcx'),    (0x63ce559, 'mov', '%r15,%rdx'),
    (0x63ce55c, 'call', '63c8490 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x680060>'),    (0x63ce561, 'mov', '$0x1,%edx'),    (0x63ce566, 'mov', '%r13,%rsi'),
    (0x63ce569, 'mov', '%rbp,%rdi'),    (0x63ce56c, 'lea', '0x343ec5(%rip),%rax        # 6712438 <__register_atfork@plt+0x3208a8>'),    (0x63ce573, 'mov', '%rbp,0x28(%rsp)'),
    (0x63ce578, 'mov', '%r13,0x30(%rsp)'),    (0x63ce57d, 'lea', '0x34605c(%rip),%r13        # 67145e0 <__register_atfork@plt+0x322a50>'),    (0x63ce584, 'mov', '(%rax),%rcx'),
    (0x63ce587, 'xor', '%eax,%eax'),    (0x63ce589, 'mov', '%r12,0x20(%rsp)'),    (0x63ce58e, 'shl', '%cl,%rdx'),
    (0x63ce591, 'mov', '%rdx,%rcx'),    (0x63ce594, 'lea', '-0x5f91c58(%rip),%rdx        # 43c943 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x590baed>'),    (0x63ce59b, 'call', '63c4c70 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x67c840>'),
    (0x63ce5a0, 'mov', '0x30(%rsp),%rsi'),    (0x63ce5a5, 'mov', '0x28(%rsp),%rdi'),    (0x63ce5aa, 'mov', '%r15,%rdx'),
    (0x63ce5ad, 'call', '63c6bf0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x67e7c0>'),    (0x63ce5b2, 'mov', '0x30(%rsp),%rdi'),    (0x63ce5b7, 'lea', '-0x5f893d5(%rip),%rsi        # 4451e9 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5903247>'),
    (0x63ce5be, 'call', '*0x28(%rsp)'),    (0x63ce5c2, 'mov', '%r13,%rdi'),    (0x63ce5c5, 'mov', '0x20(%rsp),%rbp'),
    (0x63ce5ca, 'call', '63f17b0 <pthread_mutex_trylock@plt>'),    (0x63ce5cf, 'test', '%eax,%eax'),    (0x63ce5d1, 'jne', '63ce6a0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x686270>'),
    (0x63ce5d7, 'addq', '$0x1,0x345ff9(%rip)        # 67145d8 <__register_atfork@plt+0x322a48>'),    (0x63ce5df, 'cmp', '0x345fea(%rip),%rbp        # 67145d0 <__register_atfork@plt+0x322a40>'),    (0x63ce5e6, 'je', '63ce5f7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6861c7>'),
    (0x63ce5e8, 'addq', '$0x1,0x345fd8(%rip)        # 67145c8 <__register_atfork@plt+0x322a38>'),    (0x63ce5f0, 'mov', '%rbp,0x345fd9(%rip)        # 67145d0 <__register_atfork@plt+0x322a40>'),    (0x63ce5f7, 'mov', '0x345ea2(%rip),%rdi        # 67144a0 <__register_atfork@plt+0x322910>'),
    (0x63ce5fe, 'lea', '0x20(%rsp),%rbp'),    (0x63ce603, 'mov', '%rbp,%rsi'),    (0x63ce606, 'call', '63c7080 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x67ec50>'),
    (0x63ce60b, 'mov', '%r13,%rdi'),    (0x63ce60e, 'movb', '$0x0,0x345ff3(%rip)        # 6714608 <__register_atfork@plt+0x322a78>'),    (0x63ce615, 'call', '63f0b70 <pthread_mutex_unlock@plt>'),
    (0x63ce61a, 'mov', '0x18(%rsp),%r15'),    (0x63ce61f, 'test', '%r15,%r15'),    (0x63ce622, 'je', '63ce666 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x686236>'),
    (0x63ce624, 'lea', '-0x664b(%rip),%r13        # 63c7fe0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x67fbb0>'),    (0x63ce62b, 'mov', '0x18(%r15),%rsi'),    (0x63ce62f, 'mov', '%rbp,%rcx'),
    (0x63ce632, 'mov', '%r13,%rdx'),    (0x63ce635, 'mov', '%rbx,%rdi'),    (0x63ce638, 'call', '63c78f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x67f4c0>'),
    (0x63ce63d, 'test', '%rax,%rax'),    (0x63ce640, 'jne', '63ce666 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x686236>'),    (0x63ce642, 'mov', '%rbp,%rdx'),
    (0x63ce645, 'mov', '%r15,%rsi'),    (0x63ce648, 'mov', '%rbx,%rdi'),    (0x63ce64b, 'call', '63c7fe0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x67fbb0>'),
    (0x63ce650, 'test', '%rax,%rax'),    (0x63ce653, 'jne', '63ce666 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x686236>'),    (0x63ce655, 'mov', '0x20(%r15),%rsi'),
    (0x63ce659, 'mov', '%rsi,%r15'),    (0x63ce65c, 'and', '$0xfffffffffffffffe,%r15'),    (0x63ce660, 'cmp', '$0x1,%rsi'),
    (0x63ce664, 'ja', '63ce62b <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6861fb>'),    (0x63ce666, 'mov', '%rbx,%rsi'),    (0x63ce669, 'mov', '%r12,%rdi'),
    (0x63ce66c, 'call', '63c9650 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x681220>'),    (0x63ce671, 'test', '%r14b,%r14b'),    (0x63ce674, 'jne', '63ce6b8 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x686288>'),
    (0x63ce676, 'mov', '0x88(%rsp),%rax'),    (0x63ce67e, 'sub', '%fs:0x28,%rax'),    (0x63ce687, 'jne', '63ce8b3 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x686483>'),
    (0x63ce68d, 'add', '$0x98,%rsp'),    (0x63ce694, 'pop', '%rbx'),    (0x63ce695, 'pop', '%rbp'),
    (0x63ce696, 'pop', '%r12'),    (0x63ce698, 'pop', '%r13'),    (0x63ce69a, 'pop', '%r14'),
    (0x63ce69c, 'pop', '%r15'),    (0x63ce69e, 'ret', ''),    (0x63ce69f, 'nop', ''),
    (0x63ce6a0, 'lea', '-0x40(%r13),%rdi'),    (0x63ce6a4, 'call', '63bf680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677250>'),    (0x63ce6a9, 'movb', '$0x1,0x345f58(%rip)        # 6714608 <__register_atfork@plt+0x322a78>'),
    (0x63ce6b0, 'jmp', '63ce5d7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6861a7>'),    (0x63ce6b5, 'nopl', '(%rax)'),    (0x63ce6b8, 'mov', '0x50(%rsp),%r8'),
    (0x63ce6bd, 'mov', '0x10(%rsp),%r12'),    (0x63ce6c2, 'mov', '0x40(%rsp),%rdi'),    (0x63ce6c7, 'test', '%r8,%r8'),
    (0x63ce6ca, 'je', '63ce676 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x686246>'),    (0x63ce6cc, 'js', '63ce857 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x686427>'),    (0x63ce6d2, 'pxor', '%xmm2,%xmm2'),
    (0x63ce6d6, 'cvtsi2sd', '%r8,%xmm2'),    (0x63ce6db, 'test', '%rdi,%rdi'),    (0x63ce6de, 'js', '63ce895 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x686465>'),
    (0x63ce6e4, 'pxor', '%xmm1,%xmm1'),    (0x63ce6e8, 'cvtsi2sd', '%rdi,%xmm1'),    (0x63ce6ed, 'lea', '0x343d44(%rip),%r11        # 6712438 <__register_atfork@plt+0x3208a8>'),
    (0x63ce6f4, 'mov', '$0x1,%r14d'),    (0x63ce6fa, 'movapd', '%xmm2,%xmm0'),    (0x63ce6fe, 'divsd', '%xmm1,%xmm0'),
    (0x63ce702, 'mov', '(%r11),%rcx'),    (0x63ce705, 'shl', '%cl,%r14'),    (0x63ce708, 'test', '%r14,%r14'),
    (0x63ce70b, 'js', '63ce876 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x686446>'),    (0x63ce711, 'pxor', '%xmm3,%xmm3'),    (0x63ce715, 'cvtsi2sd', '%r14,%xmm3'),
    (0x63ce71a, 'movsd', '%xmm1,0x8(%rsp)'),    (0x63ce720, 'movsd', '%xmm2,(%rsp)'),    (0x63ce725, 'divsd', '%xmm3,%xmm0'),
    (0x63ce729, 'xorpd', '-0x5f7c911(%rip),%xmm0        # 451e20 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58f6610>'),    (0x63ce731, 'call', '63f0b00 <exp@plt>'),    (0x63ce736, 'movsd', '-0x5f7548e(%rip),%xmm5        # 4592b0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58ef180>'),
    (0x63ce73e, 'movapd', '%xmm0,%xmm4'),    (0x63ce742, 'movapd', '%xmm5,%xmm0'),    (0x63ce746, 'subsd', '%xmm4,%xmm0'),
    (0x63ce74a, 'divsd', '%xmm0,%xmm5'),    (0x63ce74e, 'movsd', '(%rsp),%xmm0'),    (0x63ce753, 'mulsd', '%xmm5,%xmm0'),
    (0x63ce757, 'movsd', '%xmm5,(%rsp)'),    (0x63ce75c, 'call', '63efe40 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6a7a10>'),    (0x63ce761, 'movsd', '(%rsp),%xmm6'),
    (0x63ce766, 'comisd', '-0x5f7540e(%rip),%xmm0        # 459360 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58ef0d0>'),    (0x63ce76e, 'movsd', '0x8(%rsp),%xmm7'),    (0x63ce774, 'jae', '63ce820 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6863f0>'),
    (0x63ce77a, 'cvttsd2si', '%xmm0,%rbp'),    (0x63ce77f, 'mulsd', '%xmm6,%xmm7'),    (0x63ce783, 'movapd', '%xmm7,%xmm0'),
    (0x63ce787, 'call', '63efe40 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6a7a10>'),    (0x63ce78c, 'comisd', '-0x5f75434(%rip),%xmm0        # 459360 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58ef0d0>'),    (0x63ce794, 'jae', '63ce840 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x686410>'),
    (0x63ce79a, 'cvttsd2si', '%xmm0,%rcx'),    (0x63ce79f, 'lea', '-0x5f93f96(%rip),%rax        # 43a810 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x590dc20>'),    (0x63ce7a6, 'lea', '-0x5f970b0(%rip),%rdx        # 4376fd <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x5910d33>'),
    (0x63ce7ad, 'mov', '%r12,%r9'),    (0x63ce7b0, 'mov', '%rbp,%rsi'),    (0x63ce7b3, 'cmp', '$0x1,%r12'),
    (0x63ce7b7, 'mov', '%rax,%r13'),    (0x63ce7ba, 'mov', '%rax,%r8'),    (0x63ce7bd, 'cmove', '%rdx,%r13'),
    (0x63ce7c1, 'cmp', '$0x1,%rcx'),    (0x63ce7c5, 'lea', '-0x5a6a1a4(%rip),%rdi        # 964628 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x53e3e08>'),    (0x63ce7cc, 'cmove', '%rdx,%r8'),
    (0x63ce7d0, 'cmp', '$0x1,%rbp'),    (0x63ce7d4, 'cmovne', '%rax,%rdx'),    (0x63ce7d8, 'sub', '$0x8,%rsp'),
    (0x63ce7dc, 'xor', '%eax,%eax'),    (0x63ce7de, 'push', '%r13'),    (0x63ce7e0, 'call', '63bf5b6 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677186>'),
    (0x63ce7e5, 'xor', '%eax,%eax'),    (0x63ce7e7, 'lea', '-0x5a7312e(%rip),%rdi        # 95b6c0 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x53ecd70>'),    (0x63ce7ee, 'call', '63bf5b6 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677186>'),
    (0x63ce7f3, 'pop', '%rax'),    (0x63ce7f4, 'pop', '%rdx'),    (0x63ce7f5, 'lea', '0x344e06(%rip),%rdx        # 6713602 <__register_atfork@plt+0x321a72>'),
    (0x63ce7fc, 'cmpb', '$0x0,(%rdx)'),    (0x63ce7ff, 'je', '63ce676 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x686246>'),    (0x63ce805, 'lea', '-0x5a765e4(%rip),%rdi        # 958228 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x53f0208>'),
    (0x63ce80c, 'xor', '%eax,%eax'),    (0x63ce80e, 'call', '63bf5b6 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677186>'),    (0x63ce813, 'mov', '$0x1,%edi'),
    (0x63ce818, 'call', '63f0c70 <_exit@plt>'),    (0x63ce81d, 'nopl', '(%rax)'),    (0x63ce820, 'subsd', '-0x5f754c8(%rip),%xmm0        # 459360 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58ef0d0>'),
    (0x63ce828, 'cvttsd2si', '%xmm0,%rbp'),    (0x63ce82d, 'btc', '$0x3f,%rbp'),    (0x63ce832, 'jmp', '63ce77f <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x68634f>'),
    (0x63ce837, 'nopw', '0x0(%rax,%rax,1)'),    (0x63ce840, 'subsd', '-0x5f754e8(%rip),%xmm0        # 459360 <_ZNKSt5ctypeIcE8do_widenEc@@Base-0x58ef0d0>'),    (0x63ce848, 'cvttsd2si', '%xmm0,%rcx'),
    (0x63ce84d, 'btc', '$0x3f,%rcx'),    (0x63ce852, 'jmp', '63ce79f <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x68636f>'),    (0x63ce857, 'mov', '%r8,%r9'),
    (0x63ce85a, 'and', '$0x1,%r8d'),    (0x63ce85e, 'pxor', '%xmm2,%xmm2'),    (0x63ce862, 'shr', '$1,%r9'),
    (0x63ce865, 'or', '%r9,%r8'),    (0x63ce868, 'cvtsi2sd', '%r8,%xmm2'),    (0x63ce86d, 'addsd', '%xmm2,%xmm2'),
    (0x63ce871, 'jmp', '63ce6db <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6862ab>'),    (0x63ce876, 'mov', '%r14,%rbx'),    (0x63ce879, 'and', '$0x1,%r14d'),
    (0x63ce87d, 'pxor', '%xmm3,%xmm3'),    (0x63ce881, 'shr', '$1,%rbx'),    (0x63ce884, 'or', '%rbx,%r14'),
    (0x63ce887, 'cvtsi2sd', '%r14,%xmm3'),    (0x63ce88c, 'addsd', '%xmm3,%xmm3'),    (0x63ce890, 'jmp', '63ce71a <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6862ea>'),
    (0x63ce895, 'mov', '%rdi,%r10'),    (0x63ce898, 'and', '$0x1,%edi'),    (0x63ce89b, 'pxor', '%xmm1,%xmm1'),
    (0x63ce89f, 'shr', '$1,%r10'),    (0x63ce8a2, 'or', '%rdi,%r10'),    (0x63ce8a5, 'cvtsi2sd', '%r10,%xmm1'),
    (0x63ce8aa, 'addsd', '%xmm1,%xmm1'),    (0x63ce8ae, 'jmp', '63ce6ed <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6862bd>'),    (0x63ce8b3, 'call', '63f0d70 <__stack_chk_fail@plt>'),
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
    check("target FDE size 936", END - START == 936)
    prev = fdes[i - 1]
    check("prev FDE 0x63ce240..0x63ce501",
          prev == (0x63CE240, 0x63CE501), str(prev))
    check("prev gap 15 (0xcc padding)", START - prev[1] == 15)
    check("prev gap bytes are 0xcc int3 padding",
          node[toff(prev[1]):toff(START)] == b"\xcc" * 15)
    nxt = fdes[i + 1]
    check("next FDE 0x63ce8c0..0x63cf8bc",
          nxt == (0x63CE8C0, 0x63CF8BC), str(nxt))
    check("next gap 8 (0xcc padding)", nxt[0] - END == 8)
    check("next gap bytes are 0xcc int3 padding",
          node[toff(END):toff(nxt[0])] == b"\xcc" * 8)
    check("next FDE starts endbr64",
          node[toff(nxt[0]):toff(nxt[0]) + 4] == b"\xf3\x0f\x1e\xfa")
    check("prev FDE end is 15 bytes before this FDE start",
          prev[1] == START - 15)
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
    check("next-question FDE 0x6386b60..0x6386eb0",
          fdes[bisect.bisect_left(starts, 0x6386B60)] ==
          (0x6386B60, 0x6386EB0))
    check("#321 shared FDE 0x63c9650..0x63c9c80",
          fdes[bisect.bisect_left(starts, 0x63C9650)] ==
          (0x63C9650, 0x63C9C80))

    hexb = read(os.path.join(PACKET, "lockwait_caller_1site_indirectexp.hex"))
    check("hex exhibit raw bytes 936", len(hexb) == 936, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])
    objdump = read(os.path.join(
        PACKET, "lockwait_caller_1site_indirectexp.objdump.txt")).decode()
    lines = strict_lines(objdump)
    check("strict lines 216", len(lines) == 216, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if mnemonic_of(l) == "call"]
    check("call lines 19", len(calls) == 19, str(len(calls)))
    rets = [l for l in lines if mnemonic_of(l) == "ret"]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x63ce69e",
          sorted(addr_of(l) for l in rets) == [0x63CE69E],
          str([hex(addr_of(l)) for l in rets]))
    tgt = {}
    for l in calls:
        m = re.search(r"\tcall\s+([0-9a-f]+)", l)
        if m:
            t = int(m.group(1), 16)
            tgt[t] = tgt.get(t, 0) + 1
    indirect = [l for l in calls
                if re.search(r"\tcall\s+\*", l)]
    check("indirect calls 1", len(indirect) == 1,
          str([hex(addr_of(l)) for l in indirect]))
    check("indirect call is *0x28(%rsp) at 0x63ce5be",
          sorted(addr_of(l) for l in indirect) == [0x63CE5BE])
    expect = {0x63BF5B6: 3, 0x63BF680: 1, 0x63C4C70: 1, 0x63C6BF0: 1,
              0x63C7080: 1, 0x63C78F0: 1, 0x63C7FE0: 1, 0x63C8490: 1,
              0x63C9650: 1, 0x63EFE40: 2, 0x63F0B00: 1, 0x63F0B70: 1,
              0x63F0C70: 1, 0x63F0D70: 1, 0x63F17B0: 1}
    check("call target multiset exact", dict(tgt) == expect, str(tgt))
    check("distinct direct call targets 15", len(tgt) == 15, str(len(tgt)))
    check("no bti sites", tgt.get(0x63D9880, 0) == 0,
          str(tgt.get(0x63D9880, 0)))
    check("lu-miss sites 0",
          tgt.get(0x63D9700, 0) == 0, str(tgt.get(0x63D9700, 0)))
    check("second-handler sites 0", tgt.get(0x634EBB0, 0) == 0,
          str(tgt.get(0x634EBB0, 0)))
    check("lock-wait helper called 1 time", tgt.get(0x63BF680, 0) == 1,
          str(tgt.get(0x63BF680, 0)))
    check("lock-wait site is 0x63ce6a4",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63bf680" in l) == [0x63CE6A4])
    check("resolver 0x6365150 called 0 times", tgt.get(0x6365150, 0) == 0,
          str(tgt.get(0x6365150, 0)))
    check("stack_chk_fail plt call 1 at 0x63ce8b3",
          tgt.get(0x63F0D70, 0) == 1, str(tgt.get(0x63F0D70, 0)))
    check("trylock plt call 1 at 0x63ce5ca",
          tgt.get(0x63F17B0, 0) == 1, str(tgt.get(0x63F17B0, 0)))
    check("unlock plt call 1 at 0x63ce615",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63f0b70" in l) == [0x63CE615])
    check("exp plt call 1 at 0x63ce731",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63f0b00" in l) == [0x63CE731])
    check("_exit plt call 1 at 0x63ce818",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63f0c70" in l) == [0x63CE818])
    check("log helper 0x63bf5b6 called 3 times at the exact sites",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63bf5b6" in l) ==
          [0x63CE7E0, 0x63CE7EE, 0x63CE80E])
    check("0x63efe40 called 2 times at 0x63ce75c/0x63ce787",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63efe40" in l) == [0x63CE75C, 0x63CE787])
    check("#321 window 0x63c9650 called 1 time at 0x63ce66c",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63c9650" in l) == [0x63CE66C])
    plt_calls = [l for l in calls if "@plt" in l]
    check("PLT calls 5 (by @plt suffix, not address range)",
          len(plt_calls) == 5, str(len(plt_calls)))
    check("distinct PLT targets 5",
          len({re.search(r"\tcall\s+([0-9a-f]+)", l).group(1)
               for l in plt_calls}) == 5)
    check("no internal .text call is counted as PLT",
          not any(("63bf5b6" in l or "63c9650" in l) and "@plt" in l
                  for l in calls))
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
                  ("#334", 0x635F780), ("#335", 0x6386110)):
        check("%s window not called" % _w, tgt.get(_a, 0) == 0,
              str(tgt.get(_a, 0)))

    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", len(bsr) == 0, str([hex(addr_of(l)) for l in bsr]))
    check("shr exactly 3 at 0x63ce862/0x63ce881/0x63ce89f",
          sorted(addr_of(l) for l in lines
                 if mnemonic_of(l) == "shr") ==
          [0x63CE862, 0x63CE881, 0x63CE89F])
    check("all shr are implicit-1 decimal $1 (not $0x1)",
          all(operands_of(l).startswith("$1,") for l in lines
              if mnemonic_of(l) == "shr"))
    check("shl exactly 2 at 0x63ce58e/0x63ce705",
          sorted(addr_of(l) for l in lines
                 if mnemonic_of(l) == "shl") == [0x63CE58E, 0x63CE705])
    check("btc exactly 2 at 0x63ce82d/0x63ce84d",
          sorted(addr_of(l) for l in lines
                 if mnemonic_of(l) == "btc") == [0x63CE82D, 0x63CE84D])
    check("btc operands are $0x3f sign-flip fixups",
          all("$0x3f" in l for l in lines if mnemonic_of(l) == "btc"))
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
    check("jump lines 21", len(jmps) == 21, str(len(jmps)))

    def jump_target(line):
        m = re.search(r"\s([0-9a-f]{6,})\s*<", line)
        return int(m.group(1), 16) if m else None

    outside = []
    for l in jmps:
        t = jump_target(l)
        if t is not None and not (START <= t < END):
            outside.append((addr_of(l), t))
    check("jump closure: 0 outside the window", outside == [], str(outside))
    check("jump targets are exactly the 21 branches",
          sorted(jump_target(l) for l in jmps) ==
          [0x63CE5D7, 0x63CE5F7, 0x63CE62B, 0x63CE666, 0x63CE666, 0x63CE666,
           0x63CE676, 0x63CE676, 0x63CE6A0, 0x63CE6B8, 0x63CE6DB, 0x63CE6ED,
           0x63CE71A, 0x63CE77F, 0x63CE79F, 0x63CE820, 0x63CE840, 0x63CE857,
           0x63CE876, 0x63CE895, 0x63CE8B3],
          str(sorted(jump_target(l) for l in jmps)))
    check("endbr64 count 1",
          sum(1 for l in lines if "endbr64" in l) == 1)
    check("entry is endbr64 at 0x63ce510",
          "endbr64" in by_addr[START])
    check("canary present: 2 fs:0x28 lines",
          sum(1 for l in lines if "%fs:0x28" in l) == 2)
    check("canary load at 0x63ce534",
          "mov" in by_addr[0x63CE534] and "%fs:0x28,%rax" in by_addr[0x63CE534])
    check("canary save to 0x88(%rsp) at 0x63ce53d",
          "mov" in by_addr[0x63CE53D] and "%rax,0x88(%rsp)" in by_addr[0x63CE53D])
    check("canary check sub at 0x63ce67e",
          "sub" in by_addr[0x63CE67E] and "%fs:0x28,%rax" in by_addr[0x63CE67E])
    check("canary fail jne to stack_chk_fail at 0x63ce687",
          "jne" in by_addr[0x63CE687] and "63ce8b3" in by_addr[0x63CE687])
    check("TLS flag check absent: 0 fs:0x330 lines",
          sum(1 for l in lines if "%fs:0x330" in l) == 0)
    check("no lu-miss .bss 0x6511a00 anywhere",
          not any("6511a00" in l for l in lines))
    check("no shr $0x1c anywhere (no 10-bit tag extract)",
          not any("shr" in l and "$0x1c" in l for l in lines))
    check("no prefetch instructions",
          not any("prefetch" in l for l in lines))
    check("tzcnt 0",
          [l for l in lines if mnemonic_of(l) == "tzcnt"] == [])
    check("entry r8d save mov %r8d,%r14d at 0x63ce518",
          "mov" in by_addr[0x63CE518] and "%r8d,%r14d" in by_addr[0x63CE518])
    check("entry rdx save mov %rdx,%r13 at 0x63ce51d",
          "mov" in by_addr[0x63CE51D] and "%rdx,%r13" in by_addr[0x63CE51D])
    check("entry rdi save mov %rdi,%r12 at 0x63ce522",
          "mov" in by_addr[0x63CE522] and "%rdi,%r12" in by_addr[0x63CE522])
    check("entry rsi save mov %rsi,%rbp at 0x63ce526",
          "mov" in by_addr[0x63CE526] and "%rsi,%rbp" in by_addr[0x63CE526])
    check("mutex lea 0x67145e0 at 0x63ce57d",
          "lea" in by_addr[0x63CE57D] and "67145e0" in by_addr[0x63CE57D])
    check("trylock call at 0x63ce5ca",
          "call" in by_addr[0x63CE5CA] and "63f17b0" in by_addr[0x63CE5CA])
    check("trylock-fail jne lock-wait setup at 0x63ce5d1",
          "jne" in by_addr[0x63CE5D1] and "63ce6a0" in by_addr[0x63CE5D1])
    check("acq-count addq $0x1,0x67145d8 at 0x63ce5d7",
          "addq" in by_addr[0x63CE5D7] and "0x345ff9(%rip)" in by_addr[0x63CE5D7])
    check("owner cmp 0x67145d0,%rbp at 0x63ce5df",
          "cmp" in by_addr[0x63CE5DF] and "0x345fea(%rip)" in by_addr[0x63CE5DF])
    check("counter addq $0x1,0x67145c8 at 0x63ce5e8",
          "addq" in by_addr[0x63CE5E8] and "0x345fd8(%rip)" in by_addr[0x63CE5E8])
    check("owner store mov %rbp,0x67145d0 at 0x63ce5f0",
          "mov" in by_addr[0x63CE5F0] and "0x345fd9(%rip)" in by_addr[0x63CE5F0])
    check("under-lock call 0x63c7080 at 0x63ce606",
          "call" in by_addr[0x63CE606] and "63c7080" in by_addr[0x63CE606])
    check("waited-flag clear movb $0x0,0x6714608 at 0x63ce60e",
          "movb" in by_addr[0x63CE60E] and "0x345ff3(%rip)" in by_addr[0x63CE60E])
    check("indirect-call slot save mov %rbp,0x28(%rsp) at 0x63ce573",
          "mov" in by_addr[0x63CE573] and "%rbp,0x28(%rsp)" in by_addr[0x63CE573])
    check("indirect-call rdi reload mov 0x30(%rsp),%rdi at 0x63ce5b2",
          "mov" in by_addr[0x63CE5B2] and "0x30(%rsp),%rdi" in by_addr[0x63CE5B2])
    check("indirect-call rsi lea 0x4451e9 at 0x63ce5b7",
          "lea" in by_addr[0x63CE5B7] and "4451e9" in by_addr[0x63CE5B7])
    check("list head load mov 0x18(%rsp),%r15 at 0x63ce61a",
          "mov" in by_addr[0x63CE61A] and "0x18(%rsp),%r15" in by_addr[0x63CE61A])
    check("list walk per-node call 0x63c78f0 at 0x63ce638",
          "call" in by_addr[0x63CE638] and "63c78f0" in by_addr[0x63CE638])
    check("list walk per-node call 0x63c7fe0 at 0x63ce64b",
          "call" in by_addr[0x63CE64B] and "63c7fe0" in by_addr[0x63CE64B])
    check("tagged-pointer strip and $0xfffffffffffffffe,%r15 at 0x63ce65c",
          "and" in by_addr[0x63CE65C] and
          "$0xfffffffffffffffe,%r15" in by_addr[0x63CE65C])
    check("list walk loop-back ja 0x63ce62b at 0x63ce664",
          "ja" in by_addr[0x63CE664] and "63ce62b" in by_addr[0x63CE664])
    check("#321 call at 0x63ce66c",
          "call" in by_addr[0x63CE66C] and "63c9650" in by_addr[0x63CE66C])
    check("slow-path gate test %r14b,%r14b at 0x63ce671",
          "test" in by_addr[0x63CE671] and "%r14b,%r14b" in by_addr[0x63CE671])
    check("slow-path jne 0x63ce6b8 at 0x63ce674",
          "jne" in by_addr[0x63CE674] and "63ce6b8" in by_addr[0x63CE674])
    check("slow-path r8 load mov 0x50(%rsp),%r8 at 0x63ce6b8",
          "mov" in by_addr[0x63CE6B8] and "0x50(%rsp),%r8" in by_addr[0x63CE6B8])
    check("exp call at 0x63ce731",
          "call" in by_addr[0x63CE731] and "63f0b00" in by_addr[0x63CE731])
    check("log call 1 at 0x63ce7e0",
          "call" in by_addr[0x63CE7E0] and "63bf5b6" in by_addr[0x63CE7E0])
    check("log call 2 at 0x63ce7ee",
          "call" in by_addr[0x63CE7EE] and "63bf5b6" in by_addr[0x63CE7EE])
    check("log call 3 at 0x63ce80e",
          "call" in by_addr[0x63CE80E] and "63bf5b6" in by_addr[0x63CE80E])
    check("fatal-flag cmpb $0x0,(%rdx) at 0x63ce7fc, flag 0x6713602",
          "cmpb" in by_addr[0x63CE7FC] and "$0x0,(%rdx)" in by_addr[0x63CE7FC]
          and "6713602" in by_addr[0x63CE7F5])
    check("fatal-flag je epilogue at 0x63ce7ff",
          "je" in by_addr[0x63CE7FF] and "63ce676" in by_addr[0x63CE7FF])
    check("_exit call at 0x63ce818",
          "call" in by_addr[0x63CE818] and "63f0c70" in by_addr[0x63CE818])
    check("lock-wait setup lea -0x40(%r13),%rdi at 0x63ce6a0",
          "lea" in by_addr[0x63CE6A0] and "-0x40(%r13),%rdi" in by_addr[0x63CE6A0])
    check("lock-wait call at 0x63ce6a4",
          "call" in by_addr[0x63CE6A4] and "63bf680" in by_addr[0x63CE6A4])
    check("waited-flag set movb $0x1,0x6714608 at 0x63ce6a9",
          "movb" in by_addr[0x63CE6A9] and "0x345f58(%rip)" in by_addr[0x63CE6A9])
    check("lock-wait rejoin jmp 0x63ce5d7 at 0x63ce6b0 (NO trylock retry)",
          "jmp" in by_addr[0x63CE6B0] and "63ce5d7" in by_addr[0x63CE6B0])

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

    NORETURN = {0x63F0D70, 0x63F0C70}
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

    check("entry reaches lock-wait site 0x63ce6a4", reaches(START, 0x63CE6A4))
    check("entry reaches ret 0x63ce69e", reaches(START, 0x63CE69E))
    check("entry reaches trylock 0x63ce5ca", reaches(START, 0x63CE5CA))
    check("entry reaches epilogue canary 0x63ce676", reaches(START, 0x63CE676))
    check("entry reaches indirect call 0x63ce5be", reaches(START, 0x63CE5BE))
    check("entry reaches list-walk head 0x63ce62b", reaches(START, 0x63CE62B))
    check("entry reaches #321 call 0x63ce66c", reaches(START, 0x63CE66C))
    check("entry reaches slow path 0x63ce6b8", reaches(START, 0x63CE6B8))
    check("entry reaches log call 0x63ce7e0", reaches(START, 0x63CE7E0))
    check("entry reaches _exit 0x63ce818", reaches(START, 0x63CE818))
    check("preds of lock-wait site 0x63ce6a4 is the setup lea only",
          preds[0x63CE6A4] == {0x63CE6A0}, str(preds[0x63CE6A4]))
    check("preds of lock-wait setup 0x63ce6a0 are trylock fail and the "
          "ret-padding nop",
          preds[0x63CE6A0] == {0x63CE5D1, 0x63CE69F}, str(preds[0x63CE6A0]))
    check("preds of trylock 0x63ce5ca is the rbp reload only",
          preds[0x63CE5CA] == {0x63CE5C5}, str(preds[0x63CE5CA]))
    check("preds of rejoin 0x63ce5d7 are trylock success and the "
          "lock-wait jmp",
          preds[0x63CE5D7] == {0x63CE5D1, 0x63CE6B0}, str(preds[0x63CE5D7]))
    check("preds of ret 0x63ce69e is the final pop",
          preds[0x63CE69E] == {0x63CE69C}, str(preds[0x63CE69E]))
    check("preds of epilogue 0x63ce676 are fast path, slow-path r8==0 "
          "and fatal-flag je",
          preds[0x63CE676] == {0x63CE674, 0x63CE6CA, 0x63CE7FF},
          str(preds[0x63CE676]))
    check("preds of list-walk head 0x63ce62b are entry and loop-back",
          preds[0x63CE62B] == {0x63CE624, 0x63CE664}, str(preds[0x63CE62B]))
    check("preds of walk-exit 0x63ce666 are NULL head, helper failures "
          "and link<=1 fall-through",
          preds[0x63CE666] == {0x63CE622, 0x63CE640, 0x63CE653, 0x63CE664},
          str(preds[0x63CE666]))
    check("preds of slow path 0x63ce6b8 are r14b jne and the padding "
          "nopl",
          preds[0x63CE6B8] == {0x63CE674, 0x63CE6B5}, str(preds[0x63CE6B8]))
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
    SITE = 0x63CE6A4
    RET = 0x63CE69E
    CALL_TRYLOCK = {("CALL", 0x63CE5CA)}
    check("site rdi only def is lea -0x40(%r13),%rdi 0x63ce6a0",
          rdi_in[SITE] == {0x63CE6A0}, str(rdi_in[SITE]))
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
    check("site rbx def is the list-head lea",
          rbx_in[SITE] == {0x63CE54C}, str(rbx_in[SITE]))
    check("site rbp def is the entry-rdi reload at 0x63ce5c5",
          rbp_in[SITE] == {0x63CE5C5}, str(rbp_in[SITE]))
    check("site r12 def is the entry rdi save",
          r12_in[SITE] == {0x63CE522}, str(r12_in[SITE]))
    check("site r13 def is the mutex lea",
          r13_in[SITE] == {0x63CE57D}, str(r13_in[SITE]))
    check("site r14 def is the entry flag save",
          r14_in[SITE] == {0x63CE518}, str(r14_in[SITE]))
    check("site r15 def is the stats-struct lea",
          r15_in[SITE] == {0x63CE547}, str(r15_in[SITE]))
    check("rax at ret is the canary residue def 0x63ce67e",
          rax_in[RET] == {0x63CE67E}, str(rax_in[RET]))

    check("records lock-wait sites match census",
          [s.get("site") for s in rec.get("lock_wait_sites", [])] ==
          ["0x63ce6a4"])
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
    check("records window bytes 936",
          rec.get("window", {}).get("bytes") == 936)
    check("records window range",
          rec.get("window", {}).get("range") == "0x63ce510..0x63ce8b8")
    check("records return value is 0 (canary residue, void return)",
          rec.get("return_value", {}).get("rax") ==
          "0 (canary residue, void return)")
    check("records indirect site 0x63ce5be",
          rec.get("indirect", {}).get("site") == "0x63ce5be")
    check("records indirect target is *(entry rsi)",
          "*(entry rsi)" in rec.get("indirect", {}).get("target", ""))
    check("records log helper FDE 0x63bf5b6..0x63bf677",
          rec.get("callee", {}).get("fde") == "0x63bf5b6..0x63bf677")
    check("records log helper strict 37",
          rec.get("callee", {}).get("strict") == 37)
    check("records log helper bytes 193",
          rec.get("callee", {}).get("bytes") == 193)
    check("records #321 call site 0x63ce66c",
          rec.get("prior_window_call", {}).get("site") == "0x63ce66c")
    check("records #321 call target 0x63c9650",
          rec.get("prior_window_call", {}).get("target") == "0x63c9650")
    check("records exp path mentions btc $0x3f",
          "btc $0x3f" in rec.get("exp_path", {}).get("btc", ""))
    check("records btc count 2",
          rec.get("census", {}).get("btc") == 2)

    # Sections (own ELF parse): .bss exact end; referenced addresses.
    secmap = sections(node)
    bss = secmap[".bss"]
    check("bss section 0x64ffe40..0x6728924",
          bss[3] == 0x64FFE40 and bss[3] + bss[5] == 0x6728924, str(bss))
    for _a in (0x6712438, 0x6713602, 0x67144A0, 0x67145A0, 0x67145C8,
               0x67145D0, 0x67145D8, 0x67145E0, 0x6714608):
        check("address %s inside .bss" % hex(_a),
              bss[3] <= _a < bss[3] + bss[5])
    txt = secmap[".text"]
    check("window inside .text",
          txt[3] <= START and END <= txt[3] + txt[5])
    for _t in (0x63C8490, 0x63C4C70, 0x63C6BF0, 0x63C7080, 0x63C78F0,
               0x63C7FE0, 0x63C9650, 0x63EFE40, 0x63BF5B6, 0x63BF680):
        check("call target %s inside .text (internal, not PLT)" % hex(_t),
              txt[3] <= _t < txt[3] + txt[5])
    rod = secmap[".rodata"]
    for _a in (0x43C943, 0x4376FD, 0x43A810, 0x4451E9, 0x451E20, 0x4592B0,
               0x459360, 0x964628, 0x95B6C0, 0x958228):
        check("address %s inside .rodata" % hex(_a),
              rod[3] <= _a < rod[3] + rod[5])

    # rela counts by direct ELF parse
    dyn_total = plt_total = rel_count = 0
    ref_relocs = 0
    for nm, s in secmap.items():
        if nm == ".rela.dyn":
            dyn_total = s[5] // 24
            for j in range(dyn_total):
                off, info, add = struct.unpack_from(
                    "<QQq", node, s[4] + j * 24)
                rtype = info & 0xFFFFFFFF
                if rtype == 8:
                    rel_count += 1
                if off in (0x6712438, 0x6713602, 0x67144A0, 0x67145A0,
                           0x67145C8, 0x67145D0, 0x67145D8, 0x67145E0,
                           0x6714608):
                    ref_relocs += 1
        if nm == ".rela.plt":
            plt_total = s[5] // 24
    check("rela.dyn total 60723", dyn_total == 60723, str(dyn_total))
    check("rela.dyn RELATIVE 59534", rel_count == 59534, str(rel_count))
    check("rela.plt 278", plt_total == 278, str(plt_total))
    check("no rela lands at any referenced .bss address",
          ref_relocs == 0, str(ref_relocs))

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
    check("next candidate raw lu-miss 0", counts.get(0x6386B60, 0) == 0,
          str(counts.get(0x6386B60, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x6386B60, 0) == 0,
          str(bti_counts.get(0x6386B60, 0)))
    check("next candidate raw second-handler 0",
          sh_counts.get(0x6386B60, 0) == 0, str(sh_counts.get(0x6386B60, 0)))
    check("next candidate raw lock-wait 1",
          lw_counts.get(0x6386B60, 0) == 1,
          str(lw_counts.get(0x6386B60, 0)))
    # lock-wait frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 344", len(survey.get("survivors", [])) == 344,
          str(len(survey.get("survivors", []))))
    check("survey this window is a lock-wait survivor",
          "0x63ce510" in survey.get("survivors", []))
    check("survey this window is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x63ce510") == 1,
          str(survey.get("sites_per_fde", {}).get("0x63ce510")))
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
          "0x63ce510" not in survey.get("lu_miss_survivors", []))
    check("survey this window is NOT a second-handler survivor",
          "0x63ce510" not in survey.get("second_handler_survivors", []))
    check("survey next candidate is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x6386b60") == 1,
          str(survey.get("sites_per_fde", {}).get("0x6386b60")))
    nq = rec.get("next_question", {})
    check("next question is the lock-wait frontier",
          nq.get("frontier") == "lock-wait helper 0x63bf680 callers",
          str(nq.get("frontier")))
    check("next question range 0x6386b60..0x6386eb0",
          nq.get("range") == "0x6386b60..0x6386eb0", str(nq.get("range")))
    check("next question bytes 848", nq.get("bytes") == 848,
          str(nq.get("bytes")))
    check("next question lu-miss sites 0",
          nq.get("lu_miss_sites") == 0, str(nq.get("lu_miss_sites")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 213", nq.get("strict") == 213,
          str(nq.get("strict")))
    check("next question calls 6", nq.get("calls") == 6,
          str(nq.get("calls")))
    check("next question indirect calls 0",
          nq.get("indirect_calls") == 0, str(nq.get("indirect_calls")))
    check("next question calls by target",
          nq.get("calls_by_target") ==
          {"0x634eba0": 1, "0x63643f0": 1, "0x63bf680": 1, "0x63f0b70": 1,
           "0x63f0d70": 1, "0x63f17b0": 1},
          str(nq.get("calls_by_target")))
    check("next question lock-wait sites 1",
          nq.get("lock_wait_sites") == 1, str(nq.get("lock_wait_sites")))
    check("next question lock-wait site list",
          nq.get("lock_wait_site") == ["0x6386cb4"],
          str(nq.get("lock_wait_site")))
    check("next question second-handler sites 0",
          nq.get("second_handler_sites") == 0,
          str(nq.get("second_handler_sites")))
    check("next question bsr 0", nq.get("bsr") == 0,
          str(nq.get("bsr")))
    check("next question rets 1",
          nq.get("ret") == ["0x6386c21"], str(nq.get("ret")))
    check("next question jumps 34", nq.get("jumps") == 34,
          str(nq.get("jumps")))
    check("next question jumps outside 0", nq.get("jumps_outside_window") == 0,
          str(nq.get("jumps_outside_window")))
    check("next question endbr64 1", nq.get("endbr64") == 1,
          str(nq.get("endbr64")))
    check("next question canary present", nq.get("canary") is True,
          str(nq.get("canary")))
    check("next question plt calls 3", nq.get("plt_calls") == 3,
          str(nq.get("plt_calls")))
    check("records census strict 216",
          rec.get("census", {}).get("strict") == 216)
    check("records census calls 19",
          rec.get("census", {}).get("calls") == 19)
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
    # next candidate 0x6386b60..0x6386eb0 must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x6386B60 < p[1] and p[0] < 0x6386EB0]
    check("next candidate 0x6386b60 disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x6386EB0 and 0x6386B60 < END))

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
    check("slug not colliding with #314-#335 lu-miss/lockwait slugs",
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
                       "RE-001-node115-lockwait-caller-1site-tablecopy"))

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
                    "lockwait_caller_1site_indirectexp.hex",
                    "lockwait_caller_1site_indirectexp.objdump.txt"}
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
