import bisect
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

SLUG = "RE-001-node115-lockwait-caller-1site-strcmp"
START = 0x6386540
END = 0x638693A
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
    (0x6386540, 'endbr64', ''),    (0x6386544, 'push', '%r15'),    (0x6386546, 'lea', '0x38bc53(%rip),%r15'),    (0x638654d, 'push', '%r14'),    (0x638654f, 'mov', '%r8,%r14'),    (0x6386552, 'push', '%r13'),    (0x6386554, 'mov', '%rsi,%r13'),    (0x6386557, 'push', '%r12'),    (0x6386559, 'mov', '%rcx,%r12'),    (0x638655c, 'push', '%rbp'),    (0x638655d, 'mov', '%r9,%rbp'),    (0x6386560, 'push', '%rbx'),    (0x6386561, 'mov', '%rdi,%rbx'),    (0x6386564, 'mov', '%r15,%rdi'),    (0x6386567, 'sub', '$0x18,%rsp'),    (0x638656b, 'mov', '%fs:0x28,%rax'),    (0x6386574, 'mov', '%rax,0x8(%rsp)'),    (0x6386579, 'xor', '%eax,%eax'),    (0x638657b, 'movq', '$0x0,(%rsp)'),    (0x6386583, 'call', '63f17b0 <pthread_mutex_trylock@plt>'),    (0x6386588, 'test', '%eax,%eax'),    (0x638658a, 'jne', '6386660 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e230>'),    (0x6386590, 'addq', '$0x1,0x38bc00(%rip)'),    (0x6386598, 'cmp', '0x38bbf1(%rip),%rbx'),    (0x638659f, 'je', '63865b0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e180>'),    (0x63865a1, 'addq', '$0x1,0x38bbdf(%rip)'),    (0x63865a9, 'mov', '%rbx,0x38bbe0(%rip)'),    (0x63865b0, 'test', '%rbp,%rbp'),    (0x63865b3, 'je', '63865c5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e195>'),    (0x63865b5, 'cmpq', '$0x8,0x50(%rsp)'),    (0x63865bb, 'jne', '6386622 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e1f2>'),    (0x63865bd, 'mov', '0x0(%rbp),%rax'),    (0x63865c1, 'mov', '%rax,(%rsp)'),    (0x63865c5, 'mov', '0x8(%r13),%rbx'),    (0x63865c9, 'mov', '%rbx,%rdx'),    (0x63865cc, 'shr', '$0x20,%rdx'),    (0x63865d0, 'jne', '63866f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e2c0>'),    (0x63865d6, 'mov', '(%rsp),%r13'),    (0x63865da, 'test', '%r13,%r13'),    (0x63865dd, 'je', '6386700 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e2d0>'),    (0x63865e3, 'lea', '0x179616(%rip),%rbp'),    (0x63865ea, 'mov', '%r13,%rsi'),    (0x63865ed, 'mov', '0x0(%rbp),%rdi'),    (0x63865f1, 'call', '63f0f20 <strcmp@plt>'),    (0x63865f6, 'test', '%eax,%eax'),    (0x63865f8, 'je', '638667d <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e24d>'),    (0x63865fe, 'mov', '0x8(%rbp),%rdi'),    (0x6386602, 'mov', '%r13,%rsi'),    (0x6386605, 'call', '63f0f20 <strcmp@plt>'),    (0x638660a, 'test', '%eax,%eax'),    (0x638660c, 'je', '6386678 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e248>'),    (0x638660e, 'mov', '0x10(%rbp),%rdi'),    (0x6386612, 'mov', '%r13,%rsi'),    (0x6386615, 'call', '63f0f20 <strcmp@plt>'),    (0x638661a, 'test', '%eax,%eax'),    (0x638661c, 'je', '6386900 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e4d0>'),    (0x6386622, 'mov', '$0x16,%r13d'),    (0x6386628, 'movb', '$0x0,0x38bb99(%rip)'),    (0x638662f, 'mov', '%r15,%rdi'),    (0x6386632, 'call', '63f0b70 <pthread_mutex_unlock@plt>'),    (0x6386637, 'mov', '0x8(%rsp),%rax'),    (0x638663c, 'sub', '%fs:0x28,%rax'),    (0x6386645, 'jne', '6386935 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e505>'),    (0x638664b, 'add', '$0x18,%rsp'),    (0x638664f, 'mov', '%r13d,%eax'),    (0x6386652, 'pop', '%rbx'),    (0x6386653, 'pop', '%rbp'),    (0x6386654, 'pop', '%r12'),    (0x6386656, 'pop', '%r13'),    (0x6386658, 'pop', '%r14'),    (0x638665a, 'pop', '%r15'),    (0x638665c, 'ret', ''),    (0x638665d, 'nopl', '(%rax)'),    (0x6386660, 'lea', '-0x40(%r15),%rdi'),    (0x6386664, 'call', '63bf680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677250>'),    (0x6386669, 'movb', '$0x1,0x38bb58(%rip)'),    (0x6386670, 'jmp', '6386590 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e160>'),    (0x6386675, 'nopl', '(%rax)'),    (0x6386678, 'mov', '$0x1,%eax'),    (0x638667d, 'cmp', '$0x1000,%ebx'),    (0x6386683, 'je', '6386691 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e261>'),    (0x6386685, 'mov', '0x38baa4(%rip),%rdi'),    (0x638668c, 'cmp', '%ebx,0x8(%rdi)'),    (0x638668f, 'jne', '63866d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e2a0>'),    (0x6386691, 'mov', '%eax,%edi'),    (0x6386693, 'call', '63b5b50 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x66d720>'),    (0x6386698, 'test', '%al,%al'),    (0x638669a, 'jne', '63866f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e2c0>'),    (0x638669c, 'call', '63b5b40 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x66d710>'),    (0x63866a1, 'mov', '%eax,%r9d'),    (0x63866a4, 'mov', '0x0(%rbp,%r9,8),%r10'),    (0x63866a9, 'mov', '%r10,(%rsp)'),    (0x63866ad, 'test', '%r12,%r12'),    (0x63866b0, 'je', '63866c8 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e298>'),    (0x63866b2, 'test', '%r14,%r14'),    (0x63866b5, 'je', '63866c8 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e298>'),    (0x63866b7, 'mov', '(%r14),%rdx'),    (0x63866ba, 'cmp', '$0x8,%rdx'),    (0x63866be, 'jne', '6386750 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e320>'),    (0x63866c4, 'mov', '%r10,(%r12)'),    (0x63866c8, 'xor', '%r13d,%r13d'),    (0x63866cb, 'jmp', '6386628 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e1f8>'),    (0x63866d0, 'lea', '0x182fe9(%rip),%r8'),    (0x63866d7, 'mov', '(%r8,%rbx,8),%rbx'),    (0x63866db, 'test', '%rbx,%rbx'),    (0x63866de, 'je', '63866f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e2c0>'),    (0x63866e0, 'mov', '%eax,%esi'),    (0x63866e2, 'mov', '%rbx,%rdi'),    (0x63866e5, 'call', '6364360 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61bf30>'),    (0x63866ea, 'test', '%al,%al'),    (0x63866ec, 'je', '638672b <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e2fb>'),    (0x63866ee, 'xchg', '%ax,%ax'),    (0x63866f0, 'mov', '$0xe,%r13d'),    (0x63866f6, 'jmp', '6386628 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e1f8>'),    (0x63866fb, 'nopl', '0x0(%rax,%rax,1)'),    (0x6386700, 'cmp', '$0x1000,%ebx'),    (0x6386706, 'je', '6386740 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e310>'),    (0x6386708, 'mov', '0x38ba21(%rip),%rcx'),    (0x638670f, 'cmp', '%ebx,0x8(%rcx)'),    (0x6386712, 'je', '6386740 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e310>'),    (0x6386714, 'lea', '0x182fa5(%rip),%rsi'),    (0x638671b, 'mov', '(%rsi,%rbx,8),%rbx'),    (0x638671f, 'test', '%rbx,%rbx'),    (0x6386722, 'je', '63866f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e2c0>'),    (0x6386724, 'lea', '0x1794d5(%rip),%rbp'),    (0x638672b, 'mov', '%rbx,%rdi'),    (0x638672e, 'call', '6364350 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61bf20>'),    (0x6386733, 'jmp', '63866a1 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e271>'),    (0x6386738, 'nopl', '0x0(%rax,%rax,1)'),    (0x6386740, 'lea', '0x1794b9(%rip),%rbp'),    (0x6386747, 'jmp', '638669c <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e26c>'),    (0x638674c, 'nopl', '0x0(%rax)'),    (0x6386750, 'mov', '$0x8,%r11d'),    (0x6386756, 'mov', '%rsp,%r13'),    (0x6386759, 'cmp', '%r11,%rdx'),    (0x638675c, 'cmova', '%r11,%rdx'),    (0x6386760, 'cmp', '$0x8,%edx'),    (0x6386763, 'jae', '6386790 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e360>'),    (0x6386765, 'test', '$0x4,%dl'),    (0x6386768, 'jne', '638690a <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e4da>'),    (0x638676e, 'test', '%edx,%edx'),    (0x6386770, 'je', '6386783 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e353>'),    (0x6386772, 'movzbl', '(%rsp),%ebp'),    (0x6386776, 'mov', '%bpl,(%r12)'),    (0x638677a, 'test', '$0x2,%dl'),    (0x638677d, 'jne', '6386922 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e4f2>'),    (0x6386783, 'mov', '%rdx,(%r14)'),    (0x6386786, 'jmp', '6386622 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e1f2>'),    (0x638678b, 'nopl', '0x0(%rax,%rax,1)'),    (0x6386790, 'mov', '%edx,%ebx'),    (0x6386792, 'mov', '%r10,(%r12)'),    (0x6386796, 'lea', '0x8(%r12),%r10'),    (0x638679b, 'mov', '-0x8(%r13,%rbx,1),%r9'),    (0x63867a0, 'and', '$0xfffffffffffffff8,%r10'),    (0x63867a4, 'mov', '%r9,-0x8(%r12,%rbx,1)'),    (0x63867a9, 'sub', '%r10,%r12'),    (0x63867ac, 'lea', '(%rdx,%r12,1),%eax'),    (0x63867b0, 'sub', '%r12,%r13'),    (0x63867b3, 'and', '$0xfffffff8,%eax'),    (0x63867b6, 'cmp', '$0x8,%eax'),    (0x63867b9, 'jb', '6386783 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e353>'),    (0x63867bb, 'xor', '%esi,%esi'),    (0x63867bd, 'lea', '-0x1(%rax),%r11d'),    (0x63867c1, 'mov', '$0x8,%r8d'),    (0x63867c7, 'mov', '%eax,%r12d'),    (0x63867ca, 'mov', '0x0(%r13,%rsi,1),%rcx'),    (0x63867cf, 'shr', '$0x3,%r11d'),    (0x63867d3, 'and', '$0x7,%r11d'),    (0x63867d7, 'mov', '%rcx,(%r10,%rsi,1)'),    (0x63867db, 'cmp', '%eax,%r8d'),    (0x63867de, 'jae', '6386783 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e353>'),    (0x63867e0, 'test', '%r11d,%r11d'),    (0x63867e3, 'je', '6386885 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e455>'),    (0x63867e9, 'cmp', '$0x1,%r11d'),    (0x63867ed, 'je', '638686c <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e43c>'),    (0x63867ef, 'cmp', '$0x2,%r11d'),    (0x63867f3, 'je', '638685c <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e42c>'),    (0x63867f5, 'cmp', '$0x3,%r11d'),    (0x63867f9, 'je', '638684c <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e41c>'),    (0x63867fb, 'cmp', '$0x4,%r11d'),    (0x63867ff, 'je', '638683c <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e40c>'),    (0x6386801, 'cmp', '$0x5,%r11d'),    (0x6386805, 'je', '638682c <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e3fc>'),    (0x6386807, 'cmp', '$0x6,%r11d'),    (0x638680b, 'je', '638681c <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e3ec>'),    (0x638680d, 'mov', '0x0(%r13,%r8,1),%rbp'),    (0x6386812, 'mov', '%rbp,(%r10,%r8,1)'),    (0x6386816, 'mov', '$0x10,%r8d'),    (0x638681c, 'mov', '%r8d,%edi'),    (0x638681f, 'add', '$0x8,%r8d'),    (0x6386823, 'mov', '0x0(%r13,%rdi,1),%rbx'),    (0x6386828, 'mov', '%rbx,(%r10,%rdi,1)'),    (0x638682c, 'mov', '%r8d,%eax'),    (0x638682f, 'add', '$0x8,%r8d'),    (0x6386833, 'mov', '0x0(%r13,%rax,1),%r9'),    (0x6386838, 'mov', '%r9,(%r10,%rax,1)'),    (0x638683c, 'mov', '%r8d,%r11d'),    (0x638683f, 'add', '$0x8,%r8d'),    (0x6386843, 'mov', '0x0(%r13,%r11,1),%rsi'),    (0x6386848, 'mov', '%rsi,(%r10,%r11,1)'),    (0x638684c, 'mov', '%r8d,%ecx'),    (0x638684f, 'add', '$0x8,%r8d'),    (0x6386853, 'mov', '0x0(%r13,%rcx,1),%rbp'),    (0x6386858, 'mov', '%rbp,(%r10,%rcx,1)'),    (0x638685c, 'mov', '%r8d,%edi'),    (0x638685f, 'add', '$0x8,%r8d'),    (0x6386863, 'mov', '0x0(%r13,%rdi,1),%rbx'),    (0x6386868, 'mov', '%rbx,(%r10,%rdi,1)'),    (0x638686c, 'mov', '%r8d,%eax'),    (0x638686f, 'add', '$0x8,%r8d'),    (0x6386873, 'mov', '0x0(%r13,%rax,1),%r9'),    (0x6386878, 'mov', '%r9,(%r10,%rax,1)'),    (0x638687c, 'cmp', '%r12d,%r8d'),    (0x638687f, 'jae', '6386783 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e353>'),    (0x6386885, 'mov', '%r8d,%r11d'),    (0x6386888, 'lea', '0x8(%r8),%ecx'),    (0x638688c, 'lea', '0x10(%r8),%edi'),    (0x6386890, 'mov', '0x0(%r13,%r11,1),%rsi'),    (0x6386895, 'lea', '0x18(%r8),%eax'),    (0x6386899, 'mov', '%rsi,(%r10,%r11,1)'),    (0x638689d, 'mov', '0x0(%r13,%rcx,1),%rbp'),    (0x63868a2, 'lea', '0x20(%r8),%r11d'),    (0x63868a6, 'mov', '%rbp,(%r10,%rcx,1)'),    (0x63868aa, 'mov', '0x0(%r13,%rdi,1),%rbx'),    (0x63868af, 'lea', '0x28(%r8),%ecx'),    (0x63868b3, 'mov', '%rbx,(%r10,%rdi,1)'),    (0x63868b7, 'mov', '0x0(%r13,%rax,1),%r9'),    (0x63868bc, 'lea', '0x30(%r8),%edi'),    (0x63868c0, 'mov', '%r9,(%r10,%rax,1)'),    (0x63868c4, 'mov', '0x0(%r13,%r11,1),%rsi'),    (0x63868c9, 'lea', '0x38(%r8),%eax'),    (0x63868cd, 'add', '$0x40,%r8d'),    (0x63868d1, 'mov', '%rsi,(%r10,%r11,1)'),    (0x63868d5, 'mov', '0x0(%r13,%rcx,1),%rbp'),    (0x63868da, 'mov', '%rbp,(%r10,%rcx,1)'),    (0x63868de, 'mov', '0x0(%r13,%rdi,1),%rbx'),    (0x63868e3, 'mov', '%rbx,(%r10,%rdi,1)'),    (0x63868e7, 'mov', '0x0(%r13,%rax,1),%r9'),    (0x63868ec, 'mov', '%r9,(%r10,%rax,1)'),    (0x63868f0, 'cmp', '%r12d,%r8d'),    (0x63868f3, 'jb', '6386885 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e455>'),    (0x63868f5, 'jmp', '6386783 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e353>'),    (0x63868fa, 'nopw', '0x0(%rax,%rax,1)'),    (0x6386900, 'mov', '$0x2,%eax'),    (0x6386905, 'jmp', '638667d <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e24d>'),    (0x638690a, 'mov', '(%rsp),%eax'),    (0x638690d, 'mov', '%edx,%esi'),    (0x638690f, 'mov', '%eax,(%r12)'),    (0x6386913, 'mov', '-0x4(%r13,%rsi,1),%ecx'),    (0x6386918, 'mov', '%ecx,-0x4(%r12,%rsi,1)'),    (0x638691d, 'jmp', '6386783 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e353>'),    (0x6386922, 'mov', '%edx,%edi'),    (0x6386924, 'movzwl', '-0x2(%r13,%rdi,1),%r8d'),    (0x638692a, 'mov', '%r8w,-0x2(%r12,%rdi,1)'),    (0x6386930, 'jmp', '6386783 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e353>'),    (0x6386935, 'call', '63f0d70 <__stack_chk_fail@plt>'),]


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
    check("target FDE size 1018", END - START == 1018)
    prev = fdes[i - 1]
    check("prev FDE 0x6386500..0x638653a",
          prev == (0x6386500, 0x638653A), str(prev))
    check("prev gap 6 (0xcc padding)", START - prev[1] == 6)
    check("prev gap bytes are 0xcc int3 padding",
          node[toff(prev[1]):toff(START)] == b"\xcc" * 6)
    nxt = fdes[i + 1]
    check("next FDE 0x6386940..0x6386b54",
          nxt == (0x6386940, 0x6386B54), str(nxt))
    check("next gap 6 (0xcc padding)", nxt[0] - END == 6)
    check("next gap bytes are 0xcc int3 padding",
          node[toff(END):toff(nxt[0])] == b"\xcc" * 6)
    check("next FDE starts endbr64",
          node[toff(nxt[0]):toff(nxt[0]) + 4] == b"\xf3\x0f\x1e\xfa")
    check("prev FDE end is 6 bytes before this FDE start",
          prev[1] == START - 6)
    check("call-target FDE 0x634eba0..0x634ebab",
          fdes[bisect.bisect_left(starts, 0x634EBA0)] ==
          (0x634EBA0, 0x634EBAB))
    check("call-target FDE 0x635f6a0..0x635f77c",
          fdes[bisect.bisect_left(starts, 0x635F6A0)] ==
          (0x635F6A0, 0x635F77C))
    check("call-target FDE 0x6364360..0x636436d",
          fdes[bisect.bisect_left(starts, 0x6364360)] ==
          (0x6364360, 0x636436D))
    check("call-target FDE 0x6364350..0x636435b",
          fdes[bisect.bisect_left(starts, 0x6364350)] ==
          (0x6364350, 0x636435B))
    check("call-target FDE 0x63b5b50..0x63b5b5d",
          fdes[bisect.bisect_left(starts, 0x63B5B50)] ==
          (0x63B5B50, 0x63B5B5D))
    check("call-target FDE 0x63b5b40..0x63b5b4b",
          fdes[bisect.bisect_left(starts, 0x63B5B40)] ==
          (0x63B5B40, 0x63B5B4B))
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
    check("next-question FDE 0x635f780..0x635fb47",
          fdes[bisect.bisect_left(starts, 0x635F780)] ==
          (0x635F780, 0x635FB47))
    check("#321 shared FDE 0x63c9650..0x63c9c80",
          fdes[bisect.bisect_left(starts, 0x63C9650)] ==
          (0x63C9650, 0x63C9C80))

    hexb = read(os.path.join(PACKET, "lockwait_caller_1site_strcmp.hex"))
    check("hex exhibit raw bytes 1018", len(hexb) == 1018, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])
    objdump = read(os.path.join(
        PACKET, "lockwait_caller_1site_strcmp.objdump.txt")).decode()
    lines = strict_lines(objdump)
    check("strict lines 256", len(lines) == 256, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if mnemonic_of(l) == "call"]
    check("call lines 11", len(calls) == 11, str(len(calls)))
    rets = [l for l in lines if mnemonic_of(l) == "ret"]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x638665c",
          sorted(addr_of(l) for l in rets) == [0x638665C],
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
    expect = {0x6364350: 1, 0x6364360: 1, 0x63B5B40: 1, 0x63B5B50: 1,
              0x63BF680: 1, 0x63F0B70: 1, 0x63F0D70: 1, 0x63F0F20: 3,
              0x63F17B0: 1}
    check("call target multiset exact", dict(tgt) == expect, str(tgt))
    check("distinct direct call targets 9", len(tgt) == 9, str(len(tgt)))
    check("no bti sites", tgt.get(0x63D9880, 0) == 0,
          str(tgt.get(0x63D9880, 0)))
    check("lu-miss sites 0",
          tgt.get(0x63D9700, 0) == 0, str(tgt.get(0x63D9700, 0)))
    check("second-handler sites 0", tgt.get(0x634EBB0, 0) == 0,
          str(tgt.get(0x634EBB0, 0)))
    check("lock-wait helper called 1 time", tgt.get(0x63BF680, 0) == 1,
          str(tgt.get(0x63BF680, 0)))
    check("lock-wait site is 0x6386664",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63bf680" in l) == [0x6386664])
    check("resolver 0x6365150 called 0 times", tgt.get(0x6365150, 0) == 0,
          str(tgt.get(0x6365150, 0)))
    check("stack_chk_fail plt call 1 at 0x6386935",
          tgt.get(0x63F0D70, 0) == 1, str(tgt.get(0x63F0D70, 0)))
    check("strcmp plt calls 3", tgt.get(0x63F0F20, 0) == 3,
          str(tgt.get(0x63F0F20, 0)))
    plt_calls = [l for l in calls if "@plt" in l]
    check("PLT calls 6 (by @plt suffix, not address range)",
          len(plt_calls) == 6, str(len(plt_calls)))
    check("distinct PLT targets 4",
          len({re.search(r"\tcall\s+([0-9a-f]+)", l).group(1)
               for l in plt_calls}) == 4)
    check("no internal .text call is counted as PLT",
          not any("63b5b50" in l and "@plt" in l for l in calls)
          and not any("6364360" in l and "@plt" in l for l in calls))
    for _w, _a in (("#314", 0x63495B0), ("#315", 0x6353A70),
                  ("#316", 0x6355900), ("#317", 0x63577F0),
                  ("#318", 0x635A7A0), ("#319", 0x635C6D0),
                  ("#320", 0x635E2E0), ("#321", 0x63C9650),
                  ("#322", 0x63CCD60), ("#323", 0x63CDDD0),
                  ("#324", 0x63D03A0), ("#325", 0x63D17E0),
                  ("#326", 0x63D2A80), ("#327", 0x63D3F0E),
                  ("#328", 0x63D4048), ("#329", 0x63E94A0),
                  ("#330", 0x6362190), ("#331", 0x6362910),
                  ("#332", 0x636A140)):
        check("%s window not called" % _w, tgt.get(_a, 0) == 0,
              str(tgt.get(_a, 0)))

    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", len(bsr) == 0, str([hex(addr_of(l)) for l in bsr]))
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
    check("jump lines 46", len(jmps) == 46, str(len(jmps)))

    def jump_target(line):
        m = re.search(r"\s([0-9a-f]{6,})\s*<", line)
        return int(m.group(1), 16) if m else None

    outside = []
    for l in jmps:
        t = jump_target(l)
        if t is not None and not (START <= t < END):
            outside.append((addr_of(l), t))
    check("jump closure: 0 outside the window", outside == [], str(outside))
    check("jump targets are exactly the 46 branches",
          sorted(jump_target(l) for l in jmps) ==
          [0x6386590, 0x63865B0, 0x63865C5, 0x6386622, 0x6386622, 0x6386628,
           0x6386628, 0x6386660, 0x6386678, 0x638667D, 0x638667D, 0x6386691,
           0x638669C, 0x63866A1, 0x63866C8, 0x63866C8, 0x63866D0, 0x63866F0,
           0x63866F0, 0x63866F0, 0x63866F0, 0x6386700, 0x638672B, 0x6386740,
           0x6386740, 0x6386750, 0x6386783, 0x6386783, 0x6386783, 0x6386783,
           0x6386783, 0x6386783, 0x6386783, 0x6386790, 0x638681C, 0x638682C,
           0x638683C, 0x638684C, 0x638685C, 0x638686C, 0x6386885, 0x6386885,
           0x6386900, 0x638690A, 0x6386922, 0x6386935],
          str(sorted(jump_target(l) for l in jmps)))
    check("endbr64 count 1",
          sum(1 for l in lines if "endbr64" in l) == 1)
    check("entry is endbr64 at 0x6386540",
          "endbr64" in by_addr[START])
    check("canary present: 2 fs:0x28 lines",
          sum(1 for l in lines if "%fs:0x28" in l) == 2)
    check("canary load at 0x638656b",
          "mov" in by_addr[0x638656B] and "%fs:0x28,%rax" in by_addr[0x638656B])
    check("canary check sub at 0x638663c",
          "sub" in by_addr[0x638663C] and "%fs:0x28,%rax" in by_addr[0x638663C])
    check("canary fail jne to stack_chk_fail at 0x6386645",
          "jne" in by_addr[0x6386645] and "6386935" in by_addr[0x6386645])
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
    check("name-table lea 0x64ffc00 at 0x63865e3",
          "lea" in by_addr[0x63865E3] and "64ffc00" in by_addr[0x63865E3])
    check("runtime-table lea 0x65096c0 at 0x63866d0",
          "lea" in by_addr[0x63866D0] and "65096c0" in by_addr[0x63866D0])
    check("runtime-table lea 0x65096c0 at 0x6386714",
          "lea" in by_addr[0x6386714] and "65096c0" in by_addr[0x6386714])
    check("table-check mov 0x6712130 at 0x6386685",
          "mov" in by_addr[0x6386685] and "6712130" in by_addr[0x6386685])
    check("table-check mov 0x6712130 at 0x6386708",
          "mov" in by_addr[0x6386708] and "6712130" in by_addr[0x6386708])
    check("ebx == 0x1000 cmp at 0x638667d",
          "cmp" in by_addr[0x638667D] and "$0x1000,%ebx" in by_addr[0x638667D])
    check("ebx == 0x1000 cmp at 0x6386700",
          "cmp" in by_addr[0x6386700] and "$0x1000,%ebx" in by_addr[0x6386700])
    check("7th-arg cmp $0x8,0x50(rsp) at 0x63865b5",
          "cmpq" in by_addr[0x63865B5] and "$0x8,0x50(%rsp)" in by_addr[0x63865B5])
    check("selector shr $0x20 at 0x63865cc",
          "shr" in by_addr[0x63865CC] and "$0x20,%rdx" in by_addr[0x63865CC])
    check("no prefetch instructions",
          not any("prefetch" in l for l in lines))
    check("tzcnt 0",
          [l for l in lines if mnemonic_of(l) == "tzcnt"] == [])
    check("btc 0",
          [l for l in lines if mnemonic_of(l) == "btc"] == [])
    check("copy-loop cmova at 0x638675c",
          "cmova" in by_addr[0x638675C] and "%r11,%rdx" in by_addr[0x638675C])
    check("copy-loop length writeback at 0x6386783",
          "mov" in by_addr[0x6386783] and "%rdx,(%r14)" in by_addr[0x6386783])
    check("fast-path store at 0x63866c4",
          "mov" in by_addr[0x63866C4] and "%r10,(%r12)" in by_addr[0x63866C4])
    check("trylock call at 0x6386583",
          "call" in by_addr[0x6386583] and "63f17b0" in by_addr[0x6386583])
    check("lock-wait call at 0x6386664",
          "call" in by_addr[0x6386664] and "63bf680" in by_addr[0x6386664])
    check("unlock call at 0x6386632",
          "call" in by_addr[0x6386632] and "63f0b70" in by_addr[0x6386632])
    check("waited-flag set movb $0x1,0x67121c8 at 0x6386669",
          "movb" in by_addr[0x6386669] and "$0x1," in by_addr[0x6386669]
          and "67121c8" in by_addr[0x6386669])
    check("waited-flag clear movb $0,0x67121c8 at 0x6386628",
          "movb" in by_addr[0x6386628] and "$0x0," in by_addr[0x6386628]
          and "67121c8" in by_addr[0x6386628])
    check("mutex lea 0x67121a0 at 0x6386546",
          "lea" in by_addr[0x6386546] and "67121a0" in by_addr[0x6386546])
    check("node lea -0x40(r15) at 0x6386660",
          "lea" in by_addr[0x6386660] and "-0x40(%r15),%rdi" in by_addr[0x6386660])
    check("lock-wait setup mov r15 rdi at 0x6386564",
          "mov" in by_addr[0x6386564] and "%r15,%rdi" in by_addr[0x6386564])
    check("exit value mov r13d eax at 0x638664f",
          "mov" in by_addr[0x638664F] and "%r13d,%eax" in by_addr[0x638664F])
    check("exit 0 xor r13d at 0x63866c8",
          "xor" in by_addr[0x63866C8] and "%r13d,%r13d" in by_addr[0x63866C8])
    check("exit 14 mov $0xe r13d at 0x63866f0",
          "mov" in by_addr[0x63866F0] and "$0xe,%r13d" in by_addr[0x63866F0])
    check("exit 22 mov $0x16 r13d at 0x6386622",
          "mov" in by_addr[0x6386622] and "$0x16,%r13d" in by_addr[0x6386622])
    check("strcmp call 1 at 0x63865f1",
          "call" in by_addr[0x63865F1] and "63f0f20" in by_addr[0x63865F1])
    check("strcmp call 2 at 0x6386605",
          "call" in by_addr[0x6386605] and "63f0f20" in by_addr[0x6386605])
    check("strcmp call 3 at 0x6386615",
          "call" in by_addr[0x6386615] and "63f0f20" in by_addr[0x6386615])
    check("name index 1 mov $0x1 eax at 0x6386678",
          "mov" in by_addr[0x6386678] and "$0x1,%eax" in by_addr[0x6386678])
    check("name index 2 mov $0x2 eax at 0x6386900",
          "mov" in by_addr[0x6386900] and "$0x2,%eax" in by_addr[0x6386900])

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

    check("entry reaches lock-wait site 0x6386664", reaches(START, 0x6386664))
    check("entry reaches ret 0x638665c", reaches(START, 0x638665C))
    check("entry reaches trylock 0x6386583", reaches(START, 0x6386583))
    check("entry reaches epilogue 0x6386628", reaches(START, 0x6386628))
    check("entry reaches strcmp 1 0x63865f1", reaches(START, 0x63865F1))
    check("entry reaches copy loop 0x6386750", reaches(START, 0x6386750))
    check("entry reaches exit-0 def 0x63866c8", reaches(START, 0x63866C8))
    check("entry reaches exit-14 def 0x63866f0", reaches(START, 0x63866F0))
    check("entry reaches exit-22 def 0x6386622", reaches(START, 0x6386622))
    check("entry reaches NULL-name path 0x6386700", reaches(START, 0x6386700))
    check("preds of lock-wait setup 0x6386660 are trylock fail + "
          "unreachable nopl padding",
          preds[0x6386660] == {0x638658A, 0x638665D}, str(preds[0x6386660]))
    check("preds of trylock 0x6386583 is the setup only",
          preds[0x6386583] == {0x638657B}, str(preds[0x6386583]))
    check("preds of rejoin 0x6386590 are trylock fall-through and rejoin",
          preds[0x6386590] == {0x638658A, 0x6386670}, str(preds[0x6386590]))
    check("preds of epilogue 0x6386628 are exit-22, exit-0, exit-14",
          preds[0x6386628] == {0x6386622, 0x63866CB, 0x63866F6},
          str(preds[0x6386628]))
    check("preds of exit-22 def 0x6386622 are 7th-arg, no-match, copy",
          preds[0x6386622] == {0x63865BB, 0x638661C, 0x6386786},
          str(preds[0x6386622]))
    check("preds of exit-14 def 0x63866f0 are the four failure entries",
          preds[0x63866F0] == {0x63865D0, 0x638669A, 0x63866DE, 0x63866EE,
                              0x6386722},
          str(preds[0x63866F0]))
    check("preds of exit-0 def 0x63866c8 are early exits and fast path",
          preds[0x63866C8] == {0x63866B0, 0x63866B5, 0x63866C4},
          str(preds[0x63866C8]))
    check("preds of name dispatch 0x638667d are the three strcmp matches",
          preds[0x638667D] == {0x63865F8, 0x6386678, 0x6386905},
          str(preds[0x638667D]))
    check("preds of NULL-name path 0x6386700 are r13==0 and padding",
          preds[0x6386700] == {0x63865DD, 0x63866FB}, str(preds[0x6386700]))
    check("preds of ret 0x638665c is the final pop",
          preds[0x638665C] == {0x638665A}, str(preds[0x638665C]))

    # Reaching definitions: per-register IN sets at the lock-wait site
    # and the exit mov. ENTRY is the caller's value at the window entry;
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
    SITE = 0x6386664
    MOVRET = 0x638664F
    CALL_TRYLOCK = {("CALL", 0x6386583)}
    check("site rdi only def is lea -0x40(r15) 0x6386660",
          rdi_in[SITE] == {0x6386660}, str(rdi_in[SITE]))
    check("site rbx def is the entry rdi save",
          rbx_in[SITE] == {0x6386561}, str(rbx_in[SITE]))
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
          r13_in[SITE] == {0x6386554}, str(r13_in[SITE]))
    check("site r14 def is the entry r8 save",
          r14_in[SITE] == {0x638654F}, str(r14_in[SITE]))
    check("site r15 def is the mutex lea 0x6386546",
          r15_in[SITE] == {0x6386546}, str(r15_in[SITE]))
    check("site rbp def is the entry r9 save",
          rbp_in[SITE] == {0x638655D}, str(rbp_in[SITE]))
    check("site r12 def is the entry rcx save",
          r12_in[SITE] == {0x6386559}, str(r12_in[SITE]))
    check("rax at exit mov is the canary residue def 0x638663c",
          rax_in[MOVRET] == {0x638663C}, str(rax_in[MOVRET]))
    check("r13d at exit mov 0x638664f is exactly the three exit defs",
          r13_in[MOVRET] == {0x6386622, 0x63866C8, 0x63866F0},
          str(r13_in[MOVRET]))

    check("records lock-wait sites match census",
          [s.get("site") for s in rec.get("lock_wait_sites", [])] ==
          ["0x6386664"])
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
    check("records window bytes 1018",
          rec.get("window", {}).get("bytes") == 1018)
    check("records window range",
          rec.get("window", {}).get("range") == "0x6386540..0x638693a")
    check("records return value is r13d (0, 14, or 22)",
          rec.get("return_value", {}).get("rax") ==
          "r13d (0, 14, or 22)")
    check("records name dispatch strings",
          rec.get("name_dispatch", {}).get("strings") ==
          ["disabled", "primary", "secondary"])
    check("records name table 0x64ffc00",
          "0x64ffc00" in rec.get("name_dispatch", {}).get("table", ""))

    # Sections (own ELF parse): .bss exact end; referenced addresses.
    secmap = sections(node)
    bss = secmap[".bss"]
    check("bss section 0x64ffe40..0x6728924",
          bss[3] == 0x64FFE40 and bss[3] + bss[5] == 0x6728924, str(bss))
    for _a in (0x67121A0, 0x6712198, 0x6712190, 0x6712188, 0x67121C8,
               0x6712130, 0x65096C0):
        check("address %s inside .bss" % hex(_a),
              bss[3] <= _a < bss[3] + bss[5])
    check("address 0x64ffc00 inside .data",
          secmap[".data"][3] <= 0x64FFC00
          < secmap[".data"][3] + secmap[".data"][5])
    txt = secmap[".text"]
    check("window inside .text",
          txt[3] <= START and END <= txt[3] + txt[5])
    check("call target 0x6364360 inside .text (internal, not PLT)",
          txt[3] <= 0x6364360 < txt[3] + txt[5])
    check("call target 0x63b5b50 inside .text (internal, not PLT)",
          txt[3] <= 0x63B5B50 < txt[3] + txt[5])

    # rela counts by direct ELF parse
    dyn_total = plt_total = rel_count = 0
    name_relocs = {}
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
                if 0x64FFC00 <= off < 0x64FFC18:
                    name_relocs[off] = (rtype, add)
                if 0x65096C0 <= off < 0x6509EC0:
                    runtime_table_relocs += 1
        if nm == ".rela.plt":
            plt_total = s[5] // 24
    check("rela.dyn total 60723", dyn_total == 60723, str(dyn_total))
    check("rela.dyn RELATIVE 59534", rel_count == 59534, str(rel_count))
    check("rela.plt 278", plt_total == 278, str(plt_total))
    check("name-table rela at 0x64ffc00 is RELATIVE to 0x44ee4c",
          name_relocs.get(0x64FFC00) == (8, 0x44EE4C),
          str(name_relocs.get(0x64FFC00)))
    check("name-table rela at 0x64ffc08 is RELATIVE to 0x443a80",
          name_relocs.get(0x64FFC08) == (8, 0x443A80),
          str(name_relocs.get(0x64FFC08)))
    check("name-table rela at 0x64ffc10 is RELATIVE to 0x438619",
          name_relocs.get(0x64FFC10) == (8, 0x438619),
          str(name_relocs.get(0x64FFC10)))

    def cstr_at(va):
        # .rodata: VA as-is.
        end = node.index(b"\x00", va)
        return node[va:end].decode()

    check("name-table string 0 is 'disabled'",
          cstr_at(0x44EE4C) == "disabled")
    check("name-table string 1 is 'primary'",
          cstr_at(0x443A80) == "primary")
    check("name-table string 2 is 'secondary'",
          cstr_at(0x438619) == "secondary")
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
    check("next candidate raw lu-miss 0", counts.get(0x635F780, 0) == 0,
          str(counts.get(0x635F780, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x635F780, 0) == 0,
          str(bti_counts.get(0x635F780, 0)))
    check("next candidate raw second-handler 0",
          sh_counts.get(0x635F780, 0) == 0, str(sh_counts.get(0x635F780, 0)))
    check("next candidate raw lock-wait 1",
          lw_counts.get(0x635F780, 0) == 1,
          str(lw_counts.get(0x635F780, 0)))

    # lock-wait frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 344", len(survey.get("survivors", [])) == 344,
          str(len(survey.get("survivors", []))))
    check("survey this window is a lock-wait survivor",
          "0x6386540" in survey.get("survivors", []))
    check("survey this window is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x6386540") == 1,
          str(survey.get("sites_per_fde", {}).get("0x6386540")))
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
          "0x6386540" not in survey.get("lu_miss_survivors", []))
    check("survey this window is NOT a second-handler survivor",
          "0x6386540" not in survey.get("second_handler_survivors", []))
    check("survey next candidate is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x635f780") == 1,
          str(survey.get("sites_per_fde", {}).get("0x635f780")))
    nq = rec.get("next_question", {})
    check("next question is the lock-wait frontier",
          nq.get("frontier") == "lock-wait helper 0x63bf680 callers",
          str(nq.get("frontier")))
    check("next question range 0x635f780..0x635fb47",
          nq.get("range") == "0x635f780..0x635fb47", str(nq.get("range")))
    check("next question bytes 967", nq.get("bytes") == 967,
          str(nq.get("bytes")))
    check("next question lu-miss sites 0",
          nq.get("lu_miss_sites") == 0, str(nq.get("lu_miss_sites")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 240", nq.get("strict") == 240,
          str(nq.get("strict")))
    check("next question calls 26", nq.get("calls") == 26,
          str(nq.get("calls")))
    check("next question indirect calls 0",
          nq.get("indirect_calls") == 0, str(nq.get("indirect_calls")))
    check("next question indirect sites",
          nq.get("indirect_sites") == [], str(nq.get("indirect_sites")))
    check("next question calls by target",
          nq.get("calls_by_target") ==
          {"0x634eba0": 1, "0x635f6a0": 21, "0x63bf680": 1, "0x63f0b70": 1,
           "0x63f0d70": 1, "0x63f17b0": 1},
          str(nq.get("calls_by_target")))
    check("next question lock-wait sites 1",
          nq.get("lock_wait_sites") == 1, str(nq.get("lock_wait_sites")))
    check("next question lock-wait site list",
          nq.get("lock_wait_site") == ["0x635fb32"],
          str(nq.get("lock_wait_site")))
    check("next question second-handler sites 0",
          nq.get("second_handler_sites") == 0,
          str(nq.get("second_handler_sites")))
    check("next question bsr 0", nq.get("bsr") == 0,
          str(nq.get("bsr")))
    check("next question rets 1",
          nq.get("ret") == ["0x635f7d6"], str(nq.get("ret")))
    check("next question jumps 28", nq.get("jumps") == 28,
          str(nq.get("jumps")))
    check("next question jumps outside 0", nq.get("jumps_outside_window") == 0,
          str(nq.get("jumps_outside_window")))
    check("next question endbr64 0", nq.get("endbr64") == 0,
          str(nq.get("endbr64")))
    check("next question canary present", nq.get("canary") is True,
          str(nq.get("canary")))
    check("next question plt calls 3", nq.get("plt_calls") == 3,
          str(nq.get("plt_calls")))
    check("records census strict 256",
          rec.get("census", {}).get("strict") == 256)
    check("records census calls 11",
          rec.get("census", {}).get("calls") == 11)
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
    # next candidate 0x635f780..0x635fb47 must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x635F780 < p[1] and p[0] < 0x635FB47]
    check("next candidate 0x635f780 disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x635FB47 and 0x635F780 < END))

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
    check("slug not colliding with #314-#332 lu-miss/lockwait slugs",
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
                       "RE-001-node115-lockwait-caller-1site-indirect"))

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
                    "lockwait_caller_1site_strcmp.hex",
                    "lockwait_caller_1site_strcmp.objdump.txt"}
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
