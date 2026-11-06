import bisect
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

SLUG = "RE-001-node115-lockwait-caller-1site-resolver-fixed-200"
START = 0x63A2910
END = 0x63A2BD0
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
    (0x63a2910, 'endbr64', ''),
    (0x63a2914, 'push', '%r15'),
    (0x63a2916, 'lea', '0x36f883(%rip),%r15        # 67121a0 <__register_atfork@plt+0x320610>'),
    (0x63a291d, 'push', '%r14'),
    (0x63a291f, 'mov', '%rsi,%r14'),
    (0x63a2922, 'push', '%r13'),
    (0x63a2924, 'mov', '%r8,%r13'),
    (0x63a2927, 'push', '%r12'),
    (0x63a2929, 'mov', '%rcx,%r12'),
    (0x63a292c, 'push', '%rbp'),
    (0x63a292d, 'mov', '%rdi,%rbp'),
    (0x63a2930, 'mov', '%r15,%rdi'),
    (0x63a2933, 'push', '%rbx'),
    (0x63a2934, 'mov', '%r9,%rbx'),
    (0x63a2937, 'sub', '$0x18,%rsp'),
    (0x63a293b, 'mov', '%fs:0x28,%rax'),
    (0x63a2944, 'mov', '%rax,0x8(%rsp)'),
    (0x63a2949, 'xor', '%eax,%eax'),
    (0x63a294b, 'call', '63f17b0 <pthread_mutex_trylock@plt>'),
    (0x63a2950, 'test', '%eax,%eax'),
    (0x63a2952, 'jne', '63a2a00 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a5d0>'),
    (0x63a2958, 'addq', '$0x1,0x36f838(%rip)        # 6712198 <__register_atfork@plt+0x320608>'),
    (0x63a2960, 'cmp', '0x36f829(%rip),%rbp        # 6712190 <__register_atfork@plt+0x320600>'),
    (0x63a2967, 'je', '63a2978 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a548>'),
    (0x63a2969, 'addq', '$0x1,0x36f817(%rip)        # 6712188 <__register_atfork@plt+0x3205f8>'),
    (0x63a2971, 'mov', '%rbp,0x36f818(%rip)        # 6712190 <__register_atfork@plt+0x320600>'),
    (0x63a2978, 'mov', '$0x1,%ebp'),
    (0x63a297d, 'or', '0x50(%rsp),%rbx'),
    (0x63a2982, 'je', '63a29c0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a590>'),
    (0x63a2984, 'movb', '$0x0,0x36f83d(%rip)        # 67121c8 <__register_atfork@plt+0x320638>'),
    (0x63a298b, 'mov', '%r15,%rdi'),
    (0x63a298e, 'call', '63f0b70 <pthread_mutex_unlock@plt>'),
    (0x63a2993, 'mov', '0x8(%rsp),%rax'),
    (0x63a2998, 'sub', '%fs:0x28,%rax'),
    (0x63a29a1, 'jne', '63a2bcb <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a79b>'),
    (0x63a29a7, 'add', '$0x18,%rsp'),
    (0x63a29ab, 'mov', '%ebp,%eax'),
    (0x63a29ad, 'pop', '%rbx'),
    (0x63a29ae, 'pop', '%rbp'),
    (0x63a29af, 'pop', '%r12'),
    (0x63a29b1, 'pop', '%r13'),
    (0x63a29b3, 'pop', '%r14'),
    (0x63a29b5, 'pop', '%r15'),
    (0x63a29b7, 'ret', ''),
    (0x63a29b8, 'nopl', '0x0(%rax,%rax,1)'),
    (0x63a29c0, 'mov', '0x10(%r14),%rdi'),
    (0x63a29c4, 'call', '6388310 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fee0>'),
    (0x63a29c9, 'mov', '0x50(%rax),%rdi'),
    (0x63a29cd, 'add', '$0x200,%rdi'),
    (0x63a29d4, 'call', '63bfb90 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677760>'),
    (0x63a29d9, 'mov', '%rax,(%rsp)'),
    (0x63a29dd, 'test', '%r12,%r12'),
    (0x63a29e0, 'je', '63a29f5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a5c5>'),
    (0x63a29e2, 'test', '%r13,%r13'),
    (0x63a29e5, 'je', '63a29f5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a5c5>'),
    (0x63a29e7, 'mov', '0x0(%r13),%rdx'),
    (0x63a29eb, 'cmp', '$0x8,%rdx'),
    (0x63a29ef, 'jne', '63a2a18 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a5e8>'),
    (0x63a29f1, 'mov', '%rax,(%r12)'),
    (0x63a29f5, 'xor', '%ebp,%ebp'),
    (0x63a29f7, 'jmp', '63a2984 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a554>'),
    (0x63a29f9, 'nopl', '0x0(%rax)'),
    (0x63a2a00, 'lea', '-0x40(%r15),%rdi'),
    (0x63a2a04, 'call', '63bf680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677250>'),
    (0x63a2a09, 'movb', '$0x1,0x36f7b8(%rip)        # 67121c8 <__register_atfork@plt+0x320638>'),
    (0x63a2a10, 'jmp', '63a2958 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a528>'),
    (0x63a2a15, 'nopl', '(%rax)'),
    (0x63a2a18, 'mov', '$0x8,%ecx'),
    (0x63a2a1d, 'mov', '%rsp,%r9'),
    (0x63a2a20, 'cmp', '%rcx,%rdx'),
    (0x63a2a23, 'cmova', '%rcx,%rdx'),
    (0x63a2a27, 'cmp', '$0x8,%edx'),
    (0x63a2a2a, 'jb', '63a2b80 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a750>'),
    (0x63a2a30, 'mov', '%edx,%ebp'),
    (0x63a2a32, 'mov', '%rax,(%r12)'),
    (0x63a2a36, 'lea', '0x8(%r12),%rcx'),
    (0x63a2a3b, 'mov', '-0x8(%r9,%rbp,1),%r14'),
    (0x63a2a40, 'and', '$0xfffffffffffffff8,%rcx'),
    (0x63a2a44, 'mov', '%r14,-0x8(%r12,%rbp,1)'),
    (0x63a2a49, 'sub', '%rcx,%r12'),
    (0x63a2a4c, 'sub', '%r12,%r9'),
    (0x63a2a4f, 'add', '%edx,%r12d'),
    (0x63a2a52, 'and', '$0xfffffff8,%r12d'),
    (0x63a2a56, 'cmp', '$0x8,%r12d'),
    (0x63a2a5a, 'jb', '63a2b97 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a767>'),
    (0x63a2a60, 'mov', '(%r9,%rbx,1),%rax'),
    (0x63a2a64, 'lea', '-0x1(%r12),%esi'),
    (0x63a2a69, 'mov', '$0x8,%edi'),
    (0x63a2a6e, 'shr', '$0x3,%esi'),
    (0x63a2a71, 'mov', '%rax,(%rcx,%rbx,1)'),
    (0x63a2a75, 'and', '$0x7,%esi'),
    (0x63a2a78, 'cmp', '%r12d,%edi'),
    (0x63a2a7b, 'jae', '63a2b97 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a767>'),
    (0x63a2a81, 'test', '%esi,%esi'),
    (0x63a2a83, 'je', '63a2b10 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a6e0>'),
    (0x63a2a89, 'cmp', '$0x1,%esi'),
    (0x63a2a8c, 'je', '63a2af9 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a6c9>'),
    (0x63a2a8e, 'cmp', '$0x2,%esi'),
    (0x63a2a91, 'je', '63a2aeb <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a6bb>'),
    (0x63a2a93, 'cmp', '$0x3,%esi'),
    (0x63a2a96, 'je', '63a2ade <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a6ae>'),
    (0x63a2a98, 'cmp', '$0x4,%esi'),
    (0x63a2a9b, 'je', '63a2ad0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a6a0>'),
    (0x63a2a9d, 'cmp', '$0x5,%esi'),
    (0x63a2aa0, 'je', '63a2ac2 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a692>'),
    (0x63a2aa2, 'cmp', '$0x6,%esi'),
    (0x63a2aa5, 'je', '63a2ab4 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a684>'),
    (0x63a2aa7, 'mov', '(%r9,%rdi,1),%rbx'),
    (0x63a2aab, 'mov', '%rbx,(%rcx,%rdi,1)'),
    (0x63a2aaf, 'mov', '$0x10,%edi'),
    (0x63a2ab4, 'mov', '%edi,%r10d'),
    (0x63a2ab7, 'add', '$0x8,%edi'),
    (0x63a2aba, 'mov', '(%r9,%r10,1),%r8'),
    (0x63a2abe, 'mov', '%r8,(%rcx,%r10,1)'),
    (0x63a2ac2, 'mov', '%edi,%r11d'),
    (0x63a2ac5, 'add', '$0x8,%edi'),
    (0x63a2ac8, 'mov', '(%r9,%r11,1),%rbp'),
    (0x63a2acc, 'mov', '%rbp,(%rcx,%r11,1)'),
    (0x63a2ad0, 'mov', '%edi,%r14d'),
    (0x63a2ad3, 'add', '$0x8,%edi'),
    (0x63a2ad6, 'mov', '(%r9,%r14,1),%rsi'),
    (0x63a2ada, 'mov', '%rsi,(%rcx,%r14,1)'),
    (0x63a2ade, 'mov', '%edi,%eax'),
    (0x63a2ae0, 'add', '$0x8,%edi'),
    (0x63a2ae3, 'mov', '(%r9,%rax,1),%rbx'),
    (0x63a2ae7, 'mov', '%rbx,(%rcx,%rax,1)'),
    (0x63a2aeb, 'mov', '%edi,%r10d'),
    (0x63a2aee, 'add', '$0x8,%edi'),
    (0x63a2af1, 'mov', '(%r9,%r10,1),%r8'),
    (0x63a2af5, 'mov', '%r8,(%rcx,%r10,1)'),
    (0x63a2af9, 'mov', '%edi,%r11d'),
    (0x63a2afc, 'add', '$0x8,%edi'),
    (0x63a2aff, 'mov', '(%r9,%r11,1),%rbp'),
    (0x63a2b03, 'mov', '%rbp,(%rcx,%r11,1)'),
    (0x63a2b07, 'cmp', '%r12d,%edi'),
    (0x63a2b0a, 'jae', '63a2b97 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a767>'),
    (0x63a2b10, 'mov', '%edi,%r14d'),
    (0x63a2b13, 'lea', '0x8(%rdi),%eax'),
    (0x63a2b16, 'lea', '0x10(%rdi),%r10d'),
    (0x63a2b1a, 'mov', '(%r9,%r14,1),%rsi'),
    (0x63a2b1e, 'lea', '0x18(%rdi),%r11d'),
    (0x63a2b22, 'mov', '%rsi,(%rcx,%r14,1)'),
    (0x63a2b26, 'mov', '(%r9,%rax,1),%rbx'),
    (0x63a2b2a, 'lea', '0x20(%rdi),%r14d'),
    (0x63a2b2e, 'mov', '%rbx,(%rcx,%rax,1)'),
    (0x63a2b32, 'mov', '(%r9,%r10,1),%r8'),
    (0x63a2b36, 'lea', '0x28(%rdi),%eax'),
    (0x63a2b39, 'mov', '%r8,(%rcx,%r10,1)'),
    (0x63a2b3d, 'mov', '(%r9,%r11,1),%rbp'),
    (0x63a2b41, 'lea', '0x30(%rdi),%r10d'),
    (0x63a2b45, 'mov', '%rbp,(%rcx,%r11,1)'),
    (0x63a2b49, 'mov', '(%r9,%r14,1),%rsi'),
    (0x63a2b4d, 'lea', '0x38(%rdi),%r11d'),
    (0x63a2b51, 'add', '$0x40,%edi'),
    (0x63a2b54, 'mov', '%rsi,(%rcx,%r14,1)'),
    (0x63a2b58, 'mov', '(%r9,%rax,1),%rbx'),
    (0x63a2b5c, 'mov', '%rbx,(%rcx,%rax,1)'),
    (0x63a2b60, 'mov', '(%r9,%r10,1),%r8'),
    (0x63a2b64, 'mov', '%r8,(%rcx,%r10,1)'),
    (0x63a2b68, 'mov', '(%r9,%r11,1),%rbp'),
    (0x63a2b6c, 'mov', '%rbp,(%rcx,%r11,1)'),
    (0x63a2b70, 'cmp', '%r12d,%edi'),
    (0x63a2b73, 'jb', '63a2b10 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a6e0>'),
    (0x63a2b75, 'jmp', '63a2b97 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a767>'),
    (0x63a2b77, 'nopw', '0x0(%rax,%rax,1)'),
    (0x63a2b80, 'test', '$0x4,%dl'),
    (0x63a2b83, 'jne', '63a2ba5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a775>'),
    (0x63a2b85, 'test', '%edx,%edx'),
    (0x63a2b87, 'je', '63a2b97 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a767>'),
    (0x63a2b89, 'movzbl', '(%rsp),%r8d'),
    (0x63a2b8e, 'mov', '%r8b,(%r12)'),
    (0x63a2b92, 'test', '$0x2,%dl'),
    (0x63a2b95, 'jne', '63a2bba <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a78a>'),
    (0x63a2b97, 'mov', '%rdx,0x0(%r13)'),
    (0x63a2b9b, 'mov', '$0x16,%ebp'),
    (0x63a2ba0, 'jmp', '63a2984 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a554>'),
    (0x63a2ba5, 'mov', '(%rsp),%eax'),
    (0x63a2ba8, 'mov', '%edx,%esi'),
    (0x63a2baa, 'mov', '%eax,(%r12)'),
    (0x63a2bae, 'mov', '-0x4(%r9,%rsi,1),%edi'),
    (0x63a2bb3, 'mov', '%edi,-0x4(%r12,%rsi,1)'),
    (0x63a2bb8, 'jmp', '63a2b97 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a767>'),
    (0x63a2bba, 'mov', '%edx,%r10d'),
    (0x63a2bbd, 'movzwl', '-0x2(%r9,%r10,1),%r11d'),
    (0x63a2bc3, 'mov', '%r11w,-0x2(%r12,%r10,1)'),
    (0x63a2bc9, 'jmp', '63a2b97 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a767>'),
    (0x63a2bcb, 'call', '63f0d70 <__stack_chk_fail@plt>')
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
    check("prev FDE 0x63a2650..0x63a2910",
          prev == (0x63A2650, 0x63A2910), str(prev))
    check("prev gap 0 (contiguous, no padding)", START - prev[1] == 0)
    check("prev FDE starts endbr64 (0xf3)",
          node[toff(prev[0])] == 0xF3)
    nxt = fdes[i + 1]
    check("next FDE 0x63a2bd0..0x63a2e90 (#351 window)",
          nxt == (0x63A2BD0, 0x63A2E90), str(nxt))
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
    check("resolver FDE 0x6388310..0x6388372",
          fdes[bisect.bisect_left(starts, 0x6388310)] ==
          (0x6388310, 0x6388372))
    check("loader FDE 0x63bfb90..0x63bfb98 (8-byte trivial load helper)",
          fdes[bisect.bisect_left(starts, 0x63BFB90)] ==
          (0x63BFB90, 0x63BFB98))
    check("next-question FDE 0x63a2650..0x63a2910",
          fdes[bisect.bisect_left(starts, 0x63A2650)] ==
          (0x63A2650, 0x63A2910))
    hexb = read(os.path.join(PACKET, "lockwait_caller_1site_resolver_fixed_200.hex"))
    check("hex exhibit raw bytes 704", len(hexb) == 704, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])
    objdump = read(os.path.join(
        PACKET, "lockwait_caller_1site_resolver_fixed_200.objdump.txt")).decode()
    lines = strict_lines(objdump)
    check("strict lines 187", len(lines) == 187, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if mnemonic_of(l) == "call"]
    check("call lines 6", len(calls) == 6, str(len(calls)))
    rets = [l for l in lines if mnemonic_of(l) == "ret"]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x63a29b7",
          sorted(addr_of(l) for l in rets) == [0x63A29B7],
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
    check("lock-wait site is 0x63a2a04",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63bf680" in l) == [0x63A2A04])
    check("resolver 0x6365150 called 0 times", tgt.get(0x6365150, 0) == 0,
          str(tgt.get(0x6365150, 0)))
    check("count call 0x634eba0 NOT called (0 times)",
          tgt.get(0x634EBA0, 0) == 0, str(tgt.get(0x634EBA0, 0)))
    check("index resolver 0x6388310 called 1 time at 0x63a29c4",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "6388310" in l) == [0x63A29C4])
    check("load helper 0x63bfb90 called 1 time at 0x63a29d4",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63bfb90" in l) == [0x63A29D4])
    check("stack_chk_fail plt call 1 at 0x63a2bcb",
          tgt.get(0x63F0D70, 0) == 1, str(tgt.get(0x63F0D70, 0)))
    check("trylock plt call 1 at 0x63a294b",
          tgt.get(0x63F17B0, 0) == 1, str(tgt.get(0x63F17B0, 0)))
    check("unlock plt call 1 at 0x63a298e",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63f0b70" in l) == [0x63A298E])
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
                  ("#351", 0x63A2BD0)):
        check("%s window not called" % _w, tgt.get(_a, 0) == 0,
              str(tgt.get(_a, 0)))

    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", len(bsr) == 0, str([hex(addr_of(l)) for l in bsr]))
    check("shr exactly 1 at 0x63a2a6e",
          sorted(addr_of(l) for l in lines
                 if mnemonic_of(l) == "shr") ==
          [0x63A2A6E])
    check("shr at 0x63a2a6e is $0x3 (copy remainder)",
          "$0x3,%esi" in operands_of(by_addr[0x63A2A6E]))
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
          [0x63A2958, 0x63A2978, 0x63A2984, 0x63A2984, 0x63A29C0, 0x63A29F5, 0x63A29F5, 0x63A2A00, 0x63A2A18, 0x63A2AB4, 0x63A2AC2, 0x63A2AD0, 0x63A2ADE, 0x63A2AEB, 0x63A2AF9, 0x63A2B10, 0x63A2B10, 0x63A2B80, 0x63A2B97, 0x63A2B97, 0x63A2B97, 0x63A2B97, 0x63A2B97, 0x63A2B97, 0x63A2B97, 0x63A2BA5, 0x63A2BBA, 0x63A2BCB],
          str(sorted(jump_target(l) for l in jmps)))
    check("endbr64 count 1",
          sum(1 for l in lines if "endbr64" in l) == 1)
    check("entry is endbr64 at 0x63a2910",
          "endbr64" in by_addr[START])
    check("canary present: 2 fs:0x28 lines",
          sum(1 for l in lines if "%fs:0x28" in l) == 2)
    check("canary load at 0x63a293b",
          "mov" in by_addr[0x63A293B] and "%fs:0x28,%rax" in by_addr[0x63A293B])
    check("canary save to 0x8(%rsp) at 0x63a2944",
          "mov" in by_addr[0x63A2944] and "%rax,0x8(%rsp)" in by_addr[0x63A2944])
    check("canary check sub at 0x63a2998",
          "sub" in by_addr[0x63A2998] and "%fs:0x28,%rax" in by_addr[0x63A2998])
    check("canary fail jne to stack_chk_fail at 0x63a29a1",
          "jne" in by_addr[0x63A29A1] and "63a2bcb" in by_addr[0x63A29A1])
    check("TLS flag check absent: 0 fs:0x330 lines",
          sum(1 for l in lines if "%fs:0x330" in l) == 0)
    check("no prefetch instructions",
          not any("prefetch" in l for l in lines))
    check("tzcnt 0",
          [l for l in lines if mnemonic_of(l) == "tzcnt"] == [])
    check('entry endbr64 at 0x63a2910',
          'endbr64' in by_addr[0x63A2910])
    check('push %r15 at 0x63a2914',
          'push' in by_addr[0x63A2914] and '%r15' in by_addr[0x63A2914])
    check('mutex lea 0x67121a0 at 0x63a2916',
          'lea' in by_addr[0x63A2916] and '0x36f883(%rip),%r15' in by_addr[0x63A2916])
    check('entry rsi save mov %rsi,%r14 at 0x63a291f',
          'mov' in by_addr[0x63A291F] and '%rsi,%r14' in by_addr[0x63A291F])
    check('entry r8 save mov %r8,%r13 at 0x63a2924',
          'mov' in by_addr[0x63A2924] and '%r8,%r13' in by_addr[0x63A2924])
    check('entry rcx save mov %rcx,%r12 at 0x63a2929',
          'mov' in by_addr[0x63A2929] and '%rcx,%r12' in by_addr[0x63A2929])
    check('entry rdi save mov %rdi,%rbp at 0x63a292d',
          'mov' in by_addr[0x63A292D] and '%rdi,%rbp' in by_addr[0x63A292D])
    check('entry r9 save mov %r9,%rbx at 0x63a2934',
          'mov' in by_addr[0x63A2934] and '%r9,%rbx' in by_addr[0x63A2934])
    check('frame sub $0x18,%rsp at 0x63a2937',
          'sub' in by_addr[0x63A2937] and '$0x18,%rsp' in by_addr[0x63A2937])
    check('canary load mov %fs:0x28,%rax at 0x63a293b',
          'mov' in by_addr[0x63A293B] and '%fs:0x28,%rax' in by_addr[0x63A293B])
    check('canary save mov %rax,0x8(%rsp) at 0x63a2944',
          'mov' in by_addr[0x63A2944] and '%rax,0x8(%rsp)' in by_addr[0x63A2944])
    check('xor %eax,%eax before trylock at 0x63a2949',
          'xor' in by_addr[0x63A2949] and '%eax,%eax' in by_addr[0x63A2949])
    check('trylock call at 0x63a294b',
          'call' in by_addr[0x63A294B] and '63f17b0 <pthread_mutex_trylock@plt>' in by_addr[0x63A294B])
    check('trylock test %eax,%eax at 0x63a2950',
          'test' in by_addr[0x63A2950] and '%eax,%eax' in by_addr[0x63A2950])
    check('trylock-fail jne lock-wait setup at 0x63a2952',
          'jne' in by_addr[0x63A2952] and '63a2a00 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a5d0>' in by_addr[0x63A2952])
    check('acq-count addq $0x1,0x36f838(%rip) at 0x63a2958',
          'addq' in by_addr[0x63A2958] and '$0x1,0x36f838(%rip)' in by_addr[0x63A2958])
    check('owner cmp 0x6712190,%rbp at 0x63a2960',
          'cmp' in by_addr[0x63A2960] and '0x36f829(%rip),%rbp' in by_addr[0x63A2960])
    check('owner-unchanged je exit-1 mov at 0x63a2967',
          'je' in by_addr[0x63A2967] and '63a2978 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a548>' in by_addr[0x63A2967])
    check('counter addq $0x1,0x36f817(%rip) at 0x63a2969',
          'addq' in by_addr[0x63A2969] and '$0x1,0x36f817(%rip)' in by_addr[0x63A2969])
    check('owner store mov %rbp,0x36f818(%rip) at 0x63a2971',
          'mov' in by_addr[0x63A2971] and '%rbp,0x36f818(%rip)' in by_addr[0x63A2971])
    check('exit-1 mov $0x1,%ebp at 0x63a2978',
          'mov' in by_addr[0x63A2978] and '$0x1,%ebp' in by_addr[0x63A2978])
    check('caller-cond or 0x50(%rsp),%rbx at 0x63a297d',
          'or' in by_addr[0x63A297D] and '0x50(%rsp),%rbx' in by_addr[0x63A297D])
    check('caller-cond je lookup path at 0x63a2982',
          'je' in by_addr[0x63A2982] and '63a29c0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a590>' in by_addr[0x63A2982])
    check('waited-flag clear movb $0x0,0x36f83d(%rip) at 0x63a2984',
          'movb' in by_addr[0x63A2984] and '$0x0,0x36f83d(%rip)' in by_addr[0x63A2984])
    check('unlock rdi mov %r15,%rdi at 0x63a298b',
          'mov' in by_addr[0x63A298B] and '%r15,%rdi' in by_addr[0x63A298B])
    check('unlock call at 0x63a298e',
          'call' in by_addr[0x63A298E] and '63f0b70 <pthread_mutex_unlock@plt>' in by_addr[0x63A298E])
    check('canary reload mov 0x8(%rsp),%rax at 0x63a2993',
          'mov' in by_addr[0x63A2993] and '0x8(%rsp),%rax' in by_addr[0x63A2993])
    check('canary check sub %fs:0x28,%rax at 0x63a2998',
          'sub' in by_addr[0x63A2998] and '%fs:0x28,%rax' in by_addr[0x63A2998])
    check('canary fail jne stack_chk_fail at 0x63a29a1',
          'jne' in by_addr[0x63A29A1] and '63a2bcb <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a79b>' in by_addr[0x63A29A1])
    check('rsp restore add $0x18,%rsp at 0x63a29a7',
          'add' in by_addr[0x63A29A7] and '$0x18,%rsp' in by_addr[0x63A29A7])
    check('exit mov %ebp,%eax at 0x63a29ab',
          'mov' in by_addr[0x63A29AB] and '%ebp,%eax' in by_addr[0x63A29AB])
    check('ret at 0x63a29b7',
          'ret' in by_addr[0x63A29B7])
    check('resolver arg mov 0x10(%r14),%rdi at 0x63a29c0',
          'mov' in by_addr[0x63A29C0] and '0x10(%r14),%rdi' in by_addr[0x63A29C0])
    check('resolver call 0x6388310 at 0x63a29c4',
          'call' in by_addr[0x63A29C4] and '6388310 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fee0>' in by_addr[0x63A29C4])
    check('table base mov 0x50(%rax),%rdi at 0x63a29c9',
          'mov' in by_addr[0x63A29C9] and '0x50(%rax),%rdi' in by_addr[0x63A29C9])
    check('inline adjust add $0x200,%rdi at 0x63a29cd',
          'add' in by_addr[0x63A29CD] and '$0x200,%rdi' in by_addr[0x63A29CD])
    check('loader call 0x63bfb90 at 0x63a29d4',
          'call' in by_addr[0x63A29D4] and '63bfb90 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677760>' in by_addr[0x63A29D4])
    check('resolved value store mov %rax,(%rsp) at 0x63a29d9',
          'mov' in by_addr[0x63A29D9] and '%rax,(%rsp)' in by_addr[0x63A29D9])
    check('rcx==0 test %r12,%r12 at 0x63a29dd',
          'test' in by_addr[0x63A29DD] and '%r12,%r12' in by_addr[0x63A29DD])
    check('rcx==0 je exit-0 at 0x63a29e0',
          'je' in by_addr[0x63A29E0] and '63a29f5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a5c5>' in by_addr[0x63A29E0])
    check('r8==0 test %r13,%r13 at 0x63a29e2',
          'test' in by_addr[0x63A29E2] and '%r13,%r13' in by_addr[0x63A29E2])
    check('r8==0 je exit-0 at 0x63a29e5',
          'je' in by_addr[0x63A29E5] and '63a29f5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a5c5>' in by_addr[0x63A29E5])
    check('len load mov 0x0(%r13),%rdx at 0x63a29e7',
          'mov' in by_addr[0x63A29E7] and '0x0(%r13),%rdx' in by_addr[0x63A29E7])
    check('len cmp $0x8,%rdx at 0x63a29eb',
          'cmp' in by_addr[0x63A29EB] and '$0x8,%rdx' in by_addr[0x63A29EB])
    check('len!=8 jne copy dispatch at 0x63a29ef',
          'jne' in by_addr[0x63A29EF] and '63a2a18 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a5e8>' in by_addr[0x63A29EF])
    check('len==8 store mov %rax,(%r12) at 0x63a29f1',
          'mov' in by_addr[0x63A29F1] and '%rax,(%r12)' in by_addr[0x63A29F1])
    check('exit-0 xor %ebp,%ebp at 0x63a29f5',
          'xor' in by_addr[0x63A29F5] and '%ebp,%ebp' in by_addr[0x63A29F5])
    check('exit-0 jmp flag-clear at 0x63a29f7',
          'jmp' in by_addr[0x63A29F7] and '63a2984 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a554>' in by_addr[0x63A29F7])
    check('lock-wait setup lea -0x40(%r15),%rdi at 0x63a2a00',
          'lea' in by_addr[0x63A2A00] and '-0x40(%r15),%rdi' in by_addr[0x63A2A00])
    check('lock-wait call at 0x63a2a04',
          'call' in by_addr[0x63A2A04] and '63bf680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677250>' in by_addr[0x63A2A04])
    check('waited-flag set movb $0x1,0x36f7b8(%rip) at 0x63a2a09',
          'movb' in by_addr[0x63A2A09] and '$0x1,0x36f7b8(%rip)' in by_addr[0x63A2A09])
    check('lock-wait rejoin jmp trylock-success (NO retry) at 0x63a2a10',
          'jmp' in by_addr[0x63A2A10] and '63a2958 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a528>' in by_addr[0x63A2A10])
    check('copy mov $0x8,%ecx at 0x63a2a18',
          'mov' in by_addr[0x63A2A18] and '$0x8,%ecx' in by_addr[0x63A2A18])
    check('copy src mov %rsp,%r9 at 0x63a2a1d',
          'mov' in by_addr[0x63A2A1D] and '%rsp,%r9' in by_addr[0x63A2A1D])
    check('copy cmp %rcx,%rdx at 0x63a2a20',
          'cmp' in by_addr[0x63A2A20] and '%rcx,%rdx' in by_addr[0x63A2A20])
    check('copy min cmova %rcx,%rdx at 0x63a2a23',
          'cmova' in by_addr[0x63A2A23] and '%rcx,%rdx' in by_addr[0x63A2A23])
    check('copy cmp $0x8,%edx at 0x63a2a27',
          'cmp' in by_addr[0x63A2A27] and '$0x8,%edx' in by_addr[0x63A2A27])
    check('copy len<8 jb remainder at 0x63a2a2a',
          'jb' in by_addr[0x63A2A2A] and '63a2b80 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a750>' in by_addr[0x63A2A2A])
    check('copy mov %edx,%ebp at 0x63a2a30',
          'mov' in by_addr[0x63A2A30] and '%edx,%ebp' in by_addr[0x63A2A30])
    check('copy first qword store mov %rax,(%r12) at 0x63a2a32',
          'mov' in by_addr[0x63A2A32] and '%rax,(%r12)' in by_addr[0x63A2A32])
    check('copy dest lea 0x8(%r12),%rcx at 0x63a2a36',
          'lea' in by_addr[0x63A2A36] and '0x8(%r12),%rcx' in by_addr[0x63A2A36])
    check('copy last qword load mov -0x8(%r9,%rbp,1),%r14 at 0x63a2a3b',
          'mov' in by_addr[0x63A2A3B] and '-0x8(%r9,%rbp,1),%r14' in by_addr[0x63A2A3B])
    check('copy align and $0xfffffffffffffff8,%rcx at 0x63a2a40',
          'and' in by_addr[0x63A2A40] and '$0xfffffffffffffff8,%rcx' in by_addr[0x63A2A40])
    check('copy last qword store mov %r14,-0x8(%r12,%rbp,1) at 0x63a2a44',
          'mov' in by_addr[0x63A2A44] and '%r14,-0x8(%r12,%rbp,1)' in by_addr[0x63A2A44])
    check('copy sub %rcx,%r12 at 0x63a2a49',
          'sub' in by_addr[0x63A2A49] and '%rcx,%r12' in by_addr[0x63A2A49])
    check('copy sub %r12,%r9 at 0x63a2a4c',
          'sub' in by_addr[0x63A2A4C] and '%r12,%r9' in by_addr[0x63A2A4C])
    check('copy add %edx,%r12d at 0x63a2a4f',
          'add' in by_addr[0x63A2A4F] and '%edx,%r12d' in by_addr[0x63A2A4F])
    check('copy and $0xfffffff8,%r12d at 0x63a2a52',
          'and' in by_addr[0x63A2A52] and '$0xfffffff8,%r12d' in by_addr[0x63A2A52])
    check('loop-guard cmp $0x8,%r12d at 0x63a2a56',
          'cmp' in by_addr[0x63A2A56] and '$0x8,%r12d' in by_addr[0x63A2A56])
    check('loop-guard jb writeback at 0x63a2a5a',
          'jb' in by_addr[0x63A2A5A] and '63a2b97 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a767>' in by_addr[0x63A2A5A])
    check('duffs loop head mov (%r9,%rbx,1),%rax at 0x63a2a60',
          'mov' in by_addr[0x63A2A60] and '(%r9,%rbx,1),%rax' in by_addr[0x63A2A60])
    check('dispatch lea -0x1(%r12),%esi at 0x63a2a64',
          'lea' in by_addr[0x63A2A64] and '-0x1(%r12),%esi' in by_addr[0x63A2A64])
    check('dispatch mov $0x8,%edi at 0x63a2a69',
          'mov' in by_addr[0x63A2A69] and '$0x8,%edi' in by_addr[0x63A2A69])
    check('dispatch shr $0x3,%esi at 0x63a2a6e',
          'shr' in by_addr[0x63A2A6E] and '$0x3,%esi' in by_addr[0x63A2A6E])
    check('duffs first store mov %rax,(%rcx,%rbx,1) at 0x63a2a71',
          'mov' in by_addr[0x63A2A71] and '%rax,(%rcx,%rbx,1)' in by_addr[0x63A2A71])
    check('dispatch and $0x7,%esi at 0x63a2a75',
          'and' in by_addr[0x63A2A75] and '$0x7,%esi' in by_addr[0x63A2A75])
    check('dispatch cmp %r12d,%edi at 0x63a2a78',
          'cmp' in by_addr[0x63A2A78] and '%r12d,%edi' in by_addr[0x63A2A78])
    check('dispatch jae writeback at 0x63a2a7b',
          'jae' in by_addr[0x63A2A7B] and '63a2b97 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a767>' in by_addr[0x63A2A7B])
    check('dispatch test %esi,%esi at 0x63a2a81',
          'test' in by_addr[0x63A2A81] and '%esi,%esi' in by_addr[0x63A2A81])
    check('dispatch je D-block (esi==0) at 0x63a2a83',
          'je' in by_addr[0x63A2A83] and '63a2b10 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a6e0>' in by_addr[0x63A2A83])
    check('dispatch cmp $0x1,%esi at 0x63a2a89',
          'cmp' in by_addr[0x63A2A89] and '$0x1,%esi' in by_addr[0x63A2A89])
    check('dispatch je 0x63a2af9 (esi==1) at 0x63a2a8c',
          'je' in by_addr[0x63A2A8C] and '63a2af9 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a6c9>' in by_addr[0x63A2A8C])
    check('dispatch cmp $0x2,%esi at 0x63a2a8e',
          'cmp' in by_addr[0x63A2A8E] and '$0x2,%esi' in by_addr[0x63A2A8E])
    check('dispatch je 0x63a2aeb (esi==2) at 0x63a2a91',
          'je' in by_addr[0x63A2A91] and '63a2aeb <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a6bb>' in by_addr[0x63A2A91])
    check('dispatch cmp $0x3,%esi at 0x63a2a93',
          'cmp' in by_addr[0x63A2A93] and '$0x3,%esi' in by_addr[0x63A2A93])
    check('dispatch je 0x63a2ade (esi==3) at 0x63a2a96',
          'je' in by_addr[0x63A2A96] and '63a2ade <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a6ae>' in by_addr[0x63A2A96])
    check('dispatch cmp $0x4,%esi at 0x63a2a98',
          'cmp' in by_addr[0x63A2A98] and '$0x4,%esi' in by_addr[0x63A2A98])
    check('dispatch je 0x63a2ad0 (esi==4) at 0x63a2a9b',
          'je' in by_addr[0x63A2A9B] and '63a2ad0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a6a0>' in by_addr[0x63A2A9B])
    check('dispatch cmp $0x5,%esi at 0x63a2a9d',
          'cmp' in by_addr[0x63A2A9D] and '$0x5,%esi' in by_addr[0x63A2A9D])
    check('dispatch je 0x63a2ac2 (esi==5) at 0x63a2aa0',
          'je' in by_addr[0x63A2AA0] and '63a2ac2 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a692>' in by_addr[0x63A2AA0])
    check('dispatch cmp $0x6,%esi at 0x63a2aa2',
          'cmp' in by_addr[0x63A2AA2] and '$0x6,%esi' in by_addr[0x63A2AA2])
    check('dispatch je 0x63a2ab4 (esi==6) at 0x63a2aa5',
          'je' in by_addr[0x63A2AA5] and '63a2ab4 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a684>' in by_addr[0x63A2AA5])
    check('D-block mov %edi,%r14d at 0x63a2b10',
          'mov' in by_addr[0x63A2B10] and '%edi,%r14d' in by_addr[0x63A2B10])
    check('D-block add $0x40,%edi at 0x63a2b51',
          'add' in by_addr[0x63A2B51] and '$0x40,%edi' in by_addr[0x63A2B51])
    check('D-block cmp %r12d,%edi at 0x63a2b70',
          'cmp' in by_addr[0x63A2B70] and '%r12d,%edi' in by_addr[0x63A2B70])
    check('D-block jb D-block at 0x63a2b73',
          'jb' in by_addr[0x63A2B73] and '63a2b10 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a6e0>' in by_addr[0x63A2B73])
    check('D-block exit jmp writeback at 0x63a2b75',
          'jmp' in by_addr[0x63A2B75] and '63a2b97 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a767>' in by_addr[0x63A2B75])
    check('remainder test $0x4,%dl at 0x63a2b80',
          'test' in by_addr[0x63A2B80] and '$0x4,%dl' in by_addr[0x63A2B80])
    check('remainder 4-byte jne 0x63a2ba5 at 0x63a2b83',
          'jne' in by_addr[0x63A2B83] and '63a2ba5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a775>' in by_addr[0x63A2B83])
    check('remainder test %edx,%edx at 0x63a2b85',
          'test' in by_addr[0x63A2B85] and '%edx,%edx' in by_addr[0x63A2B85])
    check('remainder len==0 je writeback at 0x63a2b87',
          'je' in by_addr[0x63A2B87] and '63a2b97 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a767>' in by_addr[0x63A2B87])
    check('remainder 1-byte movzbl (%rsp),%r8d at 0x63a2b89',
          'movzbl' in by_addr[0x63A2B89] and '(%rsp),%r8d' in by_addr[0x63A2B89])
    check('remainder 1-byte store mov %r8b,(%r12) at 0x63a2b8e',
          'mov' in by_addr[0x63A2B8E] and '%r8b,(%r12)' in by_addr[0x63A2B8E])
    check('remainder test $0x2,%dl at 0x63a2b92',
          'test' in by_addr[0x63A2B92] and '$0x2,%dl' in by_addr[0x63A2B92])
    check('remainder 2-byte jne 0x63a2bba at 0x63a2b95',
          'jne' in by_addr[0x63A2B95] and '63a2bba <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a78a>' in by_addr[0x63A2B95])
    check('writeback mov %rdx,0x0(%r13) at 0x63a2b97',
          'mov' in by_addr[0x63A2B97] and '%rdx,0x0(%r13)' in by_addr[0x63A2B97])
    check('exit-22 mov $0x16,%ebp at 0x63a2b9b',
          'mov' in by_addr[0x63A2B9B] and '$0x16,%ebp' in by_addr[0x63A2B9B])
    check('exit-22 jmp flag-clear at 0x63a2ba0',
          'jmp' in by_addr[0x63A2BA0] and '63a2984 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a554>' in by_addr[0x63A2BA0])
    check('4-byte copy mov (%rsp),%eax at 0x63a2ba5',
          'mov' in by_addr[0x63A2BA5] and '(%rsp),%eax' in by_addr[0x63A2BA5])
    check('4-byte copy store mov %eax,(%r12) at 0x63a2baa',
          'mov' in by_addr[0x63A2BAA] and '%eax,(%r12)' in by_addr[0x63A2BAA])
    check('4-byte copy tail mov -0x4(%r9,%rsi,1),%edi at 0x63a2bae',
          'mov' in by_addr[0x63A2BAE] and '-0x4(%r9,%rsi,1),%edi' in by_addr[0x63A2BAE])
    check('4-byte copy tail store mov %edi,-0x4(%r12,%rsi,1) at 0x63a2bb3',
          'mov' in by_addr[0x63A2BB3] and '%edi,-0x4(%r12,%rsi,1)' in by_addr[0x63A2BB3])
    check('4-byte copy jmp writeback at 0x63a2bb8',
          'jmp' in by_addr[0x63A2BB8] and '63a2b97 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a767>' in by_addr[0x63A2BB8])
    check('2-byte copy mov %edx,%r10d at 0x63a2bba',
          'mov' in by_addr[0x63A2BBA] and '%edx,%r10d' in by_addr[0x63A2BBA])
    check('2-byte copy movzwl -0x2(%r9,%r10,1),%r11d at 0x63a2bbd',
          'movzwl' in by_addr[0x63A2BBD] and '-0x2(%r9,%r10,1),%r11d' in by_addr[0x63A2BBD])
    check('2-byte copy store mov %r11w,-0x2(%r12,%r10,1) at 0x63a2bc3',
          'mov' in by_addr[0x63A2BC3] and '%r11w,-0x2(%r12,%r10,1)' in by_addr[0x63A2BC3])
    check('2-byte copy jmp writeback at 0x63a2bc9',
          'jmp' in by_addr[0x63A2BC9] and '63a2b97 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65a767>' in by_addr[0x63A2BC9])
    check('stack_chk_fail call at 0x63a2bcb',
          'call' in by_addr[0x63A2BCB] and '63f0d70 <__stack_chk_fail@plt>' in by_addr[0x63A2BCB])
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

    check("entry reaches lock-wait site 0x63a2a04", reaches(START, 0x63A2A04))
    check("entry reaches ret 0x63a29b7", reaches(START, 0x63A29B7))
    check("entry reaches trylock 0x63a294b", reaches(START, 0x63A294B))
    check("entry reaches epilogue canary 0x63a2993", reaches(START, 0x63A2993))
    check("entry reaches resolver call 0x63a29c4", reaches(START, 0x63A29C4))
    check("entry reaches loader call 0x63a29d4", reaches(START, 0x63A29D4))
    check("entry reaches exit-1 block 0x63a2978", reaches(START, 0x63A2978))
    check("entry reaches exit-0 block 0x63a29f5", reaches(START, 0x63A29F5))
    check("entry reaches exit-22 block 0x63a2b9b", reaches(START, 0x63A2B9B))
    check("entry reaches copy dispatch 0x63a2a18", reaches(START, 0x63A2A18))
    check("entry reaches remainder entry 0x63a2b80", reaches(START, 0x63A2B80))
    check("entry reaches writeback 0x63a2b97", reaches(START, 0x63A2B97))
    check("entry reaches Duff's loop head 0x63a2a60 in the CFG only "
          "(guard analysis below shows it is never entered)",
          reaches(START, 0x63A2A60))
    check("entry reaches D-block 0x63a2b10 in the CFG only",
          reaches(START, 0x63A2B10))
    check("preds of lock-wait site 0x63a2a04 is the setup lea only",
          preds[0x63A2A04] == {0x63A2A00}, str(preds[0x63A2A04]))
    check("preds of lock-wait setup 0x63a2a00 are trylock fail and the "
          "padding nopl",
          preds[0x63A2A00] == {0x63A2952, 0x63A29F9}, str(preds[0x63A2A00]))
    check("preds of trylock 0x63a294b is the xor only",
          preds[0x63A294B] == {0x63A2949}, str(preds[0x63A294B]))
    check("preds of rejoin 0x63a2958 are trylock success and the "
          "lock-wait jmp",
          preds[0x63A2958] == {0x63A2952, 0x63A2A10}, str(preds[0x63A2958]))
    check("preds of ret 0x63a29b7 is the final pop",
          preds[0x63A29B7] == {0x63A29B5}, str(preds[0x63A29B7]))
    check("preds of epilogue canary 0x63a2993 is the unlock only",
          preds[0x63A2993] == {0x63A298E}, str(preds[0x63A2993]))
    check("preds of flag-clear block 0x63a2984 are caller-cond, exit-0 "
          "and exit-22",
          preds[0x63A2984] == {0x63A2982, 0x63A29F7, 0x63A2BA0},
          str(preds[0x63A2984]))
    check("preds of exit-0 block 0x63a29f5 are rcx==0, r8==0 and the "
          "len==8 store",
          preds[0x63A29F5] == {0x63A29E0, 0x63A29E5, 0x63A29F1},
          str(preds[0x63A29F5]))
    check("preds of exit-22 block 0x63a2b9b is the writeback only",
          preds[0x63A2B9B] == {0x63A2B97}, str(preds[0x63A2B9B]))
    check("preds of writeback 0x63a2b97 are the 8 copy exits",
          preds[0x63A2B97] == {0x63A2A5A, 0x63A2A7B, 0x63A2B0A, 0x63A2B75,
                               0x63A2B87, 0x63A2B95, 0x63A2BB8, 0x63A2BC9},
          str(preds[0x63A2B97]))
    check("preds of Duff's loop head 0x63a2a60 is the loop guard only",
          preds[0x63A2A60] == {0x63A2A5A}, str(preds[0x63A2A60]))
    check("preds of D-block 0x63a2b10 are dispatch esi==0, the jae "
          "fall-through and the loop-back",
          preds[0x63A2B10] == {0x63A2A83, 0x63A2B0A, 0x63A2B73},
          str(preds[0x63A2B10]))
    check("preds of copy dispatch 0x63a2a18 are len!=8 jne and the "
          "padding nopl",
          preds[0x63A2A18] == {0x63A29EF, 0x63A2A15}, str(preds[0x63A2A18]))
    check("preds of resolver call 0x63a29c4 is the lookup path only",
          preds[0x63A29C4] == {0x63A29C0}, str(preds[0x63A29C4]))
    check("preds of lookup path 0x63a29c0 are caller-cond je and the "
          "padding nopl",
          preds[0x63A29C0] == {0x63A2982, 0x63A29B8}, str(preds[0x63A29C0]))
    # The Duff's-device loop is present but dead: the guard computes
    # r12d = ((dest - ((dest+8) & ~7)) + 8) & ~7, which is 0 for every
    # destination alignment, so the jb at 0x63a2a5a is always taken.
    # Emulate the prologue arithmetic for all 8 alignments.
    def _guard_r12d(dest_mod_8):
        r12 = dest_mod_8 - 8
        return ((r12 + 8) & 0xFFFFFFFF) & ~7
    check("Duff's loop guard r12d is 0 for every dest alignment "
          "(loop dead)",
          all(_guard_r12d(k) == 0 for k in range(8)),
          str([_guard_r12d(k) for k in range(8)]))
    check("loop-guard jb at 0x63a2a5a targets the writeback",
          "jb" in by_addr[0x63A2A5A] and "63a2b97" in by_addr[0x63A2A5A])
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
    SITE = 0x63A2A04
    RET = 0x63A29B7
    CALL_TRYLOCK = {("CALL", 0x63A294B)}
    check("site rdi only def is lea -0x40(%r15),%rdi 0x63a2a00",
          rdi_in[SITE] == {0x63A2A00}, str(rdi_in[SITE]))
    check("site rsi is clobbered by the trylock only (no post-trylock "
          "restore in this window, like #339/#340/#341/#342/#343/#344/#345/#346/#347/#348/#349/#350/#351, unlike #338)",
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
          rbx_in[SITE] == {0x63A2934}, str(rbx_in[SITE]))
    check("site rbp def is the entry rdi save",
          rbp_in[SITE] == {0x63A292D}, str(rbp_in[SITE]))
    check("site r12 def is the entry rcx save",
          r12_in[SITE] == {0x63A2929}, str(r12_in[SITE]))
    check("site r13 def is the entry r8 save",
          r13_in[SITE] == {0x63A2924}, str(r13_in[SITE]))
    check("site r14 def is the entry rsi save",
          r14_in[SITE] == {0x63A291F}, str(r14_in[SITE]))
    check("site r15 def is the mutex lea",
          r15_in[SITE] == {0x63A2916}, str(r15_in[SITE]))
    check("rax at ret is the exit-value mov 0x63a29ab",
          rax_in[RET] == {0x63A29AB}, str(rax_in[RET]))
    check("ebp reaching defs at the flag-clear are the 3 exit values",
          rbp_in[0x63A2984] == {0x63A2978, 0x63A29F5, 0x63A2B9B},
          str(rbp_in[0x63A2984]))

    check("records lock-wait sites match census",
          [s.get("site") for s in rec.get("lock_wait_sites", [])] ==
          ["0x63a2a04"])
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
          rec.get("window", {}).get("range") == "0x63a2910..0x63a2bd0")
    check("records return value exits 0/1/22",
          rec.get("return_value", {}).get("rax") ==
          "ebp: 0/1/22 (mov %ebp,%eax at 0x63a29ab)")
    check("records entry gate absent (no gate byte in this window)",
          rec.get("entry_gate") is None)
    check("records count call absent (0x634eba0 NOT called here)",
          rec.get("count_call") is None)
    check("records resolver target 0x6388310",
          rec.get("resolver", {}).get("target") == "0x6388310")
    check("records resolver site 0x63a29c4",
          rec.get("resolver", {}).get("site") == "0x63a29c4")
    check("records loader target 0x63bfb90",
          rec.get("loader", {}).get("target") == "0x63bfb90")
    check("records loader site 0x63a29d4",
          rec.get("loader", {}).get("site") == "0x63a29d4")
    check("records inline adjust 0x200 at 0x63a29cd",
          rec.get("inline_adjust", {}).get("amount") == "0x200"
          and rec.get("inline_adjust", {}).get("site") == "0x63a29cd")
    check("records selector index is fixed +0x200 (no index register)",
          rec.get("selector", {}).get("index") ==
          "fixed +0x200 (no index register)")
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
    check("next candidate raw lu-miss 0", counts.get(0x63A2650, 0) == 0,
          str(counts.get(0x63A2650, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x63A2650, 0) == 0,
          str(bti_counts.get(0x63A2650, 0)))
    check("next candidate raw second-handler 0",
          sh_counts.get(0x63A2650, 0) == 0, str(sh_counts.get(0x63A2650, 0)))
    check("next candidate raw lock-wait 1",
          lw_counts.get(0x63A2650, 0) == 1,
          str(lw_counts.get(0x63A2650, 0)))
    # lock-wait frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 344", len(survey.get("survivors", [])) == 344,
          str(len(survey.get("survivors", []))))
    check("survey this window is a lock-wait survivor",
          "0x63a2910" in survey.get("survivors", []))
    check("survey this window is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x63a2910") == 1,
          str(survey.get("sites_per_fde", {}).get("0x63a2910")))
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
          "0x63a2910" not in survey.get("lu_miss_survivors", []))
    check("survey this window is NOT a second-handler survivor",
          "0x63a2910" not in survey.get("second_handler_survivors", []))
    check("survey next candidate is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x63a2650") == 1,
          str(survey.get("sites_per_fde", {}).get("0x63a2650")))
    nq = rec.get("next_question", {})
    check("next question is the lock-wait frontier",
          nq.get("frontier") == "lock-wait helper 0x63bf680 callers",
          str(nq.get("frontier")))
    check("next question range 0x63a2650..0x63a2910",
          nq.get("range") == "0x63a2650..0x63a2910", str(nq.get("range")))
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
          nq.get("lock_wait_site") == ["0x63a2744"],
          str(nq.get("lock_wait_site")))
    check("next question second-handler sites 0",
          nq.get("second_handler_sites") == 0,
          str(nq.get("second_handler_sites")))
    check("next question bsr 0", nq.get("bsr") == 0,
          str(nq.get("bsr")))
    check("next question rets 1",
          nq.get("ret") == ["0x63a26f7"], str(nq.get("ret")))
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
    # next candidate 0x63a2650..0x63a2910 must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x63A2650 < p[1] and p[0] < 0x63A2910]
    check("next candidate 0x63a2650 disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x63A2910 and 0x63A2650 < END))

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
    check("slug not colliding with #314-#351 lu-miss/lockwait slugs",
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
                       "RE-001-node115-lockwait-caller-1site-resolver-fixed-1f8"))

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
                    "lockwait_caller_1site_resolver_fixed_200.hex",
                    "lockwait_caller_1site_resolver_fixed_200.objdump.txt"}
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
