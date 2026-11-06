import bisect
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

SLUG = "RE-001-node115-lockwait-caller-1site-thunk"
START = 0x6386b60
END = 0x6386eb0
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
    (0x6386b60, 'endbr64', ''), (0x6386b64, 'push', '%r15'), (0x6386b66, 'push', '%r14'),
    (0x6386b68, 'mov', '$0x2,%r14d'), (0x6386b6e, 'push', '%r13'), (0x6386b70, 'push', '%r12'),
    (0x6386b72, 'push', '%rbp'), (0x6386b73, 'push', '%rbx'), (0x6386b74, 'sub', '$0x38,%rsp'),
    (0x6386b78, 'mov', '%r8,0x8(%rsp)'), (0x6386b7d, 'mov', '%fs:0x28,%rax'), (0x6386b86, 'mov', '%rax,0x28(%rsp)'),
    (0x6386b8b, 'lea', '0x179096(%rip),%rax        # 64ffc28 <__register_atfork@plt+0x10e098>'), (0x6386b92, 'cmpb', '$0x0,(%rax)'), (0x6386b95, 'je', '6386bfc <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e7cc>'),
    (0x6386b97, 'lea', '0x38b602(%rip),%r15        # 67121a0 <__register_atfork@plt+0x320610>'), (0x6386b9e, 'mov', '%rdi,%rbx'), (0x6386ba1, 'mov', '%rsi,%rbp'),
    (0x6386ba4, 'mov', '%rcx,%r13'), (0x6386ba7, 'mov', '%r15,%rdi'), (0x6386baa, 'mov', '%r9,%r12'),
    (0x6386bad, 'call', '63f17b0 <pthread_mutex_trylock@plt>'), (0x6386bb2, 'test', '%eax,%eax'), (0x6386bb4, 'jne', '6386cb0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e880>'),
    (0x6386bba, 'addq', '$0x1,0x38b5d6(%rip)        # 6712198 <__register_atfork@plt+0x320608>'), (0x6386bc2, 'cmp', '0x38b5c7(%rip),%rbx        # 6712190 <__register_atfork@plt+0x320600>'), (0x6386bc9, 'je', '6386bda <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e7aa>'),
    (0x6386bcb, 'addq', '$0x1,0x38b5b5(%rip)        # 6712188 <__register_atfork@plt+0x3205f8>'), (0x6386bd3, 'mov', '%rbx,0x38b5b6(%rip)        # 6712190 <__register_atfork@plt+0x320600>'), (0x6386bda, 'mov', '0x8(%rbp),%r14'),
    (0x6386bde, 'mov', '%r14,%rdx'), (0x6386be1, 'shr', '$0x20,%rdx'), (0x6386be5, 'je', '6386c28 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e7f8>'),
    (0x6386be7, 'mov', '$0xe,%r14d'), (0x6386bed, 'movb', '$0x0,0x38b5d4(%rip)        # 67121c8 <__register_atfork@plt+0x320638>'), (0x6386bf4, 'mov', '%r15,%rdi'),
    (0x6386bf7, 'call', '63f0b70 <pthread_mutex_unlock@plt>'), (0x6386bfc, 'mov', '0x28(%rsp),%rax'), (0x6386c01, 'sub', '%fs:0x28,%rax'),
    (0x6386c0a, 'jne', '6386e7c <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63ea4c>'), (0x6386c10, 'add', '$0x38,%rsp'), (0x6386c14, 'mov', '%r14d,%eax'),
    (0x6386c17, 'pop', '%rbx'), (0x6386c18, 'pop', '%rbp'), (0x6386c19, 'pop', '%r12'),
    (0x6386c1b, 'pop', '%r13'), (0x6386c1d, 'pop', '%r14'), (0x6386c1f, 'pop', '%r15'),
    (0x6386c21, 'ret', ''), (0x6386c22, 'nopw', '0x0(%rax,%rax,1)'), (0x6386c28, 'call', '634eba0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x606770>'),
    (0x6386c2d, 'cmp', '%r14d,%eax'), (0x6386c30, 'jbe', '6386be7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e7b7>'), (0x6386c32, 'lea', '0x182a87(%rip),%rcx        # 65096c0 <__register_atfork@plt+0x117b30>'),
    (0x6386c39, 'mov', '(%rcx,%r14,8),%rsi'), (0x6386c3d, 'test', '%rsi,%rsi'), (0x6386c40, 'je', '6386be7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e7b7>'),
    (0x6386c42, 'test', '%r12,%r12'), (0x6386c45, 'je', '6386c61 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e831>'), (0x6386c47, 'cmpq', '$0x8,0x70(%rsp)'),
    (0x6386c4d, 'jne', '6386d00 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e8d0>'), (0x6386c53, 'mov', '(%r12),%rdi'), (0x6386c57, 'lea', '0x20(%rsp),%r12'),
    (0x6386c5c, 'mov', '%rdi,0x20(%rsp)'), (0x6386c61, 'lea', '0x18(%rsp),%rbp'), (0x6386c66, 'mov', '%r12,%rcx'),
    (0x6386c69, 'mov', '%rbx,%rdi'), (0x6386c6c, 'mov', '$0xe,%r14d'), (0x6386c72, 'mov', '%rbp,%rdx'),
    (0x6386c75, 'call', '63643f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x61bfc0>'), (0x6386c7a, 'test', '%al,%al'), (0x6386c7c, 'jne', '6386bed <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e7bd>'),
    (0x6386c82, 'test', '%r13,%r13'), (0x6386c85, 'je', '6386ca3 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e873>'), (0x6386c87, 'mov', '0x8(%rsp),%rsi'),
    (0x6386c8c, 'test', '%rsi,%rsi'), (0x6386c8f, 'je', '6386ca3 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e873>'), (0x6386c91, 'mov', '(%rsi),%r8'),
    (0x6386c94, 'cmp', '$0x8,%r8'), (0x6386c98, 'jne', '6386cc5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e895>'), (0x6386c9a, 'mov', '0x18(%rsp),%r9'),
    (0x6386c9f, 'mov', '%r9,0x0(%r13)'), (0x6386ca3, 'xor', '%r14d,%r14d'), (0x6386ca6, 'jmp', '6386bed <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e7bd>'),
    (0x6386cab, 'nopl', '0x0(%rax,%rax,1)'), (0x6386cb0, 'lea', '-0x40(%r15),%rdi'), (0x6386cb4, 'call', '63bf680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677250>'),
    (0x6386cb9, 'movb', '$0x1,0x38b508(%rip)        # 67121c8 <__register_atfork@plt+0x320638>'), (0x6386cc0, 'jmp', '6386bba <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e78a>'), (0x6386cc5, 'mov', '$0x8,%edx'),
    (0x6386cca, 'cmp', '%rdx,%r8'), (0x6386ccd, 'cmovbe', '%r8,%rdx'), (0x6386cd1, 'cmp', '$0x8,%edx'),
    (0x6386cd4, 'jae', '6386d0b <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e8db>'), (0x6386cd6, 'test', '$0x4,%dl'), (0x6386cd9, 'jne', '6386e81 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63ea51>'),
    (0x6386cdf, 'test', '%edx,%edx'), (0x6386ce1, 'je', '6386cf5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e8c5>'), (0x6386ce3, 'movzbl', '0x18(%rsp),%ebx'),
    (0x6386ce8, 'mov', '%bl,0x0(%r13)'), (0x6386cec, 'test', '$0x2,%dl'), (0x6386cef, 'jne', '6386e9c <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63ea6c>'),
    (0x6386cf5, 'mov', '0x8(%rsp),%rbp'), (0x6386cfa, 'mov', '%rdx,0x0(%rbp)'), (0x6386cfe, 'xchg', '%ax,%ax'),
    (0x6386d00, 'mov', '$0x16,%r14d'), (0x6386d06, 'jmp', '6386bed <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e7bd>'), (0x6386d0b, 'lea', '0x8(%r13),%r9'),
    (0x6386d0f, 'mov', '0x18(%rsp),%rdi'), (0x6386d14, 'mov', '%r13,%rax'), (0x6386d17, 'mov', '%edx,%r12d'),
    (0x6386d1a, 'and', '$0xfffffffffffffff8,%r9'), (0x6386d1e, 'sub', '%r9,%rax'), (0x6386d21, 'mov', '%rdi,0x0(%r13)'),
    (0x6386d25, 'mov', '-0x8(%rbp,%r12,1),%rsi'), (0x6386d2a, 'sub', '%rax,%rbp'), (0x6386d2d, 'add', '%edx,%eax'),
    (0x6386d2f, 'and', '$0xfffffff8,%eax'), (0x6386d32, 'mov', '%rsi,-0x8(%r13,%r12,1)'), (0x6386d37, 'cmp', '$0x8,%eax'),
    (0x6386d3a, 'jb', '6386cf5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e8c5>'), (0x6386d3c, 'xor', '%r11d,%r11d'), (0x6386d3f, 'lea', '-0x1(%rax),%r10d'),
    (0x6386d43, 'mov', '$0x8,%r14d'), (0x6386d49, 'mov', '%eax,%r13d'), (0x6386d4c, 'mov', '0x0(%rbp,%r11,1),%r8'),
    (0x6386d51, 'shr', '$0x3,%r10d'), (0x6386d55, 'and', '$0x7,%r10d'), (0x6386d59, 'mov', '%r8,(%r9,%r11,1)'),
    (0x6386d5d, 'cmp', '%eax,%r14d'), (0x6386d60, 'jae', '6386cf5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e8c5>'), (0x6386d62, 'test', '%r10d,%r10d'),
    (0x6386d65, 'je', '6386e07 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e9d7>'), (0x6386d6b, 'cmp', '$0x1,%r10d'), (0x6386d6f, 'je', '6386dee <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e9be>'),
    (0x6386d71, 'cmp', '$0x2,%r10d'), (0x6386d75, 'je', '6386dde <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e9ae>'), (0x6386d77, 'cmp', '$0x3,%r10d'),
    (0x6386d7b, 'je', '6386dce <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e99e>'), (0x6386d7d, 'cmp', '$0x4,%r10d'), (0x6386d81, 'je', '6386dbe <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e98e>'),
    (0x6386d83, 'cmp', '$0x5,%r10d'), (0x6386d87, 'je', '6386dae <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e97e>'), (0x6386d89, 'cmp', '$0x6,%r10d'),
    (0x6386d8d, 'je', '6386d9e <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e96e>'), (0x6386d8f, 'mov', '0x0(%rbp,%r14,1),%rbx'), (0x6386d94, 'mov', '%rbx,(%r9,%r14,1)'),
    (0x6386d98, 'mov', '$0x10,%r14d'), (0x6386d9e, 'mov', '%r14d,%ecx'), (0x6386da1, 'add', '$0x8,%r14d'),
    (0x6386da5, 'mov', '0x0(%rbp,%rcx,1),%rdi'), (0x6386daa, 'mov', '%rdi,(%r9,%rcx,1)'), (0x6386dae, 'mov', '%r14d,%r12d'),
    (0x6386db1, 'add', '$0x8,%r14d'), (0x6386db5, 'mov', '0x0(%rbp,%r12,1),%rsi'), (0x6386dba, 'mov', '%rsi,(%r9,%r12,1)'),
    (0x6386dbe, 'mov', '%r14d,%eax'), (0x6386dc1, 'add', '$0x8,%r14d'), (0x6386dc5, 'mov', '0x0(%rbp,%rax,1),%r10'),
    (0x6386dca, 'mov', '%r10,(%r9,%rax,1)'), (0x6386dce, 'mov', '%r14d,%r11d'), (0x6386dd1, 'add', '$0x8,%r14d'),
    (0x6386dd5, 'mov', '0x0(%rbp,%r11,1),%r8'), (0x6386dda, 'mov', '%r8,(%r9,%r11,1)'), (0x6386dde, 'mov', '%r14d,%ebx'),
    (0x6386de1, 'add', '$0x8,%r14d'), (0x6386de5, 'mov', '0x0(%rbp,%rbx,1),%rcx'), (0x6386dea, 'mov', '%rcx,(%r9,%rbx,1)'),
    (0x6386dee, 'mov', '%r14d,%edi'), (0x6386df1, 'add', '$0x8,%r14d'), (0x6386df5, 'mov', '0x0(%rbp,%rdi,1),%r12'),
    (0x6386dfa, 'mov', '%r12,(%r9,%rdi,1)'), (0x6386dfe, 'cmp', '%r13d,%r14d'), (0x6386e01, 'jae', '6386cf5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e8c5>'),
    (0x6386e07, 'mov', '%r14d,%esi'), (0x6386e0a, 'lea', '0x8(%r14),%r10d'), (0x6386e0e, 'lea', '0x10(%r14),%ebx'),
    (0x6386e12, 'mov', '0x0(%rbp,%rsi,1),%rax'), (0x6386e17, 'lea', '0x18(%r14),%ecx'), (0x6386e1b, 'lea', '0x20(%r14),%r12d'),
    (0x6386e1f, 'mov', '%rax,(%r9,%rsi,1)'), (0x6386e23, 'mov', '0x0(%rbp,%r10,1),%r11'), (0x6386e28, 'lea', '0x28(%r14),%eax'),
    (0x6386e2c, 'mov', '%r11,(%r9,%r10,1)'), (0x6386e30, 'mov', '0x0(%rbp,%rbx,1),%r8'), (0x6386e35, 'lea', '0x30(%r14),%r11d'),
    (0x6386e39, 'mov', '%r8,(%r9,%rbx,1)'), (0x6386e3d, 'mov', '0x0(%rbp,%rcx,1),%rdi'), (0x6386e42, 'mov', '%rdi,(%r9,%rcx,1)'),
    (0x6386e46, 'mov', '0x0(%rbp,%r12,1),%rsi'), (0x6386e4b, 'lea', '0x38(%r14),%ecx'), (0x6386e4f, 'add', '$0x40,%r14d'),
    (0x6386e53, 'mov', '%rsi,(%r9,%r12,1)'), (0x6386e57, 'mov', '0x0(%rbp,%rax,1),%r10'), (0x6386e5c, 'mov', '%r10,(%r9,%rax,1)'),
    (0x6386e60, 'mov', '0x0(%rbp,%r11,1),%rbx'), (0x6386e65, 'mov', '%rbx,(%r9,%r11,1)'), (0x6386e69, 'mov', '0x0(%rbp,%rcx,1),%r8'),
    (0x6386e6e, 'mov', '%r8,(%r9,%rcx,1)'), (0x6386e72, 'cmp', '%r13d,%r14d'), (0x6386e75, 'jb', '6386e07 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e9d7>'),
    (0x6386e77, 'jmp', '6386cf5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e8c5>'), (0x6386e7c, 'call', '63f0d70 <__stack_chk_fail@plt>'), (0x6386e81, 'mov', '0x18(%rsp),%r10d'),
    (0x6386e86, 'mov', '%edx,%r11d'), (0x6386e89, 'mov', '%r10d,0x0(%r13)'), (0x6386e8d, 'mov', '-0x4(%rbp,%r11,1),%eax'),
    (0x6386e92, 'mov', '%eax,-0x4(%r13,%r11,1)'), (0x6386e97, 'jmp', '6386cf5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e8c5>'), (0x6386e9c, 'mov', '%edx,%r14d'),
    (0x6386e9f, 'movzwl', '-0x2(%rbp,%r14,1),%ecx'), (0x6386ea5, 'mov', '%cx,-0x2(%r13,%r14,1)'), (0x6386eab, 'jmp', '6386cf5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e8c5>'),
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
    check("target FDE size 848", END - START == 848)
    prev = fdes[i - 1]
    check("prev FDE 0x6386940..0x6386b54",
          prev == (0x6386940, 0x6386B54), str(prev))
    check("prev gap 12 (0xcc padding)", START - prev[1] == 12)
    check("prev gap bytes are 0xcc int3 padding",
          node[toff(prev[1]):toff(START)] == b"\xcc" * 12)
    nxt = fdes[i + 1]
    check("next FDE 0x6386eb0..0x6387420",
          nxt == (0x6386EB0, 0x6387420), str(nxt))
    check("next gap 0 (next FDE starts at END)", nxt[0] - END == 0)
    check("next FDE starts endbr64",
          node[toff(nxt[0]):toff(nxt[0]) + 4] == b"\xf3\x0f\x1e\xfa")
    check("prev FDE end is 12 bytes before this FDE start",
          prev[1] == START - 12)
    check("thunk FDE 0x63643f0..0x6364400",
          fdes[bisect.bisect_left(starts, 0x63643F0)] ==
          (0x63643F0, 0x6364400))
    check("count FDE 0x634eba0..0x634ebab",
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
    check("next-question FDE 0x6387ff0..0x6388303",
          fdes[bisect.bisect_left(starts, 0x6387FF0)] ==
          (0x6387FF0, 0x6388303))
    check("#321 shared FDE 0x63c9650..0x63c9c80",
          fdes[bisect.bisect_left(starts, 0x63C9650)] ==
          (0x63C9650, 0x63C9C80))

    hexb = read(os.path.join(PACKET, "lockwait_caller_1site_thunk.hex"))
    check("hex exhibit raw bytes 848", len(hexb) == 848, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])
    objdump = read(os.path.join(
        PACKET, "lockwait_caller_1site_thunk.objdump.txt")).decode()
    lines = strict_lines(objdump)
    check("strict lines 213", len(lines) == 213, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if mnemonic_of(l) == "call"]
    check("call lines 6", len(calls) == 6, str(len(calls)))
    rets = [l for l in lines if mnemonic_of(l) == "ret"]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x6386c21",
          sorted(addr_of(l) for l in rets) == [0x6386C21],
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
    expect = {0x634EBA0: 1, 0x63643F0: 1, 0x63BF680: 1, 0x63F0B70: 1,
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
    check("lock-wait site is 0x6386cb4",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63bf680" in l) == [0x6386CB4])
    check("resolver 0x6365150 called 0 times", tgt.get(0x6365150, 0) == 0,
          str(tgt.get(0x6365150, 0)))
    check("count call 0x634eba0 1 time at 0x6386c28",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "634eba0" in l) == [0x6386C28])
    check("thunk call 0x63643f0 1 time at 0x6386c75",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63643f0" in l) == [0x6386C75])
    check("stack_chk_fail plt call 1 at 0x6386e7c",
          tgt.get(0x63F0D70, 0) == 1, str(tgt.get(0x63F0D70, 0)))
    check("trylock plt call 1 at 0x6386bad",
          tgt.get(0x63F17B0, 0) == 1, str(tgt.get(0x63F17B0, 0)))
    check("unlock plt call 1 at 0x6386bf7",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63f0b70" in l) == [0x6386BF7])
    check("no #321 window call", tgt.get(0x63C9650, 0) == 0,
          str(tgt.get(0x63C9650, 0)))
    plt_calls = [l for l in calls if "@plt" in l]
    check("PLT calls 3 (by @plt suffix, not address range)",
          len(plt_calls) == 3, str(len(plt_calls)))
    check("distinct PLT targets 3",
          len({re.search(r"\tcall\s+([0-9a-f]+)", l).group(1)
               for l in plt_calls}) == 3)
    check("no internal .text call is counted as PLT",
          not any(("634eba0" in l or "63643f0" in l) and "@plt" in l
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
                  ("#334", 0x635F780), ("#335", 0x6386110),
                  ("#336", 0x63CE510)):
        check("%s window not called" % _w, tgt.get(_a, 0) == 0,
              str(tgt.get(_a, 0)))

    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", len(bsr) == 0, str([hex(addr_of(l)) for l in bsr]))
    check("shr exactly 2 at 0x6386be1/0x6386d51",
          sorted(addr_of(l) for l in lines
                 if mnemonic_of(l) == "shr") ==
          [0x6386BE1, 0x6386D51])
    check("shr at 0x6386be1 is $0x20 (high-32 extract)",
          "$0x20,%rdx" in operands_of(by_addr[0x6386BE1]))
    check("shr at 0x6386d51 is $0x3 (copy remainder)",
          "$0x3,%r10d" in operands_of(by_addr[0x6386D51]))
    check("shl 0",
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
    check("jump lines 34", len(jmps) == 34, str(len(jmps)))

    def jump_target(line):
        m = re.search(r"\s([0-9a-f]{6,})\s*<", line)
        return int(m.group(1), 16) if m else None

    outside = []
    for l in jmps:
        t = jump_target(l)
        if t is not None and not (START <= t < END):
            outside.append((addr_of(l), t))
    check("jump closure: 0 outside the window", outside == [], str(outside))
    check("jump targets are exactly the 34 branches",
          sorted(jump_target(l) for l in jmps) ==
          [0x6386BBA, 0x6386BDA, 0x6386BE7, 0x6386BE7, 0x6386BED, 0x6386BED,
          0x6386BED, 0x6386BFC, 0x6386C28, 0x6386C61, 0x6386CA3, 0x6386CA3,
          0x6386CB0, 0x6386CC5, 0x6386CF5, 0x6386CF5, 0x6386CF5, 0x6386CF5,
          0x6386CF5, 0x6386CF5, 0x6386CF5, 0x6386D00, 0x6386D0B, 0x6386D9E,
          0x6386DAE, 0x6386DBE, 0x6386DCE, 0x6386DDE, 0x6386DEE, 0x6386E07,
          0x6386E07, 0x6386E7C, 0x6386E81, 0x6386E9C],
          str(sorted(jump_target(l) for l in jmps)))
    check("endbr64 count 1",
          sum(1 for l in lines if "endbr64" in l) == 1)
    check("entry is endbr64 at 0x6386b60",
          "endbr64" in by_addr[START])
    check("canary present: 2 fs:0x28 lines",
          sum(1 for l in lines if "%fs:0x28" in l) == 2)
    check("canary load at 0x6386b7d",
          "mov" in by_addr[0x6386B7D] and "%fs:0x28,%rax" in by_addr[0x6386B7D])
    check("canary save to 0x28(%rsp) at 0x6386b86",
          "mov" in by_addr[0x6386B86] and "%rax,0x28(%rsp)" in by_addr[0x6386B86])
    check("canary check sub at 0x6386c01",
          "sub" in by_addr[0x6386C01] and "%fs:0x28,%rax" in by_addr[0x6386C01])
    check("canary fail jne to stack_chk_fail at 0x6386c0a",
          "jne" in by_addr[0x6386C0A] and "6386e7c" in by_addr[0x6386C0A])
    check("TLS flag check absent: 0 fs:0x330 lines",
          sum(1 for l in lines if "%fs:0x330" in l) == 0)
    check("no prefetch instructions",
          not any("prefetch" in l for l in lines))
    check("tzcnt 0",
          [l for l in lines if mnemonic_of(l) == "tzcnt"] == [])
    check("entry default exit mov $0x2,%r14d at 0x6386b68",
          "mov" in by_addr[0x6386B68] and "$0x2,%r14d" in by_addr[0x6386B68])
    check("entry r8 save mov %r8,0x8(%rsp) at 0x6386b78",
          "mov" in by_addr[0x6386B78] and "%r8,0x8(%rsp)" in by_addr[0x6386B78])
    check("entry gate lea 0x64ffc28 at 0x6386b8b",
          "lea" in by_addr[0x6386B8B] and "64ffc28" in by_addr[0x6386B8B])
    check("entry gate cmpb $0x0,(%rax) at 0x6386b92",
          "cmpb" in by_addr[0x6386B92] and "$0x0,(%rax)" in by_addr[0x6386B92])
    check("entry gate je epilogue at 0x6386b95",
          "je" in by_addr[0x6386B95] and "6386bfc" in by_addr[0x6386B95])
    check("mutex lea 0x67121a0 at 0x6386b97",
          "lea" in by_addr[0x6386B97] and "67121a0" in by_addr[0x6386B97])
    check("entry rdi save mov %rdi,%rbx at 0x6386b9e",
          "mov" in by_addr[0x6386B9E] and "%rdi,%rbx" in by_addr[0x6386B9E])
    check("entry rsi save mov %rsi,%rbp at 0x6386ba1",
          "mov" in by_addr[0x6386BA1] and "%rsi,%rbp" in by_addr[0x6386BA1])
    check("entry rcx save mov %rcx,%r13 at 0x6386ba4",
          "mov" in by_addr[0x6386BA4] and "%rcx,%r13" in by_addr[0x6386BA4])
    check("entry r9 save mov %r9,%r12 at 0x6386baa",
          "mov" in by_addr[0x6386BAA] and "%r9,%r12" in by_addr[0x6386BAA])
    check("trylock call at 0x6386bad",
          "call" in by_addr[0x6386BAD] and "63f17b0" in by_addr[0x6386BAD])
    check("trylock-fail jne lock-wait setup at 0x6386bb4",
          "jne" in by_addr[0x6386BB4] and "6386cb0" in by_addr[0x6386BB4])
    check("acq-count addq $0x1,0x6712198 at 0x6386bba",
          "addq" in by_addr[0x6386BBA] and "0x38b5d6(%rip)" in by_addr[0x6386BBA])
    check("owner cmp 0x6712190,%rbx at 0x6386bc2",
          "cmp" in by_addr[0x6386BC2] and "0x38b5c7(%rip)" in by_addr[0x6386BC2])
    check("owner-change je 0x6386bda at 0x6386bc9",
          "je" in by_addr[0x6386BC9] and "6386bda" in by_addr[0x6386BC9])
    check("counter addq $0x1,0x6712188 at 0x6386bcb",
          "addq" in by_addr[0x6386BCB] and "0x38b5b5(%rip)" in by_addr[0x6386BCB])
    check("owner store mov %rbx,0x6712190 at 0x6386bd3",
          "mov" in by_addr[0x6386BD3] and "0x38b5b6(%rip)" in by_addr[0x6386BD3])
    check("index load mov 0x8(%rbp),%r14 at 0x6386bda",
          "mov" in by_addr[0x6386BDA] and "0x8(%rbp),%r14" in by_addr[0x6386BDA])
    check("index mov %r14,%rdx at 0x6386bde",
          "mov" in by_addr[0x6386BDE] and "%r14,%rdx" in by_addr[0x6386BDE])
    check("high-32 je count call at 0x6386be5",
          "je" in by_addr[0x6386BE5] and "6386c28" in by_addr[0x6386BE5])
    check("exit-14 mov $0xe,%r14d at 0x6386be7",
          "mov" in by_addr[0x6386BE7] and "$0xe,%r14d" in by_addr[0x6386BE7])
    check("waited-flag clear movb $0x0,0x67121c8 at 0x6386bed",
          "movb" in by_addr[0x6386BED] and "0x38b5d4(%rip)" in by_addr[0x6386BED])
    check("unlock call at 0x6386bf7",
          "call" in by_addr[0x6386BF7] and "63f0b70" in by_addr[0x6386BF7])
    check("count call at 0x6386c28",
          "call" in by_addr[0x6386C28] and "634eba0" in by_addr[0x6386C28])
    check("count cmp %r14d,%eax at 0x6386c2d",
          "cmp" in by_addr[0x6386C2D] and "%r14d,%eax" in by_addr[0x6386C2D])
    check("count jbe exit-14 at 0x6386c30",
          "jbe" in by_addr[0x6386C30] and "6386be7" in by_addr[0x6386C30])
    check("table lea 0x65096c0 at 0x6386c32",
          "lea" in by_addr[0x6386C32] and "65096c0" in by_addr[0x6386C32])
    check("table load mov (%rcx,%r14,8),%rsi at 0x6386c39",
          "mov" in by_addr[0x6386C39] and "(%rcx,%r14,8),%rsi" in by_addr[0x6386C39])
    check("NULL-entry je exit-14 at 0x6386c40",
          "je" in by_addr[0x6386C40] and "6386be7" in by_addr[0x6386C40])
    check("test %r12,%r12 at 0x6386c42",
          "test" in by_addr[0x6386C42] and "%r12,%r12" in by_addr[0x6386C42])
    check("r9==0 je resolver setup at 0x6386c45",
          "je" in by_addr[0x6386C45] and "6386c61" in by_addr[0x6386C45])
    check("7th-arg cmpq $0x8,0x70(%rsp) at 0x6386c47",
          "cmpq" in by_addr[0x6386C47] and "$0x8,0x70(%rsp)" in by_addr[0x6386C47])
    check("7th-arg jne exit-22 at 0x6386c4d",
          "jne" in by_addr[0x6386C4D] and "6386d00" in by_addr[0x6386C4D])
    check("mov (%r12),%rdi at 0x6386c53",
          "mov" in by_addr[0x6386C53] and "(%r12),%rdi" in by_addr[0x6386C53])
    check("lea 0x20(%rsp),%r12 at 0x6386c57",
          "lea" in by_addr[0x6386C57] and "0x20(%rsp),%r12" in by_addr[0x6386C57])
    check("mov %rdi,0x20(%rsp) at 0x6386c5c",
          "mov" in by_addr[0x6386C5C] and "%rdi,0x20(%rsp)" in by_addr[0x6386C5C])
    check("resolver out lea 0x18(%rsp),%rbp at 0x6386c61",
          "lea" in by_addr[0x6386C61] and "0x18(%rsp),%rbp" in by_addr[0x6386C61])
    check("resolver rcx mov %r12,%rcx at 0x6386c66",
          "mov" in by_addr[0x6386C66] and "%r12,%rcx" in by_addr[0x6386C66])
    check("resolver rdi mov %rbx,%rdi at 0x6386c69",
          "mov" in by_addr[0x6386C69] and "%rbx,%rdi" in by_addr[0x6386C69])
    check("resolver exit-14 preset mov $0xe,%r14d at 0x6386c6c",
          "mov" in by_addr[0x6386C6C] and "$0xe,%r14d" in by_addr[0x6386C6C])
    check("resolver rdx mov %rbp,%rdx at 0x6386c72",
          "mov" in by_addr[0x6386C72] and "%rbp,%rdx" in by_addr[0x6386C72])
    check("thunk call at 0x6386c75",
          "call" in by_addr[0x6386C75] and "63643f0" in by_addr[0x6386C75])
    check("thunk test %al,%al at 0x6386c7a",
          "test" in by_addr[0x6386C7A] and "%al,%al" in by_addr[0x6386C7A])
    check("thunk-nonzero jne flag-clear at 0x6386c7c",
          "jne" in by_addr[0x6386C7C] and "6386bed" in by_addr[0x6386C7C])
    check("test %r13,%r13 at 0x6386c82",
          "test" in by_addr[0x6386C82] and "%r13,%r13" in by_addr[0x6386C82])
    check("rcx==0 je exit-0 at 0x6386c85",
          "je" in by_addr[0x6386C85] and "6386ca3" in by_addr[0x6386C85])
    check("mov 0x8(%rsp),%rsi at 0x6386c87",
          "mov" in by_addr[0x6386C87] and "0x8(%rsp),%rsi" in by_addr[0x6386C87])
    check("r8==0 je exit-0 at 0x6386c8f",
          "je" in by_addr[0x6386C8F] and "6386ca3" in by_addr[0x6386C8F])
    check("length load mov (%rsi),%r8 at 0x6386c91",
          "mov" in by_addr[0x6386C91] and "(%rsi),%r8" in by_addr[0x6386C91])
    check("length cmp $0x8,%r8 at 0x6386c94",
          "cmp" in by_addr[0x6386C94] and "$0x8,%r8" in by_addr[0x6386C94])
    check("len!=8 jne copy dispatch at 0x6386c98",
          "jne" in by_addr[0x6386C98] and "6386cc5" in by_addr[0x6386C98])
    check("resolved mov 0x18(%rsp),%r9 at 0x6386c9a",
          "mov" in by_addr[0x6386C9A] and "0x18(%rsp),%r9" in by_addr[0x6386C9A])
    check("resolved store mov %r9,0x0(%r13) at 0x6386c9f",
          "mov" in by_addr[0x6386C9F] and "%r9,0x0(%r13)" in by_addr[0x6386C9F])
    check("exit-0 xor %r14d,%r14d at 0x6386ca3",
          "xor" in by_addr[0x6386CA3] and "%r14d,%r14d" in by_addr[0x6386CA3])
    check("exit-0 jmp flag-clear at 0x6386ca6",
          "jmp" in by_addr[0x6386CA6] and "6386bed" in by_addr[0x6386CA6])
    check("copy mov $0x8,%edx at 0x6386cc5",
          "mov" in by_addr[0x6386CC5] and "$0x8,%edx" in by_addr[0x6386CC5])
    check("copy cmp %rdx,%r8 at 0x6386cca",
          "cmp" in by_addr[0x6386CCA] and "%rdx,%r8" in by_addr[0x6386CCA])
    check("copy min cmovbe %r8,%rdx at 0x6386ccd",
          "cmovbe" in by_addr[0x6386CCD] and "%r8,%rdx" in by_addr[0x6386CCD])
    check("copy cmp $0x8,%edx at 0x6386cd1",
          "cmp" in by_addr[0x6386CD1] and "$0x8,%edx" in by_addr[0x6386CD1])
    check("copy jae big-copy at 0x6386cd4",
          "jae" in by_addr[0x6386CD4] and "6386d0b" in by_addr[0x6386CD4])
    check("copy test $0x4,%dl at 0x6386cd6",
          "test" in by_addr[0x6386CD6] and "$0x4,%dl" in by_addr[0x6386CD6])
    check("copy 4-byte jne 0x6386e81 at 0x6386cd9",
          "jne" in by_addr[0x6386CD9] and "6386e81" in by_addr[0x6386CD9])
    check("copy test %edx,%edx at 0x6386cdf",
          "test" in by_addr[0x6386CDF] and "%edx,%edx" in by_addr[0x6386CDF])
    check("copy len==0 je writeback at 0x6386ce1",
          "je" in by_addr[0x6386CE1] and "6386cf5" in by_addr[0x6386CE1])
    check("copy 1-byte movzbl 0x18(%rsp),%ebx at 0x6386ce3",
          "movzbl" in by_addr[0x6386CE3] and "0x18(%rsp),%ebx" in by_addr[0x6386CE3])
    check("copy 1-byte store mov %bl,0x0(%r13) at 0x6386ce8",
          "mov" in by_addr[0x6386CE8] and "%bl,0x0(%r13)" in by_addr[0x6386CE8])
    check("copy test $0x2,%dl at 0x6386cec",
          "test" in by_addr[0x6386CEC] and "$0x2,%dl" in by_addr[0x6386CEC])
    check("copy 2-byte jne 0x6386e9c at 0x6386cef",
          "jne" in by_addr[0x6386CEF] and "6386e9c" in by_addr[0x6386CEF])
    check("writeback mov 0x8(%rsp),%rbp at 0x6386cf5",
          "mov" in by_addr[0x6386CF5] and "0x8(%rsp),%rbp" in by_addr[0x6386CF5])
    check("writeback mov %rdx,0x0(%rbp) at 0x6386cfa",
          "mov" in by_addr[0x6386CFA] and "%rdx,0x0(%rbp)" in by_addr[0x6386CFA])
    check("exit-22 mov $0x16,%r14d at 0x6386d00",
          "mov" in by_addr[0x6386D00] and "$0x16,%r14d" in by_addr[0x6386D00])
    check("exit-22 jmp flag-clear at 0x6386d06",
          "jmp" in by_addr[0x6386D06] and "6386bed" in by_addr[0x6386D06])
    check("big-copy lea 0x8(%r13),%r9 at 0x6386d0b",
          "lea" in by_addr[0x6386D0B] and "0x8(%r13),%r9" in by_addr[0x6386D0B])
    check("big-copy first qword store mov %rdi,0x0(%r13) at 0x6386d21",
          "mov" in by_addr[0x6386D21] and "%rdi,0x0(%r13)" in by_addr[0x6386D21])
    check("big-copy remainder lea -0x1(%rax),%r10d at 0x6386d3f",
          "lea" in by_addr[0x6386D3F] and "-0x1(%rax),%r10d" in by_addr[0x6386D3F])
    check("big-copy remainder and $0x7,%r10d at 0x6386d55",
          "and" in by_addr[0x6386D55] and "$0x7,%r10d" in by_addr[0x6386D55])
    check("big-copy 8-block add $0x40,%r14d at 0x6386e4f",
          "add" in by_addr[0x6386E4F] and "$0x40,%r14d" in by_addr[0x6386E4F])
    check("big-copy loop-back jb 0x6386e07 at 0x6386e75",
          "jb" in by_addr[0x6386E75] and "6386e07" in by_addr[0x6386E75])
    check("4-byte copy mov 0x18(%rsp),%r10d at 0x6386e81",
          "mov" in by_addr[0x6386E81] and "0x18(%rsp),%r10d" in by_addr[0x6386E81])
    check("2-byte copy movzwl -0x2(%rbp,%r14,1),%ecx at 0x6386e9f",
          "movzwl" in by_addr[0x6386E9F] and "-0x2(%rbp,%r14,1),%ecx" in by_addr[0x6386E9F])
    check("lock-wait setup lea -0x40(%r15),%rdi at 0x6386cb0",
          "lea" in by_addr[0x6386CB0] and "-0x40(%r15),%rdi" in by_addr[0x6386CB0])
    check("lock-wait call at 0x6386cb4",
          "call" in by_addr[0x6386CB4] and "63bf680" in by_addr[0x6386CB4])
    check("waited-flag set movb $0x1,0x67121c8 at 0x6386cb9",
          "movb" in by_addr[0x6386CB9] and "0x38b508(%rip)" in by_addr[0x6386CB9])
    check("lock-wait rejoin jmp 0x6386bba at 0x6386cc0 (trylock RETRY)",
          "jmp" in by_addr[0x6386CC0] and "6386bba" in by_addr[0x6386CC0])
    check("epilogue mov %r14d,%eax at 0x6386c14",
          "mov" in by_addr[0x6386C14] and "%r14d,%eax" in by_addr[0x6386C14])

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

    check("entry reaches lock-wait site 0x6386cb4", reaches(START, 0x6386CB4))
    check("entry reaches ret 0x6386c21", reaches(START, 0x6386C21))
    check("entry reaches trylock 0x6386bad", reaches(START, 0x6386BAD))
    check("entry reaches epilogue canary 0x6386bfc", reaches(START, 0x6386BFC))
    check("entry reaches count call 0x6386c28", reaches(START, 0x6386C28))
    check("entry reaches thunk call 0x6386c75", reaches(START, 0x6386C75))
    check("entry reaches exit-14 block 0x6386be7", reaches(START, 0x6386BE7))
    check("entry reaches exit-0 block 0x6386ca3", reaches(START, 0x6386CA3))
    check("entry reaches exit-22 block 0x6386d00", reaches(START, 0x6386D00))
    check("entry reaches copy dispatch 0x6386cc5", reaches(START, 0x6386CC5))
    check("entry reaches big-copy loop 0x6386e07", reaches(START, 0x6386E07))
    check("preds of lock-wait site 0x6386cb4 is the setup lea only",
          preds[0x6386CB4] == {0x6386CB0}, str(preds[0x6386CB4]))
    check("preds of lock-wait setup 0x6386cb0 are trylock fail and the "
          "padding nopl",
          preds[0x6386CB0] == {0x6386BB4, 0x6386CAB}, str(preds[0x6386CB0]))
    check("preds of trylock 0x6386bad is the r12 save only",
          preds[0x6386BAD] == {0x6386BAA}, str(preds[0x6386BAD]))
    check("preds of rejoin 0x6386bba are trylock success and the "
          "lock-wait jmp",
          preds[0x6386BBA] == {0x6386BB4, 0x6386CC0}, str(preds[0x6386BBA]))
    check("preds of ret 0x6386c21 is the final pop",
          preds[0x6386C21] == {0x6386C1F}, str(preds[0x6386C21]))
    check("preds of epilogue 0x6386bfc are gate-closed je and unlock",
          preds[0x6386BFC] == {0x6386B95, 0x6386BF7}, str(preds[0x6386BFC]))
    check("preds of exit-14 block 0x6386be7 are high-32, count<=index "
          "and NULL-entry",
          preds[0x6386BE7] == {0x6386BE5, 0x6386C30, 0x6386C40},
          str(preds[0x6386BE7]))
    check("preds of flag-clear block 0x6386bed are exit-14, callee "
          "failure, exit-0 and exit-22",
          preds[0x6386BED] == {0x6386BE7, 0x6386C7C, 0x6386CA6, 0x6386D06},
          str(preds[0x6386BED]))
    check("preds of exit-0 block 0x6386ca3 are rcx==0, r8==0 and "
          "len==8 copy",
          preds[0x6386CA3] == {0x6386C85, 0x6386C8F, 0x6386C9F},
          str(preds[0x6386CA3]))
    check("preds of exit-22 block 0x6386d00 are 7th-arg!=8 and "
          "copy-done fall-through",
          preds[0x6386D00] == {0x6386C4D, 0x6386CFE},
          str(preds[0x6386D00]))
    check("preds of writeback 0x6386cf5 are the 8 copy exits",
          preds[0x6386CF5] == {0x6386CE1, 0x6386CEF, 0x6386D3A, 0x6386D60,
                               0x6386E01, 0x6386E77, 0x6386E97, 0x6386EAB},
          str(preds[0x6386CF5]))
    check("preds of big-copy loop 0x6386e07 are remainder 0 and the "
          "two loop-backs",
          preds[0x6386E07] == {0x6386D65, 0x6386E01, 0x6386E75},
          str(preds[0x6386E07]))
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
    SITE = 0x6386CB4
    RET = 0x6386C21
    CALL_TRYLOCK = {("CALL", 0x6386BAD)}
    check("site rdi only def is lea -0x40(%r15),%rdi 0x6386cb0",
          rdi_in[SITE] == {0x6386CB0}, str(rdi_in[SITE]))
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
    check("site rbx def is the entry rdi save",
          rbx_in[SITE] == {0x6386B9E}, str(rbx_in[SITE]))
    check("site rbp def is the entry rsi save",
          rbp_in[SITE] == {0x6386BA1}, str(rbp_in[SITE]))
    check("site r12 def is the entry r9 save",
          r12_in[SITE] == {0x6386BAA}, str(r12_in[SITE]))
    check("site r13 def is the entry rcx save",
          r13_in[SITE] == {0x6386BA4}, str(r13_in[SITE]))
    check("site r14 def is the entry exit-2 default",
          r14_in[SITE] == {0x6386B68}, str(r14_in[SITE]))
    check("site r15 def is the mutex lea",
          r15_in[SITE] == {0x6386B97}, str(r15_in[SITE]))
    check("rax at ret is the exit-value mov 0x6386c14",
          rax_in[RET] == {0x6386C14}, str(rax_in[RET]))
    check("r14d reaching defs at the epilogue are the 4 exit values",
          r14_in[0x6386BFC] == {0x6386B68, 0x6386BE7, 0x6386C6C, 0x6386CA3,
                                0x6386D00},
          str(r14_in[0x6386BFC]))

    check("records lock-wait sites match census",
          [s.get("site") for s in rec.get("lock_wait_sites", [])] ==
          ["0x6386cb4"])
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
    check("records window bytes 848",
          rec.get("window", {}).get("bytes") == 848)
    check("records window range",
          rec.get("window", {}).get("range") == "0x6386b60..0x6386eb0")
    check("records return value exits 0/2/14/22",
          rec.get("return_value", {}).get("rax") ==
          "r14d: 0/2/14/22 (mov %r14d,%eax at 0x6386c14)")
    check("records entry gate address 0x64ffc28",
          rec.get("entry_gate", {}).get("address") == "0x64ffc28")
    check("records entry gate file byte 0x01",
          rec.get("entry_gate", {}).get("file_byte") == "0x01")
    check("records count call target 0x634eba0",
          rec.get("count_call", {}).get("target") == "0x634eba0")
    check("records thunk FDE 0x63643f0..0x6364400",
          rec.get("callee", {}).get("fde") == "0x63643f0..0x6364400")
    check("records thunk strict 3",
          rec.get("callee", {}).get("strict") == 3)
    check("records thunk bytes 16",
          rec.get("callee", {}).get("bytes") == 16)
    check("records selector index is *(entry rsi + 8)",
          rec.get("selector", {}).get("index") == "*(entry rsi + 8)")
    check("records copy dispatch is (len-1)>>3 & 7",
          rec.get("copy_loop", {}).get("dispatch") == "(len-1)>>3 & 7")
    check("records copy is 8-at-a-time",
          rec.get("copy_loop", {}).get("width") == 8)

    # Sections (own ELF parse): .bss exact end; referenced addresses.
    secmap = sections(node)
    bss = secmap[".bss"]
    check("bss section 0x64ffe40..0x6728924",
          bss[3] == 0x64FFE40 and bss[3] + bss[5] == 0x6728924, str(bss))
    for _a in (0x65096C0, 0x6712188, 0x6712190, 0x6712198, 0x67121A0,
               0x67121C8):
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
    for _t in (0x634EBA0, 0x63643F0, 0x63BF680):
        check("call target %s inside .text (internal, not PLT)" % hex(_t),
              txt[3] <= _t < txt[3] + txt[5])

    # rela counts by direct ELF parse
    dyn_total = plt_total = rel_count = 0
    gate_relocs = 0
    runtime_table_relocs = 0
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
                if off == 0x64FFC28:
                    gate_relocs += 1
                if 0x65096C0 <= off < 0x6509EC0:
                    runtime_table_relocs += 1
                if off in (0x6712188, 0x6712190, 0x6712198, 0x67121A0,
                           0x67121C8):
                    mutex_relocs += 1
        if nm == ".rela.plt":
            plt_total = s[5] // 24
    check("rela.dyn total 60723", dyn_total == 60723, str(dyn_total))
    check("rela.dyn RELATIVE 59534", rel_count == 59534, str(rel_count))
    check("rela.plt 278", plt_total == 278, str(plt_total))
    check("no rela lands at the entry-gate byte 0x64ffc28",
          gate_relocs == 0, str(gate_relocs))
    check("no rela lands in the runtime table 0x65096c0..0x6509ec0",
          runtime_table_relocs == 0, str(runtime_table_relocs))
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
    check("next candidate raw lu-miss 0", counts.get(0x6387FF0, 0) == 0,
          str(counts.get(0x6387FF0, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x6387FF0, 0) == 0,
          str(bti_counts.get(0x6387FF0, 0)))
    check("next candidate raw second-handler 0",
          sh_counts.get(0x6387FF0, 0) == 0, str(sh_counts.get(0x6387FF0, 0)))
    check("next candidate raw lock-wait 1",
          lw_counts.get(0x6387FF0, 0) == 1,
          str(lw_counts.get(0x6387FF0, 0)))
    # lock-wait frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 344", len(survey.get("survivors", [])) == 344,
          str(len(survey.get("survivors", []))))
    check("survey this window is a lock-wait survivor",
          "0x6386b60" in survey.get("survivors", []))
    check("survey this window is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x6386b60") == 1,
          str(survey.get("sites_per_fde", {}).get("0x6386b60")))
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
          "0x6386b60" not in survey.get("lu_miss_survivors", []))
    check("survey this window is NOT a second-handler survivor",
          "0x6386b60" not in survey.get("second_handler_survivors", []))
    check("survey next candidate is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x6387ff0") == 1,
          str(survey.get("sites_per_fde", {}).get("0x6387ff0")))
    nq = rec.get("next_question", {})
    check("next question is the lock-wait frontier",
          nq.get("frontier") == "lock-wait helper 0x63bf680 callers",
          str(nq.get("frontier")))
    check("next question range 0x6387ff0..0x6388303",
          nq.get("range") == "0x6387ff0..0x6388303", str(nq.get("range")))
    check("next question bytes 787", nq.get("bytes") == 787,
          str(nq.get("bytes")))
    check("next question lu-miss sites 0",
          nq.get("lu_miss_sites") == 0, str(nq.get("lu_miss_sites")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 202", nq.get("strict") == 202,
          str(nq.get("strict")))
    check("next question calls 5", nq.get("calls") == 5,
          str(nq.get("calls")))
    check("next question indirect calls 0",
          nq.get("indirect_calls") == 0, str(nq.get("indirect_calls")))
    check("next question calls by target",
          nq.get("calls_by_target") ==
          {"0x634eba0": 1, "0x63bf680": 1, "0x63f0b70": 1,
           "0x63f0d70": 1, "0x63f17b0": 1},
          str(nq.get("calls_by_target")))
    check("next question lock-wait sites 1",
          nq.get("lock_wait_sites") == 1, str(nq.get("lock_wait_sites")))
    check("next question lock-wait site list",
          nq.get("lock_wait_site") == ["0x6388124"],
          str(nq.get("lock_wait_site")))
    check("next question second-handler sites 0",
          nq.get("second_handler_sites") == 0,
          str(nq.get("second_handler_sites")))
    check("next question bsr 0", nq.get("bsr") == 0,
          str(nq.get("bsr")))
    check("next question rets 1",
          nq.get("ret") == ["0x6388055"], str(nq.get("ret")))
    check("next question jumps 33", nq.get("jumps") == 33,
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
          rec.get("census", {}).get("strict") == 213)
    check("records census calls 19",
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
    # next candidate 0x6387ff0..0x6388303 must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x6387FF0 < p[1] and p[0] < 0x6388303]
    check("next candidate 0x6387ff0 disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x6388303 and 0x6387FF0 < END))

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
                       "RE-001-node115-lockwait-caller-1site-tablecopy",
                       "RE-001-node115-lockwait-caller-1site-indirectexp"))

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
                    "lockwait_caller_1site_thunk.hex",
                    "lockwait_caller_1site_thunk.objdump.txt"}
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
