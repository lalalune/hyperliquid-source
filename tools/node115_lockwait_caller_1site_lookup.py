import bisect
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

SLUG = "RE-001-node115-lockwait-caller-1site-lookup"
START = 0x6387FF0
END = 0x6388303
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
    (0x6387ff0, 'endbr64', ''), (0x6387ff4, 'push', '%r15'), (0x6387ff6, 'mov', '$0x16,%r15d'), (0x6387ffc, 'push', '%r14'),
    (0x6387ffe, 'push', '%r13'), (0x6388000, 'push', '%r12'), (0x6388002, 'push', '%rbp'), (0x6388003, 'push', '%rbx'),
    (0x6388004, 'sub', '$0x28,%rsp'), (0x6388008, 'mov', '%rsi,0x8(%rsp)'), (0x638800d, 'mov', '%fs:0x28,%rax'), (0x6388016, 'mov', '%rax,0x18(%rsp)'),
    (0x638801b, 'xor', '%eax,%eax'), (0x638801d, 'test', '%rcx,%rcx'), (0x6388020, 'je', '6388030 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fc00>'), (0x6388022, 'mov', '%r8,%rbx'),
    (0x6388025, 'test', '%r8,%r8'), (0x6388028, 'je', '6388030 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fc00>'), (0x638802a, 'cmpq', '$0x8,(%r8)'), (0x638802e, 'je', '6388060 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fc30>'),
    (0x6388030, 'mov', '0x18(%rsp),%rax'), (0x6388035, 'sub', '%fs:0x28,%rax'), (0x638803e, 'jne', '63882eb <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63febb>'), (0x6388044, 'add', '$0x28,%rsp'),
    (0x6388048, 'mov', '%r15d,%eax'), (0x638804b, 'pop', '%rbx'), (0x638804c, 'pop', '%rbp'), (0x638804d, 'pop', '%r12'),
    (0x638804f, 'pop', '%r13'), (0x6388051, 'pop', '%r14'), (0x6388053, 'pop', '%r15'), (0x6388055, 'ret', ''),
    (0x6388056, 'cs', 'nopw 0x0(%rax,%rax,1)'), (0x6388060, 'lea', '0x38a139(%rip),%r14        # 67121a0 <__register_atfork@plt+0x320610>'), (0x6388067, 'mov', '%rdi,%r15'), (0x638806a, 'mov', '%rcx,%r13'),
    (0x638806d, 'mov', '%r9,%rbp'), (0x6388070, 'mov', '%r14,%rdi'), (0x6388073, 'call', '63f17b0 <pthread_mutex_trylock@plt>'), (0x6388078, 'mov', '0x8(%rsp),%rsi'),
    (0x638807d, 'test', '%eax,%eax'), (0x638807f, 'jne', '6388120 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fcf0>'), (0x6388085, 'addq', '$0x1,0x38a10b(%rip)        # 6712198 <__register_atfork@plt+0x320608>'), (0x638808d, 'cmp', '0x38a0fc(%rip),%r15        # 6712190 <__register_atfork@plt+0x320600>'),
    (0x6388094, 'je', '63880a5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fc75>'), (0x6388096, 'addq', '$0x1,0x38a0ea(%rip)        # 6712188 <__register_atfork@plt+0x3205f8>'), (0x638809e, 'mov', '%r15,0x38a0eb(%rip)        # 6712190 <__register_atfork@plt+0x320600>'), (0x63880a5, 'mov', '$0x1,%r15d'),
    (0x63880ab, 'or', '0x60(%rsp),%rbp'), (0x63880b0, 'jne', '63880c5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fc95>'), (0x63880b2, 'mov', '0x10(%rsi),%r12'), (0x63880b6, 'mov', '%r12,%rax'),
    (0x63880b9, 'shr', '$0x20,%rax'), (0x63880bd, 'je', '63880e0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fcb0>'), (0x63880bf, 'mov', '$0xe,%r15d'), (0x63880c5, 'movb', '$0x0,0x38a0fc(%rip)        # 67121c8 <__register_atfork@plt+0x320638>'),
    (0x63880cc, 'mov', '%r14,%rdi'), (0x63880cf, 'call', '63f0b70 <pthread_mutex_unlock@plt>'), (0x63880d4, 'jmp', '6388030 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fc00>'), (0x63880d9, 'nopl', '0x0(%rax)'),
    (0x63880e0, 'call', '634eba0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x606770>'), (0x63880e5, 'cmp', '%r12d,%eax'), (0x63880e8, 'jbe', '63880bf <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fc8f>'), (0x63880ea, 'lea', '0x1815cf(%rip),%rdx        # 65096c0 <__register_atfork@plt+0x117b30>'),
    (0x63880f1, 'mov', '(%rdx,%r12,8),%rdi'), (0x63880f5, 'test', '%rdi,%rdi'), (0x63880f8, 'je', '63880bf <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fc8f>'), (0x63880fa, 'mov', '(%rbx),%rdx'),
    (0x63880fd, 'add', '$0x29a0,%rdi'), (0x6388104, 'mov', '%rdi,0x10(%rsp)'), (0x6388109, 'cmp', '$0x8,%rdx'), (0x638810d, 'jne', '6388140 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fd10>'),
    (0x638810f, 'mov', '%rdi,0x0(%r13)'), (0x6388113, 'xor', '%r15d,%r15d'), (0x6388116, 'jmp', '63880c5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fc95>'), (0x6388118, 'nopl', '0x0(%rax,%rax,1)'),
    (0x6388120, 'lea', '-0x40(%r14),%rdi'), (0x6388124, 'call', '63bf680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677250>'), (0x6388129, 'movb', '$0x1,0x38a098(%rip)        # 67121c8 <__register_atfork@plt+0x320638>'), (0x6388130, 'mov', '0x8(%rsp),%rsi'),
    (0x6388135, 'jmp', '6388085 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fc55>'), (0x638813a, 'nopw', '0x0(%rax,%rax,1)'), (0x6388140, 'mov', '$0x8,%ecx'), (0x6388145, 'lea', '0x10(%rsp),%r10'),
    (0x638814a, 'cmp', '%rcx,%rdx'), (0x638814d, 'cmova', '%rcx,%rdx'), (0x6388151, 'cmp', '$0x8,%edx'), (0x6388154, 'jae', '6388183 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fd53>'),
    (0x6388156, 'test', '$0x4,%dl'), (0x6388159, 'jne', '63882d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fea0>'), (0x638815f, 'test', '%edx,%edx'), (0x6388161, 'je', '6388175 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fd45>'),
    (0x6388163, 'movzbl', '0x10(%rsp),%ebp'), (0x6388168, 'mov', '%bpl,0x0(%r13)'), (0x638816c, 'test', '$0x2,%dl'), (0x638816f, 'jne', '63882f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fec0>'),
    (0x6388175, 'mov', '%rdx,(%rbx)'), (0x6388178, 'mov', '$0x16,%r15d'), (0x638817e, 'jmp', '63880c5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fc95>'), (0x6388183, 'mov', '%edx,%eax'),
    (0x6388185, 'mov', '%rdi,0x0(%r13)'), (0x6388189, 'lea', '0x8(%r13),%r15'), (0x638818d, 'mov', '-0x8(%r10,%rax,1),%rdi'), (0x6388192, 'and', '$0xfffffffffffffff8,%r15'),
    (0x6388196, 'mov', '%rdi,-0x8(%r13,%rax,1)'), (0x638819b, 'sub', '%r15,%r13'), (0x638819e, 'lea', '(%rdx,%r13,1),%eax'), (0x63881a2, 'sub', '%r13,%r10'),
    (0x63881a5, 'and', '$0xfffffff8,%eax'), (0x63881a8, 'cmp', '$0x8,%eax'), (0x63881ab, 'jb', '6388175 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fd45>'), (0x63881ad, 'mov', '(%r10,%rbp,1),%r8'),
    (0x63881b1, 'lea', '-0x1(%rax),%ecx'), (0x63881b4, 'mov', '$0x8,%r11d'), (0x63881ba, 'mov', '%eax,%r13d'), (0x63881bd, 'shr', '$0x3,%ecx'),
    (0x63881c0, 'mov', '%r8,(%r15,%rbp,1)'), (0x63881c4, 'and', '$0x7,%ecx'), (0x63881c7, 'cmp', '%eax,%r11d'), (0x63881ca, 'jae', '6388175 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fd45>'),
    (0x63881cc, 'test', '%ecx,%ecx'), (0x63881ce, 'je', '6388263 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fe33>'), (0x63881d4, 'cmp', '$0x1,%ecx'), (0x63881d7, 'je', '638824b <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fe1b>'),
    (0x63881d9, 'cmp', '$0x2,%ecx'), (0x63881dc, 'je', '638823c <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fe0c>'), (0x63881de, 'cmp', '$0x3,%ecx'), (0x63881e1, 'je', '638822d <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fdfd>'),
    (0x63881e3, 'cmp', '$0x4,%ecx'), (0x63881e6, 'je', '638821e <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fdee>'), (0x63881e8, 'cmp', '$0x5,%ecx'), (0x63881eb, 'je', '638820f <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fddf>'),
    (0x63881ed, 'cmp', '$0x6,%ecx'), (0x63881f0, 'je', '6388200 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fdd0>'), (0x63881f2, 'mov', '(%r10,%r11,1),%r9'), (0x63881f6, 'mov', '%r9,(%r15,%r11,1)'),
    (0x63881fa, 'mov', '$0x10,%r11d'), (0x6388200, 'mov', '%r11d,%ebp'), (0x6388203, 'add', '$0x8,%r11d'), (0x6388207, 'mov', '(%r10,%rbp,1),%rsi'),
    (0x638820b, 'mov', '%rsi,(%r15,%rbp,1)'), (0x638820f, 'mov', '%r11d,%r12d'), (0x6388212, 'add', '$0x8,%r11d'), (0x6388216, 'mov', '(%r10,%r12,1),%rdi'),
    (0x638821a, 'mov', '%rdi,(%r15,%r12,1)'), (0x638821e, 'mov', '%r11d,%eax'), (0x6388221, 'add', '$0x8,%r11d'), (0x6388225, 'mov', '(%r10,%rax,1),%rcx'),
    (0x6388229, 'mov', '%rcx,(%r15,%rax,1)'), (0x638822d, 'mov', '%r11d,%r8d'), (0x6388230, 'add', '$0x8,%r11d'), (0x6388234, 'mov', '(%r10,%r8,1),%r9'),
    (0x6388238, 'mov', '%r9,(%r15,%r8,1)'), (0x638823c, 'mov', '%r11d,%ebp'), (0x638823f, 'add', '$0x8,%r11d'), (0x6388243, 'mov', '(%r10,%rbp,1),%rsi'),
    (0x6388247, 'mov', '%rsi,(%r15,%rbp,1)'), (0x638824b, 'mov', '%r11d,%r12d'), (0x638824e, 'add', '$0x8,%r11d'), (0x6388252, 'mov', '(%r10,%r12,1),%rdi'),
    (0x6388256, 'mov', '%rdi,(%r15,%r12,1)'), (0x638825a, 'cmp', '%r13d,%r11d'), (0x638825d, 'jae', '6388175 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fd45>'), (0x6388263, 'mov', '%r11d,%eax'),
    (0x6388266, 'lea', '0x8(%r11),%r8d'), (0x638826a, 'lea', '0x10(%r11),%ebp'), (0x638826e, 'mov', '(%r10,%rax,1),%rcx'), (0x6388272, 'lea', '0x18(%r11),%r12d'),
    (0x6388276, 'mov', '%rcx,(%r15,%rax,1)'), (0x638827a, 'mov', '(%r10,%r8,1),%r9'), (0x638827e, 'lea', '0x20(%r11),%eax'), (0x6388282, 'mov', '%r9,(%r15,%r8,1)'),
    (0x6388286, 'mov', '(%r10,%rbp,1),%rsi'), (0x638828a, 'lea', '0x28(%r11),%r8d'), (0x638828e, 'mov', '%rsi,(%r15,%rbp,1)'), (0x6388292, 'mov', '(%r10,%r12,1),%rdi'),
    (0x6388296, 'lea', '0x30(%r11),%ebp'), (0x638829a, 'mov', '%rdi,(%r15,%r12,1)'), (0x638829e, 'mov', '(%r10,%rax,1),%rcx'), (0x63882a2, 'lea', '0x38(%r11),%r12d'),
    (0x63882a6, 'add', '$0x40,%r11d'), (0x63882aa, 'mov', '%rcx,(%r15,%rax,1)'), (0x63882ae, 'mov', '(%r10,%r8,1),%r9'), (0x63882b2, 'mov', '%r9,(%r15,%r8,1)'),
    (0x63882b6, 'mov', '(%r10,%rbp,1),%rsi'), (0x63882ba, 'mov', '%rsi,(%r15,%rbp,1)'), (0x63882be, 'mov', '(%r10,%r12,1),%rdi'), (0x63882c2, 'mov', '%rdi,(%r15,%r12,1)'),
    (0x63882c6, 'cmp', '%r13d,%r11d'), (0x63882c9, 'jb', '6388263 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fe33>'), (0x63882cb, 'jmp', '6388175 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fd45>'), (0x63882d0, 'mov', '0x10(%rsp),%r8d'),
    (0x63882d5, 'mov', '%edx,%r9d'), (0x63882d8, 'mov', '%r8d,0x0(%r13)'), (0x63882dc, 'mov', '-0x4(%r10,%r9,1),%r11d'), (0x63882e1, 'mov', '%r11d,-0x4(%r13,%r9,1)'),
    (0x63882e6, 'jmp', '6388175 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fd45>'), (0x63882eb, 'call', '63f0d70 <__stack_chk_fail@plt>'), (0x63882f0, 'mov', '%edx,%esi'), (0x63882f2, 'movzwl', '-0x2(%r10,%rsi,1),%r12d'),
    (0x63882f8, 'mov', '%r12w,-0x2(%r13,%rsi,1)'), (0x63882fe, 'jmp', '6388175 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fd45>'),
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
    check("target FDE size 787", END - START == 787)
    prev = fdes[i - 1]
    check("prev FDE 0x6387880..0x6387fec",
          prev == (0x6387880, 0x6387FEC), str(prev))
    check("prev gap 4 (0xcc padding)", START - prev[1] == 4)
    check("prev gap bytes are 0xcc int3 padding",
          node[toff(prev[1]):toff(START)] == b"\xcc" * 4)
    nxt = fdes[i + 1]
    check("next FDE 0x6388310..0x6388372",
          nxt == (0x6388310, 0x6388372), str(nxt))
    check("next gap 13 (0xcc padding)", nxt[0] - END == 13)
    check("next gap bytes are 0xcc int3 padding",
          node[toff(END):toff(nxt[0])] == b"\xcc" * 13)
    check("next FDE starts push %rbx (not endbr64)",
          node[toff(nxt[0])] == 0x53)
    check("prev FDE end is 4 bytes before this FDE start",
          prev[1] == START - 4)
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
    check("thunk FDE 0x63643f0..0x6364400",
          fdes[bisect.bisect_left(starts, 0x63643F0)] ==
          (0x63643F0, 0x6364400))
    check("#337 window FDE 0x6386b60..0x6386eb0",
          fdes[bisect.bisect_left(starts, 0x6386B60)] ==
          (0x6386B60, 0x6386EB0))
    check("next-question FDE 0x63a4cf0..0x63a4fc8",
          fdes[bisect.bisect_left(starts, 0x63A4CF0)] ==
          (0x63A4CF0, 0x63A4FC8))
    hexb = read(os.path.join(PACKET, "lockwait_caller_1site_lookup.hex"))
    check("hex exhibit raw bytes 787", len(hexb) == 787, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])
    objdump = read(os.path.join(
        PACKET, "lockwait_caller_1site_lookup.objdump.txt")).decode()
    lines = strict_lines(objdump)
    check("strict lines 202", len(lines) == 202, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if mnemonic_of(l) == "call"]
    check("call lines 5", len(calls) == 5, str(len(calls)))
    rets = [l for l in lines if mnemonic_of(l) == "ret"]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x6388055",
          sorted(addr_of(l) for l in rets) == [0x6388055],
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
    expect = {0x634EBA0: 1, 0x63BF680: 1, 0x63F0B70: 1,
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
    check("lock-wait site is 0x6388124",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63bf680" in l) == [0x6388124])
    check("resolver 0x6365150 called 0 times", tgt.get(0x6365150, 0) == 0,
          str(tgt.get(0x6365150, 0)))
    check("count call 0x634eba0 1 time at 0x63880e0",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "634eba0" in l) == [0x63880E0])
    check("stack_chk_fail plt call 1 at 0x63882eb",
          tgt.get(0x63F0D70, 0) == 1, str(tgt.get(0x63F0D70, 0)))
    check("trylock plt call 1 at 0x6388073",
          tgt.get(0x63F17B0, 0) == 1, str(tgt.get(0x63F17B0, 0)))
    check("unlock plt call 1 at 0x63880cf",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63f0b70" in l) == [0x63880CF])
    check("no #321 window call", tgt.get(0x63C9650, 0) == 0,
          str(tgt.get(0x63C9650, 0)))
    plt_calls = [l for l in calls if "@plt" in l]
    check("PLT calls 3 (by @plt suffix, not address range)",
          len(plt_calls) == 3, str(len(plt_calls)))
    check("distinct PLT targets 3",
          len({re.search(r"\tcall\s+([0-9a-f]+)", l).group(1)
               for l in plt_calls}) == 3)
    check("no internal .text call is counted as PLT",
          not any(("634eba0" in l or "63bf680" in l) and "@plt" in l
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
                  ("#336", 0x63CE510), ("#337", 0x6386B60)):
        check("%s window not called" % _w, tgt.get(_a, 0) == 0,
              str(tgt.get(_a, 0)))

    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", len(bsr) == 0, str([hex(addr_of(l)) for l in bsr]))
    check("shr exactly 2 at 0x63880b9/0x63881bd",
          sorted(addr_of(l) for l in lines
                 if mnemonic_of(l) == "shr") ==
          [0x63880B9, 0x63881BD])
    check("shr at 0x63880b9 is $0x20 (high-32 extract)",
          "$0x20,%rax" in operands_of(by_addr[0x63880B9]))
    check("shr at 0x63881bd is $0x3 (copy remainder)",
          "$0x3,%ecx" in operands_of(by_addr[0x63881BD]))
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
    check("jump lines 33", len(jmps) == 33, str(len(jmps)))

    def jump_target(line):
        m = re.search(r"\s([0-9a-f]{6,})\s*<", line)
        return int(m.group(1), 16) if m else None

    outside = []
    for l in jmps:
        t = jump_target(l)
        if t is not None and not (START <= t < END):
            outside.append((addr_of(l), t))
    check("jump closure: 0 outside the window", outside == [], str(outside))
    check("jump targets are exactly the 33 branches",
          sorted(jump_target(l) for l in jmps) ==
          [0x6388030, 0x6388030, 0x6388030, 0x6388060, 0x6388085, 0x63880A5, 0x63880BF, 0x63880BF, 0x63880C5, 0x63880C5, 0x63880C5, 0x63880E0, 0x6388120, 0x6388140, 0x6388175, 0x6388175, 0x6388175, 0x6388175, 0x6388175, 0x6388175, 0x6388175, 0x6388183, 0x6388200, 0x638820F, 0x638821E, 0x638822D, 0x638823C, 0x638824B, 0x6388263, 0x6388263, 0x63882D0, 0x63882EB, 0x63882F0],
          str(sorted(jump_target(l) for l in jmps)))
    check("endbr64 count 1",
          sum(1 for l in lines if "endbr64" in l) == 1)
    check("entry is endbr64 at 0x6387ff0",
          "endbr64" in by_addr[START])
    check("canary present: 2 fs:0x28 lines",
          sum(1 for l in lines if "%fs:0x28" in l) == 2)
    check("canary load at 0x638800d",
          "mov" in by_addr[0x638800D] and "%fs:0x28,%rax" in by_addr[0x638800D])
    check("canary save to 0x18(%rsp) at 0x6388016",
          "mov" in by_addr[0x6388016] and "%rax,0x18(%rsp)" in by_addr[0x6388016])
    check("canary check sub at 0x6388035",
          "sub" in by_addr[0x6388035] and "%fs:0x28,%rax" in by_addr[0x6388035])
    check("canary fail jne to stack_chk_fail at 0x638803e",
          "jne" in by_addr[0x638803E] and "63882eb" in by_addr[0x638803E])
    check("TLS flag check absent: 0 fs:0x330 lines",
          sum(1 for l in lines if "%fs:0x330" in l) == 0)
    check("no prefetch instructions",
          not any("prefetch" in l for l in lines))
    check("tzcnt 0",
          [l for l in lines if mnemonic_of(l) == "tzcnt"] == [])
    check("entry default exit mov $0x16,%r15d at 0x6387ff6",
          "mov" in by_addr[0x6387FF6] and "$0x16,%r15d" in by_addr[0x6387FF6])
    check("entry rsi save mov %rsi,0x8(%rsp) at 0x6388008",
          "mov" in by_addr[0x6388008] and "%rsi,0x8(%rsp)" in by_addr[0x6388008])
    check("entry rcx==0 je epilogue at 0x6388020",
          "je" in by_addr[0x6388020] and "6388030" in by_addr[0x6388020])
    check("entry r8 save mov %r8,%rbx at 0x6388022",
          "mov" in by_addr[0x6388022] and "%r8,%rbx" in by_addr[0x6388022])
    check("entry r8==0 je epilogue at 0x6388028",
          "je" in by_addr[0x6388028] and "6388030" in by_addr[0x6388028])
    check("entry len==8 cmpq $0x8,(%r8) at 0x638802a",
          "cmpq" in by_addr[0x638802A] and "$0x8,(%r8)" in by_addr[0x638802A])
    check("entry len==8 je lock path at 0x638802e",
          "je" in by_addr[0x638802E] and "6388060" in by_addr[0x638802E])
    check("mutex lea 0x67121a0 at 0x6388060",
          "lea" in by_addr[0x6388060] and "67121a0" in by_addr[0x6388060])
    check("entry rdi save mov %rdi,%r15 at 0x6388067",
          "mov" in by_addr[0x6388067] and "%rdi,%r15" in by_addr[0x6388067])
    check("entry rcx save mov %rcx,%r13 at 0x638806a",
          "mov" in by_addr[0x638806A] and "%rcx,%r13" in by_addr[0x638806A])
    check("entry r9 save mov %r9,%rbp at 0x638806d",
          "mov" in by_addr[0x638806D] and "%r9,%rbp" in by_addr[0x638806D])
    check("trylock call at 0x6388073",
          "call" in by_addr[0x6388073] and "63f17b0" in by_addr[0x6388073])
    check("rsi restore mov 0x8(%rsp),%rsi at 0x6388078",
          "mov" in by_addr[0x6388078] and "0x8(%rsp),%rsi" in by_addr[0x6388078])
    check("trylock-fail jne lock-wait setup at 0x638807f",
          "jne" in by_addr[0x638807F] and "6388120" in by_addr[0x638807F])
    check("acq-count addq $0x1,0x6712198 at 0x6388085",
          "addq" in by_addr[0x6388085] and "0x38a10b(%rip)" in by_addr[0x6388085])
    check("owner cmp 0x6712190,%r15 at 0x638808d",
          "cmp" in by_addr[0x638808D] and "0x38a0fc(%rip)" in by_addr[0x638808D])
    check("owner-unchanged je 0x63880a5 at 0x6388094",
          "je" in by_addr[0x6388094] and "63880a5" in by_addr[0x6388094])
    check("counter addq $0x1,0x6712188 at 0x6388096",
          "addq" in by_addr[0x6388096] and "0x38a0ea(%rip)" in by_addr[0x6388096])
    check("owner store mov %r15,0x6712190 at 0x638809e",
          "mov" in by_addr[0x638809E] and "0x38a0eb(%rip)" in by_addr[0x638809E])
    check("exit-1 mov $0x1,%r15d at 0x63880a5",
          "mov" in by_addr[0x63880A5] and "$0x1,%r15d" in by_addr[0x63880A5])
    check("caller-cond or 0x60(%rsp),%rbp at 0x63880ab",
          "or" in by_addr[0x63880AB] and "0x60(%rsp),%rbp" in by_addr[0x63880AB])
    check("caller-cond jne flag-clear at 0x63880b0",
          "jne" in by_addr[0x63880B0] and "63880c5" in by_addr[0x63880B0])
    check("index load mov 0x10(%rsi),%r12 at 0x63880b2",
          "mov" in by_addr[0x63880B2] and "0x10(%rsi),%r12" in by_addr[0x63880B2])
    check("index mov %r12,%rax at 0x63880b6",
          "mov" in by_addr[0x63880B6] and "%r12,%rax" in by_addr[0x63880B6])
    check("high-32 je count call at 0x63880bd",
          "je" in by_addr[0x63880BD] and "63880e0" in by_addr[0x63880BD])
    check("exit-14 mov $0xe,%r15d at 0x63880bf",
          "mov" in by_addr[0x63880BF] and "$0xe,%r15d" in by_addr[0x63880BF])
    check("waited-flag clear movb $0x0,0x67121c8 at 0x63880c5",
          "movb" in by_addr[0x63880C5] and "0x38a0fc(%rip)" in by_addr[0x63880C5])
    check("unlock call at 0x63880cf",
          "call" in by_addr[0x63880CF] and "63f0b70" in by_addr[0x63880CF])
    check("unlock jmp epilogue at 0x63880d4",
          "jmp" in by_addr[0x63880D4] and "6388030" in by_addr[0x63880D4])
    check("count call at 0x63880e0",
          "call" in by_addr[0x63880E0] and "634eba0" in by_addr[0x63880E0])
    check("count cmp %r12d,%eax at 0x63880e5",
          "cmp" in by_addr[0x63880E5] and "%r12d,%eax" in by_addr[0x63880E5])
    check("count jbe exit-14 at 0x63880e8",
          "jbe" in by_addr[0x63880E8] and "63880bf" in by_addr[0x63880E8])
    check("table lea 0x65096c0 at 0x63880ea",
          "lea" in by_addr[0x63880EA] and "65096c0" in by_addr[0x63880EA])
    check("table load mov (%rdx,%r12,8),%rdi at 0x63880f1",
          "mov" in by_addr[0x63880F1] and "(%rdx,%r12,8),%rdi" in by_addr[0x63880F1])
    check("NULL-entry je exit-14 at 0x63880f8",
          "je" in by_addr[0x63880F8] and "63880bf" in by_addr[0x63880F8])
    check("len load mov (%rbx),%rdx at 0x63880fa",
          "mov" in by_addr[0x63880FA] and "(%rbx),%rdx" in by_addr[0x63880FA])
    check("inline adjust add $0x29a0,%rdi at 0x63880fd",
          "add" in by_addr[0x63880FD] and "$0x29a0,%rdi" in by_addr[0x63880FD])
    check("adjusted store mov %rdi,0x10(%rsp) at 0x6388104",
          "mov" in by_addr[0x6388104] and "%rdi,0x10(%rsp)" in by_addr[0x6388104])
    check("len cmp $0x8,%rdx at 0x6388109",
          "cmp" in by_addr[0x6388109] and "$0x8,%rdx" in by_addr[0x6388109])
    check("len!=8 jne copy dispatch at 0x638810d",
          "jne" in by_addr[0x638810D] and "6388140" in by_addr[0x638810D])
    check("len==8 store mov %rdi,0x0(%r13) at 0x638810f",
          "mov" in by_addr[0x638810F] and "%rdi,0x0(%r13)" in by_addr[0x638810F])
    check("exit-0 xor %r15d,%r15d at 0x6388113",
          "xor" in by_addr[0x6388113] and "%r15d,%r15d" in by_addr[0x6388113])
    check("exit-0 jmp flag-clear at 0x6388116",
          "jmp" in by_addr[0x6388116] and "63880c5" in by_addr[0x6388116])
    check("lock-wait setup lea -0x40(%r14),%rdi at 0x6388120",
          "lea" in by_addr[0x6388120] and "-0x40(%r14),%rdi" in by_addr[0x6388120])
    check("lock-wait call at 0x6388124",
          "call" in by_addr[0x6388124] and "63bf680" in by_addr[0x6388124])
    check("waited-flag set movb $0x1,0x67121c8 at 0x6388129",
          "movb" in by_addr[0x6388129] and "0x38a098(%rip)" in by_addr[0x6388129])
    check("rsi restore mov 0x8(%rsp),%rsi at 0x6388130",
          "mov" in by_addr[0x6388130] and "0x8(%rsp),%rsi" in by_addr[0x6388130])
    check("lock-wait rejoin jmp 0x6388085 at 0x6388135 (NO trylock retry)",
          "jmp" in by_addr[0x6388135] and "6388085" in by_addr[0x6388135])
    check("copy mov $0x8,%ecx at 0x6388140",
          "mov" in by_addr[0x6388140] and "$0x8,%ecx" in by_addr[0x6388140])
    check("copy lea 0x10(%rsp),%r10 at 0x6388145",
          "lea" in by_addr[0x6388145] and "0x10(%rsp),%r10" in by_addr[0x6388145])
    check("copy cmp %rcx,%rdx at 0x638814a",
          "cmp" in by_addr[0x638814A] and "%rcx,%rdx" in by_addr[0x638814A])
    check("copy min cmova %rcx,%rdx at 0x638814d",
          "cmova" in by_addr[0x638814D] and "%rcx,%rdx" in by_addr[0x638814D])
    check("copy cmp $0x8,%edx at 0x6388151",
          "cmp" in by_addr[0x6388151] and "$0x8,%edx" in by_addr[0x6388151])
    check("copy jae big-copy at 0x6388154",
          "jae" in by_addr[0x6388154] and "6388183" in by_addr[0x6388154])
    check("copy test $0x4,%dl at 0x6388156",
          "test" in by_addr[0x6388156] and "$0x4,%dl" in by_addr[0x6388156])
    check("copy 4-byte jne 0x63882d0 at 0x6388159",
          "jne" in by_addr[0x6388159] and "63882d0" in by_addr[0x6388159])
    check("copy test %edx,%edx at 0x638815f",
          "test" in by_addr[0x638815F] and "%edx,%edx" in by_addr[0x638815F])
    check("copy len==0 je writeback at 0x6388161",
          "je" in by_addr[0x6388161] and "6388175" in by_addr[0x6388161])
    check("copy 1-byte movzbl 0x10(%rsp),%ebp at 0x6388163",
          "movzbl" in by_addr[0x6388163] and "0x10(%rsp),%ebp" in by_addr[0x6388163])
    check("copy 1-byte store mov %bpl,0x0(%r13) at 0x6388168",
          "mov" in by_addr[0x6388168] and "%bpl,0x0(%r13)" in by_addr[0x6388168])
    check("copy test $0x2,%dl at 0x638816c",
          "test" in by_addr[0x638816C] and "$0x2,%dl" in by_addr[0x638816C])
    check("copy 2-byte jne 0x63882f0 at 0x638816f",
          "jne" in by_addr[0x638816F] and "63882f0" in by_addr[0x638816F])
    check("writeback mov %rdx,(%rbx) at 0x6388175",
          "mov" in by_addr[0x6388175] and "%rdx,(%rbx)" in by_addr[0x6388175])
    check("exit-22 mov $0x16,%r15d at 0x6388178",
          "mov" in by_addr[0x6388178] and "$0x16,%r15d" in by_addr[0x6388178])
    check("exit-22 jmp flag-clear at 0x638817e",
          "jmp" in by_addr[0x638817E] and "63880c5" in by_addr[0x638817E])
    check("big-copy first qword store mov %rdi,0x0(%r13) at 0x6388185",
          "mov" in by_addr[0x6388185] and "%rdi,0x0(%r13)" in by_addr[0x6388185])
    check("big-copy dest lea 0x8(%r13),%r15 at 0x6388189",
          "lea" in by_addr[0x6388189] and "0x8(%r13),%r15" in by_addr[0x6388189])
    check("big-copy align and $...f8,%r15 at 0x6388192",
          "and" in by_addr[0x6388192] and "$0xfffffffffffffff8,%r15" in by_addr[0x6388192])
    check("big-copy remainder lea -0x1(%rax),%ecx at 0x63881b1",
          "lea" in by_addr[0x63881B1] and "-0x1(%rax),%ecx" in by_addr[0x63881B1])
    check("big-copy remainder shr $0x3,%ecx at 0x63881bd",
          "shr" in by_addr[0x63881BD] and "$0x3,%ecx" in by_addr[0x63881BD])
    check("big-copy remainder and $0x7,%ecx at 0x63881c4",
          "and" in by_addr[0x63881C4] and "$0x7,%ecx" in by_addr[0x63881C4])
    check("big-copy dispatch je 0x6388263 (ecx==0) at 0x63881ce",
          "je" in by_addr[0x63881CE] and "6388263" in by_addr[0x63881CE])
    check("big-copy loop-back jb 0x6388263 at 0x63882c9",
          "jb" in by_addr[0x63882C9] and "6388263" in by_addr[0x63882C9])
    check("big-copy exit jmp writeback at 0x63882cb",
          "jmp" in by_addr[0x63882CB] and "6388175" in by_addr[0x63882CB])
    check("4-byte copy mov 0x10(%rsp),%r8d at 0x63882d0",
          "mov" in by_addr[0x63882D0] and "0x10(%rsp),%r8d" in by_addr[0x63882D0])
    check("2-byte copy movzwl -0x2(%r10,%rsi,1),%r12d at 0x63882f2",
          "movzwl" in by_addr[0x63882F2] and "-0x2(%r10,%rsi,1),%r12d" in by_addr[0x63882F2])
    check("epilogue mov %r15d,%eax at 0x6388048",
          "mov" in by_addr[0x6388048] and "%r15d,%eax" in by_addr[0x6388048])

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

    check("entry reaches lock-wait site 0x6388124", reaches(START, 0x6388124))
    check("entry reaches ret 0x6388055", reaches(START, 0x6388055))
    check("entry reaches trylock 0x6388073", reaches(START, 0x6388073))
    check("entry reaches epilogue canary 0x6388030", reaches(START, 0x6388030))
    check("entry reaches count call 0x63880e0", reaches(START, 0x63880E0))
    check("entry reaches exit-14 block 0x63880bf", reaches(START, 0x63880BF))
    check("entry reaches exit-0 block 0x6388113", reaches(START, 0x6388113))
    check("entry reaches exit-22 block 0x6388178", reaches(START, 0x6388178))
    check("entry reaches copy dispatch 0x6388140", reaches(START, 0x6388140))
    check("entry reaches big-copy loop 0x6388263", reaches(START, 0x6388263))
    check("preds of lock-wait site 0x6388124 is the setup lea only",
          preds[0x6388124] == {0x6388120}, str(preds[0x6388124]))
    check("preds of lock-wait setup 0x6388120 are trylock fail and the "
          "padding nopl",
          preds[0x6388120] == {0x638807F, 0x6388118}, str(preds[0x6388120]))
    check("preds of trylock 0x6388073 is the rdi save only",
          preds[0x6388073] == {0x6388070}, str(preds[0x6388073]))
    check("preds of rejoin 0x6388085 are trylock success and the "
          "lock-wait jmp",
          preds[0x6388085] == {0x638807F, 0x6388135}, str(preds[0x6388085]))
    check("preds of ret 0x6388055 is the final pop",
          preds[0x6388055] == {0x6388053}, str(preds[0x6388055]))
    check("preds of epilogue 0x6388030 are rcx==0, r8==0, len==8 and "
          "unlock",
          preds[0x6388030] == {0x6388020, 0x6388028, 0x638802E, 0x63880D4},
          str(preds[0x6388030]))
    check("preds of exit-14 block 0x63880bf are high-32, count<=index "
          "and NULL-entry",
          preds[0x63880BF] == {0x63880BD, 0x63880E8, 0x63880F8},
          str(preds[0x63880BF]))
    check("preds of flag-clear block 0x63880c5 are caller-cond, exit-14, "
          "exit-0 and exit-22",
          preds[0x63880C5] == {0x63880B0, 0x63880BF, 0x6388116, 0x638817E},
          str(preds[0x63880C5]))
    check("preds of exit-0 block 0x6388113 is the len==8 store only",
          preds[0x6388113] == {0x638810F}, str(preds[0x6388113]))
    check("preds of exit-22 block 0x6388178 is the writeback only",
          preds[0x6388178] == {0x6388175}, str(preds[0x6388178]))
    check("preds of writeback 0x6388175 are the 8 copy exits",
          preds[0x6388175] == {0x6388161, 0x638816F, 0x63881AB, 0x63881CA,
                               0x638825D, 0x63882CB, 0x63882E6, 0x63882FE},
          str(preds[0x6388175]))
    check("preds of big-copy loop 0x6388263 are dispatch ecx==0, the "
          "jae fall-through and the loop-back",
          preds[0x6388263] == {0x63881CE, 0x638825D, 0x63882C9},
          str(preds[0x6388263]))
    check("preds of count call 0x63880e0 are high-32 je and the "
          "padding nopl",
          preds[0x63880E0] == {0x63880BD, 0x63880D9}, str(preds[0x63880E0]))
    check("preds of copy dispatch 0x6388140 are len!=8 jne and the "
          "padding nopw",
          preds[0x6388140] == {0x638810D, 0x638813A}, str(preds[0x6388140]))
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
    SITE = 0x6388124
    RET = 0x6388055
    CALL_TRYLOCK = {("CALL", 0x6388073)}
    check("site rdi only def is lea -0x40(%r14),%rdi 0x6388120",
          rdi_in[SITE] == {0x6388120}, str(rdi_in[SITE]))
    check("site rsi def is the post-trylock restore 0x6388078",
          rsi_in[SITE] == {0x6388078}, str(rsi_in[SITE]))
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
    check("site rbx def is the entry r8 save",
          rbx_in[SITE] == {0x6388022}, str(rbx_in[SITE]))
    check("site rbp def is the entry r9 save",
          rbp_in[SITE] == {0x638806D}, str(rbp_in[SITE]))
    check("site r12 def is the caller ENTRY (never defined on this path)",
          r12_in[SITE] == {("ENTRY",)}, str(r12_in[SITE]))
    check("site r13 def is the entry rcx save",
          r13_in[SITE] == {0x638806A}, str(r13_in[SITE]))
    check("site r14 def is the mutex lea",
          r14_in[SITE] == {0x6388060}, str(r14_in[SITE]))
    check("site r15 def is the entry rdi save",
          r15_in[SITE] == {0x6388067}, str(r15_in[SITE]))
    check("rax at ret is the exit-value mov 0x6388048",
          rax_in[RET] == {0x6388048}, str(rax_in[RET]))
    check("r15d reaching defs at the flag-clear are the 4 exit values",
          r15_in[0x63880C5] == {0x63880A5, 0x63880BF, 0x6388113, 0x6388178},
          str(r15_in[0x63880C5]))

    check("records lock-wait sites match census",
          [s.get("site") for s in rec.get("lock_wait_sites", [])] ==
          ["0x6388124"])
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
    check("records window bytes 787",
          rec.get("window", {}).get("bytes") == 787)
    check("records window range",
          rec.get("window", {}).get("range") == "0x6387ff0..0x6388303")
    check("records return value exits 0/1/14/22",
          rec.get("return_value", {}).get("rax") ==
          "r15d: 0/1/14/22 (mov %r15d,%eax at 0x6388048)")
    check("records entry gate absent (no gate byte in this window)",
          rec.get("entry_gate") is None)
    check("records count call target 0x634eba0",
          rec.get("count_call", {}).get("target") == "0x634eba0")
    check("records count call site 0x63880e0",
          rec.get("count_call", {}).get("site") == "0x63880e0")
    check("records inline adjust 0x29a0 at 0x63880fd",
          rec.get("inline_adjust", {}).get("amount") == "0x29a0"
          and rec.get("inline_adjust", {}).get("site") == "0x63880fd")
    check("records selector index is *(entry rsi + 0x10)",
          rec.get("selector", {}).get("index") == "*(entry rsi + 0x10)")
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
    check("no .data address is referenced in this window",
          rec.get("census", {}).get("data_referenced_addresses") == [])
    check("runtime table 0x65096c0 is a .bss object (runtime-populated)",
          bss[3] <= 0x65096C0 < bss[3] + bss[5])
    txt = secmap[".text"]
    check("window inside .text",
          txt[3] <= START and END <= txt[3] + txt[5])
    for _t in (0x634EBA0, 0x63BF680):
        check("call target %s inside .text (internal, not PLT)" % hex(_t),
              txt[3] <= _t < txt[3] + txt[5])

    # rela counts by direct ELF parse
    dyn_total = plt_total = rel_count = 0
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
    check("next candidate raw lu-miss 0", counts.get(0x63A4CF0, 0) == 0,
          str(counts.get(0x63A4CF0, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x63A4CF0, 0) == 0,
          str(bti_counts.get(0x63A4CF0, 0)))
    check("next candidate raw second-handler 0",
          sh_counts.get(0x63A4CF0, 0) == 0, str(sh_counts.get(0x63A4CF0, 0)))
    check("next candidate raw lock-wait 1",
          lw_counts.get(0x63A4CF0, 0) == 1,
          str(lw_counts.get(0x63A4CF0, 0)))
    # lock-wait frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 344", len(survey.get("survivors", [])) == 344,
          str(len(survey.get("survivors", []))))
    check("survey this window is a lock-wait survivor",
          "0x6387ff0" in survey.get("survivors", []))
    check("survey this window is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x6387ff0") == 1,
          str(survey.get("sites_per_fde", {}).get("0x6387ff0")))
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
          "0x6387ff0" not in survey.get("lu_miss_survivors", []))
    check("survey this window is NOT a second-handler survivor",
          "0x6387ff0" not in survey.get("second_handler_survivors", []))
    check("survey next candidate is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x63a4cf0") == 1,
          str(survey.get("sites_per_fde", {}).get("0x63a4cf0")))
    nq = rec.get("next_question", {})
    check("next question is the lock-wait frontier",
          nq.get("frontier") == "lock-wait helper 0x63bf680 callers",
          str(nq.get("frontier")))
    check("next question range 0x63a4cf0..0x63a4fc8",
          nq.get("range") == "0x63a4cf0..0x63a4fc8", str(nq.get("range")))
    check("next question bytes 728", nq.get("bytes") == 728,
          str(nq.get("bytes")))
    check("next question lu-miss sites 0",
          nq.get("lu_miss_sites") == 0, str(nq.get("lu_miss_sites")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 191", nq.get("strict") == 191,
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
          nq.get("lock_wait_site") == ["0x63a4df4"],
          str(nq.get("lock_wait_site")))
    check("next question second-handler sites 0",
          nq.get("second_handler_sites") == 0,
          str(nq.get("second_handler_sites")))
    check("next question bsr 0", nq.get("bsr") == 0,
          str(nq.get("bsr")))
    check("next question rets 1",
          nq.get("ret") == ["0x63a4d97"], str(nq.get("ret")))
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
    check("records census strict 202",
          rec.get("census", {}).get("strict") == 202)
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
    # next candidate 0x63a4cf0..0x63a4fc8 must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x63A4CF0 < p[1] and p[0] < 0x63A4FC8]
    check("next candidate 0x63a4cf0 disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x63A4FC8 and 0x63A4CF0 < END))

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
    check("slug not colliding with #314-#337 lu-miss/lockwait slugs",
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
                       "RE-001-node115-lockwait-caller-1site-thunk"))

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
                    "lockwait_caller_1site_lookup.hex",
                    "lockwait_caller_1site_lookup.objdump.txt"}
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
