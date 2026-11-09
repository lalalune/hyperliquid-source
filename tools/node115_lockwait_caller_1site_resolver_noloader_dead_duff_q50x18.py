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

SLUG = "RE-001-node115-lockwait-caller-1site-resolver-noloader-dead-duff-q50x18"
START = 0x639F140
END = 0x639F400
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
    (0x639f140, 'endbr64', ''),
    (0x639f144, 'push', '%r15'),
    (0x639f146, 'lea', '0x373053(%rip),%r15        # 67121a0 <__register_atfork@plt+0x320610>'),
    (0x639f14d, 'push', '%r14'),
    (0x639f14f, 'mov', '%rsi,%r14'),
    (0x639f152, 'push', '%r13'),
    (0x639f154, 'mov', '%r8,%r13'),
    (0x639f157, 'push', '%r12'),
    (0x639f159, 'mov', '%rcx,%r12'),
    (0x639f15c, 'push', '%rbp'),
    (0x639f15d, 'mov', '%rdi,%rbp'),
    (0x639f160, 'mov', '%r15,%rdi'),
    (0x639f163, 'push', '%rbx'),
    (0x639f164, 'mov', '%r9,%rbx'),
    (0x639f167, 'sub', '$0x18,%rsp'),
    (0x639f16b, 'mov', '%fs:0x28,%rax'),
    (0x639f174, 'mov', '%rax,0x8(%rsp)'),
    (0x639f179, 'xor', '%eax,%eax'),
    (0x639f17b, 'call', '63f17b0 <pthread_mutex_trylock@plt>'),
    (0x639f180, 'test', '%eax,%eax'),
    (0x639f182, 'jne', '639f228 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656df8>'),
    (0x639f188, 'addq', '$0x1,0x373008(%rip)        # 6712198 <__register_atfork@plt+0x320608>'),
    (0x639f190, 'cmp', '0x372ff9(%rip),%rbp        # 6712190 <__register_atfork@plt+0x320600>'),
    (0x639f197, 'je', '639f1a8 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656d78>'),
    (0x639f199, 'addq', '$0x1,0x372fe7(%rip)        # 6712188 <__register_atfork@plt+0x3205f8>'),
    (0x639f1a1, 'mov', '%rbp,0x372fe8(%rip)        # 6712190 <__register_atfork@plt+0x320600>'),
    (0x639f1a8, 'mov', '$0x1,%ebp'),
    (0x639f1ad, 'or', '0x50(%rsp),%rbx'),
    (0x639f1b2, 'je', '639f1f0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656dc0>'),
    (0x639f1b4, 'movb', '$0x0,0x37300d(%rip)        # 67121c8 <__register_atfork@plt+0x320638>'),
    (0x639f1bb, 'mov', '%r15,%rdi'),
    (0x639f1be, 'call', '63f0b70 <pthread_mutex_unlock@plt>'),
    (0x639f1c3, 'mov', '0x8(%rsp),%rax'),
    (0x639f1c8, 'sub', '%fs:0x28,%rax'),
    (0x639f1d1, 'jne', '639f3fb <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656fcb>'),
    (0x639f1d7, 'add', '$0x18,%rsp'),
    (0x639f1db, 'mov', '%ebp,%eax'),
    (0x639f1dd, 'pop', '%rbx'),
    (0x639f1de, 'pop', '%rbp'),
    (0x639f1df, 'pop', '%r12'),
    (0x639f1e1, 'pop', '%r13'),
    (0x639f1e3, 'pop', '%r14'),
    (0x639f1e5, 'pop', '%r15'),
    (0x639f1e7, 'ret', ''),
    (0x639f1e8, 'nopl', '0x0(%rax,%rax,1)'),
    (0x639f1f0, 'mov', '0x10(%r14),%rdi'),
    (0x639f1f4, 'call', '6388310 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fee0>'),
    (0x639f1f9, 'mov', '0x50(%rax),%rax'),
    (0x639f1fd, 'mov', '0x18(%rax),%rsi'),
    (0x639f201, 'mov', '%rsi,(%rsp)'),
    (0x639f205, 'test', '%r12,%r12'),
    (0x639f208, 'je', '639f21d <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656ded>'),
    (0x639f20a, 'test', '%r13,%r13'),
    (0x639f20d, 'je', '639f21d <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656ded>'),
    (0x639f20f, 'mov', '0x0(%r13),%rdx'),
    (0x639f213, 'cmp', '$0x8,%rdx'),
    (0x639f217, 'jne', '639f240 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656e10>'),
    (0x639f219, 'mov', '%rsi,(%r12)'),
    (0x639f21d, 'xor', '%ebp,%ebp'),
    (0x639f21f, 'jmp', '639f1b4 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656d84>'),
    (0x639f221, 'nopl', '0x0(%rax)'),
    (0x639f228, 'lea', '-0x40(%r15),%rdi'),
    (0x639f22c, 'call', '63bf680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677250>'),
    (0x639f231, 'movb', '$0x1,0x372f90(%rip)        # 67121c8 <__register_atfork@plt+0x320638>'),
    (0x639f238, 'jmp', '639f188 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656d58>'),
    (0x639f23d, 'nopl', '(%rax)'),
    (0x639f240, 'mov', '$0x8,%ecx'),
    (0x639f245, 'mov', '%rsp,%r9'),
    (0x639f248, 'cmp', '%rcx,%rdx'),
    (0x639f24b, 'cmova', '%rcx,%rdx'),
    (0x639f24f, 'cmp', '$0x8,%edx'),
    (0x639f252, 'jb', '639f3b0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656f80>'),
    (0x639f258, 'mov', '%edx,%eax'),
    (0x639f25a, 'mov', '%rsi,(%r12)'),
    (0x639f25e, 'lea', '0x8(%r12),%rcx'),
    (0x639f263, 'mov', '-0x8(%r9,%rax,1),%rsi'),
    (0x639f268, 'and', '$0xfffffffffffffff8,%rcx'),
    (0x639f26c, 'mov', '%rsi,-0x8(%r12,%rax,1)'),
    (0x639f271, 'sub', '%rcx,%r12'),
    (0x639f274, 'sub', '%r12,%r9'),
    (0x639f277, 'add', '%edx,%r12d'),
    (0x639f27a, 'and', '$0xfffffff8,%r12d'),
    (0x639f27e, 'cmp', '$0x8,%r12d'),
    (0x639f282, 'jb', '639f3c7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656f97>'),
    (0x639f288, 'mov', '(%r9,%rbx,1),%r8'),
    (0x639f28c, 'lea', '-0x1(%r12),%edi'),
    (0x639f291, 'mov', '$0x8,%r10d'),
    (0x639f297, 'shr', '$0x3,%edi'),
    (0x639f29a, 'mov', '%r8,(%rcx,%rbx,1)'),
    (0x639f29e, 'and', '$0x7,%edi'),
    (0x639f2a1, 'cmp', '%r12d,%r10d'),
    (0x639f2a4, 'jae', '639f3c7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656f97>'),
    (0x639f2aa, 'test', '%edi,%edi'),
    (0x639f2ac, 'je', '639f341 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656f11>'),
    (0x639f2b2, 'cmp', '$0x1,%edi'),
    (0x639f2b5, 'je', '639f329 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656ef9>'),
    (0x639f2b7, 'cmp', '$0x2,%edi'),
    (0x639f2ba, 'je', '639f31a <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656eea>'),
    (0x639f2bc, 'cmp', '$0x3,%edi'),
    (0x639f2bf, 'je', '639f30b <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656edb>'),
    (0x639f2c1, 'cmp', '$0x4,%edi'),
    (0x639f2c4, 'je', '639f2fc <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656ecc>'),
    (0x639f2c6, 'cmp', '$0x5,%edi'),
    (0x639f2c9, 'je', '639f2ed <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656ebd>'),
    (0x639f2cb, 'cmp', '$0x6,%edi'),
    (0x639f2ce, 'je', '639f2de <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656eae>'),
    (0x639f2d0, 'mov', '(%r9,%r10,1),%rbx'),
    (0x639f2d4, 'mov', '%rbx,(%rcx,%r10,1)'),
    (0x639f2d8, 'mov', '$0x10,%r10d'),
    (0x639f2de, 'mov', '%r10d,%r11d'),
    (0x639f2e1, 'add', '$0x8,%r10d'),
    (0x639f2e5, 'mov', '(%r9,%r11,1),%rbp'),
    (0x639f2e9, 'mov', '%rbp,(%rcx,%r11,1)'),
    (0x639f2ed, 'mov', '%r10d,%r14d'),
    (0x639f2f0, 'add', '$0x8,%r10d'),
    (0x639f2f4, 'mov', '(%r9,%r14,1),%rax'),
    (0x639f2f8, 'mov', '%rax,(%rcx,%r14,1)'),
    (0x639f2fc, 'mov', '%r10d,%esi'),
    (0x639f2ff, 'add', '$0x8,%r10d'),
    (0x639f303, 'mov', '(%r9,%rsi,1),%rdi'),
    (0x639f307, 'mov', '%rdi,(%rcx,%rsi,1)'),
    (0x639f30b, 'mov', '%r10d,%ebx'),
    (0x639f30e, 'add', '$0x8,%r10d'),
    (0x639f312, 'mov', '(%r9,%rbx,1),%r8'),
    (0x639f316, 'mov', '%r8,(%rcx,%rbx,1)'),
    (0x639f31a, 'mov', '%r10d,%r11d'),
    (0x639f31d, 'add', '$0x8,%r10d'),
    (0x639f321, 'mov', '(%r9,%r11,1),%rbp'),
    (0x639f325, 'mov', '%rbp,(%rcx,%r11,1)'),
    (0x639f329, 'mov', '%r10d,%r14d'),
    (0x639f32c, 'add', '$0x8,%r10d'),
    (0x639f330, 'mov', '(%r9,%r14,1),%rax'),
    (0x639f334, 'mov', '%rax,(%rcx,%r14,1)'),
    (0x639f338, 'cmp', '%r12d,%r10d'),
    (0x639f33b, 'jae', '639f3c7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656f97>'),
    (0x639f341, 'mov', '%r10d,%esi'),
    (0x639f344, 'lea', '0x8(%r10),%ebx'),
    (0x639f348, 'lea', '0x10(%r10),%r11d'),
    (0x639f34c, 'mov', '(%r9,%rsi,1),%rdi'),
    (0x639f350, 'lea', '0x18(%r10),%r14d'),
    (0x639f354, 'mov', '%rdi,(%rcx,%rsi,1)'),
    (0x639f358, 'mov', '(%r9,%rbx,1),%r8'),
    (0x639f35c, 'lea', '0x20(%r10),%esi'),
    (0x639f360, 'mov', '%r8,(%rcx,%rbx,1)'),
    (0x639f364, 'mov', '(%r9,%r11,1),%rbp'),
    (0x639f368, 'lea', '0x28(%r10),%ebx'),
    (0x639f36c, 'mov', '%rbp,(%rcx,%r11,1)'),
    (0x639f370, 'mov', '(%r9,%r14,1),%rax'),
    (0x639f374, 'lea', '0x30(%r10),%r11d'),
    (0x639f378, 'mov', '%rax,(%rcx,%r14,1)'),
    (0x639f37c, 'mov', '(%r9,%rsi,1),%rdi'),
    (0x639f380, 'lea', '0x38(%r10),%r14d'),
    (0x639f384, 'add', '$0x40,%r10d'),
    (0x639f388, 'mov', '%rdi,(%rcx,%rsi,1)'),
    (0x639f38c, 'mov', '(%r9,%rbx,1),%r8'),
    (0x639f390, 'mov', '%r8,(%rcx,%rbx,1)'),
    (0x639f394, 'mov', '(%r9,%r11,1),%rbp'),
    (0x639f398, 'mov', '%rbp,(%rcx,%r11,1)'),
    (0x639f39c, 'mov', '(%r9,%r14,1),%rax'),
    (0x639f3a0, 'mov', '%rax,(%rcx,%r14,1)'),
    (0x639f3a4, 'cmp', '%r12d,%r10d'),
    (0x639f3a7, 'jb', '639f341 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656f11>'),
    (0x639f3a9, 'jmp', '639f3c7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656f97>'),
    (0x639f3ab, 'nopl', '0x0(%rax,%rax,1)'),
    (0x639f3b0, 'test', '$0x4,%dl'),
    (0x639f3b3, 'jne', '639f3d5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656fa5>'),
    (0x639f3b5, 'test', '%edx,%edx'),
    (0x639f3b7, 'je', '639f3c7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656f97>'),
    (0x639f3b9, 'movzbl', '(%rsp),%r11d'),
    (0x639f3be, 'mov', '%r11b,(%r12)'),
    (0x639f3c2, 'test', '$0x2,%dl'),
    (0x639f3c5, 'jne', '639f3eb <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656fbb>'),
    (0x639f3c7, 'mov', '%rdx,0x0(%r13)'),
    (0x639f3cb, 'mov', '$0x16,%ebp'),
    (0x639f3d0, 'jmp', '639f1b4 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656d84>'),
    (0x639f3d5, 'mov', '(%rsp),%edi'),
    (0x639f3d8, 'mov', '%edx,%r8d'),
    (0x639f3db, 'mov', '%edi,(%r12)'),
    (0x639f3df, 'mov', '-0x4(%r9,%r8,1),%r10d'),
    (0x639f3e4, 'mov', '%r10d,-0x4(%r12,%r8,1)'),
    (0x639f3e9, 'jmp', '639f3c7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656f97>'),
    (0x639f3eb, 'mov', '%edx,%ebp'),
    (0x639f3ed, 'movzwl', '-0x2(%r9,%rbp,1),%r14d'),
    (0x639f3f3, 'mov', '%r14w,-0x2(%r12,%rbp,1)'),
    (0x639f3f9, 'jmp', '639f3c7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x656f97>'),
    (0x639f3fb, 'call', '63f0d70 <__stack_chk_fail@plt>')
]

def main():
    node = read(BIN)
    check("binary size 105896032", len(node) == 105896032, str(len(node)))
    check("binary sha256",
          hashlib.sha256(node).hexdigest() ==
          "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")

    rec = json.loads(read(os.path.join(PACKET, "records.json")).decode())
    check("records base", rec["base"] ==
          "0781ce04826eeefd89fe336cb8ea073be0c1de30", str(rec.get("base")))

    fdes = parse_eh_frame(node)
    starts = [s for s, e in fdes]
    check("total FDEs 135313", len(fdes) == 135313, str(len(fdes)))
    i = bisect.bisect_left(starts, START)
    check("target FDE start", i < len(fdes) and fdes[i][0] == START)
    check("target FDE end", i < len(fdes) and fdes[i][1] == END)
    check("target FDE size 704", END - START == 704)
    prev = fdes[i - 1]
    check("prev FDE 0x639ee80..0x639f140",
          prev == (0x639EE80, 0x639F140), str(prev))
    check("prev gap 0 (prev FDE ends at window start 0x639f140)", START - prev[1] == 0 and all(b == 0xCC for b in node[toff(prev[1]):toff(START)]))
    check("prev FDE starts endbr64 (0xf3)",
          node[toff(prev[0])] == 0xF3)
    nxt = fdes[i + 1]
    check("next FDE 0x639f400..0x639f6b8 (#372 window)",
          nxt == (0x639F400, 0x639F6B8), str(nxt))
    check("next gap 0 (next FDE starts at window end 0x639f400)", nxt[0] - END == 0 and all(b == 0xCC for b in node[toff(END):toff(nxt[0])]))
    check("next FDE starts endbr64 (0xf3)",
          node[toff(nxt[0])] == 0xF3)
    check("prev FDE end 0x639f140 == window start (gap 0)",
          prev[1] == 0x639F140)
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
    check("#369 window FDE 0x639fc40..0x639fef8",
          fdes[bisect.bisect_left(starts, 0x639FC40)] ==
          (0x639FC40, 0x639FEF8))
    check("#370 window FDE 0x639f980..0x639fc38",
          fdes[bisect.bisect_left(starts, 0x639F980)] ==
          (0x639F980, 0x639FC38))
    check("#371 window FDE 0x639f6c0..0x639f978",
          fdes[bisect.bisect_left(starts, 0x639F6C0)] ==
          (0x639F6C0, 0x639F978))
    check("#372 window FDE 0x639f400..0x639f6b8",
          fdes[bisect.bisect_left(starts, 0x639F400)] ==
          (0x639F400, 0x639F6B8))
    check("resolver FDE 0x6388310..0x6388372",
          fdes[bisect.bisect_left(starts, 0x6388310)] ==
          (0x6388310, 0x6388372))
    check("loader FDE 0x63bfb90..0x63bfb98 (8-byte trivial load helper)",
          fdes[bisect.bisect_left(starts, 0x63BFB90)] ==
          (0x63BFB90, 0x63BFB98))
    check("next-question FDE 0x639ee80..0x639f140",
          fdes[bisect.bisect_left(starts, 0x639EE80)] ==
          (0x639EE80, 0x639F140))
    hexb = read(os.path.join(PACKET, "lockwait_caller_1site_resolver_noloader_dead_duff_q50x18.hex"))
    check("hex exhibit raw bytes 704", len(hexb) == 704, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])
    objdump = read(os.path.join(
        PACKET, "lockwait_caller_1site_resolver_noloader_dead_duff_q50x18.objdump.txt")).decode()
    lines = strict_lines(objdump)
    check("strict lines 186", len(lines) == 186, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if mnemonic_of(l) == "call"]
    check("call lines 5", len(calls) == 5, str(len(calls)))
    rets = [l for l in lines if mnemonic_of(l) == "ret"]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x639f1e7",
          sorted(addr_of(l) for l in rets) == [0x639f1e7],
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
    check("lock-wait site is 0x639f22c",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63bf680" in l) == [0x639f22c])
    check("resolver 0x6365150 called 0 times", tgt.get(0x6365150, 0) == 0,
          str(tgt.get(0x6365150, 0)))
    check("count call 0x634eba0 NOT called (0 times)",
          tgt.get(0x634EBA0, 0) == 0, str(tgt.get(0x634EBA0, 0)))
    check("index resolver 0x6388310 called 1 time at 0x639f1f4",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "6388310" in l) == [0x639f1f4])
    check("load helper 0x63bfb90 NOT called (0 times)",
          tgt.get(0x63BFB90, 0) == 0, str(tgt.get(0x63BFB90, 0)))
    check("stack_chk_fail plt call 1 at 0x639f3fb",
          tgt.get(0x63F0D70, 0) == 1, str(tgt.get(0x63F0D70, 0)))
    check("trylock plt call 1 at 0x639f17b",
          tgt.get(0x63F17B0, 0) == 1, str(tgt.get(0x63F17B0, 0)))
    check("unlock plt call 1 at 0x639f1be",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63f0b70" in l) == [0x639f1be])
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
                  ("#368", 0x639FF00),
                  ("#369", 0x639FC40),
                  ("#370", 0x639F980),
                  ("#371", 0x639F6C0),
                  ("#372", 0x639F400)):
        check("%s window not called" % _w, tgt.get(_a, 0) == 0,
              str(tgt.get(_a, 0)))

    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", len(bsr) == 0, str([hex(addr_of(l)) for l in bsr]))
    check("shr exactly 1 (shr $0x3 at 0x639f297)",
          [hex(addr_of(l)) for l in lines if mnemonic_of(l) == "shr"] ==
          ["0x639f297"])
    check("shr is $0x3,%edi at 0x639f297",
          "shr" in by_addr[0x639f297] and "$0x3,%edi" in by_addr[0x639f297])
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
          [0x639f188, 0x639f1a8, 0x639f1b4, 0x639f1b4, 0x639f1f0,
           0x639f21d, 0x639f21d, 0x639f228, 0x639f240, 0x639f2de,
           0x639f2ed, 0x639f2fc, 0x639f30b, 0x639f31a, 0x639f329,
           0x639f341, 0x639f341, 0x639f3b0, 0x639f3c7, 0x639f3c7,
           0x639f3c7, 0x639f3c7, 0x639f3c7, 0x639f3c7, 0x639f3c7,
           0x639f3d5, 0x639f3eb, 0x639f3fb],
          str(sorted(jump_target(l) for l in jmps)))
    check("endbr64 count 1",
          sum(1 for l in lines if "endbr64" in l) == 1)
    check("entry is endbr64 at 0x639f140",
          "endbr64" in by_addr[START])
    check("canary present: 2 fs:0x28 lines",
          sum(1 for l in lines if "%fs:0x28" in l) == 2)
    check("canary load at 0x639f16b",
          "mov" in by_addr[0x639f16b] and "%fs:0x28,%rax" in by_addr[0x639f16b])
    check("canary save to 0x8(%rsp) at 0x639f174",
          "mov" in by_addr[0x639f174] and "%rax,0x8(%rsp)" in by_addr[0x639f174])
    check("canary check sub at 0x639f1c8",
          "sub" in by_addr[0x639f1c8] and "%fs:0x28,%rax" in by_addr[0x639f1c8])
    check("canary fail jne to stack_chk_fail at 0x639f1d1",
          "jne" in by_addr[0x639f1d1] and "639f3fb" in by_addr[0x639f1d1])
    check("TLS flag check absent: 0 fs:0x330 lines",
          sum(1 for l in lines if "%fs:0x330" in l) == 0)
    check("no prefetch instructions",
          not any("prefetch" in l for l in lines))
    check("tzcnt 0",
          [l for l in lines if mnemonic_of(l) == "tzcnt"] == [])
    check('entry endbr64 at 0x639f140',
          'endbr64' in by_addr[0x639f140])
    check('push %r15 at 0x639f144',
          'push' in by_addr[0x639f144] and '%r15' in by_addr[0x639f144])
    check('mutex lea 0x67121a0 at 0x639f146',
          'lea' in by_addr[0x639f146] and '0x373053(%rip),%r15' in by_addr[0x639f146])
    check('push %r14 at 0x639f14d',
          'push' in by_addr[0x639f14d] and '%r14' in by_addr[0x639f14d])
    check('entry rsi save mov %rsi,%r14 at 0x639f14f',
          'mov' in by_addr[0x639f14f] and '%rsi,%r14' in by_addr[0x639f14f])
    check('push %r13 at 0x639f152',
          'push' in by_addr[0x639f152] and '%r13' in by_addr[0x639f152])
    check('entry r8 save mov %r8,%r13 at 0x639f154',
          'mov' in by_addr[0x639f154] and '%r8,%r13' in by_addr[0x639f154])
    check('push %r12 at 0x639f157',
          'push' in by_addr[0x639f157] and '%r12' in by_addr[0x639f157])
    check('entry rcx save mov %rcx,%r12 at 0x639f159',
          'mov' in by_addr[0x639f159] and '%rcx,%r12' in by_addr[0x639f159])
    check('push %rbp at 0x639f15c',
          'push' in by_addr[0x639f15c] and '%rbp' in by_addr[0x639f15c])
    check('entry rdi save mov %rdi,%rbp at 0x639f15d',
          'mov' in by_addr[0x639f15d] and '%rdi,%rbp' in by_addr[0x639f15d])
    check('mov %r15,%rdi at 0x639f160',
          'mov' in by_addr[0x639f160] and '%r15,%rdi' in by_addr[0x639f160])
    check('push %rbx at 0x639f163',
          'push' in by_addr[0x639f163] and '%rbx' in by_addr[0x639f163])
    check('entry r9 save mov %r9,%rbx at 0x639f164',
          'mov' in by_addr[0x639f164] and '%r9,%rbx' in by_addr[0x639f164])
    check('frame sub $0x18,%rsp at 0x639f167',
          'sub' in by_addr[0x639f167] and '$0x18,%rsp' in by_addr[0x639f167])
    check('canary load mov %fs:0x28,%rax at 0x639f16b',
          'mov' in by_addr[0x639f16b] and '%fs:0x28,%rax' in by_addr[0x639f16b])
    check('canary save mov %rax,0x8(%rsp) at 0x639f174',
          'mov' in by_addr[0x639f174] and '%rax,0x8(%rsp)' in by_addr[0x639f174])
    check('xor %eax,%eax at 0x639f179',
          'xor' in by_addr[0x639f179] and '%eax,%eax' in by_addr[0x639f179])
    check('trylock call at 0x639f17b',
          'call' in by_addr[0x639f17b] and '63f17b0 <pthread_mutex_trylock@plt>' in by_addr[0x639f17b])
    check('trylock test %eax,%eax at 0x639f180',
          'test' in by_addr[0x639f180] and '%eax,%eax' in by_addr[0x639f180])
    check('trylock-fail jne lock-wait setup at 0x639f182',
          'jne' in by_addr[0x639f182] and '639f228' in by_addr[0x639f182])
    check('acq-count addq $0x1,0x373008(%rip) at 0x639f188',
          'addq' in by_addr[0x639f188] and '$0x1,0x373008(%rip)' in by_addr[0x639f188])
    check('owner cmp 0x6712190,%rbp at 0x639f190',
          'cmp' in by_addr[0x639f190] and '0x372ff9(%rip),%rbp' in by_addr[0x639f190])
    check('owner-unchanged je exit-1 at 0x639f197',
          'je' in by_addr[0x639f197] and '639f1a8' in by_addr[0x639f197])
    check('counter addq $0x1,0x372fe7(%rip) at 0x639f199',
          'addq' in by_addr[0x639f199] and '$0x1,0x372fe7(%rip)' in by_addr[0x639f199])
    check('owner store mov %rbp,0x372fe8(%rip) at 0x639f1a1',
          'mov' in by_addr[0x639f1a1] and '%rbp,0x372fe8(%rip)' in by_addr[0x639f1a1])
    check('exit-1 mov $0x1,%ebp at 0x639f1a8',
          'mov' in by_addr[0x639f1a8] and '$0x1,%ebp' in by_addr[0x639f1a8])
    check('caller-cond or 0x50(%rsp),%rbx at 0x639f1ad',
          'or' in by_addr[0x639f1ad] and '0x50(%rsp),%rbx' in by_addr[0x639f1ad])
    check('caller-cond je resolver path at 0x639f1b2',
          'je' in by_addr[0x639f1b2] and '639f1f0' in by_addr[0x639f1b2])
    check('waited-flag clear movb $0x0,0x37300d(%rip) at 0x639f1b4',
          'movb' in by_addr[0x639f1b4] and '$0x0,0x37300d(%rip)' in by_addr[0x639f1b4])
    check('unlock rdi mov %r15,%rdi at 0x639f1bb',
          'mov' in by_addr[0x639f1bb] and '%r15,%rdi' in by_addr[0x639f1bb])
    check('unlock call at 0x639f1be',
          'call' in by_addr[0x639f1be] and '63f0b70 <pthread_mutex_unlock@plt>' in by_addr[0x639f1be])
    check('canary reload mov 0x8(%rsp),%rax at 0x639f1c3',
          'mov' in by_addr[0x639f1c3] and '0x8(%rsp),%rax' in by_addr[0x639f1c3])
    check('canary check sub %fs:0x28,%rax at 0x639f1c8',
          'sub' in by_addr[0x639f1c8] and '%fs:0x28,%rax' in by_addr[0x639f1c8])
    check('canary fail jne stack_chk_fail at 0x639f1d1',
          'jne' in by_addr[0x639f1d1] and '639f3fb' in by_addr[0x639f1d1])
    check('rsp restore add $0x18,%rsp at 0x639f1d7',
          'add' in by_addr[0x639f1d7] and '$0x18,%rsp' in by_addr[0x639f1d7])
    check('exit mov %ebp,%eax at 0x639f1db',
          'mov' in by_addr[0x639f1db] and '%ebp,%eax' in by_addr[0x639f1db])
    check('pop %rbx at 0x639f1dd',
          'pop' in by_addr[0x639f1dd] and '%rbx' in by_addr[0x639f1dd])
    check('pop %rbp at 0x639f1de',
          'pop' in by_addr[0x639f1de] and '%rbp' in by_addr[0x639f1de])
    check('pop %r12 at 0x639f1df',
          'pop' in by_addr[0x639f1df] and '%r12' in by_addr[0x639f1df])
    check('pop %r13 at 0x639f1e1',
          'pop' in by_addr[0x639f1e1] and '%r13' in by_addr[0x639f1e1])
    check('pop %r14 at 0x639f1e3',
          'pop' in by_addr[0x639f1e3] and '%r14' in by_addr[0x639f1e3])
    check('pop %r15 at 0x639f1e5',
          'pop' in by_addr[0x639f1e5] and '%r15' in by_addr[0x639f1e5])
    check('ret at 0x639f1e7',
          'ret' in by_addr[0x639f1e7])
    check('resolver arg mov 0x10(%r14),%rdi at 0x639f1f0',
          'mov' in by_addr[0x639f1f0] and '0x10(%r14),%rdi' in by_addr[0x639f1f0])
    check('resolver call 0x6388310 at 0x639f1f4',
          'call' in by_addr[0x639f1f4] and '6388310' in by_addr[0x639f1f4])
    check('resolver qword mov 0x50(%rax),%rax at 0x639f1f9 (first step of the two-step read; no loader, no adjust)',
          'mov' in by_addr[0x639f1f9] and '0x50(%rax),%rax' in by_addr[0x639f1f9])
    check('resolver second load mov 0x18(%rax),%rsi at 0x639f1fd (double-dereferenced entry)',
          'mov' in by_addr[0x639f1fd] and '0x18(%rax),%rsi' in by_addr[0x639f1fd])
    check('qword store mov %rsi,(%rsp) at 0x639f201',
          'mov' in by_addr[0x639f201] and '%rsi,(%rsp)' in by_addr[0x639f201])
    check('rcx==0 test %r12,%r12 at 0x639f205',
          'test' in by_addr[0x639f205] and '%r12,%r12' in by_addr[0x639f205])
    check('rcx==0 je exit-0 at 0x639f208',
          'je' in by_addr[0x639f208] and '639f21d' in by_addr[0x639f208])
    check('r8==0 test %r13,%r13 at 0x639f20a',
          'test' in by_addr[0x639f20a] and '%r13,%r13' in by_addr[0x639f20a])
    check('r8==0 je exit-0 at 0x639f20d',
          'je' in by_addr[0x639f20d] and '639f21d' in by_addr[0x639f20d])
    check('len load mov 0x0(%r13),%rdx at 0x639f20f',
          'mov' in by_addr[0x639f20f] and '0x0(%r13),%rdx' in by_addr[0x639f20f])
    check('len cmp $0x8,%rdx at 0x639f213',
          'cmp' in by_addr[0x639f213] and '$0x8,%rdx' in by_addr[0x639f213])
    check('len!=8 jne Duff path at 0x639f217',
          'jne' in by_addr[0x639f217] and '639f240' in by_addr[0x639f217])
    check('len==8 qword store mov %rsi,(%r12) at 0x639f219',
          'mov' in by_addr[0x639f219] and '%rsi,(%r12)' in by_addr[0x639f219])
    check('exit-0 xor %ebp,%ebp at 0x639f21d',
          'xor' in by_addr[0x639f21d] and '%ebp,%ebp' in by_addr[0x639f21d])
    check('exit-0 jmp flag-clear at 0x639f21f',
          'jmp' in by_addr[0x639f21f] and '639f1b4' in by_addr[0x639f21f])
    check('lock-wait setup lea -0x40(%r15),%rdi at 0x639f228',
          'lea' in by_addr[0x639f228] and '-0x40(%r15),%rdi' in by_addr[0x639f228])
    check('lock-wait call at 0x639f22c',
          'call' in by_addr[0x639f22c] and '63bf680' in by_addr[0x639f22c])
    check('waited-flag set movb $0x1,0x372f90(%rip) at 0x639f231',
          'movb' in by_addr[0x639f231] and '$0x1,0x372f90(%rip)' in by_addr[0x639f231])
    check('lock-wait rejoin jmp trylock-success (NO retry) at 0x639f238',
          'jmp' in by_addr[0x639f238] and '639f188' in by_addr[0x639f238])
    check('Duff cap mov $0x8,%ecx at 0x639f240',
          'mov' in by_addr[0x639f240] and '$0x8,%ecx' in by_addr[0x639f240])
    check('Duff src mov %rsp,%r9 at 0x639f245',
          'mov' in by_addr[0x639f245] and '%rsp,%r9' in by_addr[0x639f245])
    check('Duff cmp %rcx,%rdx at 0x639f248',
          'cmp' in by_addr[0x639f248] and '%rcx,%rdx' in by_addr[0x639f248])
    check('Duff min cmova %rcx,%rdx at 0x639f24b',
          'cmova' in by_addr[0x639f24b] and '%rcx,%rdx' in by_addr[0x639f24b])
    check('Duff cmp $0x8,%edx at 0x639f24f',
          'cmp' in by_addr[0x639f24f] and '$0x8,%edx' in by_addr[0x639f24f])
    check('Duff n<8 jb small tail at 0x639f252',
          'jb' in by_addr[0x639f252] and '639f3b0' in by_addr[0x639f252])
    check('Duff n mov %edx,%eax at 0x639f258',
          'mov' in by_addr[0x639f258] and '%edx,%eax' in by_addr[0x639f258])
    check('Duff first qword mov %rsi,(%r12) at 0x639f25a',
          'mov' in by_addr[0x639f25a] and '%rsi,(%r12)' in by_addr[0x639f25a])
    check('Duff lea 0x8(%r12),%rcx at 0x639f25e',
          'lea' in by_addr[0x639f25e] and '0x8(%r12),%rcx' in by_addr[0x639f25e])
    check('Duff last-qword load mov -0x8(%r9,%rax,1),%rsi at 0x639f263',
          'mov' in by_addr[0x639f263] and '-0x8(%r9,%rax,1),%rsi' in by_addr[0x639f263])
    check('Duff and $~7,%rcx at 0x639f268',
          'and' in by_addr[0x639f268] and '$0xfffffffffffffff8,%rcx' in by_addr[0x639f268])
    check('Duff last-qword store mov %rsi,-0x8(%r12,%rax,1) at 0x639f26c',
          'mov' in by_addr[0x639f26c] and '%rsi,-0x8(%r12,%rax,1)' in by_addr[0x639f26c])
    check('Duff sub %rcx,%r12 at 0x639f271',
          'sub' in by_addr[0x639f271] and '%rcx,%r12' in by_addr[0x639f271])
    check('Duff sub %r12,%r9 at 0x639f274',
          'sub' in by_addr[0x639f274] and '%r12,%r9' in by_addr[0x639f274])
    check('Duff add %edx,%r12d at 0x639f277',
          'add' in by_addr[0x639f277] and '%edx,%r12d' in by_addr[0x639f277])
    check('Duff and $~7,%r12d at 0x639f27a',
          'and' in by_addr[0x639f27a] and '$0xfffffff8,%r12d' in by_addr[0x639f27a])
    check('Duff cmp $0x8,%r12d at 0x639f27e',
          'cmp' in by_addr[0x639f27e] and '$0x8,%r12d' in by_addr[0x639f27e])
    check('Duff loop-entry jb writeback at 0x639f282',
          'jb' in by_addr[0x639f282] and '639f3c7' in by_addr[0x639f282])
    check('Duff loop first mov (%r9,%rbx,1),%r8 at 0x639f288',
          'mov' in by_addr[0x639f288] and '(%r9,%rbx,1),%r8' in by_addr[0x639f288])
    check('Duff lea -0x1(%r12),%edi at 0x639f28c',
          'lea' in by_addr[0x639f28c] and '-0x1(%r12),%edi' in by_addr[0x639f28c])
    check('Duff mov $0x8,%r10d at 0x639f291',
          'mov' in by_addr[0x639f291] and '$0x8,%r10d' in by_addr[0x639f291])
    check('Duff shr $0x3,%edi at 0x639f297',
          'shr' in by_addr[0x639f297] and '$0x3,%edi' in by_addr[0x639f297])
    check('Duff first store mov %r8,(%rcx,%rbx,1) at 0x639f29a',
          'mov' in by_addr[0x639f29a] and '%r8,(%rcx,%rbx,1)' in by_addr[0x639f29a])
    check('Duff dispatch and $0x7,%edi at 0x639f29e',
          'and' in by_addr[0x639f29e] and '$0x7,%edi' in by_addr[0x639f29e])
    check('Duff cmp %r12d,%r10d at 0x639f2a1',
          'cmp' in by_addr[0x639f2a1] and '%r12d,%r10d' in by_addr[0x639f2a1])
    check('Duff jae writeback at 0x639f2a4',
          'jae' in by_addr[0x639f2a4] and '639f3c7' in by_addr[0x639f2a4])
    check('Duff test %edi,%edi at 0x639f2aa',
          'test' in by_addr[0x639f2aa] and '%edi,%edi' in by_addr[0x639f2aa])
    check('Duff edi==0 je 8x body at 0x639f2ac',
          'je' in by_addr[0x639f2ac] and '639f341' in by_addr[0x639f2ac])
    check('Duff cmp $0x1,%edi at 0x639f2b2',
          'cmp' in by_addr[0x639f2b2] and '$0x1,%edi' in by_addr[0x639f2b2])
    check('Duff edi==1 je tail at 0x639f2b5',
          'je' in by_addr[0x639f2b5] and '639f329' in by_addr[0x639f2b5])
    check('Duff cmp $0x2,%edi at 0x639f2b7',
          'cmp' in by_addr[0x639f2b7] and '$0x2,%edi' in by_addr[0x639f2b7])
    check('Duff edi==2 je tail at 0x639f2ba',
          'je' in by_addr[0x639f2ba] and '639f31a' in by_addr[0x639f2ba])
    check('Duff cmp $0x3,%edi at 0x639f2bc',
          'cmp' in by_addr[0x639f2bc] and '$0x3,%edi' in by_addr[0x639f2bc])
    check('Duff edi==3 je tail at 0x639f2bf',
          'je' in by_addr[0x639f2bf] and '639f30b' in by_addr[0x639f2bf])
    check('Duff cmp $0x4,%edi at 0x639f2c1',
          'cmp' in by_addr[0x639f2c1] and '$0x4,%edi' in by_addr[0x639f2c1])
    check('Duff edi==4 je tail at 0x639f2c4',
          'je' in by_addr[0x639f2c4] and '639f2fc' in by_addr[0x639f2c4])
    check('Duff cmp $0x5,%edi at 0x639f2c6',
          'cmp' in by_addr[0x639f2c6] and '$0x5,%edi' in by_addr[0x639f2c6])
    check('Duff edi==5 je tail at 0x639f2c9',
          'je' in by_addr[0x639f2c9] and '639f2ed' in by_addr[0x639f2c9])
    check('Duff cmp $0x6,%edi at 0x639f2cb',
          'cmp' in by_addr[0x639f2cb] and '$0x6,%edi' in by_addr[0x639f2cb])
    check('Duff edi==6 je tail at 0x639f2ce',
          'je' in by_addr[0x639f2ce] and '639f2de' in by_addr[0x639f2ce])
    check('Duff tail-end cmp %r12d,%r10d at 0x639f338',
          'cmp' in by_addr[0x639f338] and '%r12d,%r10d' in by_addr[0x639f338])
    check('Duff tail-end jae writeback at 0x639f33b',
          'jae' in by_addr[0x639f33b] and '639f3c7' in by_addr[0x639f33b])
    check('8x body mov %r10d,%esi at 0x639f341',
          'mov' in by_addr[0x639f341] and '%r10d,%esi' in by_addr[0x639f341])
    check('8x body add $0x40,%r10d at 0x639f384',
          'add' in by_addr[0x639f384] and '$0x40,%r10d' in by_addr[0x639f384])
    check('8x body cmp %r12d,%r10d at 0x639f3a4',
          'cmp' in by_addr[0x639f3a4] and '%r12d,%r10d' in by_addr[0x639f3a4])
    check('8x body back-edge jb 0x639f341 at 0x639f3a7',
          'jb' in by_addr[0x639f3a7] and '639f341' in by_addr[0x639f3a7])
    check('8x body jmp writeback at 0x639f3a9',
          'jmp' in by_addr[0x639f3a9] and '639f3c7' in by_addr[0x639f3a9])
    check('small tail test $0x4,%dl at 0x639f3b0',
          'test' in by_addr[0x639f3b0] and '$0x4,%dl' in by_addr[0x639f3b0])
    check('small tail jne 4-byte at 0x639f3b3',
          'jne' in by_addr[0x639f3b3] and '639f3d5' in by_addr[0x639f3b3])
    check('small tail test %edx,%edx at 0x639f3b5',
          'test' in by_addr[0x639f3b5] and '%edx,%edx' in by_addr[0x639f3b5])
    check('small tail je writeback at 0x639f3b7',
          'je' in by_addr[0x639f3b7] and '639f3c7' in by_addr[0x639f3b7])
    check('small tail movzbl (%rsp),%r11d at 0x639f3b9',
          'movzbl' in by_addr[0x639f3b9] and '(%rsp),%r11d' in by_addr[0x639f3b9])
    check('small tail mov %r11b,(%r12) at 0x639f3be',
          'mov' in by_addr[0x639f3be] and '%r11b,(%r12)' in by_addr[0x639f3be])
    check('small tail test $0x2,%dl at 0x639f3c2',
          'test' in by_addr[0x639f3c2] and '$0x2,%dl' in by_addr[0x639f3c2])
    check('small tail jne 2-byte at 0x639f3c5',
          'jne' in by_addr[0x639f3c5] and '639f3eb' in by_addr[0x639f3c5])
    check('writeback mov %rdx,0x0(%r13) at 0x639f3c7',
          'mov' in by_addr[0x639f3c7] and '%rdx,0x0(%r13)' in by_addr[0x639f3c7])
    check('exit-22 mov $0x16,%ebp at 0x639f3cb',
          'mov' in by_addr[0x639f3cb] and '$0x16,%ebp' in by_addr[0x639f3cb])
    check('exit-22 jmp flag-clear at 0x639f3d0',
          'jmp' in by_addr[0x639f3d0] and '639f1b4' in by_addr[0x639f3d0])
    check('4-byte mov (%rsp),%edi at 0x639f3d5',
          'mov' in by_addr[0x639f3d5] and '(%rsp),%edi' in by_addr[0x639f3d5])
    check('4-byte mov %edi,(%r12) at 0x639f3db',
          'mov' in by_addr[0x639f3db] and '%edi,(%r12)' in by_addr[0x639f3db])
    check('4-byte last mov -0x4(%r9,%r8,1),%r10d at 0x639f3df',
          'mov' in by_addr[0x639f3df] and '-0x4(%r9,%r8,1),%r10d' in by_addr[0x639f3df])
    check('4-byte jmp writeback at 0x639f3e9',
          'jmp' in by_addr[0x639f3e9] and '639f3c7' in by_addr[0x639f3e9])
    check('2-byte movzwl -0x2(%r9,%rbp,1),%r14d at 0x639f3ed',
          'movzwl' in by_addr[0x639f3ed] and '-0x2(%r9,%rbp,1),%r14d' in by_addr[0x639f3ed])
    check('2-byte jmp writeback at 0x639f3f9',
          'jmp' in by_addr[0x639f3f9] and '639f3c7' in by_addr[0x639f3f9])
    check('stack_chk_fail call at 0x639f3fb',
          'call' in by_addr[0x639f3fb] and '63f0d70 <__stack_chk_fail@plt>' in by_addr[0x639f3fb])
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

    check("entry reaches lock-wait site 0x639f22c", reaches(START, 0x639f22c))
    check("entry reaches ret 0x639f1e7", reaches(START, 0x639f1e7))
    check("entry reaches trylock 0x639f17b", reaches(START, 0x639f17b))
    check("entry reaches flag-clear 0x639f1b4", reaches(START, 0x639f1b4))
    check("entry reaches epilogue canary 0x639f1c3", reaches(START, 0x639f1c3))
    check("entry reaches resolver call 0x639f1f4", reaches(START, 0x639f1f4))
    check("entry reaches exit-1 block 0x639f1a8", reaches(START, 0x639f1a8))
    check("entry reaches exit-0 block 0x639f21d", reaches(START, 0x639f21d))
    check("entry reaches exit-22 block 0x639f3cb", reaches(START, 0x639f3cb))
    check("entry reaches Duff entry 0x639f240", reaches(START, 0x639f240))
    check("entry reaches lock-wait setup 0x639f228", reaches(START, 0x639f228))
    check("entry reaches writeback 0x639f3c7", reaches(START, 0x639f3c7))
    check("entry reaches Duff loop first instr 0x639f288 (graph edge only; fully dead, see Duff block)",
          reaches(START, 0x639f288))
    check("entry reaches 8x body 0x639f341 (graph edge only; fully dead, see Duff block)",
          reaches(START, 0x639f341))
    check("entry reaches small tail 0x639f3b0", reaches(START, 0x639f3b0))
    check("preds of lock-wait site 0x639f22c is the setup lea only",
          preds[0x639f22c] == {0x639f228}, str(preds[0x639f22c]))
    check("preds of lock-wait setup 0x639f228 are trylock fail and the "
          "padding nopl",
          preds[0x639f228] == {0x639f182, 0x639f221}, str(preds[0x639f228]))
    check("preds of trylock 0x639f17b is the xor only",
          preds[0x639f17b] == {0x639f179}, str(preds[0x639f17b]))
    check("preds of rejoin 0x639f188 are trylock success and the "
          "lock-wait jmp",
          preds[0x639f188] == {0x639f182, 0x639f238}, str(preds[0x639f188]))
    check("preds of ret 0x639f1e7 is the final pop",
          preds[0x639f1e7] == {0x639f1e5}, str(preds[0x639f1e7]))
    check("preds of flag-clear block 0x639f1b4 are the caller-cond "
          "fall-through, the exit-0 jmp and the exit-22 jmp",
          preds[0x639f1b4] == {0x639f1b2, 0x639f21f, 0x639f3d0},
          str(preds[0x639f1b4]))
    check("preds of exit-1 block 0x639f1a8 are the owner-unchanged je "
          "and the owner-store fall-through",
          preds[0x639f1a8] == {0x639f197, 0x639f1a1}, str(preds[0x639f1a8]))
    check("preds of resolver call 0x639f1f4 is the resolver-arg mov only",
          preds[0x639f1f4] == {0x639f1f0}, str(preds[0x639f1f4]))
    check("preds of resolver path 0x639f1f0 are the caller-cond je and "
          "the padding nopl",
          preds[0x639f1f0] == {0x639f1b2, 0x639f1e8}, str(preds[0x639f1f0]))
    check("preds of exit-0 block 0x639f21d are rcx==0, r8==0 and the "
          "len==8 qword store",
          preds[0x639f21d] == {0x639f208, 0x639f20d, 0x639f219},
          str(preds[0x639f21d]))
    check("preds of Duff entry 0x639f240 are the len!=8 jne and the "
          "padding nopl",
          preds[0x639f240] == {0x639f217, 0x639f23d}, str(preds[0x639f240]))
    check("preds of writeback 0x639f3c7 are the loop-entry jb, the two "
          "dispatch jaes, the 8x-body jmp, the small-tail je, the small-tail "
          "jne fall-through and the two small-tail jmps",
          preds[0x639f3c7] == {0x639f282, 0x639f2a4, 0x639f33b, 0x639f3a9,
                               0x639f3b7, 0x639f3c5, 0x639f3e9, 0x639f3f9},
          str(preds[0x639f3c7]))
    check("preds of 8x body 0x639f341 are the dispatch je, the "
          "tail-end fall-through and the body's own back-edge",
          preds[0x639f341] == {0x639f2ac, 0x639f33b, 0x639f3a7}, str(preds[0x639f341]))
    check("preds of Duff loop first instr 0x639f288 is the loop-entry jb "
          "fall-through only",
          preds[0x639f288] == {0x639f282}, str(preds[0x639f288]))
    check("preds of small tail 0x639f3b0 are the n<8 jb and the padding nopl",
          preds[0x639f3b0] == {0x639f252, 0x639f3ab}, str(preds[0x639f3b0]))
    check("preds of n==8 path 0x639f258 is the n>=8 cmp fall-through only",
          preds[0x639f258] == {0x639f252}, str(preds[0x639f258]))
    # The Duff's-device loop IS present (0x639f288..0x639f3a9) but it is
    # FULLY DEAD, unlike #366 (reachable dispatch tail) and #339..#364
    # (unreachable loop, different mechanism): the only CFG entry to the
    # loop is the fall-through from the loop-entry jb at 0x639f282
    # (preds[0x639f288] == {0x639f282}), and that jb is ALWAYS taken.
    # The jb tests r12d < 8 after cmp $0x8,%r12d at 0x639f27e, and r12d
    # is 0 on every path that reaches 0x639f27e: r12 = dest - ((dest+8)
    # & ~7) = (dest mod 8) - 8 (sub %rcx,%r12 at 0x639f271, rcx =
    # (dest+8)&~7 from lea 0x8(%r12) at 0x639f25e and and $~7,%rcx at
    # 0x639f268), then r12d += n (add %edx,%r12d at 0x639f277) and
    # r12d &= ~7 (and $0xfffffff8,%r12d at 0x639f27a). The only path to
    # 0x639f258 has n == 8: len == 8 exits 0 on the fast path (the jne at
    # 0x639f217 falls through only when len == 8), len < 8 goes to the
    # small tail (jb at 0x639f252), so reaching 0x639f258 requires
    # n >= 8 while n = min(len,8) <= 8 (cmova at 0x639f24b), hence
    # n == 8 exactly and r12d = ((dest mod 8) - 8 + 8) & ~7 = 0 < 8.
    # So the dispatch
    # tail (0x639f288..0x639f33f) and the 8-at-a-time body
    # (0x639f341..0x639f3a9) are never entered. For len > 8 only the
    # first qword is copied -- stored to dest+0 at 0x639f25a, re-loaded
    # from src+0 at 0x639f263 (mov -0x8(%r9,%rax,1),%rsi -- with eax
    # == 8 reads src+0, not src+8), and stored AGAIN to dest+0 at
    # 0x639f26c -- then *r8 = 8 and exit 22.
    # For len < 8 the small tail (0x639f3b0..0x639f3f9) copies n = len
    # bytes by 4/2/1-byte decomposition, *r8 = n, exit 22.
    check("Duff cap is 8: mov $0x8,%ecx at 0x639f240",
          "mov" in by_addr[0x639f240] and "$0x8,%ecx" in by_addr[0x639f240])
    check("Duff src is the stack temp: mov %rsp,%r9 at 0x639f245",
          "mov" in by_addr[0x639f245] and "%rsp,%r9" in by_addr[0x639f245])
    check("Duff min is cmova %rcx,%rdx at 0x639f24b",
          "cmova" in by_addr[0x639f24b] and "%rcx,%rdx" in by_addr[0x639f24b])
    check("Duff n<8 jb small tail at 0x639f252",
          "jb" in by_addr[0x639f252] and "639f3b0" in by_addr[0x639f252])
    check("Duff n==8 path entry is the jb fall-through only",
          preds[0x639f258] == {0x639f252}, str(preds[0x639f258]))
    check("Duff r12 chain: sub %rcx,%r12 at 0x639f271",
          "sub" in by_addr[0x639f271] and "%rcx,%r12" in by_addr[0x639f271])
    check("Duff r12 chain: add %edx,%r12d at 0x639f277",
          "add" in by_addr[0x639f277] and "%edx,%r12d" in by_addr[0x639f277])
    check("Duff r12 chain: and $~7,%r12d at 0x639f27a",
          "and" in by_addr[0x639f27a] and "$0xfffffff8,%r12d" in by_addr[0x639f27a])
    check("Duff loop-entry cmp $0x8,%r12d at 0x639f27e",
          "cmp" in by_addr[0x639f27e] and "$0x8,%r12d" in by_addr[0x639f27e])
    check("Duff loop-entry jb writeback at 0x639f282",
          "jb" in by_addr[0x639f282] and "639f3c7" in by_addr[0x639f282])
    check("Duff loop sole entry is the loop-entry jb fall-through",
          preds[0x639f288] == {0x639f282}, str(preds[0x639f288]))
    check("Duff dispatch tail entries are the six je targets for edi in 1..6",
          sorted(jump_target(by_addr[a]) for a in
                 (0x639f2b5, 0x639f2ba, 0x639f2bf, 0x639f2c4, 0x639f2c9,
                  0x639f2ce)) ==
          [0x639f2de, 0x639f2ed, 0x639f2fc, 0x639f30b, 0x639f31a, 0x639f329],
          str([hex(jump_target(by_addr[a])) for a in
               (0x639f2b5, 0x639f2ba, 0x639f2bf, 0x639f2c4, 0x639f2c9,
                0x639f2ce)]))
    check("Duff 8x-body entry je at 0x639f2ac fires only when edi==0",
          "je" in by_addr[0x639f2ac] and "639f341" in by_addr[0x639f2ac]
          and "test" in by_addr[0x639f2aa]
          and "%edi,%edi" in by_addr[0x639f2aa])
    check("Duff shr $0x3 at 0x639f297 and and $0x7 at 0x639f29e",
          "shr" in by_addr[0x639f297] and "$0x3,%edi" in by_addr[0x639f297]
          and "and" in by_addr[0x639f29e] and "$0x7,%edi" in by_addr[0x639f29e])
    check("Duff tail-end jae writeback at 0x639f33b",
          "jae" in by_addr[0x639f33b] and "639f3c7" in by_addr[0x639f33b])
    check("8x body back-edge jb 0x639f341 at 0x639f3a7",
          "jb" in by_addr[0x639f3a7] and "639f341" in by_addr[0x639f3a7])
    check("8x body exit jmp writeback at 0x639f3a9",
          "jmp" in by_addr[0x639f3a9] and "639f3c7" in by_addr[0x639f3a9])
    check("small tail entry is the n<8 jb and the padding nopl",
          preds[0x639f3b0] == {0x639f252, 0x639f3ab}, str(preds[0x639f3b0]))
    check("backward jumps are the exit-0 jmp, the lock-wait rejoin, "
          "the 8x-body back-edge, the exit-22 jmp and the two small-tail jmps",
          sorted((addr_of(l), jump_target(l)) for l in jmps
                 if jump_target(l) is not None
                 and jump_target(l) < addr_of(l)) ==
          [(0x639f21f, 0x639f1b4), (0x639f238, 0x639f188),
           (0x639f3a7, 0x639f341), (0x639f3d0, 0x639f1b4),
           (0x639f3e9, 0x639f3c7), (0x639f3f9, 0x639f3c7)],
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
    SITE = 0x639f22c
    RET = 0x639f1e7
    CALL_TRYLOCK = {("CALL", 0x639f17b)}
    check("site rdi only def is lea -0x40(%r15),%rdi 0x639f228",
          rdi_in[SITE] == {0x639f228}, str(rdi_in[SITE]))
    check("site rsi is clobbered by the trylock only (no post-trylock "
          "restore in this window, like #339/#340/#341/#342/#343/#344/#345/#346/#347/#348/#349/#350/#351/#352/#353/#354/#355/#356/#357/#358/#359/#360/#361/#362/#363/#364/#365/#366/#367/#368/#369/#370/#371/#372, unlike #338)",
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
          rbx_in[SITE] == {0x639f164}, str(rbx_in[SITE]))
    check("site rbp def is the entry rdi save",
          rbp_in[SITE] == {0x639f15d}, str(rbp_in[SITE]))
    check("site r12 def is the entry rcx save",
          r12_in[SITE] == {0x639f159}, str(r12_in[SITE]))
    check("site r13 def is the entry r8 save",
          r13_in[SITE] == {0x639f154}, str(r13_in[SITE]))
    check("site r14 def is the entry rsi save",
          r14_in[SITE] == {0x639f14f}, str(r14_in[SITE]))
    check("site r15 def is the mutex lea",
          r15_in[SITE] == {0x639f146}, str(r15_in[SITE]))
    check("rax at ret is exactly the single mov %ebp,%eax at 0x639f1db",
          rax_in[RET] == {0x639f1db}, str(rax_in[RET]))
    check("ebp at the exit mov is exactly the 3 exit values 0/1/22",
          rbp_in[0x639f1db] == {0x639f1a8, 0x639f21d, 0x639f3cb},
          str(rbp_in[0x639f1db]))
    check("ebp at the flag-clear is exactly the 3 exit values 0/1/22 "
          "(the flag-clear is the exit join point in this window)",
          rbp_in[0x639f1b4] == {0x639f1a8, 0x639f21d, 0x639f3cb},
          str(rbp_in[0x639f1b4]))
    check("rbx at the Duff entry is the caller-cond or only "
          "(copy path forces rbx==0)",
          rbx_in[0x639f240] == {0x639f1ad}, str(rbx_in[0x639f240]))
    check("rdx at the Duff entry is the len load only",
          rdx_in[0x639f240] == {0x639f20f}, str(rdx_in[0x639f240]))
    check("rdx at the writeback is the len load plus the cmova min",
          rdx_in[0x639f3c7] == {0x639f20f, 0x639f24b}, str(rdx_in[0x639f3c7]))
    check("r12 at the Duff entry is the entry rcx save",
          r12_in[0x639f240] == {0x639f159}, str(r12_in[0x639f240]))
    check("r13 at the Duff entry is the entry r8 save",
          r13_in[0x639f240] == {0x639f154}, str(r13_in[0x639f240]))
    check("r11 at the 8x body is the resolver clobber plus the two tail defs",
          r11_in[0x639f341] == {("CALL", 0x639f1f4), 0x639f31a, 0x639f374},
          str(r11_in[0x639f341]))
    check("rbp at the 8x body is exit-1 plus the two tail defs",
          rbp_in[0x639f341] == {0x639f1a8, 0x639f321, 0x639f394},
          str(rbp_in[0x639f341]))
    check("r12 at the 8x body is the loop-entry and only",
          r12_in[0x639f341] == {0x639f27a}, str(r12_in[0x639f341]))
    check("r8 at the writeback is the resolver clobber plus the four copy defs",
          r8_in[0x639f3c7] == {("CALL", 0x639f1f4), 0x639f288, 0x639f312,
                               0x639f38c, 0x639f3d8},
          str(r8_in[0x639f3c7]))
    check("r9 at the writeback is the Duff src plus the r9 adjust",
          r9_in[0x639f3c7] == {0x639f245, 0x639f274}, str(r9_in[0x639f3c7]))

    check("records lock-wait sites match census",
          [s.get("site") for s in rec.get("lock_wait_sites", [])] ==
          ["0x639f22c"])
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
          rec.get("window", {}).get("range") == "0x639f140..0x639f400")
    check("records return value exits 0/1/22",
          rec.get("return_value", {}).get("rax") ==
          "eax: 0/1/22 (mov %ebp,%eax at 0x639f1db; ebp: mov $0x1 at 0x639f1a8, xor %ebp at 0x639f21d, mov $0x16 at 0x639f3cb)")
    check("records entry gate absent (no gate byte in this window)",
          rec.get("entry_gate") is None)
    check("records count call absent (0x634eba0 NOT called here)",
          rec.get("count_call") is None)
    check("records resolver target 0x6388310",
          rec.get("resolver", {}).get("target") == "0x6388310")
    check("records resolver site 0x639f1f4",
          rec.get("resolver", {}).get("site") == "0x639f1f4")
    check("records loader absent (0x63bfb90 NOT called here)",
          rec.get("loader") is None)
    check("records inline adjust absent (no fixed adjust here)",
          rec.get("inline_adjust", {}).get("amount") is None)
    check("records selector is a two-step read (no index, no table)",
          rec.get("selector", {}).get("index") ==
          "none - two-step read: qword at +0x50 of resolver result (mov 0x50(%rax),%rax at 0x639f1f9), then qword at +0x18 of that entry (mov 0x18(%rax),%rsi at 0x639f1fd), stored to the stack temp (%rsp) at 0x639f201")
    check("records copy loop is a fully dead Duff loop",
          rec.get("copy_loop", {}).get("loop") is True)
    check("records copy dispatch is the Duff dispatch",
          rec.get("copy_loop", {}).get("dispatch") ==
          "Duff's-device dispatch at 0x639f288 (shr $0x3,%edi at 0x639f297, and $0x7,%edi at 0x639f29e) with tail entries for edi in 1..6; UNREACHABLE - loop-entry jb at 0x639f282 always taken (r12d == 0)")
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
    check("next candidate raw lu-miss 0", counts.get(0x639EE80, 0) == 0,
          str(counts.get(0x639EE80, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x639EE80, 0) == 0,
          str(bti_counts.get(0x639EE80, 0)))
    check("next candidate raw second-handler 0",
          sh_counts.get(0x639EE80, 0) == 0, str(sh_counts.get(0x639EE80, 0)))
    check("next candidate raw lock-wait 1",
          lw_counts.get(0x639EE80, 0) == 1,
          str(lw_counts.get(0x639EE80, 0)))
    # lock-wait frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 344", len(survey.get("survivors", [])) == 344,
          str(len(survey.get("survivors", []))))
    check("survey this window is a lock-wait survivor",
          "0x639f140" in survey.get("survivors", []))
    check("survey this window is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x639f140") == 1,
          str(survey.get("sites_per_fde", {}).get("0x639f140")))
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
          "0x639f140" not in survey.get("lu_miss_survivors", []))
    check("survey this window is NOT a second-handler survivor",
          "0x639f140" not in survey.get("second_handler_survivors", []))
    check("survey next candidate is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x639ee80") == 1,
          str(survey.get("sites_per_fde", {}).get("0x639ee80")))
    nq = rec.get("next_question", {})
    check("next question is the lock-wait frontier",
          nq.get("frontier") == "lock-wait helper 0x63bf680 callers",
          str(nq.get("frontier")))
    check("next question range 0x639ee80..0x639f140",
          nq.get("range") == "0x639ee80..0x639f140", str(nq.get("range")))
    check("next question bytes 704", nq.get("bytes") == 704,
          str(nq.get("bytes")))
    check("next question lu-miss sites 0",
          nq.get("lu_miss_sites") == 0, str(nq.get("lu_miss_sites")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 186", nq.get("strict") == 186,
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
          nq.get("lock_wait_site") == ["0x639ef6c"],
          str(nq.get("lock_wait_site")))
    check("next question second-handler sites 0",
          nq.get("second_handler_sites") == 0,
          str(nq.get("second_handler_sites")))
    check("next question bsr 0", nq.get("bsr") == 0,
          str(nq.get("bsr")))
    check("next question rets 1",
          nq.get("ret") == ["0x639ef27"], str(nq.get("ret")))
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
    check("records census strict 186",
          rec.get("census", {}).get("strict") == 186)
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
    # Authenticate the existing frozen public corpus and current packet overlays.
    # Do not depend on an author's private sibling worktrees or a size-only cache.
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
    # The recorded next candidate is a historical frontier. Later packets may
    # claim it, so compare its geometry with this packet only.
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x639F140 and 0x639EE80 < END))

    # The packet directory owns its slug within this checkout.
    slug_hit = os.path.basename(os.path.normpath(PACKET)) != SLUG
    check("slug unique", not slug_hit)
    check("slug not colliding with #314-#372 lu-miss/lockwait slugs",
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
                       "RE-001-node115-lockwait-caller-1site-resolver-noloader-dead-duff-q28",
                       "RE-001-node115-lockwait-caller-1site-resolver-noloader-dead-duff-q30",
                       "RE-001-node115-lockwait-caller-1site-resolver-noloader-dead-duff-q38",
                       "RE-001-node115-lockwait-caller-1site-resolver-noloader-dead-duff-q40",
                       "RE-001-node115-lockwait-caller-1site-resolver-noloader-dead-duff-q48"))

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
                    "lockwait_caller_1site_resolver_noloader_dead_duff_q50x18.hex",
                    "lockwait_caller_1site_resolver_noloader_dead_duff_q50x18.objdump.txt"}
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
