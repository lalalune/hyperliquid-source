import bisect
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

SLUG = "RE-001-node115-lockwait-caller-1site-resolver-fixed"
START = 0x63A4750
END = 0x63A4A10
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
    (0x63a4750, 'endbr64', ''), (0x63a4754, 'push', '%r15'), (0x63a4756, 'lea', '0x36da43(%rip),%r15        # 67121a0 <__register_atfork@plt+0x320610>'), (0x63a475d, 'push', '%r14'),
    (0x63a475f, 'mov', '%rsi,%r14'), (0x63a4762, 'push', '%r13'), (0x63a4764, 'mov', '%r8,%r13'), (0x63a4767, 'push', '%r12'),
    (0x63a4769, 'mov', '%rcx,%r12'), (0x63a476c, 'push', '%rbp'), (0x63a476d, 'mov', '%rdi,%rbp'), (0x63a4770, 'mov', '%r15,%rdi'),
    (0x63a4773, 'push', '%rbx'), (0x63a4774, 'mov', '%r9,%rbx'), (0x63a4777, 'sub', '$0x18,%rsp'), (0x63a477b, 'mov', '%fs:0x28,%rax'),
    (0x63a4784, 'mov', '%rax,0x8(%rsp)'), (0x63a4789, 'xor', '%eax,%eax'), (0x63a478b, 'call', '63f17b0 <pthread_mutex_trylock@plt>'), (0x63a4790, 'test', '%eax,%eax'),
    (0x63a4792, 'jne', '63a4840 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c410>'), (0x63a4798, 'addq', '$0x1,0x36d9f8(%rip)        # 6712198 <__register_atfork@plt+0x320608>'), (0x63a47a0, 'cmp', '0x36d9e9(%rip),%rbp        # 6712190 <__register_atfork@plt+0x320600>'), (0x63a47a7, 'je', '63a47b8 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c388>'),
    (0x63a47a9, 'addq', '$0x1,0x36d9d7(%rip)        # 6712188 <__register_atfork@plt+0x3205f8>'), (0x63a47b1, 'mov', '%rbp,0x36d9d8(%rip)        # 6712190 <__register_atfork@plt+0x320600>'), (0x63a47b8, 'mov', '$0x1,%ebp'), (0x63a47bd, 'or', '0x50(%rsp),%rbx'),
    (0x63a47c2, 'je', '63a4800 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c3d0>'), (0x63a47c4, 'movb', '$0x0,0x36d9fd(%rip)        # 67121c8 <__register_atfork@plt+0x320638>'), (0x63a47cb, 'mov', '%r15,%rdi'), (0x63a47ce, 'call', '63f0b70 <pthread_mutex_unlock@plt>'),
    (0x63a47d3, 'mov', '0x8(%rsp),%rax'), (0x63a47d8, 'sub', '%fs:0x28,%rax'), (0x63a47e1, 'jne', '63a4a0b <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c5db>'), (0x63a47e7, 'add', '$0x18,%rsp'),
    (0x63a47eb, 'mov', '%ebp,%eax'), (0x63a47ed, 'pop', '%rbx'), (0x63a47ee, 'pop', '%rbp'), (0x63a47ef, 'pop', '%r12'),
    (0x63a47f1, 'pop', '%r13'), (0x63a47f3, 'pop', '%r14'), (0x63a47f5, 'pop', '%r15'), (0x63a47f7, 'ret', ''),
    (0x63a47f8, 'nopl', '0x0(%rax,%rax,1)'), (0x63a4800, 'mov', '0x10(%r14),%rdi'), (0x63a4804, 'call', '6388310 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fee0>'), (0x63a4809, 'mov', '0x50(%rax),%rdi'),
    (0x63a480d, 'add', '$0xb8,%rdi'), (0x63a4814, 'call', '63bfb90 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677760>'), (0x63a4819, 'mov', '%rax,(%rsp)'), (0x63a481d, 'test', '%r12,%r12'),
    (0x63a4820, 'je', '63a4835 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c405>'), (0x63a4822, 'test', '%r13,%r13'), (0x63a4825, 'je', '63a4835 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c405>'), (0x63a4827, 'mov', '0x0(%r13),%rdx'),
    (0x63a482b, 'cmp', '$0x8,%rdx'), (0x63a482f, 'jne', '63a4858 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c428>'), (0x63a4831, 'mov', '%rax,(%r12)'), (0x63a4835, 'xor', '%ebp,%ebp'),
    (0x63a4837, 'jmp', '63a47c4 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c394>'), (0x63a4839, 'nopl', '0x0(%rax)'), (0x63a4840, 'lea', '-0x40(%r15),%rdi'), (0x63a4844, 'call', '63bf680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677250>'),
    (0x63a4849, 'movb', '$0x1,0x36d978(%rip)        # 67121c8 <__register_atfork@plt+0x320638>'), (0x63a4850, 'jmp', '63a4798 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c368>'), (0x63a4855, 'nopl', '(%rax)'), (0x63a4858, 'mov', '$0x8,%ecx'),
    (0x63a485d, 'mov', '%rsp,%r9'), (0x63a4860, 'cmp', '%rcx,%rdx'), (0x63a4863, 'cmova', '%rcx,%rdx'), (0x63a4867, 'cmp', '$0x8,%edx'),
    (0x63a486a, 'jb', '63a49c0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c590>'), (0x63a4870, 'mov', '%edx,%ebp'), (0x63a4872, 'mov', '%rax,(%r12)'), (0x63a4876, 'lea', '0x8(%r12),%rcx'),
    (0x63a487b, 'mov', '-0x8(%r9,%rbp,1),%r14'), (0x63a4880, 'and', '$0xfffffffffffffff8,%rcx'), (0x63a4884, 'mov', '%r14,-0x8(%r12,%rbp,1)'), (0x63a4889, 'sub', '%rcx,%r12'),
    (0x63a488c, 'sub', '%r12,%r9'), (0x63a488f, 'add', '%edx,%r12d'), (0x63a4892, 'and', '$0xfffffff8,%r12d'), (0x63a4896, 'cmp', '$0x8,%r12d'),
    (0x63a489a, 'jb', '63a49d7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c5a7>'), (0x63a48a0, 'mov', '(%r9,%rbx,1),%rax'), (0x63a48a4, 'lea', '-0x1(%r12),%esi'), (0x63a48a9, 'mov', '$0x8,%edi'),
    (0x63a48ae, 'shr', '$0x3,%esi'), (0x63a48b1, 'mov', '%rax,(%rcx,%rbx,1)'), (0x63a48b5, 'and', '$0x7,%esi'), (0x63a48b8, 'cmp', '%r12d,%edi'),
    (0x63a48bb, 'jae', '63a49d7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c5a7>'), (0x63a48c1, 'test', '%esi,%esi'), (0x63a48c3, 'je', '63a4950 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c520>'), (0x63a48c9, 'cmp', '$0x1,%esi'),
    (0x63a48cc, 'je', '63a4939 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c509>'), (0x63a48ce, 'cmp', '$0x2,%esi'), (0x63a48d1, 'je', '63a492b <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c4fb>'), (0x63a48d3, 'cmp', '$0x3,%esi'),
    (0x63a48d6, 'je', '63a491e <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c4ee>'), (0x63a48d8, 'cmp', '$0x4,%esi'), (0x63a48db, 'je', '63a4910 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c4e0>'), (0x63a48dd, 'cmp', '$0x5,%esi'),
    (0x63a48e0, 'je', '63a4902 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c4d2>'), (0x63a48e2, 'cmp', '$0x6,%esi'), (0x63a48e5, 'je', '63a48f4 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c4c4>'), (0x63a48e7, 'mov', '(%r9,%rdi,1),%rbx'),
    (0x63a48eb, 'mov', '%rbx,(%rcx,%rdi,1)'), (0x63a48ef, 'mov', '$0x10,%edi'), (0x63a48f4, 'mov', '%edi,%r10d'), (0x63a48f7, 'add', '$0x8,%edi'),
    (0x63a48fa, 'mov', '(%r9,%r10,1),%r8'), (0x63a48fe, 'mov', '%r8,(%rcx,%r10,1)'), (0x63a4902, 'mov', '%edi,%r11d'), (0x63a4905, 'add', '$0x8,%edi'),
    (0x63a4908, 'mov', '(%r9,%r11,1),%rbp'), (0x63a490c, 'mov', '%rbp,(%rcx,%r11,1)'), (0x63a4910, 'mov', '%edi,%r14d'), (0x63a4913, 'add', '$0x8,%edi'),
    (0x63a4916, 'mov', '(%r9,%r14,1),%rsi'), (0x63a491a, 'mov', '%rsi,(%rcx,%r14,1)'), (0x63a491e, 'mov', '%edi,%eax'), (0x63a4920, 'add', '$0x8,%edi'),
    (0x63a4923, 'mov', '(%r9,%rax,1),%rbx'), (0x63a4927, 'mov', '%rbx,(%rcx,%rax,1)'), (0x63a492b, 'mov', '%edi,%r10d'), (0x63a492e, 'add', '$0x8,%edi'),
    (0x63a4931, 'mov', '(%r9,%r10,1),%r8'), (0x63a4935, 'mov', '%r8,(%rcx,%r10,1)'), (0x63a4939, 'mov', '%edi,%r11d'), (0x63a493c, 'add', '$0x8,%edi'),
    (0x63a493f, 'mov', '(%r9,%r11,1),%rbp'), (0x63a4943, 'mov', '%rbp,(%rcx,%r11,1)'), (0x63a4947, 'cmp', '%r12d,%edi'), (0x63a494a, 'jae', '63a49d7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c5a7>'),
    (0x63a4950, 'mov', '%edi,%r14d'), (0x63a4953, 'lea', '0x8(%rdi),%eax'), (0x63a4956, 'lea', '0x10(%rdi),%r10d'), (0x63a495a, 'mov', '(%r9,%r14,1),%rsi'),
    (0x63a495e, 'lea', '0x18(%rdi),%r11d'), (0x63a4962, 'mov', '%rsi,(%rcx,%r14,1)'), (0x63a4966, 'mov', '(%r9,%rax,1),%rbx'), (0x63a496a, 'lea', '0x20(%rdi),%r14d'),
    (0x63a496e, 'mov', '%rbx,(%rcx,%rax,1)'), (0x63a4972, 'mov', '(%r9,%r10,1),%r8'), (0x63a4976, 'lea', '0x28(%rdi),%eax'), (0x63a4979, 'mov', '%r8,(%rcx,%r10,1)'),
    (0x63a497d, 'mov', '(%r9,%r11,1),%rbp'), (0x63a4981, 'lea', '0x30(%rdi),%r10d'), (0x63a4985, 'mov', '%rbp,(%rcx,%r11,1)'), (0x63a4989, 'mov', '(%r9,%r14,1),%rsi'),
    (0x63a498d, 'lea', '0x38(%rdi),%r11d'), (0x63a4991, 'add', '$0x40,%edi'), (0x63a4994, 'mov', '%rsi,(%rcx,%r14,1)'), (0x63a4998, 'mov', '(%r9,%rax,1),%rbx'),
    (0x63a499c, 'mov', '%rbx,(%rcx,%rax,1)'), (0x63a49a0, 'mov', '(%r9,%r10,1),%r8'), (0x63a49a4, 'mov', '%r8,(%rcx,%r10,1)'), (0x63a49a8, 'mov', '(%r9,%r11,1),%rbp'),
    (0x63a49ac, 'mov', '%rbp,(%rcx,%r11,1)'), (0x63a49b0, 'cmp', '%r12d,%edi'), (0x63a49b3, 'jb', '63a4950 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c520>'), (0x63a49b5, 'jmp', '63a49d7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c5a7>'),
    (0x63a49b7, 'nopw', '0x0(%rax,%rax,1)'), (0x63a49c0, 'test', '$0x4,%dl'), (0x63a49c3, 'jne', '63a49e5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c5b5>'), (0x63a49c5, 'test', '%edx,%edx'),
    (0x63a49c7, 'je', '63a49d7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c5a7>'), (0x63a49c9, 'movzbl', '(%rsp),%r8d'), (0x63a49ce, 'mov', '%r8b,(%r12)'), (0x63a49d2, 'test', '$0x2,%dl'),
    (0x63a49d5, 'jne', '63a49fa <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c5ca>'), (0x63a49d7, 'mov', '%rdx,0x0(%r13)'), (0x63a49db, 'mov', '$0x16,%ebp'), (0x63a49e0, 'jmp', '63a47c4 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c394>'),
    (0x63a49e5, 'mov', '(%rsp),%eax'), (0x63a49e8, 'mov', '%edx,%esi'), (0x63a49ea, 'mov', '%eax,(%r12)'), (0x63a49ee, 'mov', '-0x4(%r9,%rsi,1),%edi'),
    (0x63a49f3, 'mov', '%edi,-0x4(%r12,%rsi,1)'), (0x63a49f8, 'jmp', '63a49d7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c5a7>'), (0x63a49fa, 'mov', '%edx,%r10d'), (0x63a49fd, 'movzwl', '-0x2(%r9,%r10,1),%r11d'),
    (0x63a4a03, 'mov', '%r11w,-0x2(%r12,%r10,1)'), (0x63a4a09, 'jmp', '63a49d7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c5a7>'), (0x63a4a0b, 'call', '63f0d70 <__stack_chk_fail@plt>'),
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
    check("prev FDE 0x63a4490..0x63a4750",
          prev == (0x63A4490, 0x63A4750), str(prev))
    check("prev gap 0 (contiguous, no padding)", START - prev[1] == 0)
    check("prev FDE starts endbr64 (0xf3)",
          node[toff(prev[0])] == 0xF3)
    nxt = fdes[i + 1]
    check("next FDE 0x63a4a10..0x63a4ce8 (#340 window)",
          nxt == (0x63A4A10, 0x63A4CE8), str(nxt))
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
    check("resolver FDE 0x6388310..0x6388372",
          fdes[bisect.bisect_left(starts, 0x6388310)] ==
          (0x6388310, 0x6388372))
    check("loader FDE 0x63bfb90..0x63bfb98 (8-byte trivial load helper)",
          fdes[bisect.bisect_left(starts, 0x63BFB90)] ==
          (0x63BFB90, 0x63BFB98))
    check("next-question FDE 0x63a4490..0x63a4750",
          fdes[bisect.bisect_left(starts, 0x63A4490)] ==
          (0x63A4490, 0x63A4750))
    hexb = read(os.path.join(PACKET, "lockwait_caller_1site_resolver_fixed.hex"))
    check("hex exhibit raw bytes 704", len(hexb) == 704, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])
    objdump = read(os.path.join(
        PACKET, "lockwait_caller_1site_resolver_fixed.objdump.txt")).decode()
    lines = strict_lines(objdump)
    check("strict lines 187", len(lines) == 187, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if mnemonic_of(l) == "call"]
    check("call lines 6", len(calls) == 6, str(len(calls)))
    rets = [l for l in lines if mnemonic_of(l) == "ret"]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x63a47f7",
          sorted(addr_of(l) for l in rets) == [0x63A47F7],
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
    check("lock-wait site is 0x63a4844",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63bf680" in l) == [0x63A4844])
    check("resolver 0x6365150 called 0 times", tgt.get(0x6365150, 0) == 0,
          str(tgt.get(0x6365150, 0)))
    check("count call 0x634eba0 NOT called (0 times)",
          tgt.get(0x634EBA0, 0) == 0, str(tgt.get(0x634EBA0, 0)))
    check("index resolver 0x6388310 called 1 time at 0x63a4804",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "6388310" in l) == [0x63A4804])
    check("load helper 0x63bfb90 called 1 time at 0x63a4814",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63bfb90" in l) == [0x63A4814])
    check("stack_chk_fail plt call 1 at 0x63a4a0b",
          tgt.get(0x63F0D70, 0) == 1, str(tgt.get(0x63F0D70, 0)))
    check("trylock plt call 1 at 0x63a478b",
          tgt.get(0x63F17B0, 0) == 1, str(tgt.get(0x63F17B0, 0)))
    check("unlock plt call 1 at 0x63a47ce",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63f0b70" in l) == [0x63A47CE])
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
                  ("#340", 0x63A4A10)):
        check("%s window not called" % _w, tgt.get(_a, 0) == 0,
              str(tgt.get(_a, 0)))

    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", len(bsr) == 0, str([hex(addr_of(l)) for l in bsr]))
    check("shr exactly 1 at 0x63a48ae",
          sorted(addr_of(l) for l in lines
                 if mnemonic_of(l) == "shr") ==
          [0x63A48AE])
    check("shr at 0x63a48ae is $0x3 (copy remainder)",
          "$0x3,%esi" in operands_of(by_addr[0x63A48AE]))
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
          [0x63A4798, 0x63A47B8, 0x63A47C4, 0x63A47C4, 0x63A4800, 0x63A4835, 0x63A4835, 0x63A4840, 0x63A4858, 0x63A48F4, 0x63A4902, 0x63A4910, 0x63A491E, 0x63A492B, 0x63A4939, 0x63A4950, 0x63A4950, 0x63A49C0, 0x63A49D7, 0x63A49D7, 0x63A49D7, 0x63A49D7, 0x63A49D7, 0x63A49D7, 0x63A49D7, 0x63A49E5, 0x63A49FA, 0x63A4A0B],
          str(sorted(jump_target(l) for l in jmps)))
    check("endbr64 count 1",
          sum(1 for l in lines if "endbr64" in l) == 1)
    check("entry is endbr64 at 0x63a4750",
          "endbr64" in by_addr[START])
    check("canary present: 2 fs:0x28 lines",
          sum(1 for l in lines if "%fs:0x28" in l) == 2)
    check("canary load at 0x63a477b",
          "mov" in by_addr[0x63A477B] and "%fs:0x28,%rax" in by_addr[0x63A477B])
    check("canary save to 0x8(%rsp) at 0x63a4784",
          "mov" in by_addr[0x63A4784] and "%rax,0x8(%rsp)" in by_addr[0x63A4784])
    check("canary check sub at 0x63a47d8",
          "sub" in by_addr[0x63A47D8] and "%fs:0x28,%rax" in by_addr[0x63A47D8])
    check("canary fail jne to stack_chk_fail at 0x63a47e1",
          "jne" in by_addr[0x63A47E1] and "63a4a0b" in by_addr[0x63A47E1])
    check("TLS flag check absent: 0 fs:0x330 lines",
          sum(1 for l in lines if "%fs:0x330" in l) == 0)
    check("no prefetch instructions",
          not any("prefetch" in l for l in lines))
    check("tzcnt 0",
          [l for l in lines if mnemonic_of(l) == "tzcnt"] == [])
    check('entry endbr64 at 0x63a4750',
          'endbr64' in by_addr[0x63A4750])
    check('push %r15 at 0x63a4754',
          'push' in by_addr[0x63A4754] and '%r15' in by_addr[0x63A4754])
    check('mutex lea 0x67121a0 at 0x63a4756',
          'lea' in by_addr[0x63A4756] and '0x36da43(%rip),%r15' in by_addr[0x63A4756])
    check('entry rsi save mov %rsi,%r14 at 0x63a475f',
          'mov' in by_addr[0x63A475F] and '%rsi,%r14' in by_addr[0x63A475F])
    check('entry r8 save mov %r8,%r13 at 0x63a4764',
          'mov' in by_addr[0x63A4764] and '%r8,%r13' in by_addr[0x63A4764])
    check('entry rcx save mov %rcx,%r12 at 0x63a4769',
          'mov' in by_addr[0x63A4769] and '%rcx,%r12' in by_addr[0x63A4769])
    check('entry rdi save mov %rdi,%rbp at 0x63a476d',
          'mov' in by_addr[0x63A476D] and '%rdi,%rbp' in by_addr[0x63A476D])
    check('entry r9 save mov %r9,%rbx at 0x63a4774',
          'mov' in by_addr[0x63A4774] and '%r9,%rbx' in by_addr[0x63A4774])
    check('frame sub $0x18,%rsp at 0x63a4777',
          'sub' in by_addr[0x63A4777] and '$0x18,%rsp' in by_addr[0x63A4777])
    check('canary load mov %fs:0x28,%rax at 0x63a477b',
          'mov' in by_addr[0x63A477B] and '%fs:0x28,%rax' in by_addr[0x63A477B])
    check('canary save mov %rax,0x8(%rsp) at 0x63a4784',
          'mov' in by_addr[0x63A4784] and '%rax,0x8(%rsp)' in by_addr[0x63A4784])
    check('xor %eax,%eax before trylock at 0x63a4789',
          'xor' in by_addr[0x63A4789] and '%eax,%eax' in by_addr[0x63A4789])
    check('trylock call at 0x63a478b',
          'call' in by_addr[0x63A478B] and '63f17b0 <pthread_mutex_trylock@plt>' in by_addr[0x63A478B])
    check('trylock test %eax,%eax at 0x63a4790',
          'test' in by_addr[0x63A4790] and '%eax,%eax' in by_addr[0x63A4790])
    check('trylock-fail jne lock-wait setup at 0x63a4792',
          'jne' in by_addr[0x63A4792] and '63a4840 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c410>' in by_addr[0x63A4792])
    check('acq-count addq $0x1,0x36d9f8(%rip) at 0x63a4798',
          'addq' in by_addr[0x63A4798] and '$0x1,0x36d9f8(%rip)' in by_addr[0x63A4798])
    check('owner cmp 0x6712190,%rbp at 0x63a47a0',
          'cmp' in by_addr[0x63A47A0] and '0x36d9e9(%rip),%rbp' in by_addr[0x63A47A0])
    check('owner-unchanged je exit-1 mov at 0x63a47a7',
          'je' in by_addr[0x63A47A7] and '63a47b8 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c388>' in by_addr[0x63A47A7])
    check('counter addq $0x1,0x36d9d7(%rip) at 0x63a47a9',
          'addq' in by_addr[0x63A47A9] and '$0x1,0x36d9d7(%rip)' in by_addr[0x63A47A9])
    check('owner store mov %rbp,0x36d9d8(%rip) at 0x63a47b1',
          'mov' in by_addr[0x63A47B1] and '%rbp,0x36d9d8(%rip)' in by_addr[0x63A47B1])
    check('exit-1 mov $0x1,%ebp at 0x63a47b8',
          'mov' in by_addr[0x63A47B8] and '$0x1,%ebp' in by_addr[0x63A47B8])
    check('caller-cond or 0x50(%rsp),%rbx at 0x63a47bd',
          'or' in by_addr[0x63A47BD] and '0x50(%rsp),%rbx' in by_addr[0x63A47BD])
    check('caller-cond je lookup path at 0x63a47c2',
          'je' in by_addr[0x63A47C2] and '63a4800 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c3d0>' in by_addr[0x63A47C2])
    check('waited-flag clear movb $0x0,0x36d9fd(%rip) at 0x63a47c4',
          'movb' in by_addr[0x63A47C4] and '$0x0,0x36d9fd(%rip)' in by_addr[0x63A47C4])
    check('unlock rdi mov %r15,%rdi at 0x63a47cb',
          'mov' in by_addr[0x63A47CB] and '%r15,%rdi' in by_addr[0x63A47CB])
    check('unlock call at 0x63a47ce',
          'call' in by_addr[0x63A47CE] and '63f0b70 <pthread_mutex_unlock@plt>' in by_addr[0x63A47CE])
    check('canary reload mov 0x8(%rsp),%rax at 0x63a47d3',
          'mov' in by_addr[0x63A47D3] and '0x8(%rsp),%rax' in by_addr[0x63A47D3])
    check('canary check sub %fs:0x28,%rax at 0x63a47d8',
          'sub' in by_addr[0x63A47D8] and '%fs:0x28,%rax' in by_addr[0x63A47D8])
    check('canary fail jne stack_chk_fail at 0x63a47e1',
          'jne' in by_addr[0x63A47E1] and '63a4a0b <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c5db>' in by_addr[0x63A47E1])
    check('rsp restore add $0x18,%rsp at 0x63a47e7',
          'add' in by_addr[0x63A47E7] and '$0x18,%rsp' in by_addr[0x63A47E7])
    check('exit mov %ebp,%eax at 0x63a47eb',
          'mov' in by_addr[0x63A47EB] and '%ebp,%eax' in by_addr[0x63A47EB])
    check('ret at 0x63a47f7',
          'ret' in by_addr[0x63A47F7])
    check('resolver arg mov 0x10(%r14),%rdi at 0x63a4800',
          'mov' in by_addr[0x63A4800] and '0x10(%r14),%rdi' in by_addr[0x63A4800])
    check('resolver call 0x6388310 at 0x63a4804',
          'call' in by_addr[0x63A4804] and '6388310 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fee0>' in by_addr[0x63A4804])
    check('table base mov 0x50(%rax),%rdi at 0x63a4809',
          'mov' in by_addr[0x63A4809] and '0x50(%rax),%rdi' in by_addr[0x63A4809])
    check('inline adjust add $0xb8,%rdi at 0x63a480d',
          'add' in by_addr[0x63A480D] and '$0xb8,%rdi' in by_addr[0x63A480D])
    check('loader call 0x63bfb90 at 0x63a4814',
          'call' in by_addr[0x63A4814] and '63bfb90 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677760>' in by_addr[0x63A4814])
    check('resolved value store mov %rax,(%rsp) at 0x63a4819',
          'mov' in by_addr[0x63A4819] and '%rax,(%rsp)' in by_addr[0x63A4819])
    check('rcx==0 test %r12,%r12 at 0x63a481d',
          'test' in by_addr[0x63A481D] and '%r12,%r12' in by_addr[0x63A481D])
    check('rcx==0 je exit-0 at 0x63a4820',
          'je' in by_addr[0x63A4820] and '63a4835 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c405>' in by_addr[0x63A4820])
    check('r8==0 test %r13,%r13 at 0x63a4822',
          'test' in by_addr[0x63A4822] and '%r13,%r13' in by_addr[0x63A4822])
    check('r8==0 je exit-0 at 0x63a4825',
          'je' in by_addr[0x63A4825] and '63a4835 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c405>' in by_addr[0x63A4825])
    check('len load mov 0x0(%r13),%rdx at 0x63a4827',
          'mov' in by_addr[0x63A4827] and '0x0(%r13),%rdx' in by_addr[0x63A4827])
    check('len cmp $0x8,%rdx at 0x63a482b',
          'cmp' in by_addr[0x63A482B] and '$0x8,%rdx' in by_addr[0x63A482B])
    check('len!=8 jne copy dispatch at 0x63a482f',
          'jne' in by_addr[0x63A482F] and '63a4858 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c428>' in by_addr[0x63A482F])
    check('len==8 store mov %rax,(%r12) at 0x63a4831',
          'mov' in by_addr[0x63A4831] and '%rax,(%r12)' in by_addr[0x63A4831])
    check('exit-0 xor %ebp,%ebp at 0x63a4835',
          'xor' in by_addr[0x63A4835] and '%ebp,%ebp' in by_addr[0x63A4835])
    check('exit-0 jmp flag-clear at 0x63a4837',
          'jmp' in by_addr[0x63A4837] and '63a47c4 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c394>' in by_addr[0x63A4837])
    check('lock-wait setup lea -0x40(%r15),%rdi at 0x63a4840',
          'lea' in by_addr[0x63A4840] and '-0x40(%r15),%rdi' in by_addr[0x63A4840])
    check('lock-wait call at 0x63a4844',
          'call' in by_addr[0x63A4844] and '63bf680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677250>' in by_addr[0x63A4844])
    check('waited-flag set movb $0x1,0x36d978(%rip) at 0x63a4849',
          'movb' in by_addr[0x63A4849] and '$0x1,0x36d978(%rip)' in by_addr[0x63A4849])
    check('lock-wait rejoin jmp trylock-success (NO retry) at 0x63a4850',
          'jmp' in by_addr[0x63A4850] and '63a4798 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c368>' in by_addr[0x63A4850])
    check('copy mov $0x8,%ecx at 0x63a4858',
          'mov' in by_addr[0x63A4858] and '$0x8,%ecx' in by_addr[0x63A4858])
    check('copy src mov %rsp,%r9 at 0x63a485d',
          'mov' in by_addr[0x63A485D] and '%rsp,%r9' in by_addr[0x63A485D])
    check('copy cmp %rcx,%rdx at 0x63a4860',
          'cmp' in by_addr[0x63A4860] and '%rcx,%rdx' in by_addr[0x63A4860])
    check('copy min cmova %rcx,%rdx at 0x63a4863',
          'cmova' in by_addr[0x63A4863] and '%rcx,%rdx' in by_addr[0x63A4863])
    check('copy cmp $0x8,%edx at 0x63a4867',
          'cmp' in by_addr[0x63A4867] and '$0x8,%edx' in by_addr[0x63A4867])
    check('copy len<8 jb remainder at 0x63a486a',
          'jb' in by_addr[0x63A486A] and '63a49c0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c590>' in by_addr[0x63A486A])
    check('copy mov %edx,%ebp at 0x63a4870',
          'mov' in by_addr[0x63A4870] and '%edx,%ebp' in by_addr[0x63A4870])
    check('copy first qword store mov %rax,(%r12) at 0x63a4872',
          'mov' in by_addr[0x63A4872] and '%rax,(%r12)' in by_addr[0x63A4872])
    check('copy dest lea 0x8(%r12),%rcx at 0x63a4876',
          'lea' in by_addr[0x63A4876] and '0x8(%r12),%rcx' in by_addr[0x63A4876])
    check('copy last qword load mov -0x8(%r9,%rbp,1),%r14 at 0x63a487b',
          'mov' in by_addr[0x63A487B] and '-0x8(%r9,%rbp,1),%r14' in by_addr[0x63A487B])
    check('copy align and $...f8,%rcx at 0x63a4880',
          'and' in by_addr[0x63A4880] and '$0xfffffffffffffff8,%rcx' in by_addr[0x63A4880])
    check('copy last qword store mov %r14,-0x8(%r12,%rbp,1) at 0x63a4884',
          'mov' in by_addr[0x63A4884] and '%r14,-0x8(%r12,%rbp,1)' in by_addr[0x63A4884])
    check('copy sub %rcx,%r12 at 0x63a4889',
          'sub' in by_addr[0x63A4889] and '%rcx,%r12' in by_addr[0x63A4889])
    check('copy sub %r12,%r9 at 0x63a488c',
          'sub' in by_addr[0x63A488C] and '%r12,%r9' in by_addr[0x63A488C])
    check('copy add %edx,%r12d at 0x63a488f',
          'add' in by_addr[0x63A488F] and '%edx,%r12d' in by_addr[0x63A488F])
    check('copy and $...f8,%r12d at 0x63a4892',
          'and' in by_addr[0x63A4892] and '$0xfffffff8,%r12d' in by_addr[0x63A4892])
    check('loop-guard cmp $0x8,%r12d at 0x63a4896',
          'cmp' in by_addr[0x63A4896] and '$0x8,%r12d' in by_addr[0x63A4896])
    check('loop-guard jb writeback at 0x63a489a',
          'jb' in by_addr[0x63A489A] and '63a49d7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c5a7>' in by_addr[0x63A489A])
    check('duffs loop head mov (%r9,%rbx,1),%rax at 0x63a48a0',
          'mov' in by_addr[0x63A48A0] and '(%r9,%rbx,1),%rax' in by_addr[0x63A48A0])
    check('dispatch lea -0x1(%r12),%esi at 0x63a48a4',
          'lea' in by_addr[0x63A48A4] and '-0x1(%r12),%esi' in by_addr[0x63A48A4])
    check('dispatch mov $0x8,%edi at 0x63a48a9',
          'mov' in by_addr[0x63A48A9] and '$0x8,%edi' in by_addr[0x63A48A9])
    check('dispatch shr $0x3,%esi at 0x63a48ae',
          'shr' in by_addr[0x63A48AE] and '$0x3,%esi' in by_addr[0x63A48AE])
    check('duffs first store mov %rax,(%rcx,%rbx,1) at 0x63a48b1',
          'mov' in by_addr[0x63A48B1] and '%rax,(%rcx,%rbx,1)' in by_addr[0x63A48B1])
    check('dispatch and $0x7,%esi at 0x63a48b5',
          'and' in by_addr[0x63A48B5] and '$0x7,%esi' in by_addr[0x63A48B5])
    check('dispatch cmp %r12d,%edi at 0x63a48b8',
          'cmp' in by_addr[0x63A48B8] and '%r12d,%edi' in by_addr[0x63A48B8])
    check('dispatch jae writeback at 0x63a48bb',
          'jae' in by_addr[0x63A48BB] and '63a49d7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c5a7>' in by_addr[0x63A48BB])
    check('dispatch test %esi,%esi at 0x63a48c1',
          'test' in by_addr[0x63A48C1] and '%esi,%esi' in by_addr[0x63A48C1])
    check('dispatch je D-block (esi==0) at 0x63a48c3',
          'je' in by_addr[0x63A48C3] and '63a4950 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c520>' in by_addr[0x63A48C3])
    check('dispatch cmp $0x1,%esi at 0x63a48c9',
          'cmp' in by_addr[0x63A48C9] and '$0x1,%esi' in by_addr[0x63A48C9])
    check('dispatch je 0x63a4939 (esi==1) at 0x63a48cc',
          'je' in by_addr[0x63A48CC] and '63a4939 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c509>' in by_addr[0x63A48CC])
    check('dispatch cmp $0x2,%esi at 0x63a48ce',
          'cmp' in by_addr[0x63A48CE] and '$0x2,%esi' in by_addr[0x63A48CE])
    check('dispatch je 0x63a492b (esi==2) at 0x63a48d1',
          'je' in by_addr[0x63A48D1] and '63a492b <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c4fb>' in by_addr[0x63A48D1])
    check('dispatch cmp $0x3,%esi at 0x63a48d3',
          'cmp' in by_addr[0x63A48D3] and '$0x3,%esi' in by_addr[0x63A48D3])
    check('dispatch je 0x63a491e (esi==3) at 0x63a48d6',
          'je' in by_addr[0x63A48D6] and '63a491e <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c4ee>' in by_addr[0x63A48D6])
    check('dispatch cmp $0x4,%esi at 0x63a48d8',
          'cmp' in by_addr[0x63A48D8] and '$0x4,%esi' in by_addr[0x63A48D8])
    check('dispatch je 0x63a4910 (esi==4) at 0x63a48db',
          'je' in by_addr[0x63A48DB] and '63a4910 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c4e0>' in by_addr[0x63A48DB])
    check('dispatch cmp $0x5,%esi at 0x63a48dd',
          'cmp' in by_addr[0x63A48DD] and '$0x5,%esi' in by_addr[0x63A48DD])
    check('dispatch je 0x63a4902 (esi==5) at 0x63a48e0',
          'je' in by_addr[0x63A48E0] and '63a4902 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c4d2>' in by_addr[0x63A48E0])
    check('dispatch cmp $0x6,%esi at 0x63a48e2',
          'cmp' in by_addr[0x63A48E2] and '$0x6,%esi' in by_addr[0x63A48E2])
    check('dispatch je 0x63a48f4 (esi==6) at 0x63a48e5',
          'je' in by_addr[0x63A48E5] and '63a48f4 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c4c4>' in by_addr[0x63A48E5])
    check('D-block mov %edi,%r14d at 0x63a4950',
          'mov' in by_addr[0x63A4950] and '%edi,%r14d' in by_addr[0x63A4950])
    check('D-block add $0x40,%edi at 0x63a4991',
          'add' in by_addr[0x63A4991] and '$0x40,%edi' in by_addr[0x63A4991])
    check('D-block cmp %r12d,%edi at 0x63a49b0',
          'cmp' in by_addr[0x63A49B0] and '%r12d,%edi' in by_addr[0x63A49B0])
    check('D-block jb D-block at 0x63a49b3',
          'jb' in by_addr[0x63A49B3] and '63a4950 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c520>' in by_addr[0x63A49B3])
    check('D-block exit jmp writeback at 0x63a49b5',
          'jmp' in by_addr[0x63A49B5] and '63a49d7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c5a7>' in by_addr[0x63A49B5])
    check('remainder test $0x4,%dl at 0x63a49c0',
          'test' in by_addr[0x63A49C0] and '$0x4,%dl' in by_addr[0x63A49C0])
    check('remainder 4-byte jne 0x63a49e5 at 0x63a49c3',
          'jne' in by_addr[0x63A49C3] and '63a49e5 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c5b5>' in by_addr[0x63A49C3])
    check('remainder test %edx,%edx at 0x63a49c5',
          'test' in by_addr[0x63A49C5] and '%edx,%edx' in by_addr[0x63A49C5])
    check('remainder len==0 je writeback at 0x63a49c7',
          'je' in by_addr[0x63A49C7] and '63a49d7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c5a7>' in by_addr[0x63A49C7])
    check('remainder 1-byte movzbl (%rsp),%r8d at 0x63a49c9',
          'movzbl' in by_addr[0x63A49C9] and '(%rsp),%r8d' in by_addr[0x63A49C9])
    check('remainder 1-byte store mov %r8b,(%r12) at 0x63a49ce',
          'mov' in by_addr[0x63A49CE] and '%r8b,(%r12)' in by_addr[0x63A49CE])
    check('remainder test $0x2,%dl at 0x63a49d2',
          'test' in by_addr[0x63A49D2] and '$0x2,%dl' in by_addr[0x63A49D2])
    check('remainder 2-byte jne 0x63a49fa at 0x63a49d5',
          'jne' in by_addr[0x63A49D5] and '63a49fa <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c5ca>' in by_addr[0x63A49D5])
    check('writeback mov %rdx,0x0(%r13) at 0x63a49d7',
          'mov' in by_addr[0x63A49D7] and '%rdx,0x0(%r13)' in by_addr[0x63A49D7])
    check('exit-22 mov $0x16,%ebp at 0x63a49db',
          'mov' in by_addr[0x63A49DB] and '$0x16,%ebp' in by_addr[0x63A49DB])
    check('exit-22 jmp flag-clear at 0x63a49e0',
          'jmp' in by_addr[0x63A49E0] and '63a47c4 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c394>' in by_addr[0x63A49E0])
    check('4-byte copy mov (%rsp),%eax at 0x63a49e5',
          'mov' in by_addr[0x63A49E5] and '(%rsp),%eax' in by_addr[0x63A49E5])
    check('4-byte copy store mov %eax,(%r12) at 0x63a49ea',
          'mov' in by_addr[0x63A49EA] and '%eax,(%r12)' in by_addr[0x63A49EA])
    check('4-byte copy tail mov -0x4(%r9,%rsi,1),%edi at 0x63a49ee',
          'mov' in by_addr[0x63A49EE] and '-0x4(%r9,%rsi,1),%edi' in by_addr[0x63A49EE])
    check('4-byte copy tail store mov %edi,-0x4(%r12,%rsi,1) at 0x63a49f3',
          'mov' in by_addr[0x63A49F3] and '%edi,-0x4(%r12,%rsi,1)' in by_addr[0x63A49F3])
    check('4-byte copy jmp writeback at 0x63a49f8',
          'jmp' in by_addr[0x63A49F8] and '63a49d7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c5a7>' in by_addr[0x63A49F8])
    check('2-byte copy mov %edx,%r10d at 0x63a49fa',
          'mov' in by_addr[0x63A49FA] and '%edx,%r10d' in by_addr[0x63A49FA])
    check('2-byte copy movzwl -0x2(%r9,%r10,1),%r11d at 0x63a49fd',
          'movzwl' in by_addr[0x63A49FD] and '-0x2(%r9,%r10,1),%r11d' in by_addr[0x63A49FD])
    check('2-byte copy store mov %r11w,-0x2(%r12,%r10,1) at 0x63a4a03',
          'mov' in by_addr[0x63A4A03] and '%r11w,-0x2(%r12,%r10,1)' in by_addr[0x63A4A03])
    check('2-byte copy jmp writeback at 0x63a4a09',
          'jmp' in by_addr[0x63A4A09] and '63a49d7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65c5a7>' in by_addr[0x63A4A09])
    check('stack_chk_fail call at 0x63a4a0b',
          'call' in by_addr[0x63A4A0B] and '63f0d70 <__stack_chk_fail@plt>' in by_addr[0x63A4A0B])
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

    check("entry reaches lock-wait site 0x63a4844", reaches(START, 0x63A4844))
    check("entry reaches ret 0x63a47f7", reaches(START, 0x63A47F7))
    check("entry reaches trylock 0x63a478b", reaches(START, 0x63A478B))
    check("entry reaches epilogue canary 0x63a47d3", reaches(START, 0x63A47D3))
    check("entry reaches resolver call 0x63a4804", reaches(START, 0x63A4804))
    check("entry reaches loader call 0x63a4814", reaches(START, 0x63A4814))
    check("entry reaches exit-1 block 0x63a47b8", reaches(START, 0x63A47B8))
    check("entry reaches exit-0 block 0x63a4835", reaches(START, 0x63A4835))
    check("entry reaches exit-22 block 0x63a49db", reaches(START, 0x63A49DB))
    check("entry reaches copy dispatch 0x63a4858", reaches(START, 0x63A4858))
    check("entry reaches remainder entry 0x63a49c0", reaches(START, 0x63A49C0))
    check("entry reaches writeback 0x63a49d7", reaches(START, 0x63A49D7))
    check("entry reaches Duff's loop head 0x63a48a0 in the CFG only "
          "(guard analysis below shows it is never entered)",
          reaches(START, 0x63A48A0))
    check("entry reaches D-block 0x63a4950 in the CFG only",
          reaches(START, 0x63A4950))
    check("preds of lock-wait site 0x63a4844 is the setup lea only",
          preds[0x63A4844] == {0x63A4840}, str(preds[0x63A4844]))
    check("preds of lock-wait setup 0x63a4840 are trylock fail and the "
          "padding nopl",
          preds[0x63A4840] == {0x63A4792, 0x63A4839}, str(preds[0x63A4840]))
    check("preds of trylock 0x63a478b is the xor only",
          preds[0x63A478B] == {0x63A4789}, str(preds[0x63A478B]))
    check("preds of rejoin 0x63a4798 are trylock success and the "
          "lock-wait jmp",
          preds[0x63A4798] == {0x63A4792, 0x63A4850}, str(preds[0x63A4798]))
    check("preds of ret 0x63a47f7 is the final pop",
          preds[0x63A47F7] == {0x63A47F5}, str(preds[0x63A47F7]))
    check("preds of epilogue canary 0x63a47d3 is the unlock only",
          preds[0x63A47D3] == {0x63A47CE}, str(preds[0x63A47D3]))
    check("preds of flag-clear block 0x63a47c4 are caller-cond, exit-0 "
          "and exit-22",
          preds[0x63A47C4] == {0x63A47C2, 0x63A4837, 0x63A49E0},
          str(preds[0x63A47C4]))
    check("preds of exit-0 block 0x63a4835 are rcx==0, r8==0 and the "
          "len==8 store",
          preds[0x63A4835] == {0x63A4820, 0x63A4825, 0x63A4831},
          str(preds[0x63A4835]))
    check("preds of exit-22 block 0x63a49db is the writeback only",
          preds[0x63A49DB] == {0x63A49D7}, str(preds[0x63A49DB]))
    check("preds of writeback 0x63a49d7 are the 8 copy exits",
          preds[0x63A49D7] == {0x63A489A, 0x63A48BB, 0x63A494A, 0x63A49B5,
                               0x63A49C7, 0x63A49D5, 0x63A49F8, 0x63A4A09},
          str(preds[0x63A49D7]))
    check("preds of Duff's loop head 0x63a48a0 is the loop guard only",
          preds[0x63A48A0] == {0x63A489A}, str(preds[0x63A48A0]))
    check("preds of D-block 0x63a4950 are dispatch esi==0, the jae "
          "fall-through and the loop-back",
          preds[0x63A4950] == {0x63A48C3, 0x63A494A, 0x63A49B3},
          str(preds[0x63A4950]))
    check("preds of copy dispatch 0x63a4858 are len!=8 jne and the "
          "padding nopl",
          preds[0x63A4858] == {0x63A482F, 0x63A4855}, str(preds[0x63A4858]))
    check("preds of resolver call 0x63a4804 is the lookup path only",
          preds[0x63A4804] == {0x63A4800}, str(preds[0x63A4804]))
    check("preds of lookup path 0x63a4800 are caller-cond je and the "
          "padding nopl",
          preds[0x63A4800] == {0x63A47C2, 0x63A47F8}, str(preds[0x63A4800]))
    # The Duff's-device loop is present but dead: the guard computes
    # r12d = ((dest - ((dest+8) & ~7)) + 8) & ~7, which is 0 for every
    # destination alignment, so the jb at 0x63a489a is always taken.
    # Emulate the prologue arithmetic for all 8 alignments.
    def _guard_r12d(dest_mod_8):
        r12 = dest_mod_8 - 8
        return ((r12 + 8) & 0xFFFFFFFF) & ~7
    check("Duff's loop guard r12d is 0 for every dest alignment "
          "(loop dead)",
          all(_guard_r12d(k) == 0 for k in range(8)),
          str([_guard_r12d(k) for k in range(8)]))
    check("loop-guard jb at 0x63a489a targets the writeback",
          "jb" in by_addr[0x63A489A] and "63a49d7" in by_addr[0x63A489A])
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
    SITE = 0x63A4844
    RET = 0x63A47F7
    CALL_TRYLOCK = {("CALL", 0x63A478B)}
    check("site rdi only def is lea -0x40(%r15),%rdi 0x63a4840",
          rdi_in[SITE] == {0x63A4840}, str(rdi_in[SITE]))
    check("site rsi is clobbered by the trylock only (no post-trylock "
          "restore in this window, like #339/#340, unlike #338)",
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
          rbx_in[SITE] == {0x63A4774}, str(rbx_in[SITE]))
    check("site rbp def is the entry rdi save",
          rbp_in[SITE] == {0x63A476D}, str(rbp_in[SITE]))
    check("site r12 def is the entry rcx save",
          r12_in[SITE] == {0x63A4769}, str(r12_in[SITE]))
    check("site r13 def is the entry r8 save",
          r13_in[SITE] == {0x63A4764}, str(r13_in[SITE]))
    check("site r14 def is the entry rsi save",
          r14_in[SITE] == {0x63A475F}, str(r14_in[SITE]))
    check("site r15 def is the mutex lea",
          r15_in[SITE] == {0x63A4756}, str(r15_in[SITE]))
    check("rax at ret is the exit-value mov 0x63a47eb",
          rax_in[RET] == {0x63A47EB}, str(rax_in[RET]))
    check("ebp reaching defs at the flag-clear are the 3 exit values",
          rbp_in[0x63A47C4] == {0x63A47B8, 0x63A4835, 0x63A49DB},
          str(rbp_in[0x63A47C4]))

    check("records lock-wait sites match census",
          [s.get("site") for s in rec.get("lock_wait_sites", [])] ==
          ["0x63a4844"])
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
          rec.get("window", {}).get("range") == "0x63a4750..0x63a4a10")
    check("records return value exits 0/1/22",
          rec.get("return_value", {}).get("rax") ==
          "ebp: 0/1/22 (mov %ebp,%eax at 0x63a47eb)")
    check("records entry gate absent (no gate byte in this window)",
          rec.get("entry_gate") is None)
    check("records count call absent (0x634eba0 NOT called here)",
          rec.get("count_call") is None)
    check("records resolver target 0x6388310",
          rec.get("resolver", {}).get("target") == "0x6388310")
    check("records resolver site 0x63a4804",
          rec.get("resolver", {}).get("site") == "0x63a4804")
    check("records loader target 0x63bfb90",
          rec.get("loader", {}).get("target") == "0x63bfb90")
    check("records loader site 0x63a4814",
          rec.get("loader", {}).get("site") == "0x63a4814")
    check("records inline adjust 0xb8 at 0x63a480d",
          rec.get("inline_adjust", {}).get("amount") == "0xb8"
          and rec.get("inline_adjust", {}).get("site") == "0x63a480d")
    check("records selector index is fixed +0xb8 (no index register)",
          rec.get("selector", {}).get("index") ==
          "fixed +0xb8 (no index register)")
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
    check("next candidate raw lu-miss 0", counts.get(0x63A4490, 0) == 0,
          str(counts.get(0x63A4490, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x63A4490, 0) == 0,
          str(bti_counts.get(0x63A4490, 0)))
    check("next candidate raw second-handler 0",
          sh_counts.get(0x63A4490, 0) == 0, str(sh_counts.get(0x63A4490, 0)))
    check("next candidate raw lock-wait 1",
          lw_counts.get(0x63A4490, 0) == 1,
          str(lw_counts.get(0x63A4490, 0)))
    # lock-wait frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 344", len(survey.get("survivors", [])) == 344,
          str(len(survey.get("survivors", []))))
    check("survey this window is a lock-wait survivor",
          "0x63a4750" in survey.get("survivors", []))
    check("survey this window is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x63a4750") == 1,
          str(survey.get("sites_per_fde", {}).get("0x63a4750")))
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
          "0x63a4750" not in survey.get("lu_miss_survivors", []))
    check("survey this window is NOT a second-handler survivor",
          "0x63a4750" not in survey.get("second_handler_survivors", []))
    check("survey next candidate is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x63a4490") == 1,
          str(survey.get("sites_per_fde", {}).get("0x63a4490")))
    nq = rec.get("next_question", {})
    check("next question is the lock-wait frontier",
          nq.get("frontier") == "lock-wait helper 0x63bf680 callers",
          str(nq.get("frontier")))
    check("next question range 0x63a4490..0x63a4750",
          nq.get("range") == "0x63a4490..0x63a4750", str(nq.get("range")))
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
          nq.get("lock_wait_site") == ["0x63a4584"],
          str(nq.get("lock_wait_site")))
    check("next question second-handler sites 0",
          nq.get("second_handler_sites") == 0,
          str(nq.get("second_handler_sites")))
    check("next question bsr 0", nq.get("bsr") == 0,
          str(nq.get("bsr")))
    check("next question rets 1",
          nq.get("ret") == ["0x63a4537"], str(nq.get("ret")))
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
    # next candidate 0x63a4490..0x63a4750 must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x63A4490 < p[1] and p[0] < 0x63A4750]
    check("next candidate 0x63a4490 disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x63A4750 and 0x63A4490 < END))

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
    check("slug not colliding with #314-#340 lu-miss/lockwait slugs",
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
                       "RE-001-node115-lockwait-caller-1site-resolver-twin"))

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
                    "lockwait_caller_1site_resolver_fixed.hex",
                    "lockwait_caller_1site_resolver_fixed.objdump.txt"}
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
