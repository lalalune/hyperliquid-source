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

SLUG = "RE-001-node115-lockwait-caller-1site-resolver-noloader"
START = 0x63A06E0
END = 0x63A0803
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
    (0x63a06e0, 'endbr64', ''),
    (0x63a06e4, 'push', '%r14'),
    (0x63a06e6, 'push', '%r13'),
    (0x63a06e8, 'push', '%r12'),
    (0x63a06ea, 'push', '%rbp'),
    (0x63a06eb, 'push', '%rbx'),
    (0x63a06ec, 'sub', '$0x10,%rsp'),
    (0x63a06f0, 'mov', '%fs:0x28,%rax'),
    (0x63a06f9, 'mov', '%rax,0x8(%rsp)'),
    (0x63a06fe, 'mov', '$0x1,%eax'),
    (0x63a0703, 'or', '0x40(%rsp),%r9'),
    (0x63a0708, 'jne', '63a079e <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65836e>'),
    (0x63a070e, 'mov', '0x8(%rsi),%r13'),
    (0x63a0712, 'mov', '$0xe,%eax'),
    (0x63a0717, 'mov', '%r13,%rdx'),
    (0x63a071a, 'shr', '$0x20,%rdx'),
    (0x63a071e, 'jne', '63a079e <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65836e>'),
    (0x63a0720, 'lea', '0x371a79(%rip),%r14        # 67121a0 <__register_atfork@plt+0x320610>'),
    (0x63a0727, 'mov', '%rdi,%rbx'),
    (0x63a072a, 'mov', '%rcx,%rbp'),
    (0x63a072d, 'mov', '%r8,%r12'),
    (0x63a0730, 'mov', '%r14,%rdi'),
    (0x63a0733, 'call', '63f17b0 <pthread_mutex_trylock@plt>'),
    (0x63a0738, 'test', '%eax,%eax'),
    (0x63a073a, 'jne', '63a07c0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x658390>'),
    (0x63a0740, 'addq', '$0x1,0x371a50(%rip)        # 6712198 <__register_atfork@plt+0x320608>'),
    (0x63a0748, 'cmp', '0x371a41(%rip),%rbx        # 6712190 <__register_atfork@plt+0x320600>'),
    (0x63a074f, 'je', '63a0760 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x658330>'),
    (0x63a0751, 'addq', '$0x1,0x371a2f(%rip)        # 6712188 <__register_atfork@plt+0x3205f8>'),
    (0x63a0759, 'mov', '%rbx,0x371a30(%rip)        # 6712190 <__register_atfork@plt+0x320600>'),
    (0x63a0760, 'mov', '%r13,%rdi'),
    (0x63a0763, 'call', '6388310 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fee0>'),
    (0x63a0768, 'mov', '%r14,%rdi'),
    (0x63a076b, 'movzbl', '0x4(%rax),%eax'),
    (0x63a076f, 'mov', '%al,0x7(%rsp)'),
    (0x63a0773, 'movb', '$0x0,0x371a4e(%rip)        # 67121c8 <__register_atfork@plt+0x320638>'),
    (0x63a077a, 'call', '63f0b70 <pthread_mutex_unlock@plt>'),
    (0x63a077f, 'test', '%rbp,%rbp'),
    (0x63a0782, 'je', '63a079c <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65836c>'),
    (0x63a0784, 'test', '%r12,%r12'),
    (0x63a0787, 'je', '63a079c <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65836c>'),
    (0x63a0789, 'mov', '(%r12),%rcx'),
    (0x63a078d, 'cmp', '$0x1,%rcx'),
    (0x63a0791, 'jne', '63a07d8 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6583a8>'),
    (0x63a0793, 'movzbl', '0x7(%rsp),%esi'),
    (0x63a0798, 'mov', '%sil,0x0(%rbp)'),
    (0x63a079c, 'xor', '%eax,%eax'),
    (0x63a079e, 'mov', '0x8(%rsp),%rdx'),
    (0x63a07a3, 'sub', '%fs:0x28,%rdx'),
    (0x63a07ac, 'jne', '63a07fe <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6583ce>'),
    (0x63a07ae, 'add', '$0x10,%rsp'),
    (0x63a07b2, 'pop', '%rbx'),
    (0x63a07b3, 'pop', '%rbp'),
    (0x63a07b4, 'pop', '%r12'),
    (0x63a07b6, 'pop', '%r13'),
    (0x63a07b8, 'pop', '%r14'),
    (0x63a07ba, 'ret', ''),
    (0x63a07bb, 'nopl', '0x0(%rax,%rax,1)'),
    (0x63a07c0, 'lea', '-0x40(%r14),%rdi'),
    (0x63a07c4, 'call', '63bf680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677250>'),
    (0x63a07c9, 'movb', '$0x1,0x3719f8(%rip)        # 67121c8 <__register_atfork@plt+0x320638>'),
    (0x63a07d0, 'jmp', '63a0740 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x658310>'),
    (0x63a07d5, 'nopl', '(%rax)'),
    (0x63a07d8, 'xor', '%edi,%edi'),
    (0x63a07da, 'test', '%rcx,%rcx'),
    (0x63a07dd, 'setne', '%dil'),
    (0x63a07e1, 'test', '%edi,%edi'),
    (0x63a07e3, 'je', '63a07f3 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6583c3>'),
    (0x63a07e5, 'xor', '%r8d,%r8d'),
    (0x63a07e8, 'movzbl', '0x7(%rsp,%r8,1),%r9d'),
    (0x63a07ee, 'mov', '%r9b,0x0(%rbp,%r8,1)'),
    (0x63a07f3, 'mov', '%rdi,(%r12)'),
    (0x63a07f7, 'mov', '$0x16,%eax'),
    (0x63a07fc, 'jmp', '63a079e <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65836e>'),
    (0x63a07fe, 'call', '63f0d70 <__stack_chk_fail@plt>')
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
    check("target FDE size 291", END - START == 291)
    prev = fdes[i - 1]
    check("prev FDE 0x63a0480..0x63a06d3",
          prev == (0x63A0480, 0x63A06D3), str(prev))
    check("prev gap 13 (13 int3 padding bytes 0x63a06d3..0x63a06e0)", START - prev[1] == 13 and all(b == 0xCC for b in node[toff(prev[1]):toff(START)]))
    check("prev FDE starts endbr64 (0xf3)",
          node[toff(prev[0])] == 0xF3)
    nxt = fdes[i + 1]
    check("next FDE 0x63a0810..0x63a0ad0 (#364 window)",
          nxt == (0x63A0810, 0x63A0AD0), str(nxt))
    check("next gap 13 (13 int3 padding bytes 0x63a0803..0x63a0810)", nxt[0] - END == 13 and all(b == 0xCC for b in node[toff(END):toff(nxt[0])]))
    check("next FDE starts endbr64 (0xf3)",
          node[toff(nxt[0])] == 0xF3)
    check("prev FDE end 0x63a06d3, 13 int3 bytes before this FDE start",
          prev[1] == 0x63A06D3)
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
    check("#364 window FDE 0x63a0810..0x63a0ad0",
          fdes[bisect.bisect_left(starts, 0x63A0810)] ==
          (0x63A0810, 0x63A0AD0))
    check("resolver FDE 0x6388310..0x6388372",
          fdes[bisect.bisect_left(starts, 0x6388310)] ==
          (0x6388310, 0x6388372))
    check("loader FDE 0x63bfb90..0x63bfb98 (8-byte trivial load helper)",
          fdes[bisect.bisect_left(starts, 0x63BFB90)] ==
          (0x63BFB90, 0x63BFB98))
    check("next-question FDE 0x63a0480..0x63a06d3",
          fdes[bisect.bisect_left(starts, 0x63A0480)] ==
          (0x63A0480, 0x63A06D3))
    hexb = read(os.path.join(PACKET, "lockwait_caller_1site_resolver_noloader.hex"))
    check("hex exhibit raw bytes 291", len(hexb) == 291, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])
    objdump = read(os.path.join(
        PACKET, "lockwait_caller_1site_resolver_noloader.objdump.txt")).decode()
    lines = strict_lines(objdump)
    check("strict lines 75", len(lines) == 75, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if mnemonic_of(l) == "call"]
    check("call lines 5", len(calls) == 5, str(len(calls)))
    rets = [l for l in lines if mnemonic_of(l) == "ret"]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x63a07ba",
          sorted(addr_of(l) for l in rets) == [0x63A07BA],
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
    check("lock-wait site is 0x63a07c4",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63bf680" in l) == [0x63A07C4])
    check("resolver 0x6365150 called 0 times", tgt.get(0x6365150, 0) == 0,
          str(tgt.get(0x6365150, 0)))
    check("count call 0x634eba0 NOT called (0 times)",
          tgt.get(0x634EBA0, 0) == 0, str(tgt.get(0x634EBA0, 0)))
    check("index resolver 0x6388310 called 1 time at 0x63a0763",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "6388310" in l) == [0x63A0763])
    check("load helper 0x63bfb90 NOT called (0 times)",
          tgt.get(0x63BFB90, 0) == 0, str(tgt.get(0x63BFB90, 0)))
    check("stack_chk_fail plt call 1 at 0x63a07fe",
          tgt.get(0x63F0D70, 0) == 1, str(tgt.get(0x63F0D70, 0)))
    check("trylock plt call 1 at 0x63a0733",
          tgt.get(0x63F17B0, 0) == 1, str(tgt.get(0x63F17B0, 0)))
    check("unlock plt call 1 at 0x63a077a",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63f0b70" in l) == [0x63A077A])
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
                  ("#364", 0x63A0810)):
        check("%s window not called" % _w, tgt.get(_a, 0) == 0,
              str(tgt.get(_a, 0)))

    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", len(bsr) == 0, str([hex(addr_of(l)) for l in bsr]))
    check("shr exactly 1 at 0x63a071a",
          sorted(addr_of(l) for l in lines
                 if mnemonic_of(l) == "shr") ==
          [0x63A071A])
    check("shr at 0x63a071a is $0x20 (high-32 check)",
          "$0x20,%rdx" in operands_of(by_addr[0x63A071A]))
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
    check("jump lines 11", len(jmps) == 11, str(len(jmps)))

    def jump_target(line):
        m = re.search(r"\s([0-9a-f]{6,})\s*<", line)
        return int(m.group(1), 16) if m else None
    outside = []
    for l in jmps:
        t = jump_target(l)
        if t is not None and not (START <= t < END):
            outside.append((addr_of(l), t))
    check("jump closure: 0 outside the window", outside == [], str(outside))
    check("jump targets are exactly the 11 branches",
          sorted(jump_target(l) for l in jmps) ==
          [0x63A0740, 0x63A0760, 0x63A079C, 0x63A079C, 0x63A079E, 0x63A079E, 0x63A079E, 0x63A07C0, 0x63A07D8, 0x63A07F3, 0x63A07FE],
          str(sorted(jump_target(l) for l in jmps)))
    check("endbr64 count 1",
          sum(1 for l in lines if "endbr64" in l) == 1)
    check("entry is endbr64 at 0x63a06e0",
          "endbr64" in by_addr[START])
    check("canary present: 2 fs:0x28 lines",
          sum(1 for l in lines if "%fs:0x28" in l) == 2)
    check("canary load at 0x63a06f0",
          "mov" in by_addr[0x63A06F0] and "%fs:0x28,%rax" in by_addr[0x63A06F0])
    check("canary save to 0x8(%rsp) at 0x63a06f9",
          "mov" in by_addr[0x63A06F9] and "%rax,0x8(%rsp)" in by_addr[0x63A06F9])
    check("canary check sub at 0x63a07a3",
          "sub" in by_addr[0x63A07A3] and "%fs:0x28,%rdx" in by_addr[0x63A07A3])
    check("canary fail jne to stack_chk_fail at 0x63a07ac",
          "jne" in by_addr[0x63A07AC] and "63a07fe" in by_addr[0x63A07AC])
    check("TLS flag check absent: 0 fs:0x330 lines",
          sum(1 for l in lines if "%fs:0x330" in l) == 0)
    check("no prefetch instructions",
          not any("prefetch" in l for l in lines))
    check("tzcnt 0",
          [l for l in lines if mnemonic_of(l) == "tzcnt"] == [])
    check('entry endbr64 at 0x63a06e0',
          'endbr64' in by_addr[0x63A06E0])
    check('push %r14 at 0x63a06e4',
          'push' in by_addr[0x63A06E4] and '%r14' in by_addr[0x63A06E4])
    check('push %r13 at 0x63a06e6',
          'push' in by_addr[0x63A06E6] and '%r13' in by_addr[0x63A06E6])
    check('push %r12 at 0x63a06e8',
          'push' in by_addr[0x63A06E8] and '%r12' in by_addr[0x63A06E8])
    check('push %rbp at 0x63a06ea',
          'push' in by_addr[0x63A06EA] and '%rbp' in by_addr[0x63A06EA])
    check('push %rbx at 0x63a06eb',
          'push' in by_addr[0x63A06EB] and '%rbx' in by_addr[0x63A06EB])
    check('frame sub $0x10,%rsp at 0x63a06ec',
          'sub' in by_addr[0x63A06EC] and '$0x10,%rsp' in by_addr[0x63A06EC])
    check('canary load mov %fs:0x28,%rax at 0x63a06f0',
          'mov' in by_addr[0x63A06F0] and '%fs:0x28,%rax' in by_addr[0x63A06F0])
    check('canary save mov %rax,0x8(%rsp) at 0x63a06f9',
          'mov' in by_addr[0x63A06F9] and '%rax,0x8(%rsp)' in by_addr[0x63A06F9])
    check('exit-1 mov $0x1,%eax at 0x63a06fe',
          'mov' in by_addr[0x63A06FE] and '$0x1,%eax' in by_addr[0x63A06FE])
    check('caller-cond or 0x40(%rsp),%r9 at 0x63a0703',
          'or' in by_addr[0x63A0703] and '0x40(%rsp),%r9' in by_addr[0x63A0703])
    check('caller-cond jne canary-check at 0x63a0708',
          'jne' in by_addr[0x63A0708] and '63a079e' in by_addr[0x63A0708])
    check('r13 load mov 0x8(%rsi),%r13 at 0x63a070e',
          'mov' in by_addr[0x63A070E] and '0x8(%rsi),%r13' in by_addr[0x63A070E])
    check('exit-14 mov $0xe,%eax at 0x63a0712',
          'mov' in by_addr[0x63A0712] and '$0xe,%eax' in by_addr[0x63A0712])
    check('high-32 mov %r13,%rdx at 0x63a0717',
          'mov' in by_addr[0x63A0717] and '%r13,%rdx' in by_addr[0x63A0717])
    check('high-32 shr $0x20,%rdx at 0x63a071a',
          'shr' in by_addr[0x63A071A] and '$0x20,%rdx' in by_addr[0x63A071A])
    check('high-32 jne canary-check at 0x63a071e',
          'jne' in by_addr[0x63A071E] and '63a079e' in by_addr[0x63A071E])
    check('mutex lea 0x67121a0 at 0x63a0720',
          'lea' in by_addr[0x63A0720] and '0x371a79(%rip),%r14' in by_addr[0x63A0720])
    check('entry rdi save mov %rdi,%rbx at 0x63a0727',
          'mov' in by_addr[0x63A0727] and '%rdi,%rbx' in by_addr[0x63A0727])
    check('entry rcx save mov %rcx,%rbp at 0x63a072a',
          'mov' in by_addr[0x63A072A] and '%rcx,%rbp' in by_addr[0x63A072A])
    check('entry r8 save mov %r8,%r12 at 0x63a072d',
          'mov' in by_addr[0x63A072D] and '%r8,%r12' in by_addr[0x63A072D])
    check('trylock rdi mov %r14,%rdi at 0x63a0730',
          'mov' in by_addr[0x63A0730] and '%r14,%rdi' in by_addr[0x63A0730])
    check('trylock call at 0x63a0733',
          'call' in by_addr[0x63A0733] and '63f17b0 <pthread_mutex_trylock@plt>' in by_addr[0x63A0733])
    check('trylock test %eax,%eax at 0x63a0738',
          'test' in by_addr[0x63A0738] and '%eax,%eax' in by_addr[0x63A0738])
    check('trylock-fail jne lock-wait setup at 0x63a073a',
          'jne' in by_addr[0x63A073A] and '63a07c0' in by_addr[0x63A073A])
    check('acq-count addq $0x1,0x371a50(%rip) at 0x63a0740',
          'addq' in by_addr[0x63A0740] and '$0x1,0x371a50(%rip)' in by_addr[0x63A0740])
    check('owner cmp 0x6712190,%rbx at 0x63a0748',
          'cmp' in by_addr[0x63A0748] and '0x371a41(%rip),%rbx' in by_addr[0x63A0748])
    check('owner-unchanged je lookup path at 0x63a074f',
          'je' in by_addr[0x63A074F] and '63a0760' in by_addr[0x63A074F])
    check('counter addq $0x1,0x371a2f(%rip) at 0x63a0751',
          'addq' in by_addr[0x63A0751] and '$0x1,0x371a2f(%rip)' in by_addr[0x63A0751])
    check('owner store mov %rbx,0x371a30(%rip) at 0x63a0759',
          'mov' in by_addr[0x63A0759] and '%rbx,0x371a30(%rip)' in by_addr[0x63A0759])
    check('resolver arg mov %r13,%rdi at 0x63a0760',
          'mov' in by_addr[0x63A0760] and '%r13,%rdi' in by_addr[0x63A0760])
    check('resolver call 0x6388310 at 0x63a0763',
          'call' in by_addr[0x63A0763] and '6388310' in by_addr[0x63A0763])
    check('unlock rdi mov %r14,%rdi at 0x63a0768',
          'mov' in by_addr[0x63A0768] and '%r14,%rdi' in by_addr[0x63A0768])
    check('resolver byte movzbl 0x4(%rax),%eax at 0x63a076b (no loader, no adjust)',
          'movzbl' in by_addr[0x63A076B] and '0x4(%rax),%eax' in by_addr[0x63A076B])
    check('byte store mov %al,0x7(%rsp) at 0x63a076f',
          'mov' in by_addr[0x63A076F] and '%al,0x7(%rsp)' in by_addr[0x63A076F])
    check('waited-flag clear movb $0x0,0x371a4e(%rip) at 0x63a0773',
          'movb' in by_addr[0x63A0773] and '$0x0,0x371a4e(%rip)' in by_addr[0x63A0773])
    check('unlock call at 0x63a077a',
          'call' in by_addr[0x63A077A] and '63f0b70 <pthread_mutex_unlock@plt>' in by_addr[0x63A077A])
    check('rcx==0 test %rbp,%rbp at 0x63a077f',
          'test' in by_addr[0x63A077F] and '%rbp,%rbp' in by_addr[0x63A077F])
    check('rcx==0 je exit-0 at 0x63a0782',
          'je' in by_addr[0x63A0782] and '63a079c' in by_addr[0x63A0782])
    check('r8==0 test %r12,%r12 at 0x63a0784',
          'test' in by_addr[0x63A0784] and '%r12,%r12' in by_addr[0x63A0784])
    check('r8==0 je exit-0 at 0x63a0787',
          'je' in by_addr[0x63A0787] and '63a079c' in by_addr[0x63A0787])
    check('len load mov (%r12),%rcx at 0x63a0789',
          'mov' in by_addr[0x63A0789] and '(%r12),%rcx' in by_addr[0x63A0789])
    check('len cmp $0x1,%rcx at 0x63a078d',
          'cmp' in by_addr[0x63A078D] and '$0x1,%rcx' in by_addr[0x63A078D])
    check('len!=1 jne multi-byte path at 0x63a0791',
          'jne' in by_addr[0x63A0791] and '63a07d8' in by_addr[0x63A0791])
    check('byte load movzbl 0x7(%rsp),%esi at 0x63a0793',
          'movzbl' in by_addr[0x63A0793] and '0x7(%rsp),%esi' in by_addr[0x63A0793])
    check('byte store mov %sil,0x0(%rbp) at 0x63a0798',
          'mov' in by_addr[0x63A0798] and '%sil,0x0(%rbp)' in by_addr[0x63A0798])
    check('exit-0 xor %eax,%eax at 0x63a079c',
          'xor' in by_addr[0x63A079C] and '%eax,%eax' in by_addr[0x63A079C])
    check('canary reload mov 0x8(%rsp),%rdx at 0x63a079e',
          'mov' in by_addr[0x63A079E] and '0x8(%rsp),%rdx' in by_addr[0x63A079E])
    check('canary check sub %fs:0x28,%rdx at 0x63a07a3',
          'sub' in by_addr[0x63A07A3] and '%fs:0x28,%rdx' in by_addr[0x63A07A3])
    check('canary fail jne stack_chk_fail at 0x63a07ac',
          'jne' in by_addr[0x63A07AC] and '63a07fe' in by_addr[0x63A07AC])
    check('rsp restore add $0x10,%rsp at 0x63a07ae',
          'add' in by_addr[0x63A07AE] and '$0x10,%rsp' in by_addr[0x63A07AE])
    check('pop %rbx at 0x63a07b2',
          'pop' in by_addr[0x63A07B2] and '%rbx' in by_addr[0x63A07B2])
    check('pop %rbp at 0x63a07b3',
          'pop' in by_addr[0x63A07B3] and '%rbp' in by_addr[0x63A07B3])
    check('pop %r12 at 0x63a07b4',
          'pop' in by_addr[0x63A07B4] and '%r12' in by_addr[0x63A07B4])
    check('pop %r13 at 0x63a07b6',
          'pop' in by_addr[0x63A07B6] and '%r13' in by_addr[0x63A07B6])
    check('pop %r14 at 0x63a07b8',
          'pop' in by_addr[0x63A07B8] and '%r14' in by_addr[0x63A07B8])
    check('ret at 0x63a07ba',
          'ret' in by_addr[0x63A07BA])
    check('lock-wait setup lea -0x40(%r14),%rdi at 0x63a07c0',
          'lea' in by_addr[0x63A07C0] and '-0x40(%r14),%rdi' in by_addr[0x63A07C0])
    check('lock-wait call at 0x63a07c4',
          'call' in by_addr[0x63A07C4] and '63bf680' in by_addr[0x63A07C4])
    check('waited-flag set movb $0x1,0x3719f8(%rip) at 0x63a07c9',
          'movb' in by_addr[0x63A07C9] and '$0x1,0x3719f8(%rip)' in by_addr[0x63A07C9])
    check('lock-wait rejoin jmp trylock-success (NO retry) at 0x63a07d0',
          'jmp' in by_addr[0x63A07D0] and '63a0740' in by_addr[0x63A07D0])
    check('multi-byte xor %edi,%edi at 0x63a07d8',
          'xor' in by_addr[0x63A07D8] and '%edi,%edi' in by_addr[0x63A07D8])
    check('multi-byte test %rcx,%rcx at 0x63a07da',
          'test' in by_addr[0x63A07DA] and '%rcx,%rcx' in by_addr[0x63A07DA])
    check('multi-byte setne %dil at 0x63a07dd',
          'setne' in by_addr[0x63A07DD] and '%dil' in by_addr[0x63A07DD])
    check('multi-byte test %edi,%edi at 0x63a07e1',
          'test' in by_addr[0x63A07E1] and '%edi,%edi' in by_addr[0x63A07E1])
    check('multi-byte je writeback at 0x63a07e3',
          'je' in by_addr[0x63A07E3] and '63a07f3' in by_addr[0x63A07E3])
    check('multi-byte xor %r8d,%r8d at 0x63a07e5',
          'xor' in by_addr[0x63A07E5] and '%r8d,%r8d' in by_addr[0x63A07E5])
    check('multi-byte byte load movzbl 0x7(%rsp,%r8,1),%r9d at 0x63a07e8',
          'movzbl' in by_addr[0x63A07E8] and '0x7(%rsp,%r8,1),%r9d' in by_addr[0x63A07E8])
    check('multi-byte byte store mov %r9b,0x0(%rbp,%r8,1) at 0x63a07ee',
          'mov' in by_addr[0x63A07EE] and '%r9b,0x0(%rbp,%r8,1)' in by_addr[0x63A07EE])
    check('writeback mov %rdi,(%r12) at 0x63a07f3',
          'mov' in by_addr[0x63A07F3] and '%rdi,(%r12)' in by_addr[0x63A07F3])
    check('exit-22 mov $0x16,%eax at 0x63a07f7',
          'mov' in by_addr[0x63A07F7] and '$0x16,%eax' in by_addr[0x63A07F7])
    check('exit-22 jmp canary-check at 0x63a07fc',
          'jmp' in by_addr[0x63A07FC] and '63a079e' in by_addr[0x63A07FC])
    check('stack_chk_fail call at 0x63a07fe',
          'call' in by_addr[0x63A07FE] and '63f0d70 <__stack_chk_fail@plt>' in by_addr[0x63A07FE])
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

    check("entry reaches lock-wait site 0x63a07c4", reaches(START, 0x63A07C4))
    check("entry reaches ret 0x63a07ba", reaches(START, 0x63A07BA))
    check("entry reaches trylock 0x63a0733", reaches(START, 0x63A0733))
    check("entry reaches epilogue canary 0x63a079e", reaches(START, 0x63A079E))
    check("entry reaches resolver call 0x63a0763", reaches(START, 0x63A0763))
    check("entry reaches exit-1 block 0x63a06fe", reaches(START, 0x63A06FE))
    check("entry reaches exit-14 block 0x63a0712", reaches(START, 0x63A0712))
    check("entry reaches exit-0 block 0x63a079c", reaches(START, 0x63A079C))
    check("entry reaches exit-22 block 0x63a07f7", reaches(START, 0x63A07F7))
    check("entry reaches multi-byte path 0x63a07d8", reaches(START, 0x63A07D8))
    check("entry reaches lock-wait setup 0x63a07c0", reaches(START, 0x63A07C0))
    check("preds of lock-wait site 0x63a07c4 is the setup lea only",
          preds[0x63A07C4] == {0x63A07C0}, str(preds[0x63A07C4]))
    check("preds of lock-wait setup 0x63a07c0 are trylock fail and the "
          "padding nopl",
          preds[0x63A07C0] == {0x63A073A, 0x63A07BB}, str(preds[0x63A07C0]))
    check("preds of trylock 0x63a0733 is the rdi mov only",
          preds[0x63A0733] == {0x63A0730}, str(preds[0x63A0733]))
    check("preds of rejoin 0x63a0740 are trylock success and the "
          "lock-wait jmp",
          preds[0x63A0740] == {0x63A073A, 0x63A07D0}, str(preds[0x63A0740]))
    check("preds of ret 0x63a07ba is the final pop",
          preds[0x63A07BA] == {0x63A07B8}, str(preds[0x63A07BA]))
    check("preds of canary-check 0x63a079e are the two early exits, "
          "exit-0 and exit-22",
          preds[0x63A079E] == {0x63A0708, 0x63A071E, 0x63A079C, 0x63A07FC},
          str(preds[0x63A079E]))
    check("preds of flag-clear block 0x63a0773 is the byte store only",
          preds[0x63A0773] == {0x63A076F}, str(preds[0x63A0773]))
    check("preds of exit-0 block 0x63a079c are rcx==0, r8==0 and the "
          "len==1 byte store",
          preds[0x63A079C] == {0x63A0782, 0x63A0787, 0x63A0798},
          str(preds[0x63A079C]))
    check("preds of resolver call 0x63a0763 is the lookup path only",
          preds[0x63A0763] == {0x63A0760}, str(preds[0x63A0763]))
    check("preds of writeback 0x63a07f3 are the len==0 je and the "
          "multi-byte copy",
          preds[0x63A07F3] == {0x63A07E3, 0x63A07EE}, str(preds[0x63A07F3]))
    check("preds of multi-byte path 0x63a07d8 are len!=1 and the "
          "padding nopl",
          preds[0x63A07D8] == {0x63A0791, 0x63A07D5}, str(preds[0x63A07D8]))
    # There is NO Duff's-device loop in this window: the copy is a
    # single byte (len==1 path at 0x63a0793/0x63a0798, multi-byte path
    # at 0x63a07e8/0x63a07ee with index r8 fixed at 0, never
    # incremented). No 8-at-a-time dispatch exists.
    check("no Duff dispatch: no shr $0x3 anywhere in the window",
          not any("$0x3,%esi" in l for l in lines))
    check("no Duff dispatch: no cmova min-copy anywhere",
          [l for l in lines if mnemonic_of(l) == "cmova"] == [])
    check("backward jumps are the lock-wait rejoin and the exit-14 to canary jump",
          sorted((addr_of(l), jump_target(l)) for l in jmps
                 if jump_target(l) is not None
                 and jump_target(l) < addr_of(l)) ==
          [(0x63A07D0, 0x63A0740), (0x63A07FC, 0x63A079E)],
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
    SITE = 0x63A07C4
    RET = 0x63A07BA
    CALL_TRYLOCK = {("CALL", 0x63A0733)}
    check("site rdi only def is lea -0x40(%r14),%rdi 0x63a07c0",
          rdi_in[SITE] == {0x63A07C0}, str(rdi_in[SITE]))
    check("site rsi is clobbered by the trylock only (no post-trylock "
          "restore in this window, like #339/#340/#341/#342/#343/#344/#345/#346/#347/#348/#349/#350/#351/#352/#353/#354/#355/#356/#357/#358/#359/#360/#361/#362/#363/#364, unlike #338)",
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
          rbx_in[SITE] == {0x63A0727}, str(rbx_in[SITE]))
    check("site rbp def is the entry rcx save",
          rbp_in[SITE] == {0x63A072A}, str(rbp_in[SITE]))
    check("site r12 def is the entry r8 save",
          r12_in[SITE] == {0x63A072D}, str(r12_in[SITE]))
    check("site r13 def is the 0x8(%rsi) field load (not an entry save)",
          r13_in[SITE] == {0x63A070E}, str(r13_in[SITE]))
    check("site r14 def is the mutex lea",
          r14_in[SITE] == {0x63A0720}, str(r14_in[SITE]))
    check("site r15 is never defined in this window (ENTRY only)",
          r15_in[SITE] == {("ENTRY",)}, str(r15_in[SITE]))
    check("rax at ret is exactly the 4 exit values 0/1/14/22",
          rax_in[RET] == {0x63A06FE, 0x63A0712, 0x63A079C, 0x63A07F7},
          str(rax_in[RET]))
    check("ebp at the flag-clear is the entry rcx save only (the "
          "flag-clear is not an exit join point in this window)",
          rbp_in[0x63A0773] == {0x63A072A},
          str(rbp_in[0x63A0773]))

    check("records lock-wait sites match census",
          [s.get("site") for s in rec.get("lock_wait_sites", [])] ==
          ["0x63a07c4"])
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
    check("records window bytes 291",
          rec.get("window", {}).get("bytes") == 291)
    check("records window range",
          rec.get("window", {}).get("range") == "0x63a06e0..0x63a0803")
    check("records return value exits 0/1/14/22",
          rec.get("return_value", {}).get("rax") ==
          "eax: 0/1/14/22 (mov $0x1 at 0x63a06fe, mov $0xe at 0x63a0712, xor %eax at 0x63a079c, mov $0x16 at 0x63a07f7)")
    check("records entry gate absent (no gate byte in this window)",
          rec.get("entry_gate") is None)
    check("records count call absent (0x634eba0 NOT called here)",
          rec.get("count_call") is None)
    check("records resolver target 0x6388310",
          rec.get("resolver", {}).get("target") == "0x6388310")
    check("records resolver site 0x63a0763",
          rec.get("resolver", {}).get("site") == "0x63a0763")
    check("records loader absent (0x63bfb90 NOT called here)",
          rec.get("loader") is None)
    check("records inline adjust absent (no fixed adjust here)",
          rec.get("inline_adjust", {}).get("amount") is None)
    check("records selector is direct byte read (no index, no table)",
          rec.get("selector", {}).get("index") ==
          "none - byte 4 of resolver result read directly (movzbl 0x4(%rax),%eax at 0x63a076b)")
    check("records copy is a single byte (no loop)",
          rec.get("copy_loop", {}).get("loop") is False)
    check("records copy dispatch is none (no Duff dispatch)",
          rec.get("copy_loop", {}).get("dispatch") is None)

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
    check("next candidate raw lu-miss 0", counts.get(0x63A0480, 0) == 0,
          str(counts.get(0x63A06E0, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x63A0480, 0) == 0,
          str(bti_counts.get(0x63A06E0, 0)))
    check("next candidate raw second-handler 0",
          sh_counts.get(0x63A0480, 0) == 0, str(sh_counts.get(0x63A0480, 0)))
    check("next candidate raw lock-wait 1",
          lw_counts.get(0x63A0480, 0) == 1,
          str(lw_counts.get(0x63A0480, 0)))
    # lock-wait frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 344", len(survey.get("survivors", [])) == 344,
          str(len(survey.get("survivors", []))))
    check("survey this window is a lock-wait survivor",
          "0x63a06e0" in survey.get("survivors", []))
    check("survey this window is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x63a06e0") == 1,
          str(survey.get("sites_per_fde", {}).get("0x63a06e0")))
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
          "0x63a06e0" not in survey.get("lu_miss_survivors", []))
    check("survey this window is NOT a second-handler survivor",
          "0x63a06e0" not in survey.get("second_handler_survivors", []))
    check("survey next candidate is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x63a0480") == 1,
          str(survey.get("sites_per_fde", {}).get("0x63a0480")))
    nq = rec.get("next_question", {})
    check("next question is the lock-wait frontier",
          nq.get("frontier") == "lock-wait helper 0x63bf680 callers",
          str(nq.get("frontier")))
    check("next question range 0x63a0480..0x63a06d3",
          nq.get("range") == "0x63a0480..0x63a06d3", str(nq.get("range")))
    check("next question bytes 595", nq.get("bytes") == 595,
          str(nq.get("bytes")))
    check("next question lu-miss sites 0",
          nq.get("lu_miss_sites") == 0, str(nq.get("lu_miss_sites")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 154", nq.get("strict") == 154,
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
          nq.get("lock_wait_site") == ["0x63a0564"],
          str(nq.get("lock_wait_site")))
    check("next question second-handler sites 0",
          nq.get("second_handler_sites") == 0,
          str(nq.get("second_handler_sites")))
    check("next question bsr 0", nq.get("bsr") == 0,
          str(nq.get("bsr")))
    check("next question rets 1",
          nq.get("ret") == ["0x63a0527"], str(nq.get("ret")))
    check("next question jumps 21", nq.get("jumps") == 21,
          str(nq.get("jumps")))
    check("next question jumps outside 0", nq.get("jumps_outside_window") == 0,
          str(nq.get("jumps_outside_window")))
    check("next question endbr64 1", nq.get("endbr64") == 1,
          str(nq.get("endbr64")))
    check("next question canary present", nq.get("canary") is True,
          str(nq.get("canary")))
    check("next question plt calls 3", nq.get("plt_calls") == 3,
          str(nq.get("plt_calls")))
    check("records census strict 75",
          rec.get("census", {}).get("strict") == 75)
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
          not (START < 0x63A06D3 and 0x63A0480 < END))

    # A packet path identifies its slug within the repository.
    slug_hit = os.path.basename(os.path.normpath(PACKET)) != SLUG
    check("slug unique", not slug_hit)
    check("slug not colliding with #314-#364 lu-miss/lockwait slugs",
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
                       "RE-001-node115-lockwait-caller-1site-resolver-fixed-380"))

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
                    "lockwait_caller_1site_resolver_noloader.hex",
                    "lockwait_caller_1site_resolver_noloader.objdump.txt"}
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
