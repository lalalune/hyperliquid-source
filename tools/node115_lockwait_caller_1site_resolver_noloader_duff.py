import bisect
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

SLUG = "RE-001-node115-lockwait-caller-1site-resolver-noloader-duff"
START = 0x63A0480
END = 0x63A06D3
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
    (0x63a0480, 'endbr64', ''),
    (0x63a0484, 'push', '%r15'),
    (0x63a0486, 'lea', '0x371d13(%rip),%r15        # 67121a0 <__register_atfork@plt+0x320610>'),
    (0x63a048d, 'push', '%r14'),
    (0x63a048f, 'mov', '%rsi,%r14'),
    (0x63a0492, 'push', '%r13'),
    (0x63a0494, 'mov', '%r8,%r13'),
    (0x63a0497, 'push', '%r12'),
    (0x63a0499, 'mov', '%rcx,%r12'),
    (0x63a049c, 'push', '%rbp'),
    (0x63a049d, 'mov', '%rdi,%rbp'),
    (0x63a04a0, 'mov', '%r15,%rdi'),
    (0x63a04a3, 'push', '%rbx'),
    (0x63a04a4, 'mov', '%r9,%rbx'),
    (0x63a04a7, 'sub', '$0x18,%rsp'),
    (0x63a04ab, 'mov', '%fs:0x28,%rax'),
    (0x63a04b4, 'mov', '%rax,0x8(%rsp)'),
    (0x63a04b9, 'xor', '%eax,%eax'),
    (0x63a04bb, 'call', '63f17b0 <pthread_mutex_trylock@plt>'),
    (0x63a04c0, 'test', '%eax,%eax'),
    (0x63a04c2, 'jne', '63a0560 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x658130>'),
    (0x63a04c8, 'addq', '$0x1,0x371cc8(%rip)        # 6712198 <__register_atfork@plt+0x320608>'),
    (0x63a04d0, 'cmp', '0x371cb9(%rip),%rbp        # 6712190 <__register_atfork@plt+0x320600>'),
    (0x63a04d7, 'je', '63a04e8 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6580b8>'),
    (0x63a04d9, 'addq', '$0x1,0x371ca7(%rip)        # 6712188 <__register_atfork@plt+0x3205f8>'),
    (0x63a04e1, 'mov', '%rbp,0x371ca8(%rip)        # 6712190 <__register_atfork@plt+0x320600>'),
    (0x63a04e8, 'mov', '$0x1,%ebp'),
    (0x63a04ed, 'or', '0x50(%rsp),%rbx'),
    (0x63a04f2, 'je', '63a0530 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x658100>'),
    (0x63a04f4, 'movb', '$0x0,0x371ccd(%rip)        # 67121c8 <__register_atfork@plt+0x320638>'),
    (0x63a04fb, 'mov', '%r15,%rdi'),
    (0x63a04fe, 'call', '63f0b70 <pthread_mutex_unlock@plt>'),
    (0x63a0503, 'mov', '0x8(%rsp),%rax'),
    (0x63a0508, 'sub', '%fs:0x28,%rax'),
    (0x63a0511, 'jne', '63a06ce <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65829e>'),
    (0x63a0517, 'add', '$0x18,%rsp'),
    (0x63a051b, 'mov', '%ebp,%eax'),
    (0x63a051d, 'pop', '%rbx'),
    (0x63a051e, 'pop', '%rbp'),
    (0x63a051f, 'pop', '%r12'),
    (0x63a0521, 'pop', '%r13'),
    (0x63a0523, 'pop', '%r14'),
    (0x63a0525, 'pop', '%r15'),
    (0x63a0527, 'ret', ''),
    (0x63a0528, 'nopl', '0x0(%rax,%rax,1)'),
    (0x63a0530, 'mov', '0x10(%r14),%rdi'),
    (0x63a0534, 'call', '6388310 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63fee0>'),
    (0x63a0539, 'mov', '0x18(%rax),%eax'),
    (0x63a053c, 'mov', '%eax,0x4(%rsp)'),
    (0x63a0540, 'test', '%r12,%r12'),
    (0x63a0543, 'je', '63a0558 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x658128>'),
    (0x63a0545, 'test', '%r13,%r13'),
    (0x63a0548, 'je', '63a0558 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x658128>'),
    (0x63a054a, 'mov', '0x0(%r13),%rdx'),
    (0x63a054e, 'cmp', '$0x4,%rdx'),
    (0x63a0552, 'jne', '63a0578 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x658148>'),
    (0x63a0554, 'mov', '%eax,(%r12)'),
    (0x63a0558, 'xor', '%ebp,%ebp'),
    (0x63a055a, 'jmp', '63a04f4 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6580c4>'),
    (0x63a055c, 'nopl', '0x0(%rax)'),
    (0x63a0560, 'lea', '-0x40(%r15),%rdi'),
    (0x63a0564, 'call', '63bf680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677250>'),
    (0x63a0569, 'movb', '$0x1,0x371c58(%rip)        # 67121c8 <__register_atfork@plt+0x320638>'),
    (0x63a0570, 'jmp', '63a04c8 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x658098>'),
    (0x63a0575, 'nopl', '(%rax)'),
    (0x63a0578, 'mov', '$0x4,%ecx'),
    (0x63a057d, 'lea', '0x4(%rsp),%r9'),
    (0x63a0582, 'cmp', '%rcx,%rdx'),
    (0x63a0585, 'cmova', '%rcx,%rdx'),
    (0x63a0589, 'mov', '%edx,%edi'),
    (0x63a058b, 'test', '%edx,%edx'),
    (0x63a058d, 'je', '63a06c0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x658290>'),
    (0x63a0593, 'movzbl', '(%r9,%rbx,1),%r8d'),
    (0x63a0598, 'lea', '-0x1(%rdx),%esi'),
    (0x63a059b, 'mov', '$0x1,%r11d'),
    (0x63a05a1, 'and', '$0x7,%esi'),
    (0x63a05a4, 'mov', '%r8b,(%r12,%rbx,1)'),
    (0x63a05a8, 'cmp', '%edx,%r11d'),
    (0x63a05ab, 'jae', '63a06c0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x658290>'),
    (0x63a05b1, 'test', '%esi,%esi'),
    (0x63a05b3, 'je', '63a064b <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65821b>'),
    (0x63a05b9, 'cmp', '$0x1,%esi'),
    (0x63a05bc, 'je', '63a0636 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x658206>'),
    (0x63a05be, 'cmp', '$0x2,%esi'),
    (0x63a05c1, 'je', '63a0626 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6581f6>'),
    (0x63a05c3, 'cmp', '$0x3,%esi'),
    (0x63a05c6, 'je', '63a0616 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6581e6>'),
    (0x63a05c8, 'cmp', '$0x4,%esi'),
    (0x63a05cb, 'je', '63a0606 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6581d6>'),
    (0x63a05cd, 'cmp', '$0x5,%esi'),
    (0x63a05d0, 'je', '63a05f6 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6581c6>'),
    (0x63a05d2, 'cmp', '$0x6,%esi'),
    (0x63a05d5, 'je', '63a05e6 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6581b6>'),
    (0x63a05d7, 'movzbl', '(%r9,%r11,1),%r10d'),
    (0x63a05dc, 'mov', '%r10b,(%r12,%r11,1)'),
    (0x63a05e0, 'mov', '$0x2,%r11d'),
    (0x63a05e6, 'mov', '%r11d,%ebp'),
    (0x63a05e9, 'add', '$0x1,%r11d'),
    (0x63a05ed, 'movzbl', '(%r9,%rbp,1),%r14d'),
    (0x63a05f2, 'mov', '%r14b,(%r12,%rbp,1)'),
    (0x63a05f6, 'mov', '%r11d,%ebx'),
    (0x63a05f9, 'add', '$0x1,%r11d'),
    (0x63a05fd, 'movzbl', '(%r9,%rbx,1),%eax'),
    (0x63a0602, 'mov', '%al,(%r12,%rbx,1)'),
    (0x63a0606, 'mov', '%r11d,%ecx'),
    (0x63a0609, 'add', '$0x1,%r11d'),
    (0x63a060d, 'movzbl', '(%r9,%rcx,1),%esi'),
    (0x63a0612, 'mov', '%sil,(%r12,%rcx,1)'),
    (0x63a0616, 'mov', '%r11d,%r10d'),
    (0x63a0619, 'add', '$0x1,%r11d'),
    (0x63a061d, 'movzbl', '(%r9,%r10,1),%r8d'),
    (0x63a0622, 'mov', '%r8b,(%r12,%r10,1)'),
    (0x63a0626, 'mov', '%r11d,%ebp'),
    (0x63a0629, 'add', '$0x1,%r11d'),
    (0x63a062d, 'movzbl', '(%r9,%rbp,1),%r14d'),
    (0x63a0632, 'mov', '%r14b,(%r12,%rbp,1)'),
    (0x63a0636, 'mov', '%r11d,%ebx'),
    (0x63a0639, 'add', '$0x1,%r11d'),
    (0x63a063d, 'movzbl', '(%r9,%rbx,1),%eax'),
    (0x63a0642, 'mov', '%al,(%r12,%rbx,1)'),
    (0x63a0646, 'cmp', '%edi,%r11d'),
    (0x63a0649, 'jae', '63a06c0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x658290>'),
    (0x63a064b, 'mov', '%r11d,%ecx'),
    (0x63a064e, 'lea', '0x1(%r11),%r10d'),
    (0x63a0652, 'lea', '0x2(%r11),%ebp'),
    (0x63a0656, 'lea', '0x3(%r11),%ebx'),
    (0x63a065a, 'movzbl', '(%r9,%rcx,1),%esi'),
    (0x63a065f, 'movzbl', '(%r9,%r10,1),%r8d'),
    (0x63a0664, 'movzbl', '(%r9,%rbp,1),%r14d'),
    (0x63a0669, 'movzbl', '(%r9,%rbx,1),%eax'),
    (0x63a066e, 'mov', '%sil,(%r12,%rcx,1)'),
    (0x63a0672, 'lea', '0x4(%r11),%ecx'),
    (0x63a0676, 'mov', '%r8b,(%r12,%r10,1)'),
    (0x63a067a, 'lea', '0x5(%r11),%r10d'),
    (0x63a067e, 'movzbl', '(%r9,%rcx,1),%esi'),
    (0x63a0683, 'mov', '%r14b,(%r12,%rbp,1)'),
    (0x63a0687, 'lea', '0x6(%r11),%ebp'),
    (0x63a068b, 'movzbl', '(%r9,%r10,1),%r8d'),
    (0x63a0690, 'mov', '%al,(%r12,%rbx,1)'),
    (0x63a0694, 'lea', '0x7(%r11),%ebx'),
    (0x63a0698, 'movzbl', '(%r9,%rbp,1),%r14d'),
    (0x63a069d, 'add', '$0x8,%r11d'),
    (0x63a06a1, 'movzbl', '(%r9,%rbx,1),%eax'),
    (0x63a06a6, 'mov', '%sil,(%r12,%rcx,1)'),
    (0x63a06aa, 'mov', '%r8b,(%r12,%r10,1)'),
    (0x63a06ae, 'mov', '%r14b,(%r12,%rbp,1)'),
    (0x63a06b2, 'mov', '%al,(%r12,%rbx,1)'),
    (0x63a06b6, 'cmp', '%edi,%r11d'),
    (0x63a06b9, 'jb', '63a064b <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x65821b>'),
    (0x63a06bb, 'nopl', '0x0(%rax,%rax,1)'),
    (0x63a06c0, 'mov', '%rdx,0x0(%r13)'),
    (0x63a06c4, 'mov', '$0x16,%ebp'),
    (0x63a06c9, 'jmp', '63a04f4 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x6580c4>'),
    (0x63a06ce, 'call', '63f0d70 <__stack_chk_fail@plt>')
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
    check("target FDE size 595", END - START == 595)
    prev = fdes[i - 1]
    check("prev FDE 0x63a01c0..0x63a0478",
          prev == (0x63A01C0, 0x63A0478), str(prev))
    check("prev gap 8 (8 int3 padding bytes 0x63a0478..0x63a0480)", START - prev[1] == 8 and all(b == 0xCC for b in node[toff(prev[1]):toff(START)]))
    check("prev FDE starts endbr64 (0xf3)",
          node[toff(prev[0])] == 0xF3)
    nxt = fdes[i + 1]
    check("next FDE 0x63a06e0..0x63a0803 (#365 window)",
          nxt == (0x63A06E0, 0x63A0803), str(nxt))
    check("next gap 13 (13 int3 padding bytes 0x63a06d3..0x63a06e0)", nxt[0] - END == 13 and all(b == 0xCC for b in node[toff(END):toff(nxt[0])]))
    check("next FDE starts endbr64 (0xf3)",
          node[toff(nxt[0])] == 0xF3)
    check("prev FDE end 0x63a0478, 8 int3 bytes before this FDE start",
          prev[1] == 0x63A0478)
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
    check("#365 window FDE 0x63a06e0..0x63a0803",
          fdes[bisect.bisect_left(starts, 0x63A06E0)] ==
          (0x63A06E0, 0x63A0803))
    check("resolver FDE 0x6388310..0x6388372",
          fdes[bisect.bisect_left(starts, 0x6388310)] ==
          (0x6388310, 0x6388372))
    check("loader FDE 0x63bfb90..0x63bfb98 (8-byte trivial load helper)",
          fdes[bisect.bisect_left(starts, 0x63BFB90)] ==
          (0x63BFB90, 0x63BFB98))
    check("next-question FDE 0x63a01c0..0x63a0478",
          fdes[bisect.bisect_left(starts, 0x63A01C0)] ==
          (0x63A01C0, 0x63A0478))
    hexb = read(os.path.join(PACKET, "lockwait_caller_1site_resolver_noloader_duff.hex"))
    check("hex exhibit raw bytes 595", len(hexb) == 595, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])
    objdump = read(os.path.join(
        PACKET, "lockwait_caller_1site_resolver_noloader_duff.objdump.txt")).decode()
    lines = strict_lines(objdump)
    check("strict lines 154", len(lines) == 154, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if mnemonic_of(l) == "call"]
    check("call lines 5", len(calls) == 5, str(len(calls)))
    rets = [l for l in lines if mnemonic_of(l) == "ret"]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x63a0527",
          sorted(addr_of(l) for l in rets) == [0x63A0527],
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
    check("lock-wait site is 0x63a0564",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63bf680" in l) == [0x63A0564])
    check("resolver 0x6365150 called 0 times", tgt.get(0x6365150, 0) == 0,
          str(tgt.get(0x6365150, 0)))
    check("count call 0x634eba0 NOT called (0 times)",
          tgt.get(0x634EBA0, 0) == 0, str(tgt.get(0x634EBA0, 0)))
    check("index resolver 0x6388310 called 1 time at 0x63a0534",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "6388310" in l) == [0x63A0534])
    check("load helper 0x63bfb90 NOT called (0 times)",
          tgt.get(0x63BFB90, 0) == 0, str(tgt.get(0x63BFB90, 0)))
    check("stack_chk_fail plt call 1 at 0x63a06ce",
          tgt.get(0x63F0D70, 0) == 1, str(tgt.get(0x63F0D70, 0)))
    check("trylock plt call 1 at 0x63a04bb",
          tgt.get(0x63F17B0, 0) == 1, str(tgt.get(0x63F17B0, 0)))
    check("unlock plt call 1 at 0x63a04fe",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63f0b70" in l) == [0x63A04FE])
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
                  ("#365", 0x63A06E0)):
        check("%s window not called" % _w, tgt.get(_a, 0) == 0,
              str(tgt.get(_a, 0)))

    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", len(bsr) == 0, str([hex(addr_of(l)) for l in bsr]))
    check("shr exactly 0 (no shr anywhere in this window)",
          [l for l in lines if mnemonic_of(l) == "shr"] == [])
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
          [0x63A04C8, 0x63A04E8, 0x63A04F4, 0x63A04F4, 0x63A0530,
           0x63A0558, 0x63A0558, 0x63A0560, 0x63A0578, 0x63A05E6,
           0x63A05F6, 0x63A0606, 0x63A0616, 0x63A0626, 0x63A0636,
           0x63A064B, 0x63A064B, 0x63A06C0, 0x63A06C0, 0x63A06C0, 0x63A06CE],
          str(sorted(jump_target(l) for l in jmps)))
    check("endbr64 count 1",
          sum(1 for l in lines if "endbr64" in l) == 1)
    check("entry is endbr64 at 0x63a0480",
          "endbr64" in by_addr[START])
    check("canary present: 2 fs:0x28 lines",
          sum(1 for l in lines if "%fs:0x28" in l) == 2)
    check("canary load at 0x63a04ab",
          "mov" in by_addr[0x63A04AB] and "%fs:0x28,%rax" in by_addr[0x63A04AB])
    check("canary save to 0x8(%rsp) at 0x63a04b4",
          "mov" in by_addr[0x63A04B4] and "%rax,0x8(%rsp)" in by_addr[0x63A04B4])
    check("canary check sub at 0x63a0508",
          "sub" in by_addr[0x63A0508] and "%fs:0x28,%rax" in by_addr[0x63A0508])
    check("canary fail jne to stack_chk_fail at 0x63a0511",
          "jne" in by_addr[0x63A0511] and "63a06ce" in by_addr[0x63A0511])
    check("TLS flag check absent: 0 fs:0x330 lines",
          sum(1 for l in lines if "%fs:0x330" in l) == 0)
    check("no prefetch instructions",
          not any("prefetch" in l for l in lines))
    check("tzcnt 0",
          [l for l in lines if mnemonic_of(l) == "tzcnt"] == [])
    check('entry endbr64 at 0x63a0480',
          'endbr64' in by_addr[0x63A0480])
    check('push %r15 at 0x63a0484',
          'push' in by_addr[0x63A0484] and '%r15' in by_addr[0x63A0484])
    check('mutex lea 0x67121a0 at 0x63a0486',
          'lea' in by_addr[0x63A0486] and '0x371d13(%rip),%r15' in by_addr[0x63A0486])
    check('push %r14 at 0x63a048d',
          'push' in by_addr[0x63A048D] and '%r14' in by_addr[0x63A048D])
    check('entry rsi save mov %rsi,%r14 at 0x63a048f',
          'mov' in by_addr[0x63A048F] and '%rsi,%r14' in by_addr[0x63A048F])
    check('push %r13 at 0x63a0492',
          'push' in by_addr[0x63A0492] and '%r13' in by_addr[0x63A0492])
    check('entry r8 save mov %r8,%r13 at 0x63a0494',
          'mov' in by_addr[0x63A0494] and '%r8,%r13' in by_addr[0x63A0494])
    check('push %r12 at 0x63a0497',
          'push' in by_addr[0x63A0497] and '%r12' in by_addr[0x63A0497])
    check('entry rcx save mov %rcx,%r12 at 0x63a0499',
          'mov' in by_addr[0x63A0499] and '%rcx,%r12' in by_addr[0x63A0499])
    check('push %rbp at 0x63a049c',
          'push' in by_addr[0x63A049C] and '%rbp' in by_addr[0x63A049C])
    check('entry rdi save mov %rdi,%rbp at 0x63a049d',
          'mov' in by_addr[0x63A049D] and '%rdi,%rbp' in by_addr[0x63A049D])
    check('trylock rdi mov %r15,%rdi at 0x63a04a0',
          'mov' in by_addr[0x63A04A0] and '%r15,%rdi' in by_addr[0x63A04A0])
    check('push %rbx at 0x63a04a3',
          'push' in by_addr[0x63A04A3] and '%rbx' in by_addr[0x63A04A3])
    check('entry r9 save mov %r9,%rbx at 0x63a04a4',
          'mov' in by_addr[0x63A04A4] and '%r9,%rbx' in by_addr[0x63A04A4])
    check('frame sub $0x18,%rsp at 0x63a04a7',
          'sub' in by_addr[0x63A04A7] and '$0x18,%rsp' in by_addr[0x63A04A7])
    check('canary load mov %fs:0x28,%rax at 0x63a04ab',
          'mov' in by_addr[0x63A04AB] and '%fs:0x28,%rax' in by_addr[0x63A04AB])
    check('canary save mov %rax,0x8(%rsp) at 0x63a04b4',
          'mov' in by_addr[0x63A04B4] and '%rax,0x8(%rsp)' in by_addr[0x63A04B4])
    check('trylock call at 0x63a04bb',
          'call' in by_addr[0x63A04BB] and '63f17b0 <pthread_mutex_trylock@plt>' in by_addr[0x63A04BB])
    check('trylock test %eax,%eax at 0x63a04c0',
          'test' in by_addr[0x63A04C0] and '%eax,%eax' in by_addr[0x63A04C0])
    check('trylock-fail jne lock-wait setup at 0x63a04c2',
          'jne' in by_addr[0x63A04C2] and '63a0560' in by_addr[0x63A04C2])
    check('acq-count addq $0x1,0x371cc8(%rip) at 0x63a04c8',
          'addq' in by_addr[0x63A04C8] and '$0x1,0x371cc8(%rip)' in by_addr[0x63A04C8])
    check('owner cmp 0x6712190,%rbp at 0x63a04d0',
          'cmp' in by_addr[0x63A04D0] and '0x371cb9(%rip),%rbp' in by_addr[0x63A04D0])
    check('owner-unchanged je exit-1 at 0x63a04d7',
          'je' in by_addr[0x63A04D7] and '63a04e8' in by_addr[0x63A04D7])
    check('counter addq $0x1,0x371ca7(%rip) at 0x63a04d9',
          'addq' in by_addr[0x63A04D9] and '$0x1,0x371ca7(%rip)' in by_addr[0x63A04D9])
    check('owner store mov %rbp,0x371ca8(%rip) at 0x63a04e1',
          'mov' in by_addr[0x63A04E1] and '%rbp,0x371ca8(%rip)' in by_addr[0x63A04E1])
    check('exit-1 mov $0x1,%ebp at 0x63a04e8',
          'mov' in by_addr[0x63A04E8] and '$0x1,%ebp' in by_addr[0x63A04E8])
    check('caller-cond or 0x50(%rsp),%rbx at 0x63a04ed',
          'or' in by_addr[0x63A04ED] and '0x50(%rsp),%rbx' in by_addr[0x63A04ED])
    check('caller-cond je resolver path at 0x63a04f2',
          'je' in by_addr[0x63A04F2] and '63a0530' in by_addr[0x63A04F2])
    check('waited-flag clear movb $0x0,0x371ccd(%rip) at 0x63a04f4',
          'movb' in by_addr[0x63A04F4] and '$0x0,0x371ccd(%rip)' in by_addr[0x63A04F4])
    check('unlock rdi mov %r15,%rdi at 0x63a04fb',
          'mov' in by_addr[0x63A04FB] and '%r15,%rdi' in by_addr[0x63A04FB])
    check('unlock call at 0x63a04fe',
          'call' in by_addr[0x63A04FE] and '63f0b70 <pthread_mutex_unlock@plt>' in by_addr[0x63A04FE])
    check('canary reload mov 0x8(%rsp),%rax at 0x63a0503',
          'mov' in by_addr[0x63A0503] and '0x8(%rsp),%rax' in by_addr[0x63A0503])
    check('canary check sub %fs:0x28,%rax at 0x63a0508',
          'sub' in by_addr[0x63A0508] and '%fs:0x28,%rax' in by_addr[0x63A0508])
    check('canary fail jne stack_chk_fail at 0x63a0511',
          'jne' in by_addr[0x63A0511] and '63a06ce' in by_addr[0x63A0511])
    check('rsp restore add $0x18,%rsp at 0x63a0517',
          'add' in by_addr[0x63A0517] and '$0x18,%rsp' in by_addr[0x63A0517])
    check('exit mov %ebp,%eax at 0x63a051b',
          'mov' in by_addr[0x63A051B] and '%ebp,%eax' in by_addr[0x63A051B])
    check('pop %rbx at 0x63a051d',
          'pop' in by_addr[0x63A051D] and '%rbx' in by_addr[0x63A051D])
    check('pop %rbp at 0x63a051e',
          'pop' in by_addr[0x63A051E] and '%rbp' in by_addr[0x63A051E])
    check('pop %r12 at 0x63a051f',
          'pop' in by_addr[0x63A051F] and '%r12' in by_addr[0x63A051F])
    check('pop %r13 at 0x63a0521',
          'pop' in by_addr[0x63A0521] and '%r13' in by_addr[0x63A0521])
    check('pop %r14 at 0x63a0523',
          'pop' in by_addr[0x63A0523] and '%r14' in by_addr[0x63A0523])
    check('pop %r15 at 0x63a0525',
          'pop' in by_addr[0x63A0525] and '%r15' in by_addr[0x63A0525])
    check('ret at 0x63a0527',
          'ret' in by_addr[0x63A0527])
    check('resolver arg mov 0x10(%r14),%rdi at 0x63a0530',
          'mov' in by_addr[0x63A0530] and '0x10(%r14),%rdi' in by_addr[0x63A0530])
    check('resolver call 0x6388310 at 0x63a0534',
          'call' in by_addr[0x63A0534] and '6388310' in by_addr[0x63A0534])
    check('resolver dword mov 0x18(%rax),%eax at 0x63a0539 (no loader, no adjust)',
          'mov' in by_addr[0x63A0539] and '0x18(%rax),%eax' in by_addr[0x63A0539])
    check('dword store mov %eax,0x4(%rsp) at 0x63a053c',
          'mov' in by_addr[0x63A053C] and '%eax,0x4(%rsp)' in by_addr[0x63A053C])
    check('rcx==0 test %r12,%r12 at 0x63a0540',
          'test' in by_addr[0x63A0540] and '%r12,%r12' in by_addr[0x63A0540])
    check('rcx==0 je exit-0 at 0x63a0543',
          'je' in by_addr[0x63A0543] and '63a0558' in by_addr[0x63A0543])
    check('r8==0 test %r13,%r13 at 0x63a0545',
          'test' in by_addr[0x63A0545] and '%r13,%r13' in by_addr[0x63A0545])
    check('r8==0 je exit-0 at 0x63a0548',
          'je' in by_addr[0x63A0548] and '63a0558' in by_addr[0x63A0548])
    check('len load mov 0x0(%r13),%rdx at 0x63a054a',
          'mov' in by_addr[0x63A054A] and '0x0(%r13),%rdx' in by_addr[0x63A054A])
    check('len cmp $0x4,%rdx at 0x63a054e',
          'cmp' in by_addr[0x63A054E] and '$0x4,%rdx' in by_addr[0x63A054E])
    check('len!=4 jne Duff path at 0x63a0552',
          'jne' in by_addr[0x63A0552] and '63a0578' in by_addr[0x63A0552])
    check('dword store mov %eax,(%r12) at 0x63a0554',
          'mov' in by_addr[0x63A0554] and '%eax,(%r12)' in by_addr[0x63A0554])
    check('exit-0 xor %ebp,%ebp at 0x63a0558',
          'xor' in by_addr[0x63A0558] and '%ebp,%ebp' in by_addr[0x63A0558])
    check('exit-0 jmp flag-clear at 0x63a055a',
          'jmp' in by_addr[0x63A055A] and '63a04f4' in by_addr[0x63A055A])
    check('lock-wait setup lea -0x40(%r15),%rdi at 0x63a0560',
          'lea' in by_addr[0x63A0560] and '-0x40(%r15),%rdi' in by_addr[0x63A0560])
    check('lock-wait call at 0x63a0564',
          'call' in by_addr[0x63A0564] and '63bf680' in by_addr[0x63A0564])
    check('waited-flag set movb $0x1,0x371c58(%rip) at 0x63a0569',
          'movb' in by_addr[0x63A0569] and '$0x1,0x371c58(%rip)' in by_addr[0x63A0569])
    check('lock-wait rejoin jmp trylock-success (NO retry) at 0x63a0570',
          'jmp' in by_addr[0x63A0570] and '63a04c8' in by_addr[0x63A0570])
    check('Duff cap mov $0x4,%ecx at 0x63a0578',
          'mov' in by_addr[0x63A0578] and '$0x4,%ecx' in by_addr[0x63A0578])
    check('Duff src lea 0x4(%rsp),%r9 at 0x63a057d',
          'lea' in by_addr[0x63A057D] and '0x4(%rsp),%r9' in by_addr[0x63A057D])
    check('Duff cmp %rcx,%rdx at 0x63a0582',
          'cmp' in by_addr[0x63A0582] and '%rcx,%rdx' in by_addr[0x63A0582])
    check('Duff min cmova %rcx,%rdx at 0x63a0585',
          'cmova' in by_addr[0x63A0585] and '%rcx,%rdx' in by_addr[0x63A0585])
    check('Duff n mov %edx,%edi at 0x63a0589',
          'mov' in by_addr[0x63A0589] and '%edx,%edi' in by_addr[0x63A0589])
    check('Duff test %edx,%edx at 0x63a058b',
          'test' in by_addr[0x63A058B] and '%edx,%edx' in by_addr[0x63A058B])
    check('Duff n==0 je writeback at 0x63a058d',
          'je' in by_addr[0x63A058D] and '63a06c0' in by_addr[0x63A058D])
    check('Duff first byte movzbl (%r9,%rbx,1),%r8d at 0x63a0593',
          'movzbl' in by_addr[0x63A0593] and '(%r9,%rbx,1),%r8d' in by_addr[0x63A0593])
    check('Duff lea -0x1(%rdx),%esi at 0x63a0598',
          'lea' in by_addr[0x63A0598] and '-0x1(%rdx),%esi' in by_addr[0x63A0598])
    check('Duff index mov $0x1,%r11d at 0x63a059b',
          'mov' in by_addr[0x63A059B] and '$0x1,%r11d' in by_addr[0x63A059B])
    check('Duff dispatch and $0x7,%esi at 0x63a05a1',
          'and' in by_addr[0x63A05A1] and '$0x7,%esi' in by_addr[0x63A05A1])
    check('Duff first store mov %r8b,(%r12,%rbx,1) at 0x63a05a4',
          'mov' in by_addr[0x63A05A4] and '%r8b,(%r12,%rbx,1)' in by_addr[0x63A05A4])
    check('Duff cmp %edx,%r11d at 0x63a05a8',
          'cmp' in by_addr[0x63A05A8] and '%edx,%r11d' in by_addr[0x63A05A8])
    check('Duff done jae writeback at 0x63a05ab',
          'jae' in by_addr[0x63A05AB] and '63a06c0' in by_addr[0x63A05AB])
    check('Duff test %esi,%esi at 0x63a05b1',
          'test' in by_addr[0x63A05B1] and '%esi,%esi' in by_addr[0x63A05B1])
    check('Duff dispatch je 8x body at 0x63a05b3',
          'je' in by_addr[0x63A05B3] and '63a064b' in by_addr[0x63A05B3])
    check('Duff cmp $0x1,%esi at 0x63a05b9',
          'cmp' in by_addr[0x63A05B9] and '$0x1,%esi' in by_addr[0x63A05B9])
    check('Duff esi==1 je tail at 0x63a05bc',
          'je' in by_addr[0x63A05BC] and '63a0636' in by_addr[0x63A05BC])
    check('Duff cmp $0x2,%esi at 0x63a05be',
          'cmp' in by_addr[0x63A05BE] and '$0x2,%esi' in by_addr[0x63A05BE])
    check('Duff esi==2 je tail at 0x63a05c1',
          'je' in by_addr[0x63A05C1] and '63a0626' in by_addr[0x63A05C1])
    check('Duff cmp $0x3,%esi at 0x63a05c3',
          'cmp' in by_addr[0x63A05C3] and '$0x3,%esi' in by_addr[0x63A05C3])
    check('Duff esi==3 je tail at 0x63a05c6',
          'je' in by_addr[0x63A05C6] and '63a0616' in by_addr[0x63A05C6])
    check('Duff cmp $0x6,%esi at 0x63a05d2',
          'cmp' in by_addr[0x63A05D2] and '$0x6,%esi' in by_addr[0x63A05D2])
    check('Duff esi==6 je tail at 0x63a05d5',
          'je' in by_addr[0x63A05D5] and '63a05e6' in by_addr[0x63A05D5])
    check('Duff tail-end cmp %edi,%r11d at 0x63a0646',
          'cmp' in by_addr[0x63A0646] and '%edi,%r11d' in by_addr[0x63A0646])
    check('Duff tail-end jae writeback at 0x63a0649',
          'jae' in by_addr[0x63A0649] and '63a06c0' in by_addr[0x63A0649])
    check('8x body mov %r11d,%ecx at 0x63a064b',
          'mov' in by_addr[0x63A064B] and '%r11d,%ecx' in by_addr[0x63A064B])
    check('8x body lea 0x1(%r11),%r10d at 0x63a064e',
          'lea' in by_addr[0x63A064E] and '0x1(%r11),%r10d' in by_addr[0x63A064E])
    check('8x body add $0x8,%r11d at 0x63a069d',
          'add' in by_addr[0x63A069D] and '$0x8,%r11d' in by_addr[0x63A069D])
    check('8x body cmp %edi,%r11d at 0x63a06b6',
          'cmp' in by_addr[0x63A06B6] and '%edi,%r11d' in by_addr[0x63A06B6])
    check('8x body back-edge jb 0x63a064b at 0x63a06b9',
          'jb' in by_addr[0x63A06B9] and '63a064b' in by_addr[0x63A06B9])
    check('writeback mov %rdx,0x0(%r13) at 0x63a06c0',
          'mov' in by_addr[0x63A06C0] and '%rdx,0x0(%r13)' in by_addr[0x63A06C0])
    check('exit-22 mov $0x16,%ebp at 0x63a06c4',
          'mov' in by_addr[0x63A06C4] and '$0x16,%ebp' in by_addr[0x63A06C4])
    check('exit-22 jmp flag-clear at 0x63a06c9',
          'jmp' in by_addr[0x63A06C9] and '63a04f4' in by_addr[0x63A06C9])
    check('stack_chk_fail call at 0x63a06ce',
          'call' in by_addr[0x63A06CE] and '63f0d70 <__stack_chk_fail@plt>' in by_addr[0x63A06CE])
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

    check("entry reaches lock-wait site 0x63a0564", reaches(START, 0x63A0564))
    check("entry reaches ret 0x63a0527", reaches(START, 0x63A0527))
    check("entry reaches trylock 0x63a04bb", reaches(START, 0x63A04BB))
    check("entry reaches epilogue canary 0x63a0503", reaches(START, 0x63A0503))
    check("entry reaches resolver call 0x63a0534", reaches(START, 0x63A0534))
    check("entry reaches exit-1 block 0x63a04e8", reaches(START, 0x63A04E8))
    check("entry reaches exit-0 block 0x63a0558", reaches(START, 0x63A0558))
    check("entry reaches exit-22 block 0x63a06c4", reaches(START, 0x63A06C4))
    check("entry reaches Duff entry 0x63a0578", reaches(START, 0x63A0578))
    check("entry reaches lock-wait setup 0x63a0560", reaches(START, 0x63A0560))
    check("entry reaches writeback 0x63a06c0", reaches(START, 0x63A06C0))
    check("entry reaches 8x body 0x63a064b (graph edge only; value-dead, see Duff block)",
          reaches(START, 0x63A064B))
    check("preds of lock-wait site 0x63a0564 is the setup lea only",
          preds[0x63A0564] == {0x63A0560}, str(preds[0x63A0564]))
    check("preds of lock-wait setup 0x63a0560 are trylock fail and the "
          "padding nopl",
          preds[0x63A0560] == {0x63A04C2, 0x63A055C}, str(preds[0x63A0560]))
    check("preds of trylock 0x63a04bb is the xor only",
          preds[0x63A04BB] == {0x63A04B9}, str(preds[0x63A04BB]))
    check("preds of rejoin 0x63a04c8 are trylock success and the "
          "lock-wait jmp",
          preds[0x63A04C8] == {0x63A04C2, 0x63A0570}, str(preds[0x63A04C8]))
    check("preds of ret 0x63a0527 is the final pop",
          preds[0x63A0527] == {0x63A0525}, str(preds[0x63A0527]))
    check("preds of flag-clear block 0x63a04f4 are the caller-cond "
          "fall-through, the exit-0 jmp and the exit-22 jmp",
          preds[0x63A04F4] == {0x63A04F2, 0x63A055A, 0x63A06C9},
          str(preds[0x63A04F4]))
    check("preds of exit-1 block 0x63a04e8 are the owner-unchanged je "
          "and the owner-store fall-through",
          preds[0x63A04E8] == {0x63A04D7, 0x63A04E1}, str(preds[0x63A04E8]))
    check("preds of resolver call 0x63a0534 is the resolver-arg mov only",
          preds[0x63A0534] == {0x63A0530}, str(preds[0x63A0534]))
    check("preds of exit-0 block 0x63a0558 are rcx==0, r8==0 and the "
          "len==4 dword store",
          preds[0x63A0558] == {0x63A0543, 0x63A0548, 0x63A0554},
          str(preds[0x63A0558]))
    check("preds of Duff entry 0x63a0578 are the len!=4 jne and the "
          "padding nopl",
          preds[0x63A0578] == {0x63A0552, 0x63A0575}, str(preds[0x63A0578]))
    check("preds of writeback 0x63a06c0 are the n==0 je, the done jae, "
          "the tail-end jae and the padding nopl",
          preds[0x63A06C0] == {0x63A058D, 0x63A05AB, 0x63A0649, 0x63A06BB},
          str(preds[0x63A06C0]))
    check("preds of 8x body 0x63a064b are the dispatch je, the "
          "tail-end fall-through and the body's own back-edge",
          preds[0x63A064B] == {0x63A05B3, 0x63A0649, 0x63A06B9}, str(preds[0x63A064B]))
    # The Duff's-device loop IS present and its dispatch tail IS
    # reachable, unlike #339..#364: n = min(len,4) via cmova at
    # 0x63a0585 (rcx capped at 4 at 0x63a0578); the first byte is copied
    # at 0x63a0593/0x63a05a4 with index r11d = 1; the done-jae at
    # 0x63a05ab exits only when r11d >= n, i.e. n <= 1; for n in 2..4,
    # esi = (n-1)&7 in {1,2,3} dispatches to the tail entries at
    # 0x63a0636/0x63a0626/0x63a0616, which copy the remaining bytes and
    # exit at the tail-end jae (0x63a0649). The 8-at-a-time body at
    # 0x63a064b..0x63a06b9 is VALUE-DEAD: its dispatch entry (je at
    # 0x63a05b3) fires only when esi == 0, i.e. (n-1)&7 == 0, i.e. n == 1
    # (n <= 4), but then the pre-dispatch jae already exited; and its
    # fall-through entry (from 0x63a0649) requires r11d < n after the
    # tail, but the tail leaves r11d == n, so the jae is always taken;
    # and its third predecessor (jb at 0x63a06b9) is the body's own
    # iteration back-edge, not an entry from outside the body. So no
    # path from outside the body can ever enter it.
    check("Duff cap is 4: mov $0x4,%ecx at 0x63a0578",
          "mov" in by_addr[0x63A0578] and "$0x4,%ecx" in by_addr[0x63A0578])
    check("Duff min is cmova %rcx,%rdx at 0x63a0585",
          "cmova" in by_addr[0x63A0585] and "%rcx,%rdx" in by_addr[0x63A0585])
    check("Duff dispatch tail entries are the six je targets for "
          "(n-1)&7 in 1..6",
          sorted(jump_target(by_addr[a]) for a in
                 (0x63A05BC, 0x63A05C1, 0x63A05C6, 0x63A05CB, 0x63A05D0,
                  0x63A05D5)) ==
          [0x63A05E6, 0x63A05F6, 0x63A0606, 0x63A0616, 0x63A0626, 0x63A0636],
          str([hex(jump_target(by_addr[a])) for a in
               (0x63A05BC, 0x63A05C1, 0x63A05C6, 0x63A05CB, 0x63A05D0,
                0x63A05D5)]))
    check("Duff 8x-body entry je at 0x63a05b3 fires only when (n-1)&7==0",
          "je" in by_addr[0x63A05B3] and "63a064b" in by_addr[0x63A05B3]
          and "test" in by_addr[0x63A05B1]
          and "%esi,%esi" in by_addr[0x63A05B1])
    check("Duff index is 1 at the dispatch point (mov $0x1,%r11d)",
          "mov" in by_addr[0x63A059B] and "$0x1,%r11d" in by_addr[0x63A059B])
    check("Duff pre-dispatch done-jae exits when r11d>=n (n<=1)",
          "cmp" in by_addr[0x63A05A8] and "%edx,%r11d" in by_addr[0x63A05A8]
          and "jae" in by_addr[0x63A05AB] and "63a06c0" in by_addr[0x63A05AB])
    check("Duff tail-end jae exits when r11d>=n (r11d==n after the tail)",
          "cmp" in by_addr[0x63A0646] and "%edi,%r11d" in by_addr[0x63A0646]
          and "jae" in by_addr[0x63A0649] and "63a06c0" in by_addr[0x63A0649])
    check("backward jumps are the exit-0 jmp, the lock-wait rejoin, "
          "the 8x-body back-edge and the exit-22 jmp",
          sorted((addr_of(l), jump_target(l)) for l in jmps
                 if jump_target(l) is not None
                 and jump_target(l) < addr_of(l)) ==
          [(0x63A055A, 0x63A04F4), (0x63A0570, 0x63A04C8),
           (0x63A06B9, 0x63A064B), (0x63A06C9, 0x63A04F4)],
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
    SITE = 0x63A0564
    RET = 0x63A0527
    CALL_TRYLOCK = {("CALL", 0x63A04BB)}
    check("site rdi only def is lea -0x40(%r15),%rdi 0x63a0560",
          rdi_in[SITE] == {0x63A0560}, str(rdi_in[SITE]))
    check("site rsi is clobbered by the trylock only (no post-trylock "
          "restore in this window, like #339/#340/#341/#342/#343/#344/#345/#346/#347/#348/#349/#350/#351/#352/#353/#354/#355/#356/#357/#358/#359/#360/#361/#362/#363/#364/#365, unlike #338)",
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
          rbx_in[SITE] == {0x63A04A4}, str(rbx_in[SITE]))
    check("site rbp def is the entry rdi save",
          rbp_in[SITE] == {0x63A049D}, str(rbp_in[SITE]))
    check("site r12 def is the entry rcx save",
          r12_in[SITE] == {0x63A0499}, str(r12_in[SITE]))
    check("site r13 def is the entry r8 save",
          r13_in[SITE] == {0x63A0494}, str(r13_in[SITE]))
    check("site r14 def is the entry rsi save",
          r14_in[SITE] == {0x63A048F}, str(r14_in[SITE]))
    check("site r15 def is the mutex lea",
          r15_in[SITE] == {0x63A0486}, str(r15_in[SITE]))
    check("rax at ret is exactly the single mov %ebp,%eax at 0x63a051b",
          rax_in[RET] == {0x63A051B}, str(rax_in[RET]))
    check("ebp at the exit mov is exactly the 3 exit values 0/1/22",
          rbp_in[0x63A051B] == {0x63A04E8, 0x63A0558, 0x63A06C4},
          str(rbp_in[0x63A051B]))
    check("ebp at the flag-clear is exactly the 3 exit values 0/1/22 "
          "(the flag-clear is the exit join point in this window)",
          rbp_in[0x63A04F4] == {0x63A04E8, 0x63A0558, 0x63A06C4},
          str(rbp_in[0x63A04F4]))
    check("rbx at the Duff entry is the caller-cond or only "
          "(copy path forces rbx==0)",
          rbx_in[0x63A0578] == {0x63A04ED}, str(rbx_in[0x63A0578]))
    check("rdx at the writeback is the len load plus the cmova min",
          rdx_in[0x63A06C0] == {0x63A054A, 0x63A0585}, str(rdx_in[0x63A06C0]))
    check("r9 at the Duff entry is clobbered by the resolver call only",
          r9_in[0x63A0578] == {("CALL", 0x63A0534)}, str(r9_in[0x63A0578]))
    check("r12 at the Duff entry is the entry rcx save",
          r12_in[0x63A0578] == {0x63A0499}, str(r12_in[0x63A0578]))
    check("r13 at the Duff entry is the entry r8 save",
          r13_in[0x63A0578] == {0x63A0494}, str(r13_in[0x63A0578]))

    check("records lock-wait sites match census",
          [s.get("site") for s in rec.get("lock_wait_sites", [])] ==
          ["0x63a0564"])
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
    check("records window bytes 595",
          rec.get("window", {}).get("bytes") == 595)
    check("records window range",
          rec.get("window", {}).get("range") == "0x63a0480..0x63a06d3")
    check("records return value exits 0/1/22",
          rec.get("return_value", {}).get("rax") ==
          "eax: 0/1/22 (mov %ebp,%eax at 0x63a051b; ebp: mov $0x1 at 0x63a04e8, xor %ebp at 0x63a0558, mov $0x16 at 0x63a06c4)")
    check("records entry gate absent (no gate byte in this window)",
          rec.get("entry_gate") is None)
    check("records count call absent (0x634eba0 NOT called here)",
          rec.get("count_call") is None)
    check("records resolver target 0x6388310",
          rec.get("resolver", {}).get("target") == "0x6388310")
    check("records resolver site 0x63a0534",
          rec.get("resolver", {}).get("site") == "0x63a0534")
    check("records loader absent (0x63bfb90 NOT called here)",
          rec.get("loader") is None)
    check("records inline adjust absent (no fixed adjust here)",
          rec.get("inline_adjust", {}).get("amount") is None)
    check("records selector is direct dword read (no index, no table)",
          rec.get("selector", {}).get("index") ==
          "none - dword at +0x18 of resolver result read directly (mov 0x18(%rax),%eax at 0x63a0539)")
    check("records copy loop is a reachable Duff dispatch",
          rec.get("copy_loop", {}).get("loop") is True)
    check("records copy dispatch is the Duff dispatch",
          rec.get("copy_loop", {}).get("dispatch") ==
          "Duff's-device dispatch at 0x63a05b3 (je 0x63a064b when (n-1)&7==0) with tail entries for (n-1)&7 in 1..6; reachable for len 2..4")
    check("records copy 8x body is value-dead",
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
    check("next candidate raw lu-miss 0", counts.get(0x63A01C0, 0) == 0,
          str(counts.get(0x63A01C0, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x63A01C0, 0) == 0,
          str(bti_counts.get(0x63A01C0, 0)))
    check("next candidate raw second-handler 0",
          sh_counts.get(0x63A01C0, 0) == 0, str(sh_counts.get(0x63A01C0, 0)))
    check("next candidate raw lock-wait 1",
          lw_counts.get(0x63A01C0, 0) == 1,
          str(lw_counts.get(0x63A01C0, 0)))
    # lock-wait frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 344", len(survey.get("survivors", [])) == 344,
          str(len(survey.get("survivors", []))))
    check("survey this window is a lock-wait survivor",
          "0x63a0480" in survey.get("survivors", []))
    check("survey this window is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x63a0480") == 1,
          str(survey.get("sites_per_fde", {}).get("0x63a0480")))
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
          "0x63a0480" not in survey.get("lu_miss_survivors", []))
    check("survey this window is NOT a second-handler survivor",
          "0x63a0480" not in survey.get("second_handler_survivors", []))
    check("survey next candidate is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x63a01c0") == 1,
          str(survey.get("sites_per_fde", {}).get("0x63a01c0")))
    nq = rec.get("next_question", {})
    check("next question is the lock-wait frontier",
          nq.get("frontier") == "lock-wait helper 0x63bf680 callers",
          str(nq.get("frontier")))
    check("next question range 0x63a01c0..0x63a0478",
          nq.get("range") == "0x63a01c0..0x63a0478", str(nq.get("range")))
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
          nq.get("lock_wait_site") == ["0x63a02a4"],
          str(nq.get("lock_wait_site")))
    check("next question second-handler sites 0",
          nq.get("second_handler_sites") == 0,
          str(nq.get("second_handler_sites")))
    check("next question bsr 0", nq.get("bsr") == 0,
          str(nq.get("bsr")))
    check("next question rets 1",
          nq.get("ret") == ["0x63a0267"], str(nq.get("ret")))
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
    check("records census strict 154",
          rec.get("census", {}).get("strict") == 154)
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
    # next candidate 0x63a01c0..0x63a0478 must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x63A01C0 < p[1] and p[0] < 0x63A0478]
    check("next candidate 0x63a01c0 disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x63A0478 and 0x63A01C0 < END))

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
    check("slug not colliding with #314-#365 lu-miss/lockwait slugs",
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
                       "RE-001-node115-lockwait-caller-1site-resolver-noloader"))

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
                    "lockwait_caller_1site_resolver_noloader_duff.hex",
                    "lockwait_caller_1site_resolver_noloader_duff.objdump.txt"}
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
