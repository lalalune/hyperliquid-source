import bisect
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

SLUG = "RE-001-node115-lockwait-caller-1site-tablecopy"
START = 0x6386110
END = 0x63864b9
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
    (0x6386110, 'push', '%rbp'),    (0x6386111, 'mov', '%rsp,%rbp'),    (0x6386114, 'push', '%r15'),
    (0x6386116, 'mov', '%edx,%r15d'),    (0x6386119, 'push', '%r14'),    (0x638611b, 'mov', '%esi,%r14d'),
    (0x638611e, 'push', '%r13'),    (0x6386120, 'lea', '0x38c079(%rip),%r13        # 67121a0 <__register_atfork@plt+0x320610>'),    (0x6386127, 'push', '%r12'),
    (0x6386129, 'movzbl', '%dl,%r12d'),    (0x638612d, 'push', '%rbx'),    (0x638612e, 'mov', '%rdi,%rbx'),
    (0x6386131, 'mov', '%r13,%rdi'),    (0x6386134, 'sub', '$0x28,%rsp'),    (0x6386138, 'mov', '%fs:0x28,%rax'),
    (0x6386141, 'mov', '%rax,-0x38(%rbp)'),    (0x6386145, 'xor', '%eax,%eax'),    (0x6386147, 'call', '63f17b0 <pthread_mutex_trylock@plt>'),
    (0x638614c, 'test', '%eax,%eax'),    (0x638614e, 'jne', '6386470 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e040>'),    (0x6386154, 'addq', '$0x1,0x38c03c(%rip)        # 6712198 <__register_atfork@plt+0x320608>'),
    (0x638615c, 'cmp', '0x38c02d(%rip),%rbx        # 6712190 <__register_atfork@plt+0x320600>'),    (0x6386163, 'je', '6386174 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63dd44>'),    (0x6386165, 'addq', '$0x1,0x38c01b(%rip)        # 6712188 <__register_atfork@plt+0x3205f8>'),
    (0x638616d, 'mov', '%rbx,0x38c01c(%rip)        # 6712190 <__register_atfork@plt+0x320600>'),    (0x6386174, 'mov', '0x38bfb5(%rip),%rax        # 6712130 <__register_atfork@plt+0x3205a0>'),    (0x638617b, 'mov', '0x8(%rax),%edx'),
    (0x638617e, 'cmp', '$0x1000,%r14d'),    (0x6386185, 'je', '6386190 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63dd60>'),    (0x6386187, 'cmp', '%r14d,%edx'),
    (0x638618a, 'jne', '6386418 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63dfe8>'),    (0x6386190, 'mov', '%edx,%esi'),    (0x6386192, 'mov', '%rsp,%r9'),
    (0x6386195, 'mov', '%rsp,-0x48(%rbp)'),    (0x6386199, 'shl', '$0x3,%rsi'),    (0x638619d, 'lea', '0xf(%rsi),%r8'),
    (0x63861a1, 'shr', '$0x4,%r8'),    (0x63861a5, 'shl', '$0x4,%r8'),    (0x63861a9, 'mov', '%r8,%rdi'),
    (0x63861ac, 'and', '$0xfffffffffffff000,%rdi'),    (0x63861b3, 'sub', '%rdi,%r9'),    (0x63861b6, 'cmp', '%r9,%rsp'),
    (0x63861b9, 'je', '63861d0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63dda0>'),    (0x63861bb, 'sub', '$0x1000,%rsp'),    (0x63861c2, 'orq', '$0x0,0xff8(%rsp)'),
    (0x63861cb, 'cmp', '%r9,%rsp'),    (0x63861ce, 'jne', '63861bb <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63dd8b>'),    (0x63861d0, 'and', '$0xfff,%r8d'),
    (0x63861d7, 'sub', '%r8,%rsp'),    (0x63861da, 'test', '%r8,%r8'),    (0x63861dd, 'jne', '6386488 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e058>'),
    (0x63861e3, 'mov', '%rsp,%r14'),    (0x63861e6, 'test', '%edx,%edx'),    (0x63861e8, 'je', '6386499 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e069>'),
    (0x63861ee, 'lea', '0x1834cb(%rip),%r10        # 65096c0 <__register_atfork@plt+0x117b30>'),    (0x63861f5, 'mov', '%r14,%r15'),    (0x63861f8, 'mov', '%r14,%rax'),
    (0x63861fb, 'lea', '(%rsi,%r10,1),%r11'),    (0x63861ff, 'jmp', '6386218 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63dde8>'),    (0x6386201, 'nopl', '0x0(%rax)'),
    (0x6386208, 'add', '$0x8,%r10'),    (0x638620c, 'mov', '%rdx,(%rax)'),    (0x638620f, 'add', '$0x8,%rax'),
    (0x6386213, 'cmp', '%r11,%r10'),    (0x6386216, 'je', '6386238 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63de08>'),    (0x6386218, 'mov', '(%r10),%rdx'),
    (0x638621b, 'test', '%rdx,%rdx'),    (0x638621e, 'jne', '6386208 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63ddd8>'),    (0x6386220, 'add', '$0x8,%r10'),
    (0x6386224, 'movq', '$0x0,(%rax)'),    (0x638622b, 'add', '$0x8,%rax'),    (0x638622f, 'cmp', '%r11,%r10'),
    (0x6386232, 'jne', '6386218 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63dde8>'),    (0x6386234, 'nopl', '0x0(%rax)'),    (0x6386238, 'mov', '%rsi,-0x50(%rbp)'),
    (0x638623c, 'mov', '%r13,%rdi'),    (0x638623f, 'movb', '$0x0,0x38bf82(%rip)        # 67121c8 <__register_atfork@plt+0x320638>'),    (0x6386246, 'call', '63f0b70 <pthread_mutex_unlock@plt>'),
    (0x638624b, 'mov', '-0x50(%rbp),%rcx'),    (0x638624f, 'lea', '(%r14,%rcx,1),%r13'),    (0x6386253, 'sub', '$0x8,%rcx'),
    (0x6386257, 'shr', '$0x3,%rcx'),    (0x638625b, 'add', '$0x1,%rcx'),    (0x638625f, 'and', '$0x7,%ecx'),
    (0x6386262, 'je', '638634c <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63df1c>'),    (0x6386268, 'cmp', '$0x1,%rcx'),    (0x638626c, 'je', '638632a <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63defa>'),
    (0x6386272, 'cmp', '$0x2,%rcx'),    (0x6386276, 'je', '6386311 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63dee1>'),    (0x638627c, 'cmp', '$0x3,%rcx'),
    (0x6386280, 'je', '63862f8 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63dec8>'),    (0x6386282, 'cmp', '$0x4,%rcx'),    (0x6386286, 'je', '63862df <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63deaf>'),
    (0x6386288, 'cmp', '$0x5,%rcx'),    (0x638628c, 'je', '63862c6 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63de96>'),    (0x638628e, 'cmp', '$0x6,%rcx'),
    (0x6386292, 'je', '63862ad <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63de7d>'),    (0x6386294, 'mov', '(%r14),%rsi'),    (0x6386297, 'test', '%rsi,%rsi'),
    (0x638629a, 'je', '63862a9 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63de79>'),    (0x638629c, 'mov', '%r12d,%ecx'),    (0x638629f, 'xor', '%edx,%edx'),
    (0x63862a1, 'mov', '%rbx,%rdi'),    (0x63862a4, 'call', '6360ed0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x618aa0>'),    (0x63862a9, 'lea', '0x8(%r14),%r15'),
    (0x63862ad, 'mov', '(%r15),%rsi'),    (0x63862b0, 'test', '%rsi,%rsi'),    (0x63862b3, 'je', '63862c2 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63de92>'),
    (0x63862b5, 'mov', '%r12d,%ecx'),    (0x63862b8, 'xor', '%edx,%edx'),    (0x63862ba, 'mov', '%rbx,%rdi'),
    (0x63862bd, 'call', '6360ed0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x618aa0>'),    (0x63862c2, 'add', '$0x8,%r15'),    (0x63862c6, 'mov', '(%r15),%rsi'),
    (0x63862c9, 'test', '%rsi,%rsi'),    (0x63862cc, 'je', '63862db <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63deab>'),    (0x63862ce, 'mov', '%r12d,%ecx'),
    (0x63862d1, 'xor', '%edx,%edx'),    (0x63862d3, 'mov', '%rbx,%rdi'),    (0x63862d6, 'call', '6360ed0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x618aa0>'),
    (0x63862db, 'add', '$0x8,%r15'),    (0x63862df, 'mov', '(%r15),%rsi'),    (0x63862e2, 'test', '%rsi,%rsi'),
    (0x63862e5, 'je', '63862f4 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63dec4>'),    (0x63862e7, 'mov', '%r12d,%ecx'),    (0x63862ea, 'xor', '%edx,%edx'),
    (0x63862ec, 'mov', '%rbx,%rdi'),    (0x63862ef, 'call', '6360ed0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x618aa0>'),    (0x63862f4, 'add', '$0x8,%r15'),
    (0x63862f8, 'mov', '(%r15),%rsi'),    (0x63862fb, 'test', '%rsi,%rsi'),    (0x63862fe, 'je', '638630d <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63dedd>'),
    (0x6386300, 'mov', '%r12d,%ecx'),    (0x6386303, 'xor', '%edx,%edx'),    (0x6386305, 'mov', '%rbx,%rdi'),
    (0x6386308, 'call', '6360ed0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x618aa0>'),    (0x638630d, 'add', '$0x8,%r15'),    (0x6386311, 'mov', '(%r15),%rsi'),
    (0x6386314, 'test', '%rsi,%rsi'),    (0x6386317, 'je', '6386326 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63def6>'),    (0x6386319, 'mov', '%r12d,%ecx'),
    (0x638631c, 'xor', '%edx,%edx'),    (0x638631e, 'mov', '%rbx,%rdi'),    (0x6386321, 'call', '6360ed0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x618aa0>'),
    (0x6386326, 'add', '$0x8,%r15'),    (0x638632a, 'mov', '(%r15),%rsi'),    (0x638632d, 'test', '%rsi,%rsi'),
    (0x6386330, 'je', '638633f <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63df0f>'),    (0x6386332, 'mov', '%r12d,%ecx'),    (0x6386335, 'xor', '%edx,%edx'),
    (0x6386337, 'mov', '%rbx,%rdi'),    (0x638633a, 'call', '6360ed0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x618aa0>'),    (0x638633f, 'add', '$0x8,%r15'),
    (0x6386343, 'cmp', '%r15,%r13'),    (0x6386346, 'je', '638640c <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63dfdc>'),    (0x638634c, 'mov', '(%r15),%rsi'),
    (0x638634f, 'test', '%rsi,%rsi'),    (0x6386352, 'je', '6386361 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63df31>'),    (0x6386354, 'mov', '%r12d,%ecx'),
    (0x6386357, 'xor', '%edx,%edx'),    (0x6386359, 'mov', '%rbx,%rdi'),    (0x638635c, 'call', '6360ed0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x618aa0>'),
    (0x6386361, 'mov', '0x8(%r15),%rsi'),    (0x6386365, 'lea', '0x8(%r15),%r14'),    (0x6386369, 'test', '%rsi,%rsi'),
    (0x638636c, 'je', '638637b <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63df4b>'),    (0x638636e, 'mov', '%r12d,%ecx'),    (0x6386371, 'xor', '%edx,%edx'),
    (0x6386373, 'mov', '%rbx,%rdi'),    (0x6386376, 'call', '6360ed0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x618aa0>'),    (0x638637b, 'mov', '0x8(%r14),%rsi'),
    (0x638637f, 'test', '%rsi,%rsi'),    (0x6386382, 'je', '6386391 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63df61>'),    (0x6386384, 'mov', '%r12d,%ecx'),
    (0x6386387, 'xor', '%edx,%edx'),    (0x6386389, 'mov', '%rbx,%rdi'),    (0x638638c, 'call', '6360ed0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x618aa0>'),
    (0x6386391, 'mov', '0x10(%r14),%rsi'),    (0x6386395, 'test', '%rsi,%rsi'),    (0x6386398, 'je', '63863a7 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63df77>'),
    (0x638639a, 'mov', '%r12d,%ecx'),    (0x638639d, 'xor', '%edx,%edx'),    (0x638639f, 'mov', '%rbx,%rdi'),
    (0x63863a2, 'call', '6360ed0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x618aa0>'),    (0x63863a7, 'mov', '0x18(%r14),%rsi'),    (0x63863ab, 'test', '%rsi,%rsi'),
    (0x63863ae, 'je', '63863bd <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63df8d>'),    (0x63863b0, 'mov', '%r12d,%ecx'),    (0x63863b3, 'xor', '%edx,%edx'),
    (0x63863b5, 'mov', '%rbx,%rdi'),    (0x63863b8, 'call', '6360ed0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x618aa0>'),    (0x63863bd, 'mov', '0x20(%r14),%rsi'),
    (0x63863c1, 'test', '%rsi,%rsi'),    (0x63863c4, 'je', '63863d3 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63dfa3>'),    (0x63863c6, 'mov', '%r12d,%ecx'),
    (0x63863c9, 'xor', '%edx,%edx'),    (0x63863cb, 'mov', '%rbx,%rdi'),    (0x63863ce, 'call', '6360ed0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x618aa0>'),
    (0x63863d3, 'mov', '0x28(%r14),%rsi'),    (0x63863d7, 'test', '%rsi,%rsi'),    (0x63863da, 'je', '63863e9 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63dfb9>'),
    (0x63863dc, 'mov', '%r12d,%ecx'),    (0x63863df, 'xor', '%edx,%edx'),    (0x63863e1, 'mov', '%rbx,%rdi'),
    (0x63863e4, 'call', '6360ed0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x618aa0>'),    (0x63863e9, 'mov', '0x30(%r14),%rsi'),    (0x63863ed, 'test', '%rsi,%rsi'),
    (0x63863f0, 'je', '63863ff <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63dfcf>'),    (0x63863f2, 'mov', '%r12d,%ecx'),    (0x63863f5, 'xor', '%edx,%edx'),
    (0x63863f7, 'mov', '%rbx,%rdi'),    (0x63863fa, 'call', '6360ed0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x618aa0>'),    (0x63863ff, 'lea', '0x38(%r14),%r15'),
    (0x6386403, 'cmp', '%r15,%r13'),    (0x6386406, 'jne', '638634c <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63df1c>'),    (0x638640c, 'mov', '-0x48(%rbp),%rsp'),
    (0x6386410, 'jmp', '6386448 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e018>'),    (0x6386412, 'nopw', '0x0(%rax,%rax,1)'),    (0x6386418, 'lea', '0x1832a1(%rip),%rcx        # 65096c0 <__register_atfork@plt+0x117b30>'),
    (0x638641f, 'mov', '%r13,%rdi'),    (0x6386422, 'mov', '(%rcx,%r14,8),%r14'),    (0x6386426, 'movb', '$0x0,0x38bd9b(%rip)        # 67121c8 <__register_atfork@plt+0x320638>'),
    (0x638642d, 'test', '%r14,%r14'),    (0x6386430, 'je', '63864ad <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e07d>'),    (0x6386432, 'call', '63f0b70 <pthread_mutex_unlock@plt>'),
    (0x6386437, 'movzbl', '%r15b,%ecx'),    (0x638643b, 'xor', '%edx,%edx'),    (0x638643d, 'mov', '%r14,%rsi'),
    (0x6386440, 'mov', '%rbx,%rdi'),    (0x6386443, 'call', '6360ed0 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x618aa0>'),    (0x6386448, 'mov', '-0x38(%rbp),%rax'),
    (0x638644c, 'sub', '%fs:0x28,%rax'),    (0x6386455, 'jne', '63864b4 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e084>'),    (0x6386457, 'lea', '-0x28(%rbp),%rsp'),
    (0x638645b, 'pop', '%rbx'),    (0x638645c, 'pop', '%r12'),    (0x638645e, 'pop', '%r13'),
    (0x6386460, 'pop', '%r14'),    (0x6386462, 'pop', '%r15'),    (0x6386464, 'pop', '%rbp'),
    (0x6386465, 'ret', ''),    (0x6386466, 'cs', 'nopw 0x0(%rax,%rax,1)'),    (0x6386470, 'lea', '-0x40(%r13),%rdi'),
    (0x6386474, 'call', '63bf680 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x677250>'),    (0x6386479, 'movb', '$0x1,0x38bd48(%rip)        # 67121c8 <__register_atfork@plt+0x320638>'),    (0x6386480, 'jmp', '6386154 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63dd24>'),
    (0x6386485, 'nopl', '(%rax)'),    (0x6386488, 'orq', '$0x0,-0x8(%rsp,%r8,1)'),    (0x638648e, 'mov', '%rsp,%r14'),
    (0x6386491, 'test', '%edx,%edx'),    (0x6386493, 'jne', '63861ee <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63ddbe>'),    (0x6386499, 'movb', '$0x0,0x38bd28(%rip)        # 67121c8 <__register_atfork@plt+0x320638>'),
    (0x63864a0, 'mov', '%r13,%rdi'),    (0x63864a3, 'call', '63f0b70 <pthread_mutex_unlock@plt>'),    (0x63864a8, 'jmp', '638640c <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63dfdc>'),
    (0x63864ad, 'call', '63f0b70 <pthread_mutex_unlock@plt>'),    (0x63864b2, 'jmp', '6386448 <_ZNKSt5ctypeIcE8do_widenEc@@Base+0x63e018>'),    (0x63864b4, 'call', '63f0d70 <__stack_chk_fail@plt>'),
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
    check("target FDE size 937", END - START == 937)
    prev = fdes[i - 1]
    check("prev FDE 0x6386030..0x638610a",
          prev == (0x6386030, 0x638610A), str(prev))
    check("prev gap 6 (0xcc padding)", START - prev[1] == 6)
    check("prev gap bytes are 0xcc int3 padding",
          node[toff(prev[1]):toff(START)] == b"\xcc" * 6)
    nxt = fdes[i + 1]
    check("next FDE 0x63864c0..0x63864fd",
          nxt == (0x63864C0, 0x63864FD), str(nxt))
    check("next gap 7 (0xcc padding)", nxt[0] - END == 7)
    check("next gap bytes are 0xcc int3 padding",
          node[toff(END):toff(nxt[0])] == b"\xcc" * 7)
    check("next FDE starts endbr64",
          node[toff(nxt[0]):toff(nxt[0]) + 4] == b"\xf3\x0f\x1e\xfa")
    check("prev FDE end is 6 bytes before this FDE start",
          prev[1] == START - 6)
    check("call-target FDE 0x6360ed0..0x636116d",
          fdes[bisect.bisect_left(starts, 0x6360ED0)] ==
          (0x6360ED0, 0x636116D))
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
    check("next-question FDE 0x63ce510..0x63ce8b8",
          fdes[bisect.bisect_left(starts, 0x63CE510)] ==
          (0x63CE510, 0x63CE8B8))
    check("next-question callee FDE 0x63bf5b6..0x63bf677",
          fdes[bisect.bisect_left(starts, 0x63BF5B6)] ==
          (0x63BF5B6, 0x63BF677))
    check("#321 shared FDE 0x63c9650..0x63c9c80",
          fdes[bisect.bisect_left(starts, 0x63C9650)] ==
          (0x63C9650, 0x63C9C80))

    hexb = read(os.path.join(PACKET, "lockwait_caller_1site_tablecopy.hex"))
    check("hex exhibit raw bytes 937", len(hexb) == 937, str(len(hexb)))
    check("hex exhibit equals binary slice",
          hexb == node[toff(START):toff(END)])
    objdump = read(os.path.join(
        PACKET, "lockwait_caller_1site_tablecopy.objdump.txt")).decode()
    lines = strict_lines(objdump)
    check("strict lines 258", len(lines) == 258, str(len(lines)))
    by_addr = {addr_of(l): l for l in lines}
    calls = [l for l in lines if mnemonic_of(l) == "call"]
    check("call lines 23", len(calls) == 23, str(len(calls)))
    rets = [l for l in lines if mnemonic_of(l) == "ret"]
    check("ret lines 1", len(rets) == 1, str(len(rets)))
    check("ret site 0x6386465",
          sorted(addr_of(l) for l in rets) == [0x6386465],
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
    expect = {0x6360ED0: 16, 0x63BF680: 1, 0x63F0B70: 4,
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
    check("lock-wait site is 0x6386474",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63bf680" in l) == [0x6386474])
    check("resolver 0x6365150 called 0 times", tgt.get(0x6365150, 0) == 0,
          str(tgt.get(0x6365150, 0)))
    check("stack_chk_fail plt call 1 at 0x63864b4",
          tgt.get(0x63F0D70, 0) == 1, str(tgt.get(0x63F0D70, 0)))
    check("trylock plt call 1 at 0x6386147",
          tgt.get(0x63F17B0, 0) == 1, str(tgt.get(0x63F17B0, 0)))
    check("unlock plt calls 4 at 0x6386246/0x6386432/0x63864a3/0x63864ad",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "63f0b70" in l) ==
          [0x6386246, 0x6386432, 0x63864A3, 0x63864AD])
    check("callee 0x6360ed0 called 16 times at the exact sites",
          sorted(a for a, l in ((addr_of(l), l) for l in calls)
                 if "6360ed0" in l) ==
          [0x63862A4, 0x63862BD, 0x63862D6, 0x63862EF, 0x6386308, 0x6386321,
           0x638633A, 0x638635C, 0x6386376, 0x638638C, 0x63863A2, 0x63863B8,
           0x63863CE, 0x63863E4, 0x63863FA, 0x6386443])
    plt_calls = [l for l in calls if "@plt" in l]
    check("PLT calls 6 (by @plt suffix, not address range)",
          len(plt_calls) == 6, str(len(plt_calls)))
    check("distinct PLT targets 3",
          len({re.search(r"\tcall\s+([0-9a-f]+)", l).group(1)
               for l in plt_calls}) == 3)
    check("no internal .text call is counted as PLT",
          not any("6360ed0" in l and "@plt" in l for l in calls))
    for _w, _a in (("#314", 0x63495B0), ("#315", 0x6353A70),
                  ("#316", 0x6355900), ("#317", 0x63577F0),
                  ("#318", 0x635A7A0), ("#319", 0x635C6D0),
                  ("#320", 0x635E2E0), ("#321", 0x63C9650),
                  ("#322", 0x63CCD60), ("#323", 0x63CDDD0),
                  ("#324", 0x63D03A0), ("#325", 0x63D17E0),
                  ("#326", 0x63D2A80), ("#327", 0x63D3F0E),
                  ("#328", 0x63D4048), ("#329", 0x63E94A0),
                  ("#330", 0x6362190), ("#331", 0x6362910),
                  ("#332", 0x636A140), ("#333", 0x6386540),
                  ("#334", 0x635F780)):
        check("%s window not called" % _w, tgt.get(_a, 0) == 0,
              str(tgt.get(_a, 0)))

    bsr = [l for l in lines if re.search(r"\tbsr\s", l)]
    check("bsr 0", len(bsr) == 0, str([hex(addr_of(l)) for l in bsr]))
    check("shr exactly 2 at 0x63861a1 and 0x6386257",
          sorted(addr_of(l) for l in lines
                 if mnemonic_of(l) == "shr") == [0x63861A1, 0x6386257])
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
    check("jump lines 43", len(jmps) == 43, str(len(jmps)))

    def jump_target(line):
        m = re.search(r"\s([0-9a-f]{6,})\s*<", line)
        return int(m.group(1), 16) if m else None

    outside = []
    for l in jmps:
        t = jump_target(l)
        if t is not None and not (START <= t < END):
            outside.append((addr_of(l), t))
    check("jump closure: 0 outside the window", outside == [], str(outside))
    check("jump targets are exactly the 43 branches",
          sorted(jump_target(l) for l in jmps) ==
          [0x6386154, 0x6386174, 0x6386190, 0x63861BB, 0x63861D0, 0x63861EE,
           0x6386208, 0x6386218, 0x6386218, 0x6386238, 0x63862A9, 0x63862AD,
           0x63862C2, 0x63862C6, 0x63862DB, 0x63862DF, 0x63862F4, 0x63862F8,
           0x638630D, 0x6386311, 0x6386326, 0x638632A, 0x638633F, 0x638634C,
           0x638634C, 0x6386361, 0x638637B, 0x6386391, 0x63863A7, 0x63863BD,
           0x63863D3, 0x63863E9, 0x63863FF, 0x638640C, 0x638640C, 0x6386418,
           0x6386448, 0x6386448, 0x6386470, 0x6386488, 0x6386499, 0x63864AD,
           0x63864B4],
          str(sorted(jump_target(l) for l in jmps)))
    check("endbr64 count 0",
          sum(1 for l in lines if "endbr64" in l) == 0)
    check("entry is push %rbp at 0x6386110 (no endbr64)",
          "push" in by_addr[START] and "%rbp" in by_addr[START])
    check("canary present: 2 fs:0x28 lines",
          sum(1 for l in lines if "%fs:0x28" in l) == 2)
    check("canary load at 0x6386138",
          "mov" in by_addr[0x6386138] and "%fs:0x28,%rax" in by_addr[0x6386138])
    check("canary save to -0x38(rbp) at 0x6386141",
          "mov" in by_addr[0x6386141] and "%rax,-0x38(%rbp)" in by_addr[0x6386141])
    check("canary check sub at 0x638644c",
          "sub" in by_addr[0x638644C] and "%fs:0x28,%rax" in by_addr[0x638644C])
    check("canary fail jne to stack_chk_fail at 0x6386455",
          "jne" in by_addr[0x6386455] and "63864b4" in by_addr[0x6386455])
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
    check("no prefetch instructions",
          not any("prefetch" in l for l in lines))
    check("tzcnt 0",
          [l for l in lines if mnemonic_of(l) == "tzcnt"] == [])
    check("btc 0",
          [l for l in lines if mnemonic_of(l) == "btc"] == [])
    check("entry owner mov %rdi,%rbx at 0x638612e",
          "mov" in by_addr[0x638612E] and "%rdi,%rbx" in by_addr[0x638612E])
    check("entry index mov %esi,%r14d at 0x638611b",
          "mov" in by_addr[0x638611B] and "%esi,%r14d" in by_addr[0x638611B])
    check("entry byte flag mov %edx,%r15d at 0x6386116",
          "mov" in by_addr[0x6386116] and "%edx,%r15d" in by_addr[0x6386116])
    check("entry byte flag movzbl %dl,%r12d at 0x6386129",
          "movzbl" in by_addr[0x6386129] and "%dl,%r12d" in by_addr[0x6386129])
    check("mutex lea 0x67121a0 at 0x6386120",
          "lea" in by_addr[0x6386120] and "67121a0" in by_addr[0x6386120])
    check("trylock call at 0x6386147",
          "call" in by_addr[0x6386147] and "63f17b0" in by_addr[0x6386147])
    check("trylock-fail jne lock-wait setup at 0x638614e",
          "jne" in by_addr[0x638614E] and "6386470" in by_addr[0x638614E])
    check("acq-count addq $0x1,0x6712198 at 0x6386154",
          "addq" in by_addr[0x6386154] and "0x38c03c(%rip)" in by_addr[0x6386154])
    check("owner cmp 0x6712190,%rbx at 0x638615c",
          "cmp" in by_addr[0x638615C] and "0x38c02d(%rip)" in by_addr[0x638615C])
    check("counter addq $0x1,0x6712188 at 0x6386165",
          "addq" in by_addr[0x6386165] and "0x38c01b(%rip)" in by_addr[0x6386165])
    check("owner store mov %rbx,0x6712190 at 0x638616d",
          "mov" in by_addr[0x638616D] and "0x38c01c(%rip)" in by_addr[0x638616D])
    check("count-struct mov 0x6712130,%rax at 0x6386174",
          "mov" in by_addr[0x6386174] and "6712130" in by_addr[0x6386174])
    check("count mov 0x8(%rax),%edx at 0x638617b",
          "mov" in by_addr[0x638617B] and "0x8(%rax),%edx" in by_addr[0x638617B])
    check("sentinel cmp $0x1000,%r14d at 0x638617e",
          "cmp" in by_addr[0x638617E] and "$0x1000,%r14d" in by_addr[0x638617E])
    check("sentinel je all-entries at 0x6386185",
          "je" in by_addr[0x6386185] and "6386190" in by_addr[0x6386185])
    check("count cmp %r14d,%edx at 0x6386187",
          "cmp" in by_addr[0x6386187] and "%r14d,%edx" in by_addr[0x6386187])
    check("selector jne single-entry at 0x638618a",
          "jne" in by_addr[0x638618A] and "6386418" in by_addr[0x638618A])
    check("VLA shl $0x3,%rsi at 0x6386199",
          "shl" in by_addr[0x6386199] and "$0x3,%rsi" in by_addr[0x6386199])
    check("VLA rsp save mov %rsp,-0x48(%rbp) at 0x6386195",
          "mov" in by_addr[0x6386195] and "%rsp,-0x48(%rbp)" in by_addr[0x6386195])
    check("VLA align shr $0x4,%r8 at 0x63861a1",
          "shr" in by_addr[0x63861A1] and "$0x4,%r8" in by_addr[0x63861A1])
    check("VLA probe sub $0x1000,%rsp at 0x63861bb",
          "sub" in by_addr[0x63861BB] and "$0x1000,%rsp" in by_addr[0x63861BB])
    check("VLA probe orq $0,0xff8(%rsp) at 0x63861c2",
          "orq" in by_addr[0x63861C2] and "$0x0,0xff8(%rsp)" in by_addr[0x63861C2])
    check("VLA remainder sub %r8,%rsp at 0x63861d7",
          "sub" in by_addr[0x63861D7] and "%r8,%rsp" in by_addr[0x63861D7])
    check("count==0 je 0x6386499 at 0x63861e8",
          "je" in by_addr[0x63861E8] and "6386499" in by_addr[0x63861E8])
    check("table lea 0x65096c0 at 0x63861ee",
          "lea" in by_addr[0x63861EE] and "65096c0" in by_addr[0x63861EE])
    check("copy NULL zero movq $0x0,(%rax) at 0x6386224",
          "movq" in by_addr[0x6386224] and "$0x0,(%rax)" in by_addr[0x6386224])
    check("copy done mov %rsi,-0x50(%rbp) at 0x6386238",
          "mov" in by_addr[0x6386238] and "%rsi,-0x50(%rbp)" in by_addr[0x6386238])
    check("waited-flag clear movb $0x0,0x67121c8 at 0x638623f",
          "movb" in by_addr[0x638623F] and "0x38bf82(%rip)" in by_addr[0x638623F])
    check("unlock after copy at 0x6386246",
          "call" in by_addr[0x6386246] and "63f0b70" in by_addr[0x6386246])
    check("duffs sub $0x8,%rcx at 0x6386253",
          "sub" in by_addr[0x6386253] and "$0x8,%rcx" in by_addr[0x6386253])
    check("duffs shr $0x3,%rcx at 0x6386257",
          "shr" in by_addr[0x6386257] and "$0x3,%rcx" in by_addr[0x6386257])
    check("duffs and $0x7,%ecx at 0x638625f",
          "and" in by_addr[0x638625F] and "$0x7,%ecx" in by_addr[0x638625F])
    check("dispatch je D 0x638634c at 0x6386262",
          "je" in by_addr[0x6386262] and "638634c" in by_addr[0x6386262])
    check("dispatch je 0x638632a at 0x638626c",
          "je" in by_addr[0x638626C] and "638632a" in by_addr[0x638626C])
    check("dispatch je 0x6386311 at 0x6386276",
          "je" in by_addr[0x6386276] and "6386311" in by_addr[0x6386276])
    check("dispatch je 0x63862f8 at 0x6386280",
          "je" in by_addr[0x6386280] and "63862f8" in by_addr[0x6386280])
    check("dispatch je 0x63862df at 0x6386286",
          "je" in by_addr[0x6386286] and "63862df" in by_addr[0x6386286])
    check("dispatch je 0x63862c6 at 0x638628c",
          "je" in by_addr[0x638628C] and "63862c6" in by_addr[0x638628C])
    check("dispatch je 0x63862ad at 0x6386292",
          "je" in by_addr[0x6386292] and "63862ad" in by_addr[0x6386292])
    check("remainder exit je epilogue at 0x6386346",
          "je" in by_addr[0x6386346] and "638640c" in by_addr[0x6386346])
    check("D-loop r15+=0x38 lea at 0x63863ff",
          "lea" in by_addr[0x63863FF] and "0x38(%r14),%r15" in by_addr[0x63863FF])
    check("D-loop back jne 0x638634c at 0x6386406",
          "jne" in by_addr[0x6386406] and "638634c" in by_addr[0x6386406])
    check("epilogue rsp restore mov -0x48(%rbp),%rsp at 0x638640c",
          "mov" in by_addr[0x638640C] and "-0x48(%rbp),%rsp" in by_addr[0x638640C])
    check("single-entry table lea 0x65096c0 at 0x6386418",
          "lea" in by_addr[0x6386418] and "65096c0" in by_addr[0x6386418])
    check("single-entry load mov (%rcx,%r14,8),%r14 at 0x6386422",
          "mov" in by_addr[0x6386422] and "(%rcx,%r14,8),%r14" in by_addr[0x6386422])
    check("single-entry flag clear movb $0x0,0x67121c8 at 0x6386426",
          "movb" in by_addr[0x6386426] and "0x38bd9b(%rip)" in by_addr[0x6386426])
    check("single-entry NULL je unlock at 0x6386430",
          "je" in by_addr[0x6386430] and "63864ad" in by_addr[0x6386430])
    check("single-entry unlock at 0x6386432",
          "call" in by_addr[0x6386432] and "63f0b70" in by_addr[0x6386432])
    check("single-entry helper call at 0x6386443",
          "call" in by_addr[0x6386443] and "6360ed0" in by_addr[0x6386443])
    check("lock-wait setup lea -0x40(%r13),%rdi at 0x6386470",
          "lea" in by_addr[0x6386470] and "-0x40(%r13),%rdi" in by_addr[0x6386470])
    check("lock-wait call at 0x6386474",
          "call" in by_addr[0x6386474] and "63bf680" in by_addr[0x6386474])
    check("waited-flag set movb $0x1,0x67121c8 at 0x6386479",
          "movb" in by_addr[0x6386479] and "0x38bd48(%rip)" in by_addr[0x6386479])
    check("lock-wait retry jmp 0x6386154 at 0x6386480",
          "jmp" in by_addr[0x6386480] and "6386154" in by_addr[0x6386480])
    check("count==0 flag clear movb $0x0,0x67121c8 at 0x6386499",
          "movb" in by_addr[0x6386499] and "0x38bd28(%rip)" in by_addr[0x6386499])
    check("count==0 unlock at 0x63864a3",
          "call" in by_addr[0x63864A3] and "63f0b70" in by_addr[0x63864A3])
    check("count==0 jmp epilogue at 0x63864a8",
          "jmp" in by_addr[0x63864A8] and "638640c" in by_addr[0x63864A8])
    check("NULL single-entry unlock at 0x63864ad",
          "call" in by_addr[0x63864AD] and "63f0b70" in by_addr[0x63864AD])

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

    check("entry reaches lock-wait site 0x6386474", reaches(START, 0x6386474))
    check("entry reaches ret 0x6386465", reaches(START, 0x6386465))
    check("entry reaches trylock 0x6386147", reaches(START, 0x6386147))
    check("entry reaches epilogue canary 0x6386448", reaches(START, 0x6386448))
    check("entry reaches all-entries 0x6386190", reaches(START, 0x6386190))
    check("entry reaches single-entry 0x6386418", reaches(START, 0x6386418))
    check("entry reaches D-loop 0x638634c", reaches(START, 0x638634C))
    check("entry reaches copy loop 0x63861ee", reaches(START, 0x63861EE))
    check("entry reaches VLA probe 0x63861bb", reaches(START, 0x63861BB))
    check("entry reaches count==0 path 0x6386499", reaches(START, 0x6386499))
    check("entry reaches remainder dispatch 0x6386253", reaches(START, 0x6386253))
    check("preds of lock-wait site 0x6386474 is the setup lea only",
          preds[0x6386474] == {0x6386470}, str(preds[0x6386474]))
    check("preds of lock-wait setup 0x6386470 are trylock fail and the "
          "ret-padding nopw",
          preds[0x6386470] == {0x638614E, 0x6386466}, str(preds[0x6386470]))
    check("preds of trylock 0x6386147 is the canary save only",
          preds[0x6386147] == {0x6386145}, str(preds[0x6386147]))
    check("preds of rejoin 0x6386154 are trylock success and the "
          "lock-wait retry",
          preds[0x6386154] == {0x638614E, 0x6386480}, str(preds[0x6386154]))
    check("preds of ret 0x6386465 is the final pop",
          preds[0x6386465] == {0x6386464}, str(preds[0x6386465]))
    check("preds of D head 0x638634c are dispatch, remainder exit, "
          "loop-back",
          preds[0x638634C] == {0x6386262, 0x6386346, 0x6386406},
          str(preds[0x638634C]))
    check("preds of epilogue 0x638640c are remainder done, D-loop done, "
          "count==0 path",
          preds[0x638640C] == {0x6386346, 0x6386406, 0x63864A8},
          str(preds[0x638640C]))
    check("preds of canary 0x6386448 are epilogue jmp, single-entry "
          "fall-through, NULL single-entry jmp",
          preds[0x6386448] == {0x6386410, 0x6386443, 0x63864B2},
          str(preds[0x6386448]))
    check("preds of single-entry 0x6386418 are selector jne and the "
          "padding nopw",
          preds[0x6386418] == {0x638618A, 0x6386412}, str(preds[0x6386418]))
    check("preds of all-entries 0x6386190 are sentinel je and selector "
          "fall-through",
          preds[0x6386190] == {0x6386185, 0x638618A}, str(preds[0x6386190]))
    check("preds of copy loop 0x63861ee are count!=0 fall-through and the "
          "probe-path jne",
          preds[0x63861EE] == {0x63861E8, 0x6386493}, str(preds[0x63861EE]))

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
    SITE = 0x6386474
    RET = 0x6386465
    CALL_TRYLOCK = {("CALL", 0x6386147)}
    check("site rdi only def is lea -0x40(%r13),%rdi 0x6386470",
          rdi_in[SITE] == {0x6386470}, str(rdi_in[SITE]))
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
          rbx_in[SITE] == {0x638612E}, str(rbx_in[SITE]))
    check("site rbp def is the entry push",
          rbp_in[SITE] == {0x6386111}, str(rbp_in[SITE]))
    check("site r12 def is the byte-flag movzbl",
          r12_in[SITE] == {0x6386129}, str(r12_in[SITE]))
    check("site r13 def is the mutex lea",
          r13_in[SITE] == {0x6386120}, str(r13_in[SITE]))
    check("site r14 def is the entry index save",
          r14_in[SITE] == {0x638611B}, str(r14_in[SITE]))
    check("site r15 def is the entry byte-flag save",
          r15_in[SITE] == {0x6386116}, str(r15_in[SITE]))
    check("rax at ret is the canary residue def 0x638644c",
          rax_in[RET] == {0x638644C}, str(rax_in[RET]))

    check("records lock-wait sites match census",
          [s.get("site") for s in rec.get("lock_wait_sites", [])] ==
          ["0x6386474"])
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
    check("records window bytes 937",
          rec.get("window", {}).get("bytes") == 937)
    check("records window range",
          rec.get("window", {}).get("range") == "0x6386110..0x63864b9")
    check("records return value is 0 (canary residue, void return)",
          rec.get("return_value", {}).get("rax") ==
          "0 (canary residue, void return)")
    check("records selector count struct 0x6712130",
          "0x6712130" in rec.get("selector", {}).get("count", ""))
    check("records selector single-entry path 0x6386418",
          "0x6386418" in rec.get("selector", {}).get("single_entry", ""))
    check("records vla copy mentions the runtime table 0x65096c0",
          "0x65096c0" in rec.get("vla", {}).get("copy", ""))
    check("records callee FDE 0x6360ed0..0x636116d",
          rec.get("callee", {}).get("fde") == "0x6360ed0..0x636116d")
    check("records callee strict 150",
          rec.get("callee", {}).get("strict") == 150)
    check("records callee lock-wait site 0x6361158",
          rec.get("callee", {}).get("lock_wait_site") == "0x6361158")
    check("records duffs dispatch mentions & 7",
          "& 7" in rec.get("duffs", {}).get("dispatch", ""))
    check("records duffs loop is 8 elements per iteration",
          "8 elements per iteration" in rec.get("duffs", {}).get("loop", ""))

    # Sections (own ELF parse): .bss exact end; referenced addresses.
    secmap = sections(node)
    bss = secmap[".bss"]
    check("bss section 0x64ffe40..0x6728924",
          bss[3] == 0x64FFE40 and bss[3] + bss[5] == 0x6728924, str(bss))
    for _a in (0x65096C0, 0x6712130, 0x6712188, 0x6712190, 0x6712198,
               0x67121A0, 0x67121C8):
        check("address %s inside .bss" % hex(_a),
              bss[3] <= _a < bss[3] + bss[5])
    txt = secmap[".text"]
    check("window inside .text",
          txt[3] <= START and END <= txt[3] + txt[5])
    check("call target 0x6360ed0 inside .text (internal, not PLT)",
          txt[3] <= 0x6360ED0 < txt[3] + txt[5])

    # rela counts by direct ELF parse
    dyn_total = plt_total = rel_count = 0
    ref_relocs = 0
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
                if off in (0x65096C0, 0x6712130, 0x6712188, 0x6712190,
                           0x6712198, 0x67121A0, 0x67121C8):
                    ref_relocs += 1
                if 0x65096C0 <= off < 0x6509EC0:
                    runtime_table_relocs += 1
        if nm == ".rela.plt":
            plt_total = s[5] // 24
    check("rela.dyn total 60723", dyn_total == 60723, str(dyn_total))
    check("rela.dyn RELATIVE 59534", rel_count == 59534, str(rel_count))
    check("rela.plt 278", plt_total == 278, str(plt_total))
    check("no rela lands at any referenced .bss address",
          ref_relocs == 0, str(ref_relocs))
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
    check("next candidate raw lu-miss 0", counts.get(0x63CE510, 0) == 0,
          str(counts.get(0x63CE510, 0)))
    check("next candidate raw bti 0", bti_counts.get(0x63CE510, 0) == 0,
          str(bti_counts.get(0x63CE510, 0)))
    check("next candidate raw second-handler 0",
          sh_counts.get(0x63CE510, 0) == 0, str(sh_counts.get(0x63CE510, 0)))
    check("next candidate raw lock-wait 1",
          lw_counts.get(0x63CE510, 0) == 1,
          str(lw_counts.get(0x63CE510, 0)))

    # lock-wait frontier survey consistency (records.json)
    survey = rec.get("survey", {})
    check("survey survivors 344", len(survey.get("survivors", [])) == 344,
          str(len(survey.get("survivors", []))))
    check("survey this window is a lock-wait survivor",
          "0x6386110" in survey.get("survivors", []))
    check("survey this window is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x6386110") == 1,
          str(survey.get("sites_per_fde", {}).get("0x6386110")))
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
          "0x6386110" not in survey.get("lu_miss_survivors", []))
    check("survey this window is NOT a second-handler survivor",
          "0x6386110" not in survey.get("second_handler_survivors", []))
    check("survey next candidate is a 1-site survivor",
          survey.get("sites_per_fde", {}).get("0x63ce510") == 1,
          str(survey.get("sites_per_fde", {}).get("0x63ce510")))
    nq = rec.get("next_question", {})
    check("next question is the lock-wait frontier",
          nq.get("frontier") == "lock-wait helper 0x63bf680 callers",
          str(nq.get("frontier")))
    check("next question range 0x63ce510..0x63ce8b8",
          nq.get("range") == "0x63ce510..0x63ce8b8", str(nq.get("range")))
    check("next question bytes 936", nq.get("bytes") == 936,
          str(nq.get("bytes")))
    check("next question lu-miss sites 0",
          nq.get("lu_miss_sites") == 0, str(nq.get("lu_miss_sites")))
    check("next question bti sites 0",
          nq.get("bin_table_init_sites") == 0,
          str(nq.get("bin_table_init_sites")))
    check("next question strict 216", nq.get("strict") == 216,
          str(nq.get("strict")))
    check("next question calls 19", nq.get("calls") == 19,
          str(nq.get("calls")))
    check("next question indirect calls 1",
          nq.get("indirect_calls") == 1, str(nq.get("indirect_calls")))
    check("next question indirect sites",
          nq.get("indirect_sites") == ["0x63ce5be"],
          str(nq.get("indirect_sites")))
    check("next question calls by target",
          nq.get("calls_by_target") ==
          {"0x63bf5b6": 3, "0x63bf680": 1, "0x63c4c70": 1, "0x63c6bf0": 1,
           "0x63c7080": 1, "0x63c78f0": 1, "0x63c7fe0": 1, "0x63c8490": 1,
           "0x63c9650": 1, "0x63efe40": 2, "0x63f0b00": 1, "0x63f0b70": 1,
           "0x63f0c70": 1, "0x63f0d70": 1, "0x63f17b0": 1},
          str(nq.get("calls_by_target")))
    check("next question lock-wait sites 1",
          nq.get("lock_wait_sites") == 1, str(nq.get("lock_wait_sites")))
    check("next question lock-wait site list",
          nq.get("lock_wait_site") == ["0x63ce6a4"],
          str(nq.get("lock_wait_site")))
    check("next question second-handler sites 0",
          nq.get("second_handler_sites") == 0,
          str(nq.get("second_handler_sites")))
    check("next question bsr 0", nq.get("bsr") == 0,
          str(nq.get("bsr")))
    check("next question rets 1",
          nq.get("ret") == ["0x63ce69e"], str(nq.get("ret")))
    check("next question jumps 21", nq.get("jumps") == 21,
          str(nq.get("jumps")))
    check("next question jumps outside 0", nq.get("jumps_outside_window") == 0,
          str(nq.get("jumps_outside_window")))
    check("next question endbr64 1", nq.get("endbr64") == 1,
          str(nq.get("endbr64")))
    check("next question canary present", nq.get("canary") is True,
          str(nq.get("canary")))
    check("next question plt calls 5", nq.get("plt_calls") == 5,
          str(nq.get("plt_calls")))
    check("records census strict 258",
          rec.get("census", {}).get("strict") == 258)
    check("records census calls 23",
          rec.get("census", {}).get("calls") == 23)
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
    # next candidate 0x63ce510..0x63ce8b8 must itself be disjoint from priors
    nxt_bad = [p for p in priors
               if 0x63CE510 < p[1] and p[0] < 0x63CE8B8]
    check("next candidate 0x63ce510 disjoint from priors",
          nxt_bad == [], str(nxt_bad[:3]))
    # next candidate must also be disjoint from this window
    check("next candidate disjoint from this window",
          not (START < 0x63CE8B8 and 0x63CE510 < END))

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
    check("slug not colliding with #314-#334 lu-miss/lockwait slugs",
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
                       "RE-001-node115-lockwait-caller-1site-duffs"))

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
                    "lockwait_caller_1site_tablecopy.hex",
                    "lockwait_caller_1site_tablecopy.objdump.txt"}
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
