#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-dispatch-construct.

Byte reads only; never executes the node binary. Checks:
  1. binary size + SHA-256
  2. ten exhibit byte slices + strict mnemonic counts
  3. resolver entry (strchr), append store, numeric branch
     (strtol, ud2 trap target, indirect resolver call)
  4. sibling gate (leaf +0x20 check, resolver call, NULL out_slot)
  5. FDE 6 stats.mutexes setup + loop (FDE 1 call, table end)
  6. wrapper resolve-from-root (root lea, tail jmp to resolver)
  7. mutex table + mutexes children cross-check via .rela.dyn
  8. censuses: E8/E9 scans for dispatcher, sibling, resolver,
     sweep, wrapper; lea/movabs address-taken scans
  9. disjointness vs the merged tree (excluding self and
     census/cited-only metadata subtrees)
 10. MANIFEST.sha256 entries, when the manifest exists
 11. invoke / walk-invoke / gated-helper censuses + root children
     names via .rela.dyn
Exit 0 only when every check passes.
"""

import glob
import hashlib
import json
import os
import re
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(
    ROOT, "research", "work-items", "RE-001-node115-lu-dispatch-construct")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
EXPECT_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECT_SIZE = 105896032

EXHIBITS = [
    ("resolver_entry", 0x636E340, 0x636E380, 19),
    ("resolver_append", 0x636E5B9, 0x636E62F, 27),
    ("resolver_numeric_return", 0x636E62F, 0x636E6D6, 45),
    ("sibling_gate", 0x63A8F10, 0x63A8F4F, 20),
    ("fde6_sibl_setup", 0x63E83A5, 0x63E83D3, 9),
    ("fde6_loop", 0x63E83E4, 0x63E844E, 26),
    ("wrapper_resolve_root", 0x63A8990, 0x63A89F0, 34),
    ("helper_gate_invoke", 0x635DEE0, 0x635DF87, 49),
    ("walk_invoke_gate", 0x63A8C00, 0x63A8C48, 21),
    ("helper_resolve_root", 0x635DF90, 0x635E01F, 39),
]

ROOT_CHILDREN = [
    "version", "epoch", "background_thread", "max_background_threads",
    "thread", "config", "opt", "tcache", "arena", "arenas", "prof",
    "stats", "experimental",
]
MY_RANGES = [(s, e) for (_, s, e, _) in EXHIBITS]

EXPECT_DISP_E8 = {
    0x63DC1CB, 0x63DC299, 0x63DC360, 0x63DC428, 0x63DC4F7, 0x63DC5BE,
    0x63DC639, 0x63DDD82, 0x63DDE07, 0x63DDE84, 0x63DDF26, 0x63DDFAC,
    0x63DE043, 0x63DE0C2, 0x63E02B9, 0x63E036D, 0x63E03EA, 0x63E04B9,
    0x63E0539, 0x63E05C0, 0x63E063E, 0x63E06BC, 0x63E073B, 0x63E07BA,
    0x63E0837, 0x63E08B4, 0x63E0933, 0x63E09B2, 0x63E0A30, 0x63E0AAE,
    0x63E0B9A, 0x63E0C63, 0x63E0D25, 0x63E0DEE, 0x63E0EAE, 0x63E0F6F,
    0x63E0FF9, 0x63E31AF, 0x63E323D, 0x63E32C6, 0x63E334F, 0x63E350B,
    0x63E62E8, 0x63E6378, 0x63E6400, 0x63E6482, 0x63E650A, 0x63E658C,
    0x63E796C, 0x63E79E1, 0x63E7A5F, 0x63E7AD3, 0x63E7B5B, 0x63E7BCD,
}
EXPECT_SIBL_E8 = {
    0x63DC146, 0x63DDBAE, 0x63DDC13, 0x63DDC63, 0x63DDCBC, 0x63E00EE,
    0x63E0151, 0x63E019F, 0x63E01F8, 0x63E0B1C, 0x63E3116, 0x63E3481,
    0x63E5B71, 0x63E5BD9, 0x63E61F4, 0x63E6255, 0x63E7862, 0x63E78BA,
    0x63E83C3,
}
EXPECT_RESOLV_E8 = {0x63A891C, 0x63A8F37, 0x63A9287}
EXPECT_RESOLV_E9 = {0x63A89DB}

MUTEX_TABLE = [
    "background_thread", "max_per_bg_thd", "ctl", "prof",
    "prof_thds_data", "prof_dump", "prof_recent_alloc",
    "prof_recent_dump", "prof_stats",
]

FAILURES = []


def check(name, ok, detail=""):
    print(("%s %s %s" % ("PASS" if ok else "FAIL", name, detail)).strip())
    if not ok:
        FAILURES.append(name)


def read_binary():
    with open(BINARY, "rb") as f:
        return f.read()


def parse_rela(data):
    off0, size = 0x6BE8, 0x163CC8
    rela = {}
    for i in range(size // 24):
        o, _info, add = struct.unpack(
            "<QQq", data[off0 + i * 24: off0 + i * 24 + 24])
        rela[o] = add
    return rela


def strict_count(objdump_path):
    pat = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")
    n = 0
    with open(objdump_path) as f:
        for line in f:
            if pat.match(line):
                n += 1
    return n


def rel32_target(data, call_va):
    off = call_va - 0x1000
    rel = struct.unpack("<i", data[off + 1: off + 5])[0]
    return call_va + 5 + rel


def lea_target(data, lea_va):
    off = lea_va - 0x1000
    rel = struct.unpack("<i", data[off + 3: off + 7])[0]
    return lea_va + 7 + rel


def read_cstr(data, va):
    end = data.find(b"\x00", va)
    return data[va:end].decode()


def collect_claimed(root):
    """Recursive range+fde collector over records.json files.

    Excludes census and cited-only metadata subtrees; deduplicates
    by real path; excludes this packet's own directory.
    """

    def walk(obj, out, skip):
        if isinstance(obj, dict):
            for k, v in obj.items():
                sk = skip or k in ("census", "cited_only_not_claimed")
                if (k in ("range", "fde") and isinstance(v, list)
                        and len(v) == 2
                        and all(isinstance(x, str)
                                and x.startswith("0x") for x in v)):
                    if not sk:
                        out.append((int(v[0], 16), int(v[1], 16)))
                else:
                    walk(v, out, sk)
        elif isinstance(obj, list):
            for v in obj:
                walk(v, out, skip)

    files = set()
    for f in glob.glob(os.path.join(
            root, "research", "work-items", "**", "records.json"),
            recursive=True):
        if os.path.realpath(f).startswith(os.path.realpath(PACKET)):
            continue
        files.add(os.path.realpath(f))
    claimed = set()
    for f in files:
        try:
            with open(f) as fh:
                doc = json.load(fh)
        except Exception:
            continue
        ranges = []
        walk(doc, ranges, False)
        claimed.update(ranges)
    return claimed


def main():
    data = read_binary()
    check("binary size", len(data) == EXPECT_SIZE, str(len(data)))
    check("binary sha256",
          hashlib.sha256(data).hexdigest() == EXPECT_SHA)

    # Exhibit bytes + strict counts.
    for name, s, e, expect_n in EXHIBITS:
        with open(os.path.join(PACKET, name + ".hex"), "rb") as f:
            raw = f.read()
        check(name + ".hex bytes",
              raw == data[s - 0x1000: e - 0x1000], "%d bytes" % (e - s))
        check(name + " strict count",
              strict_count(os.path.join(PACKET, name + ".objdump.txt"))
              == expect_n, str(expect_n))

    # Resolver entry: pushes + strchr call.
    ent = data[0x636E340 - 0x1000: 0x636E380 - 0x1000]
    check("resolver entry pushes", ent[:4] == bytes([0x41, 0x57, 0x41, 0x56]))
    check("resolver strchr target",
          rel32_target(data, 0x636E36F) == 0x63F1AA0)
    with open(os.path.join(PACKET, "resolver_append.objdump.txt")) as f:
        app = f.read()
    check("resolver append store",
          "mov    %rbx,0x0(%rbp,%r15,8)" in app)
    with open(os.path.join(
            PACKET, "resolver_numeric_return.objdump.txt")) as f:
        num = f.read()
    check("resolver strtol target",
          rel32_target(data, 0x636E63F) == 0x63BE700)
    check("resolver trap target",
          "jne    636e32e" in num)
    check("resolver indirect call", "call   *0x8(%rbp)" in num)

    # Sibling gate.
    with open(os.path.join(PACKET, "sibling_gate.objdump.txt")) as f:
        gate = f.read()
    check("sibling leaf gate", "cmpq   $0x0,0x20(%rsi)" in gate)
    check("sibling resolver target",
          rel32_target(data, 0x63A8F37) == 0x636E340)
    check("sibling NULL out_slot", "xor    %ecx,%ecx" in gate)

    # FDE 6 setup + loop.
    check("fde6 stats.mutexes string",
          read_cstr(data, lea_target(data, 0x63E83B5)) == "stats.mutexes")
    check("fde6 sibl target",
          rel32_target(data, 0x63E83C3) == 0x63A8D00)
    check("fde6 fde1 target",
          rel32_target(data, 0x63E8412) == 0x63DC0BB)
    check("fde6 loop end",
          lea_target(data, 0x63E8441) == 0x64FFDC8)

    # Wrapper resolve-from-root.
    wrap = data[0x63A8990 - 0x1000: 0x63A89F0 - 0x1000]
    check("wrapper entry endbr64", wrap[:4] == bytes.fromhex("f30f1efa"))
    check("wrapper root lea",
          lea_target(data, 0x63A89CE) == 0x64DA4C0)
    off = 0x63A89DB - 0x1000
    rel = struct.unpack("<i", data[off + 1: off + 5])[0]
    check("wrapper tail jmp to resolver",
          0x63A89DB + 5 + rel == 0x636E340)

    # Mutex table + mutexes children via .rela.dyn.
    rela = parse_rela(data)
    got_table = [read_cstr(data, rela[0x64FFD80 + i * 8])
                 for i in range(9)]
    check("mutex table names", got_table == MUTEX_TABLE,
          ",".join(got_table))
    ok_children = True
    for i in range(10):
        base = 0x64DAC60 + i * 40
        flag = data[base - 0x2000]
        count = struct.unpack(
            "<Q", data[base - 0x2000 + 0x10: base - 0x2000 + 0x18])[0]
        hnd = rela.get(base + 0x20, 0)
        if flag != 1:
            ok_children = False
        if i < 9 and (count != 7 or hnd != 0):
            ok_children = False
        if i == 9 and (count != 0 or hnd != 0x63A5BF0):
            ok_children = False
        if i < 9 and read_cstr(data, rela[base + 0x08]) != MUTEX_TABLE[i]:
            ok_children = False
        if i == 9 and read_cstr(data, rela[base + 0x08]) != "reset":
            ok_children = False
    check("mutexes children cross-check", ok_children)
    check("sweep rela.dyn slots",
          [o for o, a in rela.items() if a == 0x63A5BF0] == [0x64DADE8])

    # Censuses: one E8/E9 pass + one address-taken pass.
    base_va, base_off = 0x1419300, 0x1418300
    text = data[base_off: base_off + 0x4FD7700]
    e8 = {0x63A8FF0: set(), 0x63A8D00: set(), 0x636E340: set(),
          0x63A5BF0: set(), 0x63A8990: set(), 0x63A88A0: set(),
          0x63A89F0: set(), 0x635DEE0: set(), 0x635E020: set(),
          0x635DF90: set()}
    e9 = {0x63A8FF0: set(), 0x63A8D00: set(), 0x636E340: set(),
          0x63A5BF0: set(), 0x63A8990: set(), 0x63A88A0: set(),
          0x63A89F0: set(), 0x635DEE0: set(), 0x635E020: set(),
          0x635DF90: set()}
    for i in range(len(text) - 5):
        op = text[i]
        if op not in (0xE8, 0xE9):
            continue
        rel = struct.unpack("<i", text[i + 1: i + 5])[0]
        tgt = base_va + i + 5 + rel
        if tgt in e8:
            (e8 if op == 0xE8 else e9)[tgt].add(base_va + i)
    check("dispatcher E8 census", e8[0x63A8FF0] == EXPECT_DISP_E8,
          "%d sites" % len(e8[0x63A8FF0]))
    check("dispatcher E9 census", len(e9[0x63A8FF0]) == 0)
    check("sibling E8 census", e8[0x63A8D00] == EXPECT_SIBL_E8,
          "%d sites" % len(e8[0x63A8D00]))
    check("sibling E9 census", len(e9[0x63A8D00]) == 0)
    check("resolver E8 census", e8[0x636E340] == EXPECT_RESOLV_E8,
          "%d sites" % len(e8[0x636E340]))
    check("resolver E9 census", e9[0x636E340] == EXPECT_RESOLV_E9,
          "%d sites" % len(e9[0x636E340]))
    check("sweep E8 census", len(e8[0x63A5BF0]) == 0)
    check("sweep E9 census", len(e9[0x63A5BF0]) == 0)
    check("wrapper E8 census", len(e8[0x63A8990]) == 0)
    check("wrapper E9 census", e9[0x63A8990] == {0x635DFD3},
          "%d sites" % len(e9[0x63A8990]))
    check("invoke E8 census", len(e8[0x63A88A0]) == 0)
    check("invoke E9 census", e9[0x63A88A0] == {0x635DF37},
          "%d sites" % len(e9[0x63A88A0]))
    check("walk-invoke E8 census", e8[0x63A89F0] == {0x635E07D},
          "%d sites" % len(e8[0x63A89F0]))
    check("walk-invoke E9 census", len(e9[0x63A89F0]) == 0)
    check("helper-gate E8 census", len(e8[0x635DEE0]) == 110,
          "%d sites" % len(e8[0x635DEE0]))
    check("helper-gate E9 census", len(e9[0x635DEE0]) == 0)
    check("helper-walk E8 census", len(e8[0x635E020]) == 56,
          "%d sites" % len(e8[0x635E020]))
    check("helper-walk E9 census", len(e9[0x635E020]) == 0)
    check("helper-resolve E8 census", len(e8[0x635DF90]) == 55,
          "%d sites" % len(e8[0x635DF90]))
    check("helper-resolve E9 census", len(e9[0x635DF90]) == 0)
    taken = {t: [] for t in e8}
    for m in re.finditer(rb"\x48\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]",
                         text):
        o = m.start()
        rel = struct.unpack("<i", text[o + 3: o + 7])[0]
        va = base_va + o
        if va + 7 + rel in taken:
            taken[va + 7 + rel].append(va)
    for m in re.finditer(rb"[\x48\x49][\xb8-\xbf]", text):
        o = m.start()
        imm = struct.unpack("<Q", text[o + 2: o + 10])[0]
        if imm in taken:
            taken[imm].append(base_va + o)
    check("address-taken census",
          all(len(v) == 0 for v in taken.values()),
          str({hex(k): len(v) for k, v in taken.items()}))
    check("dispatcher rela.dyn slots",
          [o for o, a in rela.items() if a == 0x63A8FF0] == [])
    check("sibling rela.dyn slots",
          [o for o, a in rela.items() if a == 0x63A8D00] == [])
    check("resolver rela.dyn slots",
          [o for o, a in rela.items() if a == 0x636E340] == [])
    check("wrapper rela.dyn slots",
          [o for o, a in rela.items() if a == 0x63A8990] == [])
    check("invoke rela.dyn slots",
          [o for o, a in rela.items() if a == 0x63A88A0] == [])
    check("walk-invoke rela.dyn slots",
          [o for o, a in rela.items() if a == 0x63A89F0] == [])
    check("helper-gate rela.dyn slots",
          [o for o, a in rela.items() if a == 0x635DEE0] == [])
    check("helper-walk rela.dyn slots",
          [o for o, a in rela.items() if a == 0x635E020] == [])
    check("helper-resolve rela.dyn slots",
          [o for o, a in rela.items() if a == 0x635DF90] == [])

    # Helper-resolve exhibit: tail-jump to wrapper; wrapper takes its
    # name from its rsi (mov %rbp,%rdx in the tail-jump block).
    off = 0x635DFD3 - 0x1000
    rel = struct.unpack("<i", data[off + 1: off + 5])[0]
    check("helper-resolve tail jmp to wrapper",
          0x635DFD3 + 5 + rel == 0x63A8990)
    with open(os.path.join(PACKET, "wrapper_resolve_root.objdump.txt")) as f:
        wro = f.read()
    check("wrapper name from rsi",
          "mov    %rbp,%rdx" in wro)

    # Helper-gate exhibit: tail-jump to invoke; walk-invoke gate:
    # handler load from +0x20 plus indirect tail-call.
    off = 0x635DF37 - 0x1000
    rel = struct.unpack("<i", data[off + 1: off + 5])[0]
    check("helper-gate tail jmp to invoke",
          0x635DF37 + 5 + rel == 0x63A88A0)
    with open(os.path.join(PACKET, "walk_invoke_gate.objdump.txt")) as f:
        wig = f.read()
    check("walk-invoke handler gate",
          "mov    0x20(%rax),%rax" in wig)
    check("walk-invoke tail-call",
          "jmp    *%rax" in wig)

    # Root children names via .rela.dyn.
    got_root = [read_cstr(data, rela[0x64DA500 + i * 40 + 0x08])
                for i in range(13)]
    check("root children names", got_root == ROOT_CHILDREN,
          ",".join(got_root))

    # Disjointness vs merged tree.
    claimed = collect_claimed(ROOT)
    overlaps = [(a, b) for (a, b) in claimed
                if any(x < b and a < y for x, y in MY_RANGES)]
    check("disjointness vs merged tree", len(overlaps) == 0,
          "%d unique claimed ranges, %d overlaps"
          % (len(claimed), len(overlaps)))

    # MANIFEST, when present.
    man = os.path.join(PACKET, "MANIFEST.sha256")
    if os.path.exists(man):
        ok = True
        with open(man) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                digest, rel = line.split(None, 1)
                path = os.path.normpath(os.path.join(PACKET, rel))
                with open(path, "rb") as fh:
                    got = hashlib.sha256(fh.read()).hexdigest()
                if got != digest:
                    ok = False
        check("MANIFEST entries", ok)

    if FAILURES:
        print("FAILURES: %d" % len(FAILURES))
        sys.exit(1)
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
