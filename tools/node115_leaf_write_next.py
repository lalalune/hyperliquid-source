#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-leaf-write-next (packet #259).

Byte reads only; the node binary is never executed. Checks: binary
identity, exhibit bytes + strict mnemonic counts, objdump regeneration
(header line stripped), rel32 call/jump targets, .rodata option strings,
.rela.dyn leaf-handler slots, single-pass E8/E9 direct-entry census,
disjointness against all prior packets, and MANIFEST hashes.
"""
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if "--root" in sys.argv:
    ROOT = sys.argv[sys.argv.index("--root") + 1]
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-001-node115-lu-leaf-write-next")
OWN_SLUG = "RE-001-node115-lu-leaf-write-next"
BASE_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BASE_SIZE = 105896032
TEXT_OFF, TEXT_SIZE = 0x1418300, 0x4FD7700  # .text file range

ok = True
npass = 0


def check(name, cond, detail=""):
    global ok, npass
    if cond:
        npass += 1
        print(f"PASS {name}")
    else:
        ok = False
        print(f"FAIL {name} {detail}")


def toff(va):
    return va - 0x1000


def rel32_target(data, site):
    off = toff(site)
    rel = struct.unpack("<i", data[off + 1: off + 5])[0]
    return site + 5 + rel


def strict_count(path):
    pat = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")
    n = 0
    with open(path) as f:
        for line in f:
            if pat.match(line):
                n += 1
    return n


def main():
    global ok
    with open(BIN, "rb") as f:
        data = f.read()
    check("binary size", len(data) == BASE_SIZE, f"got {len(data)}")
    check("binary sha256",
          hashlib.sha256(data).hexdigest() == BASE_SHA)
    with open(os.path.join(PACKET, "records.json")) as f:
        rec = json.load(f)
    check("records packet slug", rec["packet"] == OWN_SLUG)

    # Exhibit bytes + strict counts + objdump regeneration.
    for e in rec["exhibits"]:
        name = e["name"]
        s, en = int(e["range"][0], 16), int(e["range"][1], 16)
        with open(os.path.join(PACKET, name + ".hex"), "rb") as f:
            raw = f.read()
        check(f"{name} bytes", raw == data[toff(s):toff(en)] and
              len(raw) == e["bytes"] == en - s,
              f"len {len(raw)} want {en - s}")
        check(f"{name} strict count",
              strict_count(os.path.join(PACKET, name + ".objdump.txt"))
              == e["strict"])
        out = subprocess.run(
            ["objdump", "-d", f"--start-address={hex(s)}",
             f"--stop-address={hex(en)}", BIN],
            capture_output=True, text=True).stdout
        with open(os.path.join(PACKET, name + ".objdump.txt")) as f:
            saved = f.read()
        # Drop the first line (embeds the invoked binary path).
        check(f"{name} objdump regeneration",
              out.split("\n", 1)[1] == saved.split("\n", 1)[1])

    # rel32 call/jump target spot checks.
    spots = [
        (0x63A5757, 0x63A5550), (0x63A57C5, 0x63BF680),
        (0x636DFA9, 0x63C3C90), (0x636E02F, 0x63C3D50),
        (0x636D3D6, 0x63C40F0), (0x636D420, 0x63C40E0),
        (0x636D192, 0x63C4110), (0x636D1F4, 0x63C4100),
        (0x636DA4E, 0x63C3B90), (0x636DA93, 0x63C3C10),
        (0x636D94C, 0x63C4060), (0x636D974, 0x63C3FE0),
        (0x636E29C, 0x63ED090), (0x636E2F8, 0x63ED070),
        (0x636E2A9, 0x63EF5E0), (0x63EF7C5, 0x63BF680),
        (0x63EF7B1, 0x63EEC10), (0x63ED881, 0x63EF5E0),
        (0x63ED89B, 0x63ED090), (0x634BFF8, 0x63F1500),
        (0x634C028, 0x63F1500), (0x634D07F, 0x63F1500),
        (0x634C305, 0x63F1500), (0x634D0CB, 0x63F1500),
        (0x634E5BF, 0x63F1500),
    ]
    for site, want in spots:
        got = rel32_target(data, site)
        check(f"call target {hex(site)}", got == want,
              f"got {hex(got)} want {hex(want)}")

    # .rodata option strings (VA as-is).
    def cstr(va):
        end = data.index(b"\x00", va)
        return data[va:end].decode()
    check("rodata prof", cstr(0x4343E3) == "prof", cstr(0x4343E3))
    check("rodata true", cstr(0x43F883) == "true", cstr(0x43F883))
    check("rodata false", cstr(0x430E89) == "false", cstr(0x430E89))
    check("rodata prof_leak_error", cstr(0x44C4AA) == "prof_leak_error",
          cstr(0x44C4AA))
    check("rodata log format",
          cstr(0x967C70).startswith("<jemalloc>: -- Set conf value: "))

    # .rela.dyn leaf-handler slots.
    rela = subprocess.run(["readelf", "-r", BIN],
                          capture_output=True, text=True).stdout
    rela_map = {}
    for line in rela.splitlines():
        m = re.match(r"^\s*([0-9a-f]+)\s+[0-9a-f]+\s+R_X86_64_RELATIVE\s+"
                     r"([0-9a-f]+)", line)
        if m:
            rela_map[int(m.group(1), 16)] = int(m.group(2), 16)
    for leaf, info in rec["census"]["leaf_nodes"].items():
        slot = int(info["rela_slot"], 16)
        want = int(info["handler"], 16)
        check(f"rela slot {leaf}", rela_map.get(slot) == want,
              f"got {rela_map.get(slot)} want {hex(want)}")

    # Single-pass E8/E9 census over .text.
    targets = {}
    for leaf, info in rec["census"]["leaf_nodes"].items():
        targets[leaf] = int(info["handler"], 16)
    targets["tls_helper"] = 0x63EF640
    targets["fn_eec10"] = 0x63EEC10
    targets["fn_ed870"] = 0x63ED870
    inv = {v: k for k, v in targets.items()}
    found = {k: {"E8": [], "E9": []} for k in targets}
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    for off in range(len(text) - 5):
        byte = text[off]
        if byte in (0xE8, 0xE9):
            rel = struct.unpack_from("<i", text, off + 1)[0]
            tgt = TEXT_OFF + off + 0x1000 + 5 + rel
            if tgt in inv:
                found[inv[tgt]]["E8" if byte == 0xE8 else "E9"].append(
                    TEXT_OFF + off + 0x1000)
    for leaf, entry in rec["census"]["leaf_handler_direct_entries"].items():
        got = found[leaf]
        check(f"{leaf} direct entries",
              got["E8"] == entry["E8"] and got["E9"] == entry["E9"],
              f"E8={got['E8']} E9={got['E9']}")
    for key, entry in [("tls_helper", rec["census"]["tls_helper_callers"]),
                       ("fn_eec10", rec["census"]["fn_eec10_callers"]),
                       ("fn_ed870", rec["census"]["fn_ed870_callers"])]:
        got = found[key]
        want_e8 = [int(x, 16) for x in entry["E8"]]
        want_e9 = [int(x, 16) for x in entry["E9"]]
        check(f"{key} census", got["E8"] == want_e8 and got["E9"] == want_e9,
              f"E8={got['E8']} E9={got['E9']}")

    # Disjointness: recursive range collector, census/cited subtrees
    # excluded, deduplicated by packet slug, own slug excluded.
    # Only "range" fields are claims (the exhibited byte windows).
    # "fde" fields are enclosing-function annotations, NOT claims:
    # packet #258's exhibits annotate the whole option-parser FDE
    # 0x6349be0..0x634eb7c while claiming only the small prof-byte
    # store windows inside it, so collecting "fde" would falsely
    # block this packet's disjoint parser windows.
    def collect(obj, skip):
        ranges = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in ("census", "cited_only_not_claimed"):
                    continue
                if k == "range" and isinstance(v, list) and len(v) == 2 \
                        and all(isinstance(x, str) and x.startswith("0x")
                                for x in v):
                    ranges.append((int(v[0], 16), int(v[1], 16)))
                else:
                    ranges.extend(collect(v, skip))
        elif isinstance(obj, list):
            for v in obj:
                ranges.extend(collect(v, skip))
        return ranges

    roots = [os.path.join(ROOT, "research", "work-items")]
    for wt in ("hl-wt-calls255-115", "hl-wt-calls256-115",
               "hl-wt-calls257-115", "hl-wt-calls258-115"):
        roots.append(os.path.join(os.path.expanduser("~"), "workspace",
                                  wt, "research", "work-items"))
    seen_slugs = set()
    others = []
    for root in roots:
        if not os.path.isdir(root):
            continue
        for slug in sorted(os.listdir(root)):
            if slug == OWN_SLUG or slug in seen_slugs:
                continue
            rp = os.path.join(root, slug, "records.json")
            if not os.path.isfile(rp):
                continue
            try:
                with open(rp) as f:
                    other = json.load(f)
            except (ValueError, OSError):
                continue
            seen_slugs.add(slug)
            others.extend(collect(other, None))
    mine = [(int(e["range"][0], 16), int(e["range"][1], 16))
            for e in rec["exhibits"]]
    overlap = []
    for s, e in mine:
        for os_, oe in others:
            if s < oe and os_ < e:
                overlap.append(((hex(s), hex(e)), (hex(os_), hex(oe))))
    check("disjointness vs prior packets", not overlap,
          f"overlaps: {overlap[:5]}")
    print(f"INFO prior claimed ranges scanned: {len(others)}")

    # MANIFEST: every entry hashes OK, and no unlisted packet file.
    man = {}
    with open(os.path.join(PACKET, "MANIFEST.sha256")) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            h, p = line.split(None, 1)
            man[p] = h
    for rel, want in man.items():
        full = os.path.normpath(os.path.join(PACKET, rel))
        with open(full, "rb") as f:
            got = hashlib.sha256(f.read()).hexdigest()
        check(f"MANIFEST {rel}", got == want)
    listed = set(man) | {"MANIFEST.sha256"}
    actual = set()
    for fn in os.listdir(PACKET):
        actual.add(fn)
    actual.add("../../../tools/node115_leaf_write_next.py")
    actual.add("../../../tests/test_node115_leaf_write_next.py")
    check("MANIFEST coverage", actual == listed,
          f"unlisted={actual - listed} missing={listed - actual}")

    print(f"{'ALL CHECKS PASSED' if ok else 'FAILURES PRESENT'} "
          f"({npass} PASS)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
