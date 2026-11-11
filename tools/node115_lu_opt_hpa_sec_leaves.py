"""Static verifier for RE-001-node115-lu-opt-hpa-sec-leaves.

Byte reads only; never executes the node binary. Usage:
  python3 tools/node115_lu_opt_hpa_sec_leaves.py [packet_dir] [binary]
Defaults: the packet dir under this repo and artifacts/node/115/hl-node.

Checks: binary identity, exhibit bytes, strict counts, objdump
regeneration (path-embedding header line stripped), .eh_frame FDE
bounds, .rela.dyn leaf slots and opt-children-array order, .data
file values, whole-.text E8 census (0 direct entries per leaf),
jump-target containment, single-ret counts, disjointness against
prior claimed ranges, and MANIFEST hashes.

For tests only, the env var HL265_PRIOR_ROOTS (colon-separated
directories) overrides the prior-record scan roots; without it the
verifier scans the merged tree plus packets #183-#264 worktrees.
"""

import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

FAILS = []
PASSES = [0]


def fail(msg):
    FAILS.append(msg)
    print("FAIL:", msg)


def check(cond, msg):
    if cond:
        PASSES[0] += 1
    else:
        fail(msg)


def section_map(data):
    e_shoff = struct.unpack("<Q", data[0x28:0x30])[0]
    e_shentsize = struct.unpack("<H", data[0x3A:0x3C])[0]
    e_shnum = struct.unpack("<H", data[0x3C:0x3E])[0]
    e_shstrndx = struct.unpack("<H", data[0x3E:0x40])[0]

    def sh(i):
        p = e_shoff + i * e_shentsize
        return struct.unpack("<IIQQQQIIQQ", data[p:p + 64])

    shstr_off = sh(e_shstrndx)[4]

    def sname(n):
        end = data.index(b"\0", shstr_off + n)
        return data[shstr_off + n:end].decode()

    out = {}
    for i in range(e_shnum):
        s = sh(i)
        out[sname(s[0])] = s
    return out


def va_to_off(data, va):
    e_phoff = struct.unpack("<Q", data[0x20:0x28])[0]
    n = struct.unpack("<H", data[0x38:0x3A])[0]
    sz = struct.unpack("<H", data[0x36:0x38])[0]
    for i in range(n):
        p = e_phoff + i * sz
        t, fl, off, v, pa, fsz, msz, al = struct.unpack(
            "<IIQQQQQQ", data[p:p + 56])
        if t == 1 and v <= va < v + fsz:
            return off + (va - v)
    return None


STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")
INSN_RE = re.compile(
    r"^\s*([0-9a-f]+):\t[0-9a-f ]+\t([a-z][a-z0-9.]*)")
JUMP_MNEMS = {
    "jmp", "je", "jne", "ja", "jae", "jb", "jbe", "jl", "jle", "jg",
    "jge", "jo", "jno", "js", "jns", "jp", "jnp", "jcxz", "jecxz",
    "jrcxz",
}


def strict_count(lines):
    return sum(1 for l in lines if STRICT_RE.match(l))


def strip_header(lines):
    """Drop the objdump file-format line (embeds the invoked path)."""
    return [l for l in lines if "file format" not in l]


def parse_eh_frame(data, secs):
    """Return {fde_start: fde_size} from .eh_frame (sdata4 pcrel)."""
    _, _, _, _, base, size, _, _, _, _ = secs[".eh_frame"]
    out = {}
    pos = 0
    while pos < size:
        length = struct.unpack_from("<I", data, base + pos)[0]
        if length == 0:
            break
        cie_id = struct.unpack_from("<I", data, base + pos + 4)[0]
        if cie_id != 0:
            p = base + pos + 8
            init = struct.unpack_from("<i", data, p)[0] + p
            rng = struct.unpack_from("<I", data, p + 4)[0]
            out[init] = rng
        pos += 4 + length
    return out


SKIP_KEYS = ("census", "cited", "survey", "callers",
             "largest_caller_fde", "fde")


def parse_range_value(v):
    """Parse a range value into (start, end) ints or None."""
    if isinstance(v, str) and ".." in v:
        a, b = v.split("..")
        return (int(a, 16), int(b, 16))
    if isinstance(v, list) and len(v) == 2:
        a, b = v
        if isinstance(a, int) and isinstance(b, int):
            return (a, b)
        if isinstance(a, str) and isinstance(b, str):
            return (int(a, 16), int(b, 16))
    return None


def collect_ranges(node, out):
    """Range-only collector: exhibited windows only, never fde/census
    metadata. Mirrors packet #253's recursive collector plus the
    #259 range-only rule and the #260/#261/#264 shape coverage."""
    if isinstance(node, dict):
        for key, val in node.items():
            if key in SKIP_KEYS:
                continue
            if key in ("exhibits", "windows"):
                items = val if isinstance(val, list) else (
                    val.values() if isinstance(val, dict) else [])
                for e in items:
                    if not isinstance(e, dict):
                        continue
                    r = None
                    if "range" in e:
                        r = parse_range_value(e["range"])
                    elif "start" in e and "end" in e:
                        s, en = e["start"], e["end"]
                        if isinstance(s, int) and isinstance(en, int):
                            r = (s, en)
                        elif isinstance(s, str) and isinstance(en, str):
                            r = (int(s, 16), int(en, 16))
                    if r is not None:
                        out.append(r)
            else:
                collect_ranges(val, out)
    elif isinstance(node, list):
        for val in node:
            collect_ranges(val, out)


def main():
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    packet_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        repo, "research", "work-items",
        "RE-001-node115-lu-opt-hpa-sec-leaves")
    binary = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        repo, "artifacts", "node", "115", "hl-node")
    data = open(binary, "rb").read()
    secs = section_map(data)
    records = json.load(open(os.path.join(packet_dir, "records.json")))

    # 1. Binary identity.
    check(len(data) == records["binary_size"], "binary size mismatch")
    check(hashlib.sha256(data).hexdigest() == records["binary_sha256"],
          "binary sha256 mismatch")
    check(records["base"] == "05bc2de303c05525b71e7e257426e741bc66a390",
          "base commit mismatch")

    # 2. Exhibit bytes, strict counts, objdump regeneration.
    fdes = parse_eh_frame(data, secs)
    for e in records["exhibits"]:
        name = e["name"]
        s, en = e["start"], e["end"]
        check(en - s == e["size"], "%s: start/end mismatch" % name)
        raw = open(os.path.join(packet_dir, e["hex"]), "rb").read()
        check(len(raw) == e["size"], "%s: hex size mismatch" % name)
        off = va_to_off(data, s)
        check(data[off:off + e["size"]] == raw,
              "%s: hex bytes differ from binary" % name)
        lines = open(os.path.join(packet_dir, e["objdump"])).read()
        lines = lines.splitlines()
        check(strict_count(lines) == e["strict_instructions"],
              "%s: strict count %d != %d" % (
                  name, strict_count(lines), e["strict_instructions"]))
        regen = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % s,
             "--stop-address=%#x" % en, binary],
            capture_output=True, text=True).stdout.splitlines()
        check(strip_header(regen) == strip_header(lines),
              "%s: objdump regeneration differs" % name)
        # FDE bounds from .eh_frame, not endbr64 scanning.
        check(fdes.get(s) == e["size"],
              "%s: eh_frame size %s != %d" % (
                  name, fdes.get(s), e["size"]))
        # Entry shape + contract markers.
        txt = "\n".join(lines)
        entry = [l for l in lines if INSN_RE.match(l) and
                 int(INSN_RE.match(l).group(1), 16) == s]
        check(len(entry) == 1 and "endbr64" in entry[0],
              "%s: no endbr64 at entry" % name)
        check("mov    $0x16" in txt, "%s: no 0x16 short-read return" % name)
        check("cmp    $0x8" in txt, "%s: no size-8 compare" % name)
        # Single ret, jump containment.
        mnems = [INSN_RE.match(l).group(2) for l in lines
                 if INSN_RE.match(l)]
        check(mnems.count("ret") == 1,
              "%s: ret count %d != 1" % (name, mnems.count("ret")))
        for l in lines:
            m = INSN_RE.match(l)
            if not m:
                continue
            addr = int(m.group(1), 16)
            mnem = m.group(2)
            if mnem in JUMP_MNEMS:
                toks = l.split("\t")[-1].strip().split()
                tgt = toks[1] if len(toks) > 1 else ""
                try:
                    t = int(tgt, 16)
                except ValueError:
                    fail("%s: unparsable jump target %r" % (name, tgt))
                    continue
                check(s <= t < en,
                      "%s: jump %#x outside FDE" % (name, t))

    # 3. Totals.
    check(sum(e["size"] for e in records["exhibits"]) ==
          records["total_claimed_bytes"], "total bytes mismatch")
    check(sum(e["strict_instructions"] for e in records["exhibits"]) ==
          records["total_strict_instructions"], "total strict mismatch")

    # 4. .rela.dyn leaf slots + opt children array order.
    _, _, _, _, roff, rsize, _, _, _, rentsize = secs[".rela.dyn"]
    rela = {}
    for p in range(roff, roff + rsize, rentsize):
        r_off, r_info, r_add = struct.unpack("<QQq", data[p:p + 24])
        if r_info & 0xFFFFFFFF == 8:
            rela[r_off] = r_add

    def cstr(va):
        off = va_to_off(data, va)
        end = data.index(b"\0", off)
        return data[off:end].decode()

    prev_slot = None
    for leaf in records["leaves"]:
        node = int(leaf["node"], 16)
        handler = int(leaf["handler"].split("..")[0], 16)
        check(rela.get(node + 0x20) == handler,
              "%s: node+0x20 addend != handler" % leaf["leaf"])
        nameva = rela.get(node + 0x08)
        check(nameva is not None and cstr(nameva) ==
              leaf["leaf"].split("/", 1)[1],
              "%s: node+0x08 name mismatch" % leaf["leaf"])
        slot = 0x64de2e0 + leaf["opt_children_group"] * 40 + 32
        check(rela.get(slot) == handler,
              "%s: opt children group slot != handler" % leaf["leaf"])
        if prev_slot is not None:
            check(slot > prev_slot, "opt children slots out of order")
        prev_slot = slot
        # .data file value.
        vaddr = int(leaf["value"].split()[-1], 16)
        _, _, _, daddr, doff, _, _, _, _, _ = secs[".data"]
        foff = doff + (vaddr - daddr)
        val = struct.unpack("<Q", data[foff:foff + 8])[0]
        check(val == int(leaf["file_value"], 16),
              "%s: .data file value %#x != %s" % (
                  leaf["leaf"], val, leaf["file_value"]))

    # 5. Whole-.text E8 census: 0 direct entries per leaf.
    _, _, _, taddr, toff, tsize, _, _, _, _ = secs[".text"]
    text = data[toff:toff + tsize]
    targets = set()
    for i in range(len(text) - 5):
        if text[i] == 0xE8:
            rel = struct.unpack("<i", text[i + 1:i + 5])[0]
            targets.add(taddr + i + 5 + rel)
    for leaf in records["leaves"]:
        handler = int(leaf["handler"].split("..")[0], 16)
        check(handler not in targets,
              "%s: direct E8 entry found" % leaf["leaf"])

    # 6. Disjointness against prior claimed ranges.
    override = os.environ.get("HL265_PRIOR_ROOTS")
    if override:
        roots = override.split(":")
        paths = []
        for r in roots:
            paths += glob.glob(os.path.join(
                r, "research", "work-items", "*", "records.json"))
    else:
        paths = glob.glob(os.path.join(
            repo, "research", "work-items", "*", "records.json"))
        paths += glob.glob(os.path.join(
            os.path.expanduser("~"), "workspace", "hl-wt-calls*",
            "research", "work-items", "*", "records.json"))
    priors = []
    seen_dirs = set()
    for p in paths:
        slug = os.path.basename(os.path.dirname(p))
        if slug == "RE-001-node115-lu-opt-hpa-sec-leaves":
            continue
        if slug in seen_dirs:
            continue
        seen_dirs.add(slug)
        try:
            collect_ranges(json.load(open(p)), priors)
        except Exception:
            pass
    print("prior claimed ranges collected: %d (from %d packet dirs)"
          % (len(priors), len(seen_dirs)))
    mine = [(e["start"], e["end"]) for e in records["exhibits"]]
    for m in mine:
        for pr in priors:
            check(not (m[0] < pr[1] and pr[0] < m[1]),
                  "overlap: %#x..%#x vs prior %#x..%#x" % (
                      m[0], m[1], pr[0], pr[1]))
    for a, b in [(0x63b8820, 0x63b8d85), (0x63ec890, 0x63ec8a3),
                 (0x63d9700, 0x63d987b)]:
        for m in mine:
            check(not (m[0] < b and a < m[1]),
                  "overlap with explicit prior %#x..%#x" % (a, b))
    for i, m in enumerate(mine):
        for j, n in enumerate(mine):
            if i != j:
                check(not (m[0] < n[1] and n[0] < m[1]),
                      "self-overlap %#x..%#x" % (m[0], m[1]))

    # 7. MANIFEST hashes. Paths are repo-relative by construction:
    # packet-dir files resolve inside the packet dir, while
    # ../../../tools|tests paths resolve at the repo root, so a temp
    # copy of the packet outside the repo still verifies.
    man = open(os.path.join(packet_dir, "MANIFEST.sha256")).read()
    man = man.splitlines()
    listed = set()
    # Packet slug from records, not the directory basename: a temp
    # copy of the packet lives under a different directory name.
    slug = records["packet"]
    for line in man:
        h, _, path = line.partition("  ")
        listed.add(path)
        rel = os.path.normpath(os.path.join(
            "research", "work-items", slug, path))
        full = os.path.join(repo, rel)
        check(hashlib.sha256(open(full, "rb").read()).hexdigest() == h,
              "MANIFEST hash mismatch: %s" % path)
    expect = {"README.md", "EVIDENCE.md", "records.json"}
    expect |= {e["hex"] for e in records["exhibits"]}
    expect |= {e["objdump"] for e in records["exhibits"]}
    expect |= {"../../../tools/node115_lu_opt_hpa_sec_leaves.py",
               "../../../tests/test_node115_lu_opt_hpa_sec_leaves.py"}
    check(listed == expect, "MANIFEST file set mismatch: %s" %
          (listed ^ expect,))

    if FAILS:
        print("VERIFIER FAIL: %d PASS, %d FAIL" % (PASSES[0], len(FAILS)))
        return 1
    print("VERIFIER OK: %d PASS, 0 FAIL" % PASSES[0])
    return 0


if __name__ == "__main__":
    sys.exit(main())
