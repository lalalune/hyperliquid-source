#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-bintableinit-caller-2sites-walk-rsp.

Byte reads only; never executes the target binary. Run from the worktree root.
Exit 0 only when every check passes; each failure is printed with FAIL.
"""
import bisect
import glob
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PACKET_DIR = os.path.join(
    ROOT, "research", "work-items",
    "RE-001-node115-lu-bintableinit-caller-2sites-walk-rsp")
BIN = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
WINDOW = (0x6349780, 0x6349BD9)
PREV_FDE = (0x63495B0, 0x6349775)
NEXT_FDE = (0x6349BE0, 0x634EB7C)
EXPECTED_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECTED_SIZE = 105896032
EXPECTED = {"strict": 230, "calls": 5, "bti": 2, "miss": 2, "ret": 0,
            "bsr": 1, "locksub": 0}
BTI_SITES = ["63498e6", "6349a43"]
MISS_SITES = ["6349b99", "6349bcf"]
SITE_BLOCKS = {"63498e6": "63498e0", "6349a43": "6349a3d"}
SITE_JE = {"63498e6": "63497bc", "6349a43": "6349868"}
SITE_TEST = {"63498e6": "test   %rdi,%rdi", "6349a43": "test   %rbp,%rbp"}
SITE_REJOIN = {"63498e6": "63497c2", "6349a43": "634986e"}
EXIT_JMPS = {"634982d": "63637f0", "63498d8": "63bd6c0", "6349974": "6363260"}
CANARY = ["6349805", "63498a7", "6349945"]

fails = []
passes = []


def check(name, ok, detail=""):
    (passes if ok else fails).append(name)
    print(("PASS " if ok else "FAIL ") + name + ((" -- " + detail) if detail else ""))


def uleb(data, pos):
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def sleb(data, pos):
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            if b & 0x40:
                result -= (1 << shift)
            break
    return result, pos


ENC_SIZE = {0x01: None, 0x02: 2, 0x03: 4, 0x04: 8, 0x09: None,
            0x0A: 2, 0x0B: 4, 0x0C: 8, 0x00: 8}


def enc_value(data, pos, enc):
    fmt = enc & 0x0F
    if fmt == 0x01:
        return uleb(data, pos)
    if fmt == 0x09:
        return sleb(data, pos)
    size = ENC_SIZE[fmt]
    raw = int.from_bytes(data[pos:pos + size], "little", signed=(fmt >= 0x0A))
    return raw, pos + size


def parse_eh_frame(data, base_va):
    """Return list of (start, end) FDEs. CIE pointer is relative to the
    CIE_id field (rec+4, not rec). CIE offsets are hex, not decimal.
    Version-1 CIEs carry the return-address register as a single byte."""
    fdes = []
    cies = {}
    pos = 0
    n = len(data)
    while pos + 8 <= n:
        length = struct.unpack("<I", data[pos:pos + 4])[0]
        if length == 0:
            break
        if length == 0xFFFFFFFF:
            length = struct.unpack("<Q", data[pos + 4:pos + 12])[0]
            hdr = 12
        else:
            hdr = 4
        rec_end = pos + hdr + length
        cie_id = struct.unpack("<I", data[pos + hdr:pos + hdr + 4])[0]
        if cie_id == 0:
            body = pos + hdr + 4
            version = data[body]
            body += 1
            aug_end = data.index(b"\x00", body)
            aug = data[body:aug_end].decode("latin1")
            body = aug_end + 1
            # DWARF order: code alignment, data alignment, return-address
            # register FIRST, then 'z' augmentation data (not the reverse).
            _, body = uleb(data, body)  # code alignment
            _, body = sleb(data, body)  # data alignment
            if version == 1:
                body += 1  # return-address register, single byte
            else:
                _, body = uleb(data, body)
            fde_enc = None
            if aug.startswith("z"):
                _, body = uleb(data, body)  # augmentation data length
                q = body
                for ch in aug[1:]:
                    if ch == "R":
                        fde_enc = data[q]
                        q += 1
                    elif ch == "P":
                        penc = data[q]
                        q += 1
                        _, q = enc_value(data, q, penc)
                    elif ch == "L":
                        q += 1
                    elif ch == "b":
                        q += 1
                    elif ch == "e":
                        q += 2
                    else:
                        raise ValueError("unknown aug %r" % ch)
                body = q
            cies[pos] = fde_enc
        else:
            cie_addr = (pos + hdr) - cie_id
            fde_enc = cies.get(cie_addr)
            if fde_enc != 0x1B:
                raise ValueError("unexpected FDE encoding %r at %#x"
                                 % (fde_enc, pos))
            field = pos + hdr + 4
            loc = struct.unpack("<i", data[field:field + 4])[0] + field + base_va
            rng = struct.unpack("<I", data[field + 4:field + 8])[0]
            fdes.append((loc, loc + rng))
        pos = rec_end
    return fdes


def main():
    blob = open(BIN, "rb").read()
    check("binary size", len(blob) == EXPECTED_SIZE, str(len(blob)))
    check("binary sha256",
          hashlib.sha256(blob).hexdigest() == EXPECTED_SHA)

    # ELF section headers
    e_shoff = struct.unpack("<Q", blob[0x28:0x30])[0]
    e_shentsize, e_shnum = struct.unpack("<HH", blob[0x3A:0x3E])
    e_shstrndx = struct.unpack("<H", blob[0x3E:0x40])[0]

    def sh(i):
        o = e_shoff + i * e_shentsize
        return struct.unpack("<IIQQQQIIQQ", blob[o:o + 64])

    _, _, _, _, stroff, strsize, _, _, _, _ = sh(e_shstrndx)

    def nm(n):
        e = blob.index(b"\x00", stroff + n)
        return blob[stroff + n:e].decode()

    sections = {}
    for i in range(e_shnum):
        name, _typ, _flags, addr, off, size, _link, _info, _align, entsize = sh(i)
        sections[nm(name)] = (addr, off, size, entsize)

    eh_addr, eh_off, eh_size, _ = sections[".eh_frame"]
    fdes = parse_eh_frame(blob[eh_off:eh_off + eh_size], eh_addr)
    # .eh_frame order is NOT VA-sorted (local inversions exist); sort
    # before any bisect-based enclosing lookup, or matches silently vanish.
    fdes = sorted(fdes)
    check("window FDE present", WINDOW in fdes)
    check("prev FDE bounds", PREV_FDE in fdes)
    check("next FDE bounds", NEXT_FDE in fdes)
    check("gap before 11", WINDOW[0] - PREV_FDE[1] == 11)
    check("padding after 7", NEXT_FDE[0] - WINDOW[1] == 7)

    def toff(va):
        return va - 0x1000

    gap = blob[toff(PREV_FDE[1]):toff(WINDOW[0])]
    check("gap int3", gap == b"\xcc" * 11, gap.hex())
    pad = blob[toff(WINDOW[1]):toff(NEXT_FDE[0])]
    check("padding int3", pad == b"\xcc" * 7, pad.hex())

    # exhibits
    hex_path = os.path.join(
        PACKET_DIR, "bintableinit_caller_walk_rsp_2sites.hex")
    raw = open(hex_path, "rb").read()
    check("exhibit bytes",
          raw == blob[toff(WINDOW[0]):toff(WINDOW[1])] and len(raw) == 1113)

    obj_path = os.path.join(
        PACKET_DIR, "bintableinit_caller_walk_rsp_2sites.objdump.txt")
    lines = open(obj_path, errors="replace").read().splitlines()
    strict_pat = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t[a-z]")
    strict = [ln for ln in lines if strict_pat.match(ln)]
    calls = [ln for ln in lines if re.search(r"\tcall\s", ln)]
    rets = [ln for ln in lines if re.search(r"\tret\s*$", ln)]
    bti = [ln for ln in lines if "call" in ln and "63d9880" in ln]
    miss = [ln for ln in lines if "call" in ln and "63d9700" in ln]
    bsr = [ln for ln in lines if re.search(r"\tbsr\s", ln)]
    locksub = [ln for ln in lines if re.search(r"\tlock sub\s", ln)]
    check("strict count", len(strict) == EXPECTED["strict"], str(len(strict)))
    check("call census", len(calls) == EXPECTED["calls"], str(len(calls)))
    check("ret count", len(rets) == EXPECTED["ret"], str(len(rets)))
    check("bti sites", [ln.split(":")[0].strip() for ln in bti] == BTI_SITES)
    check("miss sites", [ln.split(":")[0].strip() for ln in miss] == MISS_SITES)
    check("bsr count", len(bsr) == EXPECTED["bsr"], str(len(bsr)))
    check("bsr site", len(bsr) == 1
          and bsr[0].split(":")[0].strip() == "63499aa")
    check("lock sub count", len(locksub) == EXPECTED["locksub"],
          str(len(locksub)))

    def idx_at(addr):
        for i, ln in enumerate(lines):
            if ln.strip().startswith(addr + ":"):
                return i
        return None

    for site, block in SITE_BLOCKS.items():
        bi = idx_at(block)
        si = idx_at(site)
        block_lines = lines[bi:si + 1] if bi is not None and si is not None else []
        # plain rsp: mov %rsp,%r12 then mov %r12,%rdi (use \s+ for the
        # objdump mnemonic padding; single-space substrings miss lines)
        rsp_ok = (any(re.search(r"mov\s+%rsp,%r12", ln) for ln in block_lines)
                  and any(re.search(r"mov\s+%r12,%rdi", ln) for ln in block_lines))
        check("site " + site + " plain rsp", rsp_ok)
        je = SITE_JE[site]
        ji = idx_at(je)
        tgt_ok = False
        test_ok = False
        if ji is not None:
            tgt_ok = ("je" in lines[ji] and block in lines[ji])
            test_ok = any(re.search(r"test\s+", ln)
                          and SITE_TEST[site].split(",")[1] in ln
                          for ln in lines[max(0, ji - 3):ji])
        check("site " + site + " je target", tgt_ok)
        check("site " + site + " test", test_ok)
        # exactly one je targets this block
        n_je = sum(1 for ln in lines
                   if re.search(r"\tje\s", ln) and block in ln)
        check("site " + site + " single je", n_je == 1, str(n_je))
        # rejoin: a jmp to the rejoin address within the next 2 strict
        # lines after the call (a mov may intervene)
        addr = SITE_REJOIN[site]
        if si is not None:
            following = [ln for ln in lines[si + 1:] if strict_pat.match(ln)][:2]
            ok = any("jmp" in ln and addr in ln for ln in following)
            check("site " + site + " rejoin", ok,
                  following[0].strip()[:60] if following else "none")

    # entry gate: lea 0x6713606, cmpb $0x0, je 0x6349838
    gate_ok = False
    for i, ln in enumerate(lines):
        if "lea" in ln and "6713606" in ln:
            window_lines = lines[i:i + 4]
            gate_ok = (any("cmpb" in x and "$0x0" in x for x in window_lines)
                       and any("je" in x and "6349838" in x for x in window_lines))
            break
    check("entry gate 6713606", gate_ok)

    # size-class block: movabs threshold + bsr inside 0x6349980 block
    sb = idx_at("6349980")
    sb_ok = False
    if sb is not None:
        sb_lines = lines[sb:sb + 30]
        sb_ok = (any("movabs" in x and "0x7000000000000000" in x for x in sb_lines)
                 and any("bsr" in x for x in sb_lines))
    check("size-class block 6349980", sb_ok)

    # canary checks
    for ca in CANARY:
        ci = idx_at(ca)
        ok = False
        if ci is not None:
            for ln in lines[ci:ci + 5]:
                if "jne" in ln and "6349ba3" in ln:
                    ok = True
        check("canary check " + ca, ok)
    fail_idx = idx_at("6349ba3")
    check("stack_chk_fail call",
          fail_idx is not None and "63f0d70" in lines[fail_idx])

    # exits: exactly the three window-leaving jmps, each after an epilogue
    def tgt_of(ln):
        m = re.search(r"\b(63[0-9a-f]{5})\s*<", ln)
        return int(m.group(1), 16) if m else None

    leaving = {}
    for i, ln in enumerate(lines):
        if re.search(r"\tjmp\s", ln):
            t = tgt_of(ln)
            if t is not None and not (WINDOW[0] <= t < WINDOW[1]):
                leaving[ln.split(":")[0].strip()] = "%x" % t
    check("three tail-jump exits", leaving == EXIT_JMPS, str(leaving))
    for site in EXIT_JMPS:
        si = idx_at(site)
        epi_ok = False
        if si is not None:
            prev = lines[max(0, si - 10):si]
            epi_ok = (any("add" in x and "$0x190" in x for x in prev)
                      and sum(1 for x in prev if re.search(r"\tpop\s", x)) >= 2)
        check("exit " + site + " epilogue", epi_ok)

    # all conditional branch targets stay inside the window
    cond_pat = re.compile(r"\t(j[e]?|jne|jbe|ja|jb|jae|jge|jl|jle|jg|js|jns|jo|jno|jp|jnp)\s+")
    outside = []
    for ln in lines:
        m = cond_pat.search(ln)
        if m:
            t = tgt_of(ln)
            if t is not None and not (WINDOW[0] <= t < WINDOW[1]):
                outside.append(ln.strip())
    check("conditional branches in-window", not outside, str(outside[:3]))

    # records consistency
    rec = json.load(open(os.path.join(PACKET_DIR, "records.json")))
    check("records window", rec.get("window") == "0x6349780..0x6349bd9")
    check("records strict", rec.get("strict_count") == EXPECTED["strict"])
    check("records calls", rec.get("calls_total") == EXPECTED["calls"])
    check("records bsr", rec.get("bsr_count") == EXPECTED["bsr"])
    check("records ret", rec.get("ret_count") == EXPECTED["ret"])
    check("records slug",
          rec.get("slug") == "RE-001-node115-lu-bintableinit-caller-2sites-walk-rsp")
    check("records bti sites",
          [s.get("site") for s in rec.get("bin_table_init_sites", [])]
          == ["0x63498e6", "0x6349a43"])
    check("records miss sites",
          [s.get("site") for s in rec.get("lu_miss_sites", [])]
          == ["0x6349b99", "0x6349bcf"])

    # rela census via section headers
    for sec, want_total, want_rel in ((".rela.dyn", 60723, 59534),
                                      (".rela.plt", 278, 0)):
        _a, off, size, entsize = sections[sec]
        nent = size // entsize
        rel = sum(1 for j in range(nent)
                  if struct.unpack("<Q", blob[off + j * entsize + 8:
                                             off + j * entsize + 16])[0] == 8)
        check(sec + " census", nent == want_total and rel == want_rel,
              "%d/%d" % (nent, rel))

    # disjointness: range-only collector; handles BOTH hex-string and
    # decimal-integer start/end (two merged-tree records files use ints;
    # an int-only collector silently skipped them on the first survey pass)
    SKIP = ("census", "cited", "survey", "callers", "largest_caller_fde")

    def num(x):
        return x if isinstance(x, int) else int(x, 16)

    def collect(obj, out):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in SKIP or k == "fde":
                    continue
                if k in ("exhibits", "windows"):
                    items = v if isinstance(v, list) else (
                        list(v.values()) if isinstance(v, dict) else [])
                    for e in items:
                        if isinstance(e, dict):
                            if "range" in e:
                                r = e["range"]
                                out.append((num(r[0]), num(r[1]))
                                           if isinstance(r, list)
                                           else tuple(num(x)
                                                      for x in r.split("..")))
                            elif "start" in e and "end" in e:
                                out.append((num(e["start"]), num(e["end"])))
                else:
                    collect(v, out)
        elif isinstance(obj, list):
            for v in obj:
                collect(v, out)

    priors = []
    skipped = []
    paths = set(glob.glob(os.path.join(
        ROOT, "research", "work-items", "*", "records.json")))
    paths |= set(glob.glob("/home/hatch/workspace/hl-wt-calls*/research/work-items/*/records.json"))
    for d in paths:
        try:
            collect(json.load(open(d)), priors)
        except Exception:
            skipped.append(d)
    priors = [p for p in priors if p != WINDOW]
    bad = [p for p in priors if WINDOW[0] < p[1] and p[0] < WINDOW[1]]
    check("disjointness NONE", not bad, str(bad[:3]))
    check("priors scanned", len(priors) > 1000, str(len(priors)))
    check("no records skipped", not skipped, str(skipped[:3]))

    # slug uniqueness: committed tree must not contain the slug dir
    slug = "RE-001-node115-lu-bintableinit-caller-2sites-walk-rsp"
    tree_hit = False
    try:
        out = subprocess.run(["git", "ls-tree", "HEAD", "--name-only",
                              "research/work-items/"], cwd=ROOT,
                             capture_output=True, text=True, timeout=60)
        tree_hit = slug in out.stdout.split()
    except Exception:
        tree_hit = False
    check("slug not in committed tree", not tree_hit)
    # dir-scan fallback: any other dir with this slug but a different window
    clash = False
    for d in glob.glob("/home/hatch/workspace/hl-wt-calls*/research/work-items/" + slug):
        if os.path.abspath(d) == os.path.abspath(PACKET_DIR):
            continue
        try:
            w = json.load(open(os.path.join(d, "records.json"))).get("window")
            if w != "0x6349780..0x6349bd9":
                clash = True
        except Exception:
            pass
    check("slug dir-scan no clash", not clash)

    # raw-e8 census grouped by own parsed FDEs
    t_addr, t_off, t_size, _ = sections[".text"]
    starts = [s for s, _ in fdes]
    cnt = {}
    pos = 0
    text = blob[t_off:t_off + t_size]
    while True:
        pos = text.find(b"\xe8", pos)
        if pos < 0:
            break
        rel = struct.unpack("<i", text[pos + 1:pos + 5])[0]
        if t_addr + pos + 5 + rel == 0x63D9880:
            va = t_addr + pos
            i = bisect.bisect_right(starts, va) - 1
            if i >= 0 and fdes[i][0] <= va < fdes[i][1]:
                cnt[fdes[i]] = cnt.get(fdes[i], 0) + 1
        pos += 1
    check("raw total 108", sum(cnt.values()) == 108, str(sum(cnt.values())))
    check("raw this FDE 2", cnt.get(WINDOW) == 2, str(cnt.get(WINDOW)))
    tiers = {}
    for v in cnt.values():
        tiers[v] = tiers.get(v, 0) + 1
    check("raw tiers", tiers == {10: 1, 8: 1, 6: 2, 5: 1, 4: 8, 2: 12, 1: 17},
          str(tiers))

    # MANIFEST digests
    man = open(os.path.join(PACKET_DIR, "MANIFEST.sha256")).read().splitlines()
    ok = True
    for ln in man:
        if not ln.strip():
            continue
        digest, path = ln.split(None, 1)
        path = path.lstrip("*").strip()
        full = os.path.normpath(os.path.join(PACKET_DIR, path))
        if not os.path.exists(full):
            ok = False
            print("FAIL manifest missing " + path)
            continue
        if hashlib.sha256(open(full, "rb").read()).hexdigest() != digest:
            ok = False
            print("FAIL manifest digest " + path)
    check("MANIFEST digests", ok, "%d entries" % len(man))

    print("PASS count: %d, FAIL count: %d" % (len(passes), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
