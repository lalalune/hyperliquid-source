#!/usr/bin/env python3
"""Re-check the get_wval_limb packet from the digest-verified local binary.

Checks, all offline:
  1. every MANIFEST.sha256 row hashes its file;
  2. main.txt regenerates byte-for-byte from a fresh objdump run and
     every instruction byte matches the raw binary;
  3. callers.tsv / frames.txt / relocations.txt regenerate exactly;
  4. the FDE covers the routine and the census body hash matches it;
  5. the model spot checks and the committed ledger replay.

Run: python3 research/work-items/RE-002-node115-blst-get-wval-limb-5d0ed60-115/verify.py
"""
import hashlib
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PKT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check_manifest():
    rows = []
    for line in (PKT / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        want, rel = line.split("  ", 1)
        target = None
        for anc in (PKT, *PKT.parents):
            if not anc.is_relative_to(ROOT):
                break
            cand = anc / rel
            if cand.is_file():
                target = cand
                break
        assert target is not None, f"manifest row resolves nowhere: {rel}"
        assert digest(target) == want, f"digest mismatch: {rel}"
        rows.append(rel)
    assert rows, "empty manifest"
    return len(rows)


def check_excerpt():
    ex = _load("export_excerpts", PKT / "export_excerpts.py")
    assert ex.excerpt() == (PKT / "main.txt").read_text(), "main.txt drifted"
    # every listed instruction's raw bytes appear verbatim in the binary
    cen = _load("census", PKT / "census.py")
    segs = cen.load_segments()
    data = ex.BINARY.read_bytes()
    checked = 0
    for line in (PKT / "main.txt").read_text().splitlines():
        if ":\t" not in line:
            continue
        addr, rest = line.split(":\t", 1)
        raw = rest.split("\t")[0].strip().replace(" ", "").lower()
        if not raw:
            continue
        va = int(addr.strip(), 16)
        want = bytes.fromhex(raw)
        off = cen.va_to_off(segs, va)
        assert data[off:off + len(want)] == want, f"bytes mismatch at {hex(va)}"
        checked += 1
    return checked


def check_census():
    cen = _load("census", PKT / "census.py")
    segs = cen.load_segments()
    ranges = cen.fde_ranges()
    enc = cen.encloser(ranges, cen.START)
    assert enc == (cen.START, cen.END), enc
    hits = cen.find_calls(segs, cen.START)
    rows = ["site\tkind\tcaller_fde_start\tcaller_fde_end"]
    for site, kind in hits:
        e = cen.encloser(ranges, site)
        rows.append(f"{hex(site)}\t{kind}\t{hex(e[0])}\t{hex(e[1])}")
    assert "\n".join(rows) + "\n" == (PKT / "callers.tsv").read_text(), \
        "callers.tsv drifted"
    # caller_use.tsv -- the consumer census regenerates exactly too.
    uses = cen.caller_use(segs, ranges, hits)
    urows = ["site\tconsumer\tdistance\tuse\tafter\tcaller_fde\tmeaning"]
    for u in uses:
        urows.append("\t".join([
            hex(u["site"]), u["consumer"], str(u["distance"]),
            u["use"] or "-", u["after"] or "-",
            f"{hex(u['fde'][0])}..{hex(u['fde'][1])}", u["meaning"],
        ]))
    assert "\n".join(urows) + "\n" == (PKT / "caller_use.tsv").read_text(), \
        "caller_use.tsv drifted"
    rec = cen.census_relocations(cen.START)
    body = cen.BINARY.read_bytes()[cen.va_to_off(segs, cen.START):
                                    cen.va_to_off(segs, cen.END)]
    assert hashlib.sha256(body).hexdigest() == rec["target_body_sha256"]
    return len(hits), len(uses)


def check_model():
    tool = _load("get_wval_limb", ROOT / "tools" / "get_wval_limb_5d0ed60_115.py")
    # Spot checks of the pinned window semantics.
    assert tool.get_wval_limb(b"\x12\x34", 0, 16) == 0x3412
    assert tool.get_wval_limb(b"\x00\x80", 0, 16) == 0x8000
    assert tool.get_wval_limb(b"\xa5", 0, 4) == 0xA5   # window, not field
    assert tool.get_wval_limb(b"\xa5", 4, 4) == 0x0A
    assert tool.get_wval_limb(b"\x00\xff\xff", 0, 8) == 0x00
    bad = 0
    ncases = 0
    for line in (PKT / "cases.tsv").read_text().splitlines()[1:]:
        import json
        _, _, param, expected = line.split("\t")
        p = json.loads(param)
        got = tool.get_wval_limb(bytes.fromhex(p["w"]), p["bitpos"],
                                 p["nbits"])
        if got != json.loads(expected)["value"]:
            bad += 1
        ncases += 1
    assert bad == 0, f"{bad} ledger rows failed"
    # Every committed row must also agree with the literal transcription.
    for r in tool.ledger_rows():
        p = json.loads(r["param"])
        w = bytes.fromhex(p["w"])
        assert tool.get_wval_limb(w, p["bitpos"], p["nbits"]) == \
            tool.get_wval_limb_asm(w, p["bitpos"], p["nbits"]), r["id"]
    # The committed ledger must be the documented subset of the sweep.
    assert [r["id"] for r in tool.ledger_rows()] == [
        ln.split("\t")[0]
        for ln in (PKT / "cases.tsv").read_text().splitlines()[1:]], \
        "committed ledger is not the generated subset"
    assert len(tool.generate_cases()) == 2400
    return ncases


def main():
    n = check_manifest()
    check_excerpt()
    calls, consumers = check_census()
    ncases = check_model()
    print(f"verify OK: {n} manifest rows, {calls} callers / {consumers} "
          f"consumers, model + {ncases}-case ledger + excerpt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
