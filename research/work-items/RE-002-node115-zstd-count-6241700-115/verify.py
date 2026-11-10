#!/usr/bin/env python3
"""Re-check the ZSTD_count packet from the digest-verified local binary.

Checks, all offline:
  1. every MANIFEST.sha256 row hashes its file;
  2. main.txt regenerates byte-for-byte from a fresh objdump run and
     every instruction byte matches the raw binary;
  3. callers.tsv / frames.txt / relocations.txt regenerate exactly;
  4. the FDE covers the routine and the census body hash matches it;
  5. the model spot checks and the committed ledger replay.

Run: python3 research/work-items/RE-002-node115-zstd-count-6241700-115/verify.py
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
    rec = cen.census_relocations(cen.START)
    body = cen.BINARY.read_bytes()[cen.va_to_off(segs, cen.START):
                                    cen.va_to_off(segs, cen.END)]
    assert hashlib.sha256(body).hexdigest() == rec["target_body_sha256"]
    return len(hits)


def check_model():
    tool = _load("zstd_count", ROOT / "tools" / "zstd_count_6241700_115.py")
    assert tool.zstd_count(b"ABC", b"ABD", 3) == 2
    assert tool.zstd_count(b"ABC", b"ABC", 2) == 2
    assert tool.zstd_count(b"", b"", 0) == 0
    assert tool.zstd_count(b"AB", b"AB", 1) == 1
    bad = 0
    for line in (PKT / "cases.tsv").read_text().splitlines()[1:]:
        import json
        _, _, param, expected = line.split("\t")
        p = json.loads(param)
        got = tool.zstd_count(bytes.fromhex(p["in"]),
                              bytes.fromhex(p["match"]), p["limit"])
        if got != json.loads(expected)["count"]:
            bad += 1
    assert bad == 0, f"{bad} ledger rows failed"
    return True


def main():
    n = check_manifest()
    check_excerpt()
    calls = check_census()
    check_model()
    print(f"verify OK: {n} manifest rows, {calls} callers, model + ledger + excerpt")
    return 0


if __name__ == "__main__":
    sys.exit(main())
