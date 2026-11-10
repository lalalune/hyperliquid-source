#!/usr/bin/env python3
"""Verify the GetBGJobLimits 0x5dd5f00 packet, re-deriving every claim.

Nothing here trusts the packet's own tables: the excerpt is re-read from the
artifact, the claim anchors are re-decoded, the caller census is recomputed from
`.text` and `.eh_frame`, and the model is re-checked against the decoded
instruction stream over the whole sweep and the 300-row ledger.

Usage: python3 verify.py
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(PACKET))

from tools.rocksdb_get_bg_job_limits_5dd5f00_115 import (  # noqa: E402
    START, END, SIZE, SYMBOL, K_DEFAULT, M32, INT_MIN, INT_MAX,
    FAMILIES, BOUNDARY_CASES, LEDGER_PER_FAMILY, LAYOUT,
    instruction_stream, accesses, get_bg_job_limits, decoded, decoded_packed,
    model_packed, pack, unpack_flushes, unpack_compactions, s32, agree,
    generate_cases, ledger_rows, cases_tsv_rows, sweep,
)


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


census_mod = load(PACKET / "census.py", "pkt_census")
semantics_mod = load(PACKET / "semantics.py", "pkt_semantics")
CENSUS = census_mod.census()
SEM = semantics_mod.rows()
DATA = BINARY.read_bytes()
_WINDOW, DIGEST = semantics_mod.window_bytes()


# --------------------------------------------------------------------------
def check_manifest():
    rows = [r.split(None, 1) for r in
            (PACKET / "MANIFEST.sha256").read_text().strip().splitlines()]
    assert rows, "empty manifest"
    for digest, rel in rows:
        p = Path(rel)
        p = p if p.is_absolute() else (ROOT / rel if rel.startswith(
            ("tools/", "tests/")) else PACKET / rel)
        assert p.is_file(), f"manifest names a missing file: {rel}"
        got = hashlib.sha256(p.read_bytes()).hexdigest()
        assert got == digest, f"hash mismatch: {rel}"
    inside = {str((PACKET / r).resolve()) for _, r in rows
              if not r.startswith(("tools/", "tests/"))}
    on_disk = {str(p.resolve()) for p in PACKET.rglob("*")
               if p.is_file() and p.name != "MANIFEST.sha256"
               and "__pycache__" not in p.parts}
    assert inside == on_disk, ("files not in the manifest: "
                               f"{sorted(on_disk - inside)}; "
                               f"manifest rows without a file: "
                               f"{sorted(inside - on_disk)}")
    return len(rows)


def artifact_body():
    """(bytes, file offset) of the window, read straight from the artifact."""
    segs = []
    for line in subprocess.check_output(["readelf", "-lW", str(BINARY)]).decode().splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            segs.append((int(p[2], 16), int(p[1], 16), int(p[4], 16)))
    for v, o, f in segs:
        if v <= START < v + f:
            return DATA, o + (START - v)
    raise AssertionError("the entry is in no LOAD segment")


def check_excerpt():
    insns = instruction_stream()
    assert insns[0].addr == START, insns[0]
    assert insns[0].mnemonic == "endbr64", insns[0]
    assert insns[-1].end() == END, insns[-1]
    assert len(insns) == 29, len(insns)
    blob = b"".join(i.raw for i in insns)
    data, off = artifact_body()
    assert blob == data[off:off + SIZE], "the excerpt bytes are not the artifact bytes"
    assert data[off - 7:off] == b"\xcc" * 7, "no int3 padding below the entry"
    assert data[off + SIZE:off + SIZE + 5] == b"\xcc" * 5, "no int3 padding above the end"
    # the next FDE starts 5 bytes after this one ends: END is a real function end
    assert (PACKET / "frames.txt").read_text().count(
        f"pc={START:016x}..{END:016x}") == 1
    digest = hashlib.sha256(blob).hexdigest()
    assert digest == DIGEST
    assert (PACKET / "relocations.txt").read_text().count(digest) >= 1, \
        "the body digest is not recorded in relocations.txt"
    return len(insns), digest


def check_semantics():
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    insns = {i.addr: i for i in instruction_stream()}
    assert len(SEM) == len(insns) == 29, (len(SEM), len(insns))
    assert [r["va"] for r in SEM] == [i.addr for i in instruction_stream()]
    data, off = artifact_body()
    # objdump mnemonic -> the mnemonic capstone gives for the same bytes (the
    # only differences are the padding nop spellings)
    same = {"nopl": "nop", "nopw": "nop", "nop": "nop"}
    for r in SEM:
        ins = insns[r["va"]]
        assert r["size"] == len(ins.raw), r
        assert r["bytes"] == ins.raw.hex(), r
        assert r["instruction"] == (ins.mnemonic + (" " + ins.op_str if ins.op_str else "")).strip(), r
        raw = data[off + r["va"] - START:off + r["va"] - START + len(ins.raw)]
        assert raw.hex() == r["bytes"]
        # an independent decode of the same bytes: one instruction, same length,
        # and the same mnemonic (modulo nop spelling), which is what makes the
        # claimed span a real instruction boundary
        dec = list(md.disasm(raw, r["va"]))
        assert len(dec) == 1, (r, dec)
        assert dec[0].size == len(ins.raw), (r, dec[0].size)
        assert same.get(ins.mnemonic, ins.mnemonic) == same.get(dec[0].mnemonic, dec[0].mnemonic), \
            (r, dec[0].mnemonic)
    # every anchor is a claim, and the row set covers the window exactly once
    spans = sorted((r["va"], r["va"] + r["size"]) for r in SEM)
    assert spans[0][0] == START and spans[-1][1] == END
    for a, b in zip(spans, spans[1:]):
        assert a[1] == b[0], (a, b)
    assert sum(r["size"] for r in SEM) == SIZE
    return len(SEM)


def check_census():
    assert CENSUS["direct_calls"] == 4, CENSUS["direct_calls"]
    assert CENSUS["tail_jumps"] == 0
    assert CENSUS["caller_fdes"] == 3, CENSUS["caller_fdes"]
    assert CENSUS["consumers"] == {"register-copy": 3, "arithmetic": 1}, CENSUS["consumers"]
    assert CENSUS["sites_reading_the_return"] == 4
    assert CENSUS["discarded_sites"] == 0
    sites = [f"{r['site']:#x}" for r in CENSUS["rows"]]
    assert sites == ["0x5d7265a", "0x5d7267c", "0x5dfceed", "0x5e5cff5"], sites
    fdes = {f"{r['caller_fde_start']:#x}..{r['caller_fde_end']:#x}" for r in CENSUS["rows"]}
    assert fdes == {"0x5d71fe0..0x5d72e50", "0x5dfcea0..0x5dfcfb6",
                    "0x5e5cf70..0x5e5df0f"}, fdes
    # the census files are the census
    callers = [l.split("\t") for l in (PACKET / "callers.tsv").read_text().splitlines()[1:] if l]
    assert len(callers) == 4
    uses = [l.split("\t") for l in (PACKET / "caller_use.tsv").read_text().splitlines()[1:] if l]
    assert len(uses) == 4
    for row, cols in zip(CENSUS["rows"], uses):
        site, consumer, distance, use, after, split, split_va, fde, meaning = cols
        assert site == f"{row['site']:#x}" and consumer == row["consumer"]
        assert distance == str(row["distance"]) and use == row["use"] and after == row["after"]
        assert split == row["split"] and meaning == row["meaning"]
        assert split_va == (f"{row['split_va']:#x}" if row["split_va"] else "-")
    # every site splits the packed pair itself: three signed, one unsigned
    assert CENSUS["splits"] == {"sar": 3, "shr": 1}, CENSUS["splits"]
    assert [(r["split"], f"{r['split_va']:#x}") for r in CENSUS["rows"]] == [
        ("sar", "0x5d7268d"), ("sar", "0x5d72689"),
        ("sar", "0x5dfcef9"), ("shr", "0x5e5d00c")], \
        [(r["split"], r["split_va"]) for r in CENSUS["rows"]]
    for r in CENSUS["rows"]:
        assert r["split"] != "none" and r["split_va"] is not None, r
        assert r["caller_fde_start"] < r["site"] < r["caller_fde_end"], r
    return CENSUS


def check_model():
    assert sweep() == [], sweep()[:3]
    rows = ledger_rows()
    assert [r["family"] for r in rows].count("derived") == LEDGER_PER_FAMILY
    for family in FAMILIES:
        assert sum(1 for r in rows if r["family"] == family) == LEDGER_PER_FAMILY
    assert len(rows) == 300
    for r in rows:
        assert r["agree"], r
        assert r["decoded"] == r["packed"], r
        f, c = get_bg_job_limits(r["flushes"], r["compactions"], r["jobs"], bool(r["multi_db"]))
        assert pack(f, c) == r["packed"], r
    # the ledger on disk is the ledger we just recomputed
    disk = [l.split("\t") for l in (PACKET / "cases.tsv").read_text().splitlines()[1:] if l]
    assert len(disk) == 300, len(disk)
    fresh = [l.split("\t") for l in cases_tsv_rows(rows)[1:]]
    assert disk == fresh
    # boundaries and the rules they pin
    assert get_bg_job_limits(K_DEFAULT, K_DEFAULT, 7, True) == (1, 6)
    assert get_bg_job_limits(K_DEFAULT, K_DEFAULT, 8, True) == (2, 6)
    assert get_bg_job_limits(K_DEFAULT, K_DEFAULT, 24, True) == (6, 18)
    assert get_bg_job_limits(K_DEFAULT, K_DEFAULT, 24, False) == (6, 1)
    assert get_bg_job_limits(K_DEFAULT, 3, 24, True) == (1, 3)
    assert get_bg_job_limits(0, 0, 0, True) == (1, 1)
    assert get_bg_job_limits(-2, -2, 0, True) == (1, 1)
    assert get_bg_job_limits(K_DEFAULT, K_DEFAULT, INT_MIN, True) == (1, INT_MAX)
    assert get_bg_job_limits(K_DEFAULT, K_DEFAULT, INT_MAX, True) == ((INT_MAX >> 2), INT_MAX - (INT_MAX >> 2))
    # the packed layout is what the callers unpack
    assert LAYOUT == {"flushes": (0, 32), "compactions": (32, 32)}
    p = decoded_packed(2, 3, 0, True)
    assert unpack_flushes(p) == 2 and unpack_compactions(p) == 3 and p == 0x300000002
    assert s32(0xFFFFFFFF) == -1
    # no memory, and the emulator really ran the 26 non-nop instructions
    acc = accesses()
    assert acc["loads"] == [] and acc["stores"] == [], acc
    assert acc["non_nop_instructions_checked"] == 26, acc
    assert all(agree(args) for _, args in generate_cases(seed=7))
    return len(rows)


def main():
    rows = check_manifest()
    n, digest = check_excerpt()
    claims = check_semantics()
    c = check_census()
    ledger = check_model()
    print(f"verify OK: {rows} manifest rows, {claims} claim anchors, "
          f"{n} instructions, body {digest[:12]}..., "
          f"{c['direct_calls']} calls / {c['caller_fdes']} caller FDEs "
          f"{c['consumers']}, {ledger}-row ledger, sweep + 300-case ledger agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
