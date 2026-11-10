#!/usr/bin/env python3
"""Self-check for the _tr_flush_bits evidence packet.

Re-reads every claim in this directory against the digest-verified artifact and
re-runs the model against decoded execution of the routine's own bytes.

Run: python3 research/work-items/RE-002-node115-libz-tr-flush-bits-630b9c0-115/verify.py
"""
import hashlib
import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
TOOL = ROOT / "tools" / "tr_flush_bits_630b9c0_115.py"
START, END = 0x630B9C0, 0x630BA48


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def check_manifest():
    rows = [r.split(None, 1) for r in
            (PACKET / "MANIFEST.sha256").read_text().splitlines() if r.strip()]
    assert rows, "empty manifest"
    for digest, rel in rows:
        # Packet-local rows are relative to this directory; the model and the
        # tests live outside it and are recorded repo-root-relative.
        p = (PACKET / rel)
        p = p if p.is_file() else (ROOT / rel)
        p = p.resolve()
        assert p.is_file(), f"manifest names a missing file: {rel}"
        got = hashlib.sha256(p.read_bytes()).hexdigest()
        assert got == digest, f"hash mismatch: {rel}"
    inside = {str((PACKET / r).resolve()) for _, r in rows
              if (PACKET / r).is_file()}
    on_disk = {str(p.resolve()) for p in PACKET.rglob("*")
               if p.is_file() and p.name != "MANIFEST.sha256"
               and "__pycache__" not in p.parts}
    assert inside == on_disk, ("files not in the manifest: "
                               f"{sorted(on_disk - inside)}; "
                               f"manifest rows without a file: "
                               f"{sorted(inside - on_disk)}")
    return len(rows)


def va_to_off(va):
    out = subprocess.check_output(["readelf", "-lW", str(BINARY)]).decode()
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            v, o, f = int(p[2], 16), int(p[1], 16), int(p[4], 16)
            if v <= va < v + f:
                return o + (va - v)
    raise ValueError(hex(va))


def window_bytes():
    data = BINARY.read_bytes()
    return data[va_to_off(START):va_to_off(END)]


def check_excerpt():
    tool = load(TOOL, "ev")
    insns = tool.instruction_stream()
    blob = b"".join(i.raw for i in insns)
    assert blob == window_bytes(), "the committed excerpt is not the routine's bytes"
    assert insns[0].addr == START and insns[0].mnemonic == "endbr64"
    assert insns[-1].end() == END
    assert (PACKET / "main.txt").read_text().splitlines()[0].startswith(
        f"{START:016x} <")
    frames = (PACKET / "frames.txt").read_text()
    assert f"pc={START:016x}..{END:016x}" in frames, "FDE bound missing"
    reloc = (PACKET / "relocations.txt").read_text()
    assert "no relocations" in reloc
    digest = hashlib.sha256(blob).hexdigest()
    assert digest in reloc, "the excerpt digest is not the recorded body digest"
    return len(insns), digest


def check_semantics():
    sem = load(PACKET / "semantics.py", "sem")
    assert sem.START == START and sem.END == END
    rows = sem.rows()
    assert len(rows) >= 20, len(rows)
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td) / "semantics.tsv"
        sem.write(tmp)
        assert tmp.read_text() == (PACKET / "semantics.tsv").read_text(), \
            "semantics.tsv is stale: regenerate with semantics.py"
    data = BINARY.read_bytes()
    vas = set()
    for r in rows:
        va = int(r["va"], 16)
        assert START <= va < END, r
        raw = data[va_to_off(va):va_to_off(va) + int(r["size"])]
        assert raw.hex() == r["bytes"], f"anchor bytes differ at {r['va']}"
        vas.add(va)
    for required in (0x630B9C4, 0x630B9CD, 0x630B9D2, 0x630B9EB, 0x630B9EE,
                     0x630B9F5, 0x630BA36, 0x630BA3D):
        assert required in vas, hex(required)
    return len(rows)


def check_census():
    lines = (PACKET / "callers.tsv").read_text().splitlines()
    assert lines[0].split("\t") == ["site", "kind", "caller_fde_start",
                                    "caller_fde_end"]
    callers = [l.split("\t") for l in lines[1:] if l.strip()]
    assert len(callers) == 26, f"expected 26 callers, got {len(callers)}"
    for site, kind, f0, f1 in callers:
        assert kind == "call", callers
        assert int(f0, 16) < int(site, 16) <= int(f1, 16), callers
    uses = [l.split("\t") for l in
            (PACKET / "caller_use.tsv").read_text().splitlines()[1:] if l.strip()]
    assert len(uses) == len(callers), "one consumer row per call site"
    seen = {}
    for u in uses:
        seen[u[1]] = seen.get(u[1], 0) + 1
    assert seen == {"overwritten": 26}, seen
    # every site discards rax: the census class is only the "discarded" one
    assert set(seen) <= {"dead", "overwritten"}, seen
    rec = __import__("json").loads((PACKET / "records.json").read_text())
    census = rec["caller_census"]
    assert census["direct_calls"] == len(callers)
    assert census["discarded_sites"] == len(uses)
    assert census["sites_reading_the_return"] == 0, seen
    contract = census["contract"]
    assert contract.startswith("void-style"), contract
    return len(callers), len(uses), seen


def check_model():
    tool = load(TOOL, "ev")
    # the three-way dispatch, boundaries first
    assert tool.flush_bits(0, 0x1234, 5) == (0, 0x1234, 5, [], 0)
    assert tool.flush_bits(7, 0x1234, 5) == (7, 0x1234, 5, [], 7)
    assert tool.flush_bits(8, 0x1234, 5) == (0, 0x12, 6, [0x34], 5)
    assert tool.flush_bits(0xF, 0xABCD, 0) == (7, 0xAB, 1, [0xCD], 0)
    assert tool.flush_bits(0x10, 0x1234, 5) == (0, 0, 7, [0x34, 0x12], 0)
    assert tool.flush_bits(0x10, 0xFF00, 2) == (0, 0, 4, [0x00, 0xFF], 0)
    # out-of-range POSITIVE values take the one-byte path
    for v, new_v in ((17, 9), (18, 10), (23, 15), (24, 16), (100, 92)):
        got = tool.flush_bits(v, 0x1234, 0)
        assert got[:2] == (new_v, 0x12) and got[3] == [0x34], (v, got)
    # the SIGNED test: anything with bit 31 set emits nothing, unchanged
    for v in (0x80000000, 0x80000001, 0xFFFFFFFE, 0xFFFFFFFF):
        assert tool.flush_bits(v, 0xFFFF, 3) == (v, 0xFFFF, 3, [], v), hex(v)
    # the three rax leftovers
    assert tool.flush_bits(3, 0, 7)[4] == 3          # nothing to do -> bi_valid
    assert tool.flush_bits(9, 0, 7)[4] == 7          # one byte      -> old pending
    assert tool.flush_bits(0x10, 0, 7)[4] == 0       # two bytes     -> 0
    # the emit addresses: ascending, at the PRE-increment index
    _, stores = tool.flush_accesses(9, 0x1234, 4)
    assert [(a, s) for a, s in stores
            if tool.BUFFER <= a < tool.BUFFER + 0x100] == [(0x8004, 1)], stores
    _, stores = tool.flush_accesses(0x10, 0x1234, 4)
    assert [(a, s) for a, s in stores
            if tool.BUFFER <= a < tool.BUFFER + 0x100] == [(0x8004, 1),
                                                           (0x8005, 1)], stores
    sweep = tool.generate_cases()
    assert len(sweep) == 2400, len(sweep)
    fams = {}
    for c in sweep:
        fams[c["family"]] = fams.get(c["family"], 0) + 1
        assert tool.flush_bits(c["bi_valid"], c["bi_buf"], c["pending"]) == \
            tool.flush_bits_decoded(c["bi_valid"], c["bi_buf"],
                                    c["pending"]), c
    assert fams == {f: 480 for f in tool.FAMILIES}, fams
    ledger = tool.ledger_rows()
    assert len(ledger) == 300, len(ledger)
    assert [r["id"] for r in ledger] == list(range(1, 301))
    per = {}
    for r in ledger:
        ans = tool.replay_case(r)
        assert (r["new_bi_valid"], r["new_bi_buf"], r["new_pending"],
                r["emitted"], r["leftover"]) == ans, r
        per[r["family"]] = per.get(r["family"], 0) + 1
    assert per == {f: 60 for f in tool.FAMILIES}, per
    committed = (PACKET / "cases.tsv").read_text().splitlines()
    assert len(committed) == 1 + len(ledger), len(committed)
    return len(ledger), len(sweep), per


def main():
    rows = check_manifest()
    insns, digest = check_excerpt()
    anchors = check_semantics()
    callers, consumers, seen = check_census()
    ledger, sweep, per = check_model()
    print(f"verify OK: {rows} manifest rows, {callers} callers / {consumers} "
          f"consumers {seen}, {anchors} claim anchors, model + {ledger}-case "
          f"ledger {per} + excerpt ({insns} instructions, body {digest[:12]}…, "
          f"{sweep}-case sweep)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
