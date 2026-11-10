#!/usr/bin/env python3
"""Self-check for the BIT_reloadDStream_internal evidence packet.

Re-reads every claim in this directory against the digest-verified artifact and
re-runs the model against decoded execution of the routine's own bytes.

Run: python3 research/work-items/RE-002-node115-zstd-bit-reload-dstream-internal-628f710-115/verify.py
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
TOOL = ROOT / "tools" / "bit_reload_dstream_internal_628f710_115.py"
START, END = 0x628F710, 0x628F732


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
    assert insns[0].addr == START and insns[0].mnemonic == "mov"
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
    assert len(rows) >= 12, len(rows)
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
    for required in (0x628F710, 0x628F719, 0x628F71C, 0x628F722, 0x628F729,
                     0x628F72C, 0x628F72F):
        assert required in vas, hex(required)
    return len(rows)


def check_census():
    lines = (PACKET / "callers.tsv").read_text().splitlines()
    assert lines[0].split("\t") == ["site", "kind", "caller_fde_start",
                                    "caller_fde_end"]
    callers = [l.split("\t") for l in lines[1:] if l.strip()]
    assert len(callers) == 16, f"expected 16 callers, got {len(callers)}"
    for site, kind, f0, f1 in callers:
        assert kind == "call", callers
        assert int(f0, 16) < int(site, 16) <= int(f1, 16), callers
    uses = [l.split("\t") for l in
            (PACKET / "caller_use.tsv").read_text().splitlines()[1:] if l.strip()]
    assert len(uses) == len(callers), "one consumer row per call site"
    seen = {}
    for u in uses:
        seen[u[1]] = seen.get(u[1], 0) + 1
    assert seen == {"dead": 6, "overwritten": 10}, seen
    # the census classes are only the two "discarded" ones: no site reads rax
    assert set(seen) <= {"dead", "overwritten"}, seen
    rec = __import__("json").loads((PACKET / "records.json").read_text())
    census = rec["caller_census"]
    assert census["direct_calls"] == len(callers)
    assert census["discarded_sites"] == len(uses)
    assert census["sites_reading_the_return"] == 0, seen
    contract = census["contract"]
    assert contract.startswith("returns the constant 0"), contract
    return len(callers), len(uses), seen


def check_model():
    tool = load(TOOL, "ev")
    PTR = tool.PTR_BASE
    # the split: the sub-byte remainder survives, the whole bytes rewind
    assert tool.reload(0, 0x11, PTR) == (0x11, 0, PTR, 0)
    assert tool.reload(7, 0x11, PTR) == (0x11, 7, PTR, 0)
    assert tool.reload(8, 0x11, PTR) == (0x11, 0, PTR - 1, 0)
    assert tool.reload(0x10, 0x11, PTR) == (0x11, 0, PTR - 2, 0)
    assert tool.reload(9, 0x11, PTR) == (0x11, 1, PTR - 1, 0)
    assert tool.reload(0xFFFFFFFF, 0x11, PTR) == (0x11, 7, PTR - 0x1FFFFFFF, 0)
    assert tool.reload(0x80000000, 0x11, PTR) == (0x11, 0, PTR - 0x10000000, 0)
    # the container is the word read at the rewound pointer, and the status is 0
    for bits in (0, 1, 7, 8, 9, 0x1234, 0xFFFFFFFF):
        assert tool.reload(bits, 0xABCDEF, PTR)[0] == 0xABCDEF
        assert tool.reload(bits, 0xABCDEF, PTR)[3] == 0
    # the access claim: one 8-byte load at the rewound pointer, three struct stores
    loads, stores = tool.access_addresses(9, 0x1122334455667788)
    self_ptr = PTR - 1
    assert (self_ptr, 8) in loads, loads
    assert len([x for x in loads if x[1] == 8 and x[0] == self_ptr]) == 1
    assert sorted(s for _, s in stores) == [4, 8, 8], stores
    # the body has no comparison and no conditional branch: status is constant
    insns = tool.instruction_stream()
    assert not any(i.mnemonic in ("cmp", "test") for i in insns)
    assert not any(i.mnemonic.startswith("j") for i in insns)
    sweep = tool.generate_cases()
    assert len(sweep) == 2400, len(sweep)
    fams = {}
    for c in sweep:
        fams[c["family"]] = fams.get(c["family"], 0) + 1
        assert tool.reload(c["bits"], c["word"], PTR) == \
            tool.reload_decoded(c["bits"], c["word"], PTR), c
    assert fams == {"sub_byte": 600, "aligned": 600, "mixed": 600,
                    "extreme": 600}, fams
    ledger = tool.ledger_rows()
    assert len(ledger) == 300, len(ledger)
    assert [r["id"] for r in ledger] == list(range(1, 301))
    per = {}
    for r in ledger:
        ans = tool.replay_case(r)
        assert (r["container"], r["bits_after"], r["new_ptr"],
                r["status"]) == ans, r
        assert r["bytes_consumed"] == r["bits"] >> tool.BIT_SHIFT, r
        assert r["bits_after"] == r["bits"] & tool.BIT_MASK, r
        assert r["status"] == tool.STATUS_UNFINISHED, r
        per[r["family"]] = per.get(r["family"], 0) + 1
    assert per == {f: 75 for f in tool.FAMILIES}, per
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
