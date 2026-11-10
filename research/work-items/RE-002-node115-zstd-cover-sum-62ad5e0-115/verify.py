#!/usr/bin/env python3
"""Self-check for the COVER_sum evidence packet.

Re-reads every claim in this directory against the digest-verified artifact and
re-runs the model against decoded execution of the routine's own bytes.

Run: python3 research/work-items/RE-002-node115-zstd-cover-sum-62ad5e0-115/verify.py
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
TOOL = ROOT / "tools" / "cover_sum_62ad5e0_115.py"
START, END = 0x62AD5E0, 0x62AD641
CALLER_FDE = ("0x62ac520", "0x62ac9c9")


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
    tool = load(TOOL, "cover")
    insns = tool.instruction_stream()
    blob = b"".join(i.raw for i in insns)
    assert blob == window_bytes(), "the committed excerpt is not the routine's bytes"
    assert insns[0].addr == START and insns[0].mnemonic == "endbr64"
    assert insns[-1].end() == END and insns[-1].mnemonic == "jmp"
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
    for required in (0x62AD5E6, 0x62AD5EB, 0x62AD608, 0x62AD623, 0x62AD62C):
        assert required in vas, hex(required)
    return len(rows)


def check_census():
    lines = (PACKET / "callers.tsv").read_text().splitlines()
    assert lines[0].split("\t") == ["site", "kind", "caller_fde_start",
                                    "caller_fde_end"]
    callers = [l.split("\t") for l in lines[1:] if l.strip()]
    assert len(callers) == 3, f"expected 3 callers, got {len(callers)}"
    for site, kind, f0, f1 in callers:
        assert kind == "call", callers
        assert int(f0, 16) < int(site, 16) <= int(f1, 16), callers
        assert (f0, f1) == CALLER_FDE, (f0, f1)
    uses = [l.split("\t") for l in
            (PACKET / "caller_use.tsv").read_text().splitlines()[1:] if l.strip()]
    assert len(uses) == len(callers), "one consumer row per call site"
    seen = {}
    for u in uses:
        seen[u[1]] = seen.get(u[1], 0) + 1
    assert seen == {"register-copy": 2, "store": 1}, seen
    return len(callers), len(uses), seen


def check_model():
    tool = load(TOOL, "cover")
    m64 = (1 << 64) - 1
    assert tool.cover_sum([], 0) == 0
    assert tool.cover_sum([7, 9], 1) == 7                 # n == 1 path
    assert tool.cover_sum([1, 2, 3], 2) == 3              # vector path only
    assert tool.cover_sum([1, 2, 3], 3) == 6              # plus the tail add
    assert tool.cover_sum([m64, 1], 2) == 0               # wraps modulo 2**64
    assert tool.cover_sum([m64, 1, 2], 3) == 2
    sweep = tool.generate_cases()
    assert len(sweep) == 2400, len(sweep)
    fams = {}
    for c in sweep:
        fams[c["family"]] = fams.get(c["family"], 0) + 1
        assert tool.cover_sum(c["splits"], c["n"]) == \
            tool.cover_sum_decoded(c["splits"], c["n"]), c
    assert fams == {"empty": 600, "single": 600, "pairs": 600, "odd": 600}, fams
    ledger = tool.ledger_rows()
    assert len(ledger) == 300, len(ledger)
    assert [r["id"] for r in ledger] == list(range(1, 301))
    for r in ledger:
        assert tool.replay_case(r) == r["expected"], r
        assert tool.cover_sum_decoded(r["splits"], r["n"]) == r["expected"], r
    committed = (PACKET / "cases.tsv").read_text().splitlines()
    assert len(committed) == 1 + len(ledger), len(committed)
    return len(ledger), len(sweep)


def main():
    rows = check_manifest()
    insns, digest = check_excerpt()
    anchors = check_semantics()
    callers, consumers, seen = check_census()
    ledger, sweep = check_model()
    print(f"verify OK: {rows} manifest rows, {callers} callers / {consumers} "
          f"consumers {seen}, {anchors} claim anchors, model + {ledger}-case "
          f"ledger + excerpt ({insns} instructions, body {digest[:12]}…, "
          f"{sweep}-case sweep)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
