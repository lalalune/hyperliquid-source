#!/usr/bin/env python3
"""Self-check for the MaxFileSizeForL0MetaPin evidence packet.

Re-reads every claim in this directory against the digest-verified artifact
and re-runs the model against decoded execution of the routine's own bytes.

Run: python3 research/work-items/RE-002-node115-rocksdb-max-file-size-for-l0-meta-pin-607f490-115/verify.py
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
TOOL = ROOT / "tools" / "max_file_size_for_l0_meta_pin_607f490_115.py"
START, END = 0x607F490, 0x607F4BB


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
    # Rows inside the packet must be exactly the packet's files; rows that
    # point outside it (the model under tools/, the tests) must exist too.
    root = str(PACKET) + "/"
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


def check_excerpt():
    data = BINARY.read_bytes()
    off = va_to_off(START)
    blob = data[off:va_to_off(END)]
    tool = load(TOOL, "l0meta")
    insns = tool.instruction_stream()
    assert b"".join(i.raw for i in insns) == blob, \
        "the committed excerpt is not the routine's bytes"
    assert insns[0].addr == START and insns[-1].end() == END
    text = (PACKET / "main.txt").read_text().splitlines()
    assert text[0].startswith(f"{START:016x} <"), text[0]
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
    assert len(rows) >= 8, len(rows)
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td) / "semantics.tsv"
        sem.write(tmp)
        assert tmp.read_text() == (PACKET / "semantics.tsv").read_text(), \
            "semantics.tsv is stale: regenerate with semantics.py"
    data = BINARY.read_bytes()
    for r in rows:
        va = int(r["va"], 16)
        off = va_to_off(va)
        raw = data[off:off + int(r["size"])]
        assert raw.hex() == r["bytes"], f"anchor bytes differ at {r['va']}"
    return len(rows)


def check_census():
    callers = [l for l in (PACKET / "callers.tsv").read_text().splitlines()[1:]
               if l.strip()]
    assert len(callers) == 12, f"expected 12 callers, got {len(callers)}"
    for line in callers:
        site, kind, f0, f1 = line.split("\t")
        assert kind == "call", line
        assert int(site, 16) and int(f0, 16) < int(site, 16) <= int(f1, 16), line
    uses = [l.split("\t") for l in
            (PACKET / "caller_use.tsv").read_text().splitlines()[1:] if l.strip()]
    assert len(uses) == len(callers), "one consumer row per call site"
    seen = {}
    for u in uses:
        seen[u[1]] = seen.get(u[1], 0) + 1
    assert seen == {"register-copy": 4, "stack-arg": 4, "store": 3,
                    "overwritten": 1}, seen
    return len(callers), len(uses), seen


def check_model():
    tool = load(TOOL, "l0meta")
    G = tool.GUARD
    assert tool.max_file_size_for_l0_meta_pin(G) == tool.SENTINEL  # exact
    assert tool.max_file_size_for_l0_meta_pin(G + 1) == tool.SENTINEL
    assert tool.max_file_size_for_l0_meta_pin(5) == 6      # truncated half
    assert tool.max_file_size_for_l0_meta_pin(6) == 9
    for v in (0, 1, 2, 3, 0xFFFF, 1 << 63):
        assert tool.max_file_size_for_l0_meta_pin(v) == 3 * (v >> 1), hex(v)
    ledger = tool.ledger_rows()
    assert len(ledger) == 300, len(ledger)
    assert [r["id"] for r in ledger] == list(range(1, 301))
    sweep = tool.generate_cases()
    assert len(sweep) == 2400, len(sweep)
    for c in sweep:
        v = c["value"]
        assert tool.max_file_size_for_l0_meta_pin(v) == \
            tool.max_file_size_for_l0_meta_pin_decoded(v), hex(v)
    for r in ledger:
        assert tool.replay_case(r) == r["expected"], r
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
          f"consumers, {anchors} claim anchors, model + {ledger}-case ledger + "
          f"excerpt ({insns} instructions, body {digest[:12]}…, "
          f"{sweep}-case sweep)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
