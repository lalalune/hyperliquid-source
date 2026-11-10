#!/usr/bin/env python3
"""Self-check for the EncodeVarint32 evidence packet.

Re-reads every claim in this directory against the digest-verified artifact and
re-runs the model against decoded execution of the routine's own bytes.

Run: python3 research/work-items/RE-002-node115-rocksdb-encode-varint32-61bd410-115/verify.py
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
TOOL = ROOT / "tools" / "encode_varint32_61bd410_115.py"
START, END = 0x61BD410, 0x61BD4E9


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
    assert len(rows) >= 15, len(rows)
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
    for required in (0x61BD417, 0x61BD41C, 0x61BD474, 0x61BD4A0,
                     0x61BD4CB, 0x61BD423):
        assert required in vas, hex(required)
    return len(rows)


def check_census():
    lines = (PACKET / "callers.tsv").read_text().splitlines()
    assert lines[0].split("\t") == ["site", "kind", "caller_fde_start",
                                    "caller_fde_end"]
    callers = [l.split("\t") for l in lines[1:] if l.strip()]
    assert len(callers) == 165, f"expected 165 callers, got {len(callers)}"
    for site, kind, f0, f1 in callers:
        assert kind == "call", callers
        assert int(f0, 16) < int(site, 16) <= int(f1, 16), callers
    uses = [l.split("\t") for l in
            (PACKET / "caller_use.tsv").read_text().splitlines()[1:] if l.strip()]
    assert len(uses) == len(callers), "one consumer row per call site"
    seen = {}
    for u in uses:
        seen[u[1]] = seen.get(u[1], 0) + 1
    assert seen == {"arithmetic": 139, "register-copy": 24, "store": 2}, seen
    assert not any(u[1] == "overwritten" for u in uses), \
        "no call site discards the end pointer"
    rec = __import__("json").loads((PACKET / "records.json").read_text())
    contract = rec["caller_census"]["contract"]
    assert contract.startswith("returns dst+n"), contract
    sub = [u for u in uses if u[3].startswith("sub rax,")]
    assert rec["caller_census"]["arithmetic_sites_recovering_the_length"] == len(sub)
    return len(callers), len(uses), seen


def check_model():
    tool = load(TOOL, "ev")
    # the five classes, at each boundary and one past it
    assert tool.varint_len(0) == 1 and tool.varint_len(0x7F) == 1
    assert tool.varint_len(0x80) == 2 and tool.varint_len(0x3FFF) == 2
    assert tool.varint_len(0x4000) == 3 and tool.varint_len(0x1FFFFF) == 3
    assert tool.varint_len(0x200000) == 4 and tool.varint_len(0x0FFFFFFF) == 4
    assert tool.varint_len(0x10000000) == 5 and tool.varint_len(0xFFFFFFFF) == 5
    # the encoded bytes at the same points
    assert tool.encode_varint32(0x80) == [0x80, 0x01]
    assert tool.encode_varint32(0x3FFF) == [0xFF, 0x7F]
    assert tool.encode_varint32(0x4000) == [0x80, 0x80, 0x01]
    assert tool.encode_varint32(0x1FFFFF) == [0xFF, 0xFF, 0x7F]
    assert tool.encode_varint32(0x200000) == [0x80, 0x80, 0x80, 0x01]
    assert tool.encode_varint32(0x0FFFFFFF) == [0xFF, 0xFF, 0xFF, 0x7F]
    assert tool.encode_varint32(0x10000000) == [0x80, 0x80, 0x80, 0x80, 0x01]
    assert tool.encode_varint32(0xFFFFFFFF) == [0xFF] * 4 + [0x0F]
    # the 4-byte class is the single-32-bit-store class
    assert tool.uses_single_32bit_store(0x200000)
    assert tool.uses_single_32bit_store(0x0FFFFFFF)
    assert not any(tool.uses_single_32bit_store(v) for v in
                   (0, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1FFFFF,
                    0x10000000, 0xFFFFFFFF))
    sweep = tool.generate_cases()
    assert len(sweep) == 2400, len(sweep)
    fams = {}
    for c in sweep:
        fams[c["family"]] = fams.get(c["family"], 0) + 1
        assert tool.encode_varint32(c["value"]) == \
            tool.encode_varint32_decoded(c["value"]), hex(c["value"])
    assert fams == {"one": 480, "two": 480, "three": 480, "four": 480,
                    "five": 480}, fams
    ledger = tool.ledger_rows()
    assert len(ledger) == 300, len(ledger)
    assert [r["id"] for r in ledger] == list(range(1, 301))
    per = {}
    for r in ledger:
        assert tool.replay_case(r) == r["bytes"], r
        assert tool.encode_varint32_decoded(r["value"]) == r["bytes"], r
        per[r["family"]] = per.get(r["family"], 0) + 1
        assert r["nbytes"] == len(r["bytes"])
        assert r["store32"] == (r["nbytes"] == 4)
    assert per == {"one": 60, "two": 60, "three": 60, "four": 60, "five": 60}, per
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
