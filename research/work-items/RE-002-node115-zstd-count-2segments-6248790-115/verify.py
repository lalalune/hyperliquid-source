#!/usr/bin/env python3
"""Self-check for the ZSTD_count_2segments evidence packet.

Run: python3 research/work-items/RE-002-node115-zstd-count-2segments-6248790-115/verify.py

Checks, in order: every MANIFEST.sha256 row against its file; the committed
excerpt against the digest-verified artifact; every claim anchor's bytes;
the caller census, the consumer classification and the contract; the model
against the committed ledger and the 2,400-case sweep.
"""
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

import capstone

ROOT = Path(__file__).resolve().parents[3]
PACKET = (ROOT / "research" / "work-items"
          / "RE-002-node115-zstd-count-2segments-6248790-115")
TOOL = ROOT / "tools" / "zstd_count_2segments_6248790_115.py"
BINARY = ROOT / "artifacts" / "node" / "115" / "hl-node"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
START = 0x6248790
END = 0x624899A

# the anchors a reader should be able to find without the rest of the packet
REQUIRED_ANCHORS = (0x6248790, 0x6248793, 0x6248797, 0x62487A4, 0x62487A8,
                    0x62487E1, 0x62487F3, 0x62487FB, 0x6248836, 0x624884A,
                    0x6248863, 0x6248886, 0x62488E8)

EXPECTED_CONSUMERS = {"arithmetic": 44, "register-copy": 12}

# The nine call sites whose first read of %rax is a memory-base use; the
# classifier missed them until the 2026-11-10 review (see `classify_rax_use`).
MEMORY_BASE_SITES = ("0x62630db", "0x6263b5b", "0x6268009", "0x62690a9",
                     "0x626e999", "0x626ff19", "0x6273f9d", "0x627559a",
                     "0x627789b")


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


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


def va_to_off(va):
    out = subprocess.check_output(["readelf", "-lW", str(BINARY)]).decode()
    for line in out.splitlines():
        p = line.split()
        if p and p[0] == "LOAD":
            v, o, f = int(p[2], 16), int(p[1], 16), int(p[4], 16)
            if v <= va < v + f:
                return o + (va - v)
    raise AssertionError(f"{va:#x} is not in any LOAD segment")


def window_bytes():
    data = BINARY.read_bytes()
    return data[va_to_off(START):va_to_off(END)]


def check_excerpt():
    tool = load(TOOL, "ev_tool_excerpt")
    insns = tool.instruction_stream()
    blob = b"".join(i.raw for i in insns)
    assert blob == window_bytes(), "the committed excerpt is not the routine's bytes"
    # the body starts with `mov %rdx,%r9`, NOT endbr64: no CET landing pad here
    assert insns[0].addr == START, insns[0]
    assert insns[0].mnemonic == "mov" and insns[0].op_str == "%rdx,%r9", insns[0]
    assert not any(i.mnemonic == "endbr64" for i in insns), \
        "this routine has no CET landing pad"
    # ... and the four bytes below the window are int3 padding, so the window
    # boundary is a real function start
    data = BINARY.read_bytes()
    assert data[va_to_off(START) - 4:va_to_off(START)] == b"\xcc\xcc\xcc\xcc"
    assert insns[-1].end() == END, insns[-1]
    assert len(insns) == 150, len(insns)
    assert (PACKET / "main.txt").read_text().splitlines()[0].startswith(
        f"{START:016x} <"), "the excerpt header is not the bound address"
    frames = (PACKET / "frames.txt").read_text()
    assert f"pc={START:016x}..{END:016x}" in frames, "FDE bound missing"
    reloc = (PACKET / "relocations.txt").read_text()
    assert "no relocations" in reloc
    assert DIGEST[:16] in reloc or hashlib.sha256(window_bytes()).hexdigest() \
        in reloc, "the excerpt digest is not the recorded body digest"
    digest = hashlib.sha256(window_bytes()).hexdigest()
    assert digest in reloc, "the excerpt digest is not the recorded body digest"
    return len(insns), digest


def check_semantics():
    sem = load(PACKET / "semantics.py", "ev_semantics")
    assert sem.START == START and sem.END == END
    rows = sem.rows()
    assert len(rows) >= 20, len(rows)
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        sem.write(Path(tmp) / "semantics.tsv")
        assert (Path(tmp) / "semantics.tsv").read_text() == \
            (PACKET / "semantics.tsv").read_text(), "semantics.tsv is stale"
    data = BINARY.read_bytes()
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    vas = set()
    for r in rows:
        va = int(r["va"], 16)
        assert START <= va < END, r
        off = va_to_off(va)
        ins = next(iter(md.disasm(data[off:off + 15], va)))
        raw = data[off:off + ins.size]
        assert raw.hex() == r["bytes"], f"anchor bytes differ at {r['va']}"
        vas.add(va)
    for required in REQUIRED_ANCHORS:
        assert required in vas, hex(required)
    return len(rows)


def check_census():
    lines = (PACKET / "callers.tsv").read_text().splitlines()
    assert lines[0].split("\t") == ["site", "kind", "caller_fde_start",
                                    "caller_fde_end"]
    callers = [l.split("\t") for l in lines[1:] if l.strip()]
    assert len(callers) == 56, f"expected 56 callers, got {len(callers)}"
    for site, kind, f0, f1 in callers:
        assert kind == "call", callers
        assert int(f0, 16) < int(site, 16) <= int(f1, 16), callers
    uses = [l.split("\t") for l in
            (PACKET / "caller_use.tsv").read_text().splitlines()[1:] if l.strip()]
    assert len(uses) == len(callers), "one consumer row per call site"
    seen = {}
    for u in uses:
        seen[u[1]] = seen.get(u[1], 0) + 1
    assert seen == EXPECTED_CONSUMERS, seen
    # Every call site really does read the count: the first use must name a rax
    # register, and no site may be classified as a discarded call. This is the
    # non-tautological form of "all 56 sites consume the return" - the previous
    # version compared census["sites_reading_the_return"] with len(callers),
    # which the census had itself derived from len(callers).
    tokens = {"rax", "eax", "ax", "al", "ah"}
    memory_base = set()
    for u in uses:
        assert u[1] not in ("overwritten", "dead"), (
            f"{u[0]} discards the count ({u[1]})")
        assert tokens & set(re.split(r"[^a-z0-9]+", u[3].lower())), (
            f"{u[0]}: the first use does not read a rax register: {u[3]}")
        if "[rax" in u[3].replace(" ", ""):
            memory_base.add(u[0])
    missing = [s for s in MEMORY_BASE_SITES if s not in memory_base]
    assert not missing, f"memory-base reads not detected at {missing}"
    rec = json.loads((PACKET / "records.json").read_text())
    census = rec["caller_census"]
    assert census["direct_calls"] == len(callers)
    assert census["tail_jumps"] == 0
    assert census["consumers"] == seen, census["consumers"]
    assert census["sites_reading_the_return"] == len(callers), census
    contract = census["contract"]
    assert contract.startswith("value-returning"), contract
    return len(callers), len(uses), seen


def check_model():
    tool = load(TOOL, "ev_tool_model")
    # a planted prefix that never reaches mEnd: the first-segment count
    for n, tail, dist, p1, want in ((8, 16, 16, 0, 0), (8, 16, 16, 1, 1),
                                    (16, 8, 16, 7, 7), (4, 4, 8, 3, 3)):
        c = {"family": "prefix", "n": n, "tail": tail, "dist": dist,
             "plant1": p1, "plant2": 0}
        b = tool._case(c)
        got = tool.count_2segments(b["mem"], b["geometry"])
        assert got == (want, want, 0, False), (c, got)
        assert tool.count_2segments_decoded(b["mem"], b["geometry"]) == want, c
    # a planted wrap: len1 + len2, and the count is the INPUT-side length
    for n, tail, dist, p1, p2, want in ((16, 4, 16, 4, 0, 4),
                                        (16, 4, 16, 4, 1, 5),
                                        (32, 8, 40, 8, 3, 11),
                                        (16, 1, 16, 1, 7, 8)):
        c = {"family": "wrap", "n": n, "tail": tail, "dist": dist,
             "plant1": p1, "plant2": p2}
        b = tool._case(c)
        got = tool.count_2segments(b["mem"], b["geometry"])
        assert got == (want, tail, want - tail, True), (c, got)
        assert tool.count_2segments_decoded(b["mem"], b["geometry"]) == want, c
    # an empty tail wraps immediately
    b = tool._case({"family": "empty_tail", "n": 8, "tail": 0, "dist": 8,
                    "plant1": 0, "plant2": 8})
    assert tool.count_2segments(b["mem"], b["geometry"]) == (8, 0, 8, True)
    # The routine writes no caller memory. The emulator keeps pushes on its own
    # stack, so the store capture alone is vacuous evidence (a 2026-11-10 review
    # point): the decoded stream is what pins it - no instruction has a memory
    # destination, and the only implicit memory writes are the two callee-saved
    # spills, matched by four pops on the two return paths.
    from capstone.x86_const import X86_OP_MEM
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    stream = list(md.disasm(window_bytes(), START))
    assert len(stream) == 150, len(stream)
    explicit_stores = [f"{i.mnemonic} {i.op_str}" for i in stream
                       if i.operands and i.operands[0].type == X86_OP_MEM
                       and i.mnemonic not in ("cmp", "test", "lea", "nop")]
    assert explicit_stores == [], explicit_stores
    assert [i.op_str for i in stream if i.mnemonic == "push"] == ["rbp", "rbx"]
    assert [i.op_str for i in stream if i.mnemonic == "pop"] == [
        "rbx", "rbp", "rbx", "rbp"]
    b = tool._case({"family": "wrap", "n": 32, "tail": 8, "dist": 40,
                    "plant1": 8, "plant2": 3})
    loads, stores = tool.accesses(b["mem"], b["geometry"])
    assert stores == [], stores
    assert loads, "the routine must read something"
    assert {s for _, s in loads} <= {1, 2, 4, 8}, loads
    sweep = tool.generate_cases()
    assert len(sweep) == 2400, len(sweep)
    fams = {}
    for c in sweep:
        fams[c["family"]] = fams.get(c["family"], 0) + 1
        b = tool._case(c)
        model = tool.count_2segments(b["mem"], b["geometry"])
        decoded = tool.count_2segments_decoded(b["mem"], b["geometry"])
        assert model[0] == decoded, (c, model, decoded)
    assert fams == {f: 480 for f in tool.FAMILIES}, fams
    ledger = tool.ledger_rows()
    assert len(ledger) == 300, len(ledger)
    assert [r["id"] for r in ledger] == list(range(1, 301))
    per = {}
    for r in ledger:
        assert tool.replay_case(r) == r["expected"], r
        assert r["len1"] + r["len2"] == r["expected"], r
        if not r["wrapped"]:
            assert r["len2"] == 0, r
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
          f"ledger {per} + excerpt ({insns} instructions, body {digest[:12]}..., "
          f"{sweep}-case sweep)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
