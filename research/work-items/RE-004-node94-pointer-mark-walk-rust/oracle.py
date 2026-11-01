"""Pre-Rust immutable-orbit / first-barrier oracle; never executes target code."""
import datetime
import gzip
import hashlib
import itertools
import json
from pathlib import Path
import random
import struct
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections
import foundation_pointer_mark_walk as prior
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, __version__ as capstone_version

MAX, MASK = 2**64 - 1, 2**56 - 1
CALLER_HASHES = (
    "534a1c396c12bf55f9ec60e58f574359700b85dcae92b019cb39745be79d8a97",
    "e4c79a86a391f0cf0bbeae2e9e08a03edeaaa8b01364170a3ac46bcb3e6c9eb3",
    "5e0dafc940f3f34ef4dfdddcd29bb49e67a8d9ed7230dd72fa99ffeac2c437af",
    "d1200655f120f04341c8137238c24fc7647c180005b32bf6a9622e9017990f92",
)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def mapping(data):
    secs = sections(data)

    def offset(va, size):
        found = [s for s in secs if s["type"] != 8 and s["address"] <= va
                 and va + size <= s["address"] + s["size"]]
        require(len(found) == 1, "VA mapping is not unique")
        return found[0]["offset"] + va - found[0]["address"]

    return secs, offset


def structure(data):
    secs, offset = mapping(data)
    read = lambda va, size: data[offset(va, size):offset(va, size) + size]
    eh = next(s for s in secs if s["name"] == ".eh_frame")
    for relative, raw in ((0, prior.CIE0), (0x6205d0, prior.CIE2)):
        require(read(eh["address"] + relative, len(raw)) == raw, "CIE changed")
    frames = []
    for relative, raw, start, end in [(0x297df0, prior.FDE, prior.START, prior.END),
                                     (0x297e04, prior.NEXT, prior.PAD_END, 0x50e6ab4),
                                     *prior.CALLER_FDES]:
        record = read(eh["address"] + relative, len(raw))
        require(record == raw, "FDE bytes changed")
        pc = eh["address"] + relative + 8 + struct.unpack_from("<i", record, 8)[0]
        extent = struct.unpack_from("<I", record, 12)[0]
        require((pc, pc + extent) == (start, end), "FDE extent changed")
        cie = relative + 4 - struct.unpack_from("<I", record, 4)[0]
        require(cie == (0 if relative in (0x297df0, 0x297e04) else 0x6205d0), "CIE pointer changed")
        frames.append({"offset": hex(relative), "start": hex(start), "end": hex(end),
                       "record_hex": record.hex(), "cie_offset": hex(cie)})
    body = read(prior.START, prior.END - prior.START)
    require(body == prior.BODY, "Complete leaf body changed")
    require(read(prior.END, 14) == b"\xcc" * 14, "Leaf padding changed")
    require(read(prior.START - 7, 7) == b"\xcc" * 7, "Preceding gap changed")
    decoded = []
    hashes = []
    for ordinal, (start, end) in enumerate([(prior.START, prior.END)] +
                                          [(a, b) for _, _, a, b in prior.CALLER_FDES]):
        raw = read(start, end - start)
        sha = hashlib.sha256(raw).hexdigest()
        if ordinal:
            require(sha == CALLER_HASHES[ordinal - 1], "Complete caller body changed")
        rows = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(raw, start))
        require(b"".join(i.bytes for i in rows) == raw, "Incomplete linear decode")
        decoded.append([{"va": hex(i.address), "hex": i.bytes.hex(), "mnemonic": i.mnemonic,
                         "operands": i.op_str} for i in rows])
        hashes.append(sha)
    require(not any(r["mnemonic"] == "call" for r in decoded[0]), "Unexpected leaf call")
    for index, (site, raw, setup) in enumerate(prior.CALLERS):
        sites = {int(r["va"], 16): r for r in decoded[index + 1]}
        require(sites[site]["mnemonic"] == "call" and sites[site]["operands"] == hex(prior.START),
                "Direct caller edge changed")
        require(read(site, len(raw)) == raw and read(site - len(setup), len(setup)) == setup,
                "Caller setup changed")
    relocation_count = 0
    for section in secs:
        if section["name"].startswith(".rela."):
            require(section["size"] % 24 == 0, "Malformed RELA extent")
            for _, _, addend in struct.iter_unpack("<QQq", read(section["address"], section["size"])):
                require(addend != prior.START, "Unexpected naming relocation")
                relocation_count += 1
    text = next(s for s in secs if s["name"] == ".text")
    code, direct, pos = read(text["address"], text["size"]), [], 0
    while (pos := code.find(b"\xe8", pos)) >= 0:
        if pos + 5 <= len(code) and text["address"] + pos + 5 + struct.unpack_from("<i", code, pos + 1)[0] == prior.START:
            direct.append(text["address"] + pos)
        pos += 1
    require(direct == [c[0] for c in prior.CALLERS], "Direct call scan changed")
    return {"target_sha256": prior.SHA256, "body_sha256": hashes[0], "caller_sha256": hashes[1:],
            "frames": frames, "capstone_version": capstone_version,
            "leaf": decoded[0], "callers": decoded[1:],
            "direct_e8_sites": [hex(x) for x in direct], "naming_relocations": 0,
            "relocation_records": relocation_count, "text_scan_bytes": len(code),
            "prior_evidence_sha256": digest(ROOT / "research/work-items/foundation-pointer-mark-walk-94/evidence.json"),
            "prior_checker_sha256": digest(ROOT / "tools/foundation_pointer_mark_walk.py")}


def admit():
    raw = prior.TARGET.read_bytes()
    require(len(raw) == 91774280 and hashlib.sha256(raw).hexdigest() == prior.SHA256,
            "Target identity changed")
    return structure(raw)


def expected(links, stamps, inline, tail, base, mark):
    """Enumerate an immutable orbit, select first barrier, then batch its prefix.

    Unlike the Rust loop this first ignores all stamp outcomes, then calculates
    the earliest initial non-sentinel or repeated payload. Deferred terminals
    ensure unread missing data never outranks an earlier stopping barrier.
    """
    values = dict(stamps)

    def finish(status):
        return status + "|" + ",".join(f"{values[n]:016x}" for n, _ in stamps)

    for rows in (links, stamps):
        ids = [row[0] for row in rows]
        if 0 in ids or len(set(ids)) != len(ids):
            # Invalid maps are refused before any state changes, even unused.
            return "map|" + ",".join(f"{v:016x}" for _, v in stamps)
    graph = {identity: (nxt, node) for identity, nxt, node in links}
    count = (base + len(tail)) % 2**64
    entries = inline + tail
    for entry in range(min(count, len(entries) + 1)):
        if entry == len(entries):
            return finish(f"entry:{entry:016x}")
        head = entries[entry]
        if head not in graph:
            return finish(f"link:{head:016x}")
        cursor, visited, payloads = graph[head][0], set(), []
        terminal = "ok"
        while cursor != head:
            if cursor in visited:
                terminal = f"cycle:{entry:016x}"
                break
            visited.add(cursor)
            if cursor not in graph:
                terminal = f"link:{cursor:016x}"
                break
            nxt, node = graph[cursor]
            if node not in values:
                terminal = f"node:{node:016x}"
                break
            payloads.append(node)
            cursor = nxt
        barriers = [i for i, node in enumerate(payloads) if values[node] != MASK]
        if mark != MASK:
            first = {}
            for i, node in enumerate(payloads):
                if node in first:
                    barriers.append(i)
                first.setdefault(node, i)
            # A closing link revisits an already marked payload and stops.
            if terminal.startswith("cycle:"):
                barriers.append(len(payloads))
        stop = min(barriers) if barriers else len(payloads)
        for node in set(payloads[:stop]):
            values[node] = mark
        if not barriers and terminal != "ok":
            return finish(terminal)
    return finish("ok")


def fixture_bytes():
    cases = set()

    def include(links, stamps, inline=(1,) * 8, tail=(), base=1, marks=(1, MASK, MAX)):
        for mark in marks:
            cases.add((tuple(links), tuple(stamps), tuple(inline), tuple(tail), base, mark))

    # Every labelled functional graph with 1..3 non-head links, including
    # head returns and missing/null successors; every payload sharing map;
    # every initial sentinel/non-sentinel assignment, and three mark values.
    for n in range(1, 4):
        ids, payload_ids = tuple(range(2, n + 2)), tuple(range(101, 101 + n))
        for successors in itertools.product((0, 1, *ids), repeat=n):
            for payloads in itertools.product(payload_ids, repeat=n):
                links = ((1, 2, 0),) + tuple((ids[i], successors[i], payloads[i]) for i in range(n))
                for marks in itertools.product((0, MASK), repeat=n):
                    include(links, tuple(zip(payload_ids, marks)))
    include((), ())
    include(((1, 1, 999),), ())
    # Fixed inline/tail selector and wrapping count: distinct one-link heads.
    links = tuple(row for i in range(12) for row in ((10 + i, 30 + i, 0), (30 + i, 10 + i, 100 + i)))
    stamps = tuple((100 + i, MASK) for i in range(12))
    inline = tuple(range(10, 18))
    for length in range(5):
        tail = tuple(range(18, 18 + length))
        for base in (0, 1, 6, 7, 8, 9, 12, MAX, MAX - length, (MAX - length + 1) & MAX):
            include(links, stamps, inline, tail, base, (0, 2**32 + 1, 2**63, MASK, MAX))
    # Shared payload/link state across entries, absent data behind barriers,
    # high-bit IDs, mark-width boundaries, and refusal ordering.
    rng = random.Random(0x50e69f0)
    for _ in range(4096):
        n = rng.randrange(1, 9)
        ids = tuple((i + 1) * 0x100 + (2**63 if i % 2 else 0) for i in range(n))
        pids = tuple(0x10000 + i for i in range(n))
        links = tuple((i, rng.choice((0, *ids)), rng.choice((999, *pids))) for i in ids)
        stamps = tuple((i, rng.choice((0, 1, MASK - 1, MASK, MASK, MAX))) for i in pids)
        inline = tuple(rng.choice((999, *ids)) for _ in range(8))
        tail = tuple(rng.choice(ids) for _ in range(rng.randrange(5)))
        include(links, stamps, inline, tail, rng.choice((0, 1, 2, 7, 8, 9, MAX)),
                (rng.choice((0, 1, 2**32 + 1, 2**63, MASK, MAX)),))
    for bad_links, bad_stamps in ((((0, 0, 1),), ((1, MASK),)),
                                  (((1, 1, 1), (1, 0, 1)), ((1, MASK),)),
                                  (((1, 1, 1),), ((0, MASK),)),
                                  (((1, 1, 1),), ((1, MASK), (1, 0)))):
        for base in (0, 1):
            include(bad_links, bad_stamps, base=base)
    inputs, outputs, coverage = [], [], {}
    for links, stamps, inline, tail, base, mark in sorted(cases):
        fmt = lambda numbers: ",".join(f"{n:016x}" for n in numbers)
        rows = lambda table: ";".join(fmt(row) for row in table) or "-"
        inputs.append("\t".join((f"{base:016x}", f"{mark:016x}", fmt(inline), fmt(tail) or "-",
                                  rows(links), rows(stamps))))
        result = expected(links, stamps, inline, tail, base, mark)
        outputs.append(result)
        kind = result.split("|")[0].split(":")[0]
        coverage[kind] = coverage.get(kind, 0) + 1
    return (("\n".join(inputs) + "\n").encode(), ("\n".join(outputs) + "\n").encode(),
            {"cases": len(inputs), "statuses": coverage, "random_seed": "0x50e69f0",
             "exhaustive_non_head_links": [1, 2, 3], "random_cases_before_dedup": 4096})


def freeze():
    require(not (ROOT / "src/node94-pointer-mark-walk").exists(), "Rust already exists; cannot pre-Rust freeze")
    frozen = PACKET / "frozen"
    require(not (frozen / "ORACLE-FREEZE.json").exists(), "Refusing to replace existing freeze")
    facts = admit()
    inputs, expected_bytes, coverage = fixture_bytes()
    for name, raw in (("inputs.tsv", inputs), ("expected.txt", expected_bytes)):
        (frozen / (name + ".gz")).write_bytes(gzip.compress(raw, mtime=0))
    record = {"frozen_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "source_base_commit": "56c0ec672bd8fdcfaa80f2db700a61e6240b3663",
              "rust_source_present": False, "oracle_source_sha256": digest(__file__),
              "inputs_sha256": hashlib.sha256(inputs).hexdigest(),
              "expected_sha256": hashlib.sha256(expected_bytes).hexdigest(),
              "coverage": coverage, "static_facts": facts}
    (frozen / "ORACLE-FREEZE.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps({"oracle_source_sha256": record["oracle_source_sha256"], "coverage": coverage}, indent=2))


if __name__ == "__main__":
    freeze()
