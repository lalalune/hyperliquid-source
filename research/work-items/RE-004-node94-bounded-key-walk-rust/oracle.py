"""Pre-Rust orbit/barrier oracle for the complete bounded key-walk leaf."""
import datetime
import gzip
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections
import foundation_bounded_key_walk as prior
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, __version__ as capstone_version

MAX = 2**64 - 1
CALLER_START, CALLER_END, CALL_SITE = 0x25767b0, 0x2576b6d, 0x2576999


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
    require(read(eh["address"], len(prior.CIE0)) == prior.CIE0, "CIE changed")
    caller_cie = bytes.fromhex("1c00000000000000017a504c5200017810079b29ca7b041b1b0c070890010000")
    require(read(eh["address"] + 0x2dc714, len(caller_cie)) == caller_cie, "Caller CIE changed")
    frames = []
    for relative, raw, start, end in [(0x2e56c, prior.FDE, prior.START, prior.END),
                                    (0x3eb2cc, prior.CALLER, CALLER_START, CALLER_END)]:
        record = read(eh["address"] + relative, len(raw))
        require(record == raw, "FDE bytes changed")
        pc = eh["address"] + relative + 8 + struct.unpack_from("<i", record, 8)[0]
        extent = struct.unpack_from("<I", record, 12)[0]
        require((pc, pc + extent) == (start, end), "FDE extent changed")
        require(eh["address"] + relative + 4 - struct.unpack_from("<I", record, 4)[0]
                == eh["address"] + (0 if start == prior.START else 0x2dc714), "FDE CIE pointer changed")
        frames.append({"offset": hex(relative), "start": hex(start), "end": hex(end),
                       "record_hex": record.hex()})
    body = read(prior.START, prior.END - prior.START)
    caller = read(CALLER_START, CALLER_END - CALLER_START)
    require(body == prior.BODY, "Complete leaf body changed")
    require(read(prior.END, 6) == b"\xcc" * 6, "Leaf padding changed")
    require(read(prior.START - 8, 8) == b"\xcc" * 8, "Preceding gap changed")
    require(hashlib.sha256(caller).hexdigest() ==
            "32d9b2347fb9e9f05d430695f4af7b683e92283e13459ac9dc3fc4b0ec138498",
            "Complete caller body changed")
    rows = []
    for start, raw in ((prior.START, body), (CALLER_START, caller)):
        decoded = list(Cs(CS_ARCH_X86, CS_MODE_64).disasm(raw, start))
        require(b"".join(i.bytes for i in decoded) == raw, "Incomplete linear decode")
        rows.append([{"va": hex(i.address), "hex": i.bytes.hex(), "mnemonic": i.mnemonic,
                      "operands": i.op_str} for i in decoded])
    sites = {int(r["va"], 16): r for r in rows[1]}
    require(sites[CALL_SITE]["mnemonic"] == "call" and
            sites[CALL_SITE]["operands"] == hex(prior.START), "Caller edge changed")
    require(sites[0x2576993]["hex"] == "4c89ef" and sites[0x2576996]["hex"] == "4c89fe",
            "Caller output/record setup changed")
    require(not any(r["mnemonic"] == "call" for r in rows[0]), "Unexpected leaf call")
    # Complete naming-relocation and direct-e8 pattern scans. The sole found
    # call is qualified above against a full caller decode, not only a pattern.
    relocation_count = 0
    for section in secs:
        if section["name"].startswith(".rela."):
            require(section["size"] % 24 == 0, "Malformed relocation extent")
            for _, _, addend in struct.iter_unpack("<QQq", read(section["address"], section["size"])):
                require(addend != prior.START, "Unexpected naming relocation")
                relocation_count += 1
    text = next(s for s in secs if s["name"] == ".text")
    code, direct, pos = read(text["address"], text["size"]), [], 0
    while (pos := code.find(b"\xe8", pos)) >= 0:
        if pos + 5 <= len(code) and text["address"] + pos + 5 + struct.unpack_from("<i", code, pos + 1)[0] == prior.START:
            direct.append(text["address"] + pos)
        pos += 1
    require(direct == [CALL_SITE], "Direct call scan changed")
    return {"target_sha256": prior.SHA256, "body_sha256": hashlib.sha256(body).hexdigest(),
            "caller_sha256": hashlib.sha256(caller).hexdigest(), "frames": frames,
            "capstone_version": capstone_version, "leaf": rows[0], "caller": rows[1],
            "caller_cie_offset": "0x2dc714", "caller_cie_hex": caller_cie.hex(),
            "direct_e8_sites": [hex(x) for x in direct], "naming_relocations": 0,
            "relocation_records": relocation_count, "text_scan_bytes": len(code),
            "prior_evidence_sha256": digest(ROOT / "research/work-items/foundation-bounded-key-walk-94/evidence.json"),
            "prior_checker_sha256": digest(ROOT / "tools/foundation_bounded_key_walk.py")}


def admit():
    raw = prior.TARGET.read_bytes()
    require(len(raw) == 91774280 and hashlib.sha256(raw).hexdigest() == prior.SHA256,
            "Target identity changed")
    return structure(raw)


def expected(nodes, start, index, key):
    """Enumerate the functional-graph orbit, then choose the first barrier.

    Orbit construction ignores gate outcomes. It includes the first closing
    cycle edge, and records missing-node/end terminals without raising early.
    Thus an earlier gate can outrank an unread missing successor or cycle.
    """
    identifiers = [row[0] for row in nodes]
    if 0 in identifiers or len(set(identifiers)) != len(identifiers):
        return "map", "map"
    graph = {identity: (nxt, e4, e6) for identity, nxt, e4, e6 in nodes}
    if start not in graph:
        return f"missing:{start:016x}", "missing"

    def triple(values, kind):
        return "ok:" + ",".join(f"{x:016x}" for x in values), kind

    if key < graph[start][2]:
        return triple((start, index, key), "first")
    orbit, edges, seen = [], [], set()
    current = start
    while current not in seen:
        seen.add(current)
        orbit.append(current)
        nxt = graph[current][0]
        if nxt == 0:
            terminal = "end", current
            break
        if nxt not in graph:
            terminal = "missing", nxt
            break
        edges.append((current, nxt))
        current = nxt
    else:
        terminal = "cycle", current
    barriers = [(j + 1, nxt, graph[old][1]) for j, (old, nxt) in enumerate(edges)
                if graph[old][1] < graph[nxt][2]]
    if barriers:
        steps, stopping, gate = min(barriers)
        return triple((stopping, (index + steps) % 2**64, gate), "barrier")
    kind, last = terminal
    if kind == "end":
        return triple((0, last, (index + len(orbit) - 1) % 2**64), "exhausted")
    if kind == "missing":
        return f"missing:{last:016x}", "missing"
    return "cycle", "cycle"


def fixture_bytes():
    cases = set()
    keys = (0, 1, 65535, 65536, 2**32, 2**63, MAX)
    indices = (0, MAX - 1, MAX)

    def include(nodes, roots=None, selected_keys=keys, selected_indices=indices):
        nodes = tuple(nodes)
        for start in (roots if roots is not None else [nodes[0][0] if nodes else 0x1000]):
            for key in selected_keys:
                for index in selected_indices:
                    cases.add((nodes, start, index, key))

    include(())
    # Every functional graph on 1..3 labelled nodes, including null links,
    # crossed with every assignment from these four gate-word pairs.
    gates = ((0, 0), (0, 1), (1, 0), (65535, 65535))
    for length in range(1, 4):
        ids = tuple(0x1000 + 0x100 * i for i in range(length))
        for successors in itertools.product((0, *ids), repeat=length):
            for words in itertools.product(gates, repeat=length):
                nodes = tuple((ids[i], successors[i], *words[i]) for i in range(length))
                include(nodes)
    # Unsigned16 equality/sign/power boundaries in both gate positions.
    words = {0, 1, 2, 32767, 32768, 32769, 65534, 65535}
    for bit in range(16):
        words.update(x for x in (2**bit - 1, 2**bit, 2**bit + 1) if x <= 65535)
    for word in sorted(words):
        for other in (max(0, word - 1), word, min(65535, word + 1)):
            include(((0x1000, 0x1100, word, 0), (0x1100, 0, 0, other)))
            include(((0x1000, 0x1000, word, other),))
    # Longer chains, cycles, a gate on the final cycle-closing edge, and map
    # permutations. No source-order relation between IDs and map rows is assumed.
    for length in (4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 127, 128, 129, 257):
        ids = [0x10000 + i * 0x100 for i in range(length)]
        for cyclic in (False, True):
            rows = [(identity, ids[i + 1] if i + 1 < length else (ids[0] if cyclic else 0),
                     65535, 0) for i, identity in enumerate(ids)]
            include(rows)
            include(rows[::-1], roots=[ids[0]])
            rows[-1] = (rows[-1][0], rows[-1][1], 0, rows[-1][3])
            rows[0] = (*rows[0][:3], 1)
            include(rows, selected_keys=(1, MAX))
    # Safe-map refusal classes and gate-first admission of unread successors.
    special = [(), ((0, 0, 0, 1),), ((1, 0, 0, 0), (1, 0, 1, 1)),
               ((1, 99, 0, 1),), ((1, 2, 0, 0), (2, 99, 0, 1)),
               ((1, 2, 1, 0), (2, 99, 1, 1)),
               ((MAX, MAX - 256, 0, 0), (MAX - 256, 0, 65535, 1))]
    for rows in special:
        include(rows, roots=(0, 1, 99, MAX))
    inputs, answers, counts = [], [], {}
    for nodes, start, index, key in sorted(cases):
        table = ",".join(f"{a:016x}:{b:016x}:{c:04x}:{d:04x}" for a, b, c, d in nodes) or "-"
        inputs.append(f"{start:016x}\t{index:016x}\t{key:016x}\t{table}\n")
        answer, kind = expected(nodes, start, index, key)
        answers.append(answer + "\n")
        counts[kind] = counts.get(kind, 0) + 1
    coverage = {"cases": len(cases), "outcomes": counts,
                "distinct_maps": len({row[0] for row in cases}), "largest_map": max(len(row[0]) for row in cases),
                "exhaustive_small_maps": "all successor assignments on1..3nodes and gate pairs{(0,0),(0,1),(1,0),(65535,65535)}",
                "index_values": list(indices), "default_keys": list(keys)}
    return "".join(inputs).encode(), "".join(answers).encode(), coverage


def freeze():
    require(not (ROOT / "src/node94-bounded-key-walk/lib.rs").exists(), "Rust already exists; cannot prefreeze")
    destination = PACKET / "frozen"
    require(not (destination / "ORACLE-FREEZE.json").exists(), "Freeze already exists")
    facts = admit()
    inputs, expected_rows, coverage = fixture_bytes()
    for name, raw in (("inputs.tsv", inputs), ("expected.txt", expected_rows)):
        (destination / (name + ".gz")).write_bytes(gzip.compress(raw, mtime=0))
    record = {"created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "authorship_order": "Orbit/first-barrier oracle and fixtures frozen before new Rust source existed",
              "oracle_source_sha256": digest(__file__), "static_facts": facts,
              "inputs_sha256": hashlib.sha256(inputs).hexdigest(),
              "expected_sha256": hashlib.sha256(expected_rows).hexdigest(), "coverage": coverage}
    (destination / "ORACLE-FREEZE.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(coverage, indent=2))


if __name__ == "__main__":
    freeze()


