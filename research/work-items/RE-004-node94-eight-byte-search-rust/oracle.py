"""Pre-Rust interval-partition oracle for the complete bounded search leaf."""
import datetime
import functools
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
import foundation_eight_byte_binary_search as prior
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, __version__ as capstone_version

MAX = 2**64 - 1
CALLER_START, CALLER_END, CALL_SITE = 0x52cab00, 0x52cab83, 0x52cab17


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
    frames = []
    for relative, raw, start, end in [(0x2ac1ec, prior.FDE, prior.START, prior.END),
                                    *prior.CALLER_FDES]:
        record = read(eh["address"] + relative, len(raw))
        require(record == raw, "FDE bytes changed")
        pc = eh["address"] + relative + 8 + struct.unpack_from("<i", record, 8)[0]
        extent = struct.unpack_from("<I", record, 12)[0]
        require((pc, pc + extent) == (start, end), "FDE extent changed")
        require(eh["address"] + relative + 4 - struct.unpack_from("<I", record, 4)[0]
                == eh["address"], "FDE CIE pointer changed")
        frames.append({"offset": hex(relative), "start": hex(start), "end": hex(end),
                       "record_hex": record.hex()})
    body = read(prior.START, prior.END - prior.START)
    caller = read(CALLER_START, CALLER_END - CALLER_START)
    require(body == prior.BODY, "Complete leaf body changed")
    require(read(prior.END, 13) == b"\xcc" * 13, "Leaf padding changed")
    require(hashlib.sha256(caller).hexdigest() ==
            "b18992ef147b490f1c8384ed337c4e6ccc3956ff485c449148d3d7697fd970f6",
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
    require(sites[0x52cab08]["hex"] == "488d3d31374c00", "Global descriptor setup changed")
    descriptor = [s for s in secs if s["address"] <= 0x578e240
                  and 0x578e260 <= s["address"] + s["size"]]
    require(len(descriptor) == 1 and descriptor[0]["type"] == 8, "Descriptor no longer NOBITS")
    require(sum(r["mnemonic"].startswith("j") and r["mnemonic"] != "jmp"
                for r in rows[0]) == 5, "Conditional branch count changed")
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
            "descriptor": {"va": "0x578e240", "section": descriptor[0]["name"], "file_backed": False},
            "direct_e8_sites": [hex(x) for x in direct], "naming_relocations": 0,
            "relocation_records": relocation_count, "text_scan_bytes": len(code),
            "prior_evidence_sha256": digest(ROOT / "research/work-items/foundation-eight-byte-binary-search-94/evidence.json"),
            "prior_checker_sha256": digest(ROOT / "tools/foundation_eight_byte_binary_search.py")}


def admit():
    raw = prior.TARGET.read_bytes()
    require(len(raw) == 91774280 and hashlib.sha256(raw).hexdigest() == prior.SHA256,
            "Target identity changed")
    return structure(raw)


@functools.lru_cache(maxsize=None)
def regions(entries):
    """Enumerate ALL terminal index constraints, independently of query.

    Each leaf is an integer interval (exclusive minimum, inclusive maximum].
    No query-dependent search, registers, instructions or machine evaluation.
    Empty intervals are allowed for duplicates and unsorted arrays.
    """
    leaves = []

    def partition(begin, end, minimum, maximum):
        if begin == end:
            leaves.append((begin, minimum, maximum))
            return
        pivot = (begin + end) // 2
        boundary = entries[pivot]
        partition(begin, pivot, minimum, min(maximum, boundary))
        partition(pivot + 1, end, max(minimum, boundary), maximum)

    partition(0, len(entries), -1, MAX)
    require(len(leaves) == len(entries) + 1, "Terminal index count changed")
    nonempty = sorted((lo, hi) for _, lo, hi in leaves if lo < hi)
    previous = -1
    for lo, hi in nonempty:
        require(lo == previous, "Intervals do not partition all u64 queries")
        previous = hi
    require(previous == MAX, "Intervals do not cover the domain")
    return tuple(leaves)


def expected(entries, key, limit):
    if key >= limit:
        return (len(entries) - 1) % 2**64
    admitted = [index for index, lo, hi in regions(entries) if lo < key <= hi]
    require(len(admitted) == 1, "Query has no unique terminal index")
    if all(a <= b for a, b in zip(entries, entries[1:])):
        require(admitted[0] == sum(value < key for value in entries), "Independent sorted rank differs")
    return admitted[0]


def fixture_bytes():
    cases = set()
    alphabet = (0, 1, 2**63, MAX)
    queries = (0, 1, 2, 2**63 - 1, 2**63, 2**63 + 1, MAX - 1, MAX)

    def include(entries, keys):
        entries = tuple(entries)
        regions(entries)  # Check the full partition even if a limit bypasses it.
        for key in keys:
            for limit in {0, key, min(MAX, key + 1), MAX}:
                cases.add((entries, key, limit))

    # Exhaust every ordered array up to length five, with duplicates, sorted
    # and unsorted arrangements and both sides of the signed boundary.
    for length in range(6):
        for entries in itertools.product(alphabet, repeat=length):
            include(entries, queries)
    lengths = set(range(6, 66))
    for bit in range(1, 11):
        lengths.update((2**bit - 1, 2**bit, 2**bit + 1))
    state = 0xD94B18A321C7E605
    for length in sorted(lengths):
        ascending = tuple(i * (MAX // max(1, length - 1)) for i in range(length))
        random = []
        for _ in range(length):
            state = (state * 6364136223846793005 + 1442695040888963407) % 2**64
            random.append(state)
        for entries in (ascending, ascending[::-1], tuple(random), tuple(sorted(random)), (7,) * length):
            pivots = {entries[0], entries[-1], entries[length // 2]}
            keys = set(queries) | {x + d for x in pivots for d in (-1, 0, 1) if 0 <= x + d <= MAX}
            include(entries, keys)
    inputs, answers, sorted_search, unsorted_search, shortcut, empty_wrap = [], [], 0, 0, 0, 0
    for entries, key, limit in sorted(cases):
        table = ",".join(f"{value:016x}" for value in entries) or "-"
        inputs.append(f"{key:016x}\t{limit:016x}\t{table}\n")
        answers.append(str(expected(entries, key, limit)) + "\n")
        if key >= limit:
            shortcut += 1
            empty_wrap += int(not entries)
        elif all(a <= b for a, b in zip(entries, entries[1:])):
            sorted_search += 1
        else:
            unsorted_search += 1
    coverage = {"cases": len(cases), "distinct_tables": len({row[0] for row in cases}),
                "sorted_search": sorted_search, "unsorted_search": unsorted_search,
                "limit_shortcut": shortcut, "empty_shortcut_wrap": empty_wrap,
                "exhaustive_short_arrays": "length0..5 over{0,1,2^63,2^64-1}",
                "maximum_fixture_length": max(map(len, (row[0] for row in cases))),
                "additional_lengths": sorted(lengths), "seed": "0xd94b18a321c7e605"}
    return "".join(inputs).encode(), "".join(answers).encode(), coverage


def freeze():
    require(not (ROOT / "src/node94-eight-byte-search/lib.rs").exists(), "Rust already exists; cannot prefreeze")
    destination = PACKET / "frozen"
    require(not (destination / "ORACLE-FREEZE.json").exists(), "Freeze already exists")
    facts = admit()
    inputs, expected_rows, coverage = fixture_bytes()
    for name, raw in (("inputs.tsv", inputs), ("expected.txt", expected_rows)):
        (destination / (name + ".gz")).write_bytes(gzip.compress(raw, mtime=0))
    record = {"created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "authorship_order": "Interval-partition oracle and fixtures frozen before new Rust source existed",
              "oracle_source_sha256": digest(__file__), "static_facts": facts,
              "inputs_sha256": hashlib.sha256(inputs).hexdigest(),
              "expected_sha256": hashlib.sha256(expected_rows).hexdigest(), "coverage": coverage}
    (destination / "ORACLE-FREEZE.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(coverage, indent=2))


if __name__ == "__main__":
    freeze()
