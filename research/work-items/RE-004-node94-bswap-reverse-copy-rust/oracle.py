"""Pre-Rust backward byte-provenance oracle; never executes target code."""
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
import foundation_bswap_reverse_copy as prior
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, __version__ as capstone_version

MAX = 2**64 - 1
CALLER_HASHES = (
    "69c27f5dbcb1d51d8b653c3c57be2c9f9bd4e7432af6522b678eff328f8d8868",
    "cc8efbe85432416f98447419ace49eb077efae428d6dc9fd1019fed40991b7e4",
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
    for relative, raw in ((0, prior.CIE0),):
        require(read(eh["address"] + relative, len(raw)) == raw, "CIE changed")
    frames = []
    for relative, raw, start, end in [(0x2d81c8, prior.FDE, prior.START, prior.END),
                                     (0x2d81dc, prior.NEXT, prior.PAD_END, 0x5632e7f),
                                     *prior.CALLER_FDES]:
        record = read(eh["address"] + relative, len(raw))
        require(record == raw, "FDE bytes changed")
        pc = eh["address"] + relative + 8 + struct.unpack_from("<i", record, 8)[0]
        extent = struct.unpack_from("<I", record, 12)[0]
        require((pc, pc + extent) == (start, end), "FDE extent changed")
        cie = relative + 4 - struct.unpack_from("<I", record, 4)[0]
        require(cie == 0, "CIE pointer changed")
        frames.append({"offset": hex(relative), "start": hex(start), "end": hex(end),
                       "record_hex": record.hex(), "cie_offset": hex(cie)})
    body = read(prior.START, prior.END - prior.START)
    require(body == prior.BODY, "Complete leaf body changed")
    require(read(prior.END, 5) == b"\xcc" * 5, "Leaf padding changed")
    require(read(prior.START - 2, 2) == b"\xcc" * 2, "Preceding gap changed")
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
    for index, site in enumerate(prior.CALLERS):
        sites = {int(r["va"], 16): r for r in decoded[index + 1]}
        require(sites[site]["mnemonic"] == "call" and sites[site]["operands"] == hex(prior.START),
                "Direct caller edge changed")
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
    require(direct == prior.CALLERS, "Direct call scan changed")
    return {"target_sha256": prior.SHA256, "body_sha256": hashes[0], "caller_sha256": hashes[1:],
            "frames": frames, "capstone_version": capstone_version,
            "leaf": decoded[0], "callers": decoded[1:],
            "direct_e8_sites": [hex(x) for x in direct], "naming_relocations": 0,
            "relocation_records": relocation_count, "text_scan_bytes": len(code),
            "prior_evidence_sha256": digest(ROOT / "research/work-items/foundation-bswap-reverse-copy-94/evidence.json"),
            "prior_checker_sha256": digest(ROOT / "tools/foundation_bswap_reverse_copy.py")}


def admit():
    raw = prior.TARGET.read_bytes()
    require(len(raw) == 91774280 and hashlib.sha256(raw).hexdigest() == prior.SHA256,
            "Target identity changed")
    return structure(raw)


def expected(memory, source, destination):
    """Resolve each output byte backward to an untouched original input byte.

    Each destination byte belongs to one of four disjoint writes. A read at
    stage t observes only writes with lower stage numbers. Recursing through
    that earlier write strictly decreases t, so no forward mutation is needed.
    """
    if source + 32 > len(memory) or destination + 32 > len(memory):
        return "bounds|" + memory.hex()

    def origin(address, before):
        relative = address - destination
        if 0 <= relative < 32:
            stage, within = divmod(relative, 8)
            if stage < before:
                return origin(source + 31 - 8 * stage - within, stage)
        return address

    final = bytes(memory[origin(address, 4)] for address in range(len(memory)))
    # RAX contains the last qword load after BSWAP, before its final store.
    last_source = bytes(memory[origin(source + j, 3)] for j in range(8))
    result = int.from_bytes(last_source, "big")
    return f"ok:{result:016x}|" + final.hex()


def fixture_bytes():
    cases = set()
    rng = random.Random(0x5632d90)

    def include(memory, source, destination):
        cases.add((bytes(memory), source, destination))

    # Every overlap displacement, nearby disjoint boundaries, and all eight
    # byte alignments. Several backgrounds expose unchanged-region damage.
    for delta in range(-40, 41):
        for alignment in range(8):
            source = 40 + alignment
            destination = source + delta
            size = max(source, destination) + 32 + 5
            patterns = [bytes(size), bytes([255]) * size,
                        bytes(i % 256 for i in range(size)),
                        bytes((i * 37 + 11) % 256 for i in range(size)),
                        bytes(rng.randrange(256) for _ in range(size))]
            for memory in patterns:
                include(memory, source, destination)
    # All source-byte bit basis vectors at each overlapping displacement.
    # Every output byte is an original input-byte selection, established by
    # the provenance proof; these distinguish source-origin maps directly.
    for delta in range(-31, 32):
        source, destination, size = 32, 32 + delta, 96
        for byte in range(32):
            for bit in range(8):
                memory = bytearray(size)
                memory[source + byte] = 1 << bit
                include(memory, source, destination)
    # Exact bounds, empty/short regions and offsets whose +32 would overflow
    # native usize on the 64-bit validation host. Errors preserve all bytes.
    for size in (0, 1, 7, 8, 15, 16, 24, 31, 32, 33, 63, 64, 65, 96):
        points = {0, 1, max(0, size - 32), max(0, size - 31), size, size + 1,
                  2**32, 2**63, MAX - 32, MAX - 31, MAX}
        memory = bytes((i * 17 + 129) % 256 for i in range(size))
        for source in points:
            for destination in points:
                include(memory, source, destination)
    for _ in range(2048):
        size = rng.randrange(32, 193)
        memory = bytes(rng.randrange(256) for _ in range(size))
        include(memory, rng.randrange(size - 31), rng.randrange(size - 31))
    inputs, outputs = [], []
    coverage = {"cases": len(cases), "success": 0, "bounds": 0,
                "overlapping": 0, "same_offset": 0, "disjoint": 0,
                "random_seed": "0x5632d90", "basis_cases": 63 * 32 * 8}
    for memory, source, destination in sorted(cases):
        inputs.append(f"{source:016x}\t{destination:016x}\t{memory.hex() or '-'}")
        result = expected(memory, source, destination)
        outputs.append(result)
        if result.startswith("bounds"):
            coverage["bounds"] += 1
        else:
            coverage["success"] += 1
            if source == destination:
                coverage["same_offset"] += 1
            if abs(source - destination) < 32:
                coverage["overlapping"] += 1
            else:
                coverage["disjoint"] += 1
    return (("\n".join(inputs) + "\n").encode(), ("\n".join(outputs) + "\n").encode(), coverage)


def freeze():
    require(not (ROOT / "src/node94-bswap-reverse-copy").exists(), "Rust already exists; cannot pre-Rust freeze")
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
