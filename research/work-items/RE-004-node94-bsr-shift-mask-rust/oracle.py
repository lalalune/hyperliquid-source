"""Pre-Rust arithmetic-interval oracle and bounded static admission."""
from collections import Counter
import gzip
import hashlib
import json
from pathlib import Path
import random
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
TARGET = ROOT / "artifacts/node/94/hl-node"
SOURCE = ROOT / "src/node94-bsr-shift-mask/lib.rs"
TARGET_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
BODY_SHA256 = "b85a1e72bd3d84ce2bfb404662d562a60ac734147d4086a47bf9323cbc128fb1"
PERIOD, MODULUS = 2 ** 63, 2 ** 64
CALLERS = ((0x2bfecc, 0x54c5620, 0x54c7547, 0x54c6268),
           (0x2bff34, 0x54c7550, 0x54c8ca5, 0x54c85d5))
WITNESSES = {"zero": 0, "one": 1, "field_boundary": 16, "shift_floor": 9,
             "final_floor_last": 32, "rank_six": 33, "rank_seven": 65,
             "rank_eight": 129, "high_bit": PERIOD, "wrapped_one": PERIOD + 1,
             "wrapped_32": PERIOD + 32, "maximum": MODULUS - 1}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def structure(data):
    """Structural checks independent of full identity for corruption controls."""
    sys.path.insert(0, str(ROOT / "tools"))
    from elf_index import sections
    import capstone

    secs = {s["name"]: s for s in sections(data)}
    text, eh = secs[".text"], secs[".eh_frame"]

    def code(va, size):
        offset = text["offset"] + va - text["address"]
        require(text["offset"] <= offset and offset + size <= text["offset"] + text["size"],
                "Code range outside .text")
        return data[offset:offset + size], offset

    body, body_offset = code(0x54b4390, 66)
    require(hashlib.sha256(body).hexdigest() == BODY_SHA256, "Complete body changed")
    padding, padding_offset = code(0x54b43d2, 14)
    require(padding == b"\xcc" * 14, "FDE padding changed")
    cie = data[eh["offset"]:eh["offset"] + 24]
    require(cie.hex() == "1400000000000000017a5200017810011b0c070890010000", "CIE changed")
    frames = []
    for offset, start, end in ((0x2bf8c8, 0x54b4390, 0x54b43d2),
                               *((o, a, b) for o, a, b, _ in CALLERS)):
        file_offset = eh["offset"] + offset
        length = struct.unpack_from("<I", data, file_offset)[0] + 4
        raw = data[file_offset:file_offset + length]
        require(len(raw) >= 16, "Truncated FDE record")
        pc = eh["address"] + offset + 8 + struct.unpack_from("<i", raw, 8)[0]
        extent = struct.unpack_from("<I", raw, 12)[0]
        require((pc, pc + extent) == (start, end), "Decoded FDE range changed")
        require(struct.unpack_from("<I", raw, 4)[0] == offset + 4, "FDE CIE link changed")
        frames.append({"section_offset": hex(offset), "file_offset": file_offset,
                       "start": hex(pc), "end_exclusive": hex(pc + extent), "raw_hex": raw.hex()})
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    callers = []
    for _, start, end, call in CALLERS:
        raw, file_offset = code(start, end - start)
        instructions = list(decoder.disasm(raw, start))
        require(sum(i.size for i in instructions) == len(raw), "Incomplete caller linear decode")
        hits = [i for i in instructions if i.mnemonic == "call" and i.op_str == "0x54b4390"]
        require([i.address for i in hits] == [call], "Caller instruction sites changed")
        callers.append({"start": hex(start), "end_exclusive": hex(end), "bytes": len(raw),
                        "sha256": hashlib.sha256(raw).hexdigest(),
                        "linear_instructions": len(instructions), "call_va": hex(call),
                        "call_file_offset": file_offset + call - start, "call_hex": hits[0].bytes.hex()})
    return {"start": "0x54b4390", "end_exclusive": "0x54b43d2", "body_bytes": 66,
            "body_hex": body.hex(), "body_sha256": BODY_SHA256, "body_file_offset": body_offset,
            "padding_hex": padding.hex(), "padding_file_offset": padding_offset,
            "cie_hex": cie.hex(), "cie_file_offset": eh["offset"], "frames": frames,
            "callers": callers, "capstone_version": capstone.__version__,
            "neighbor_semantics_included": False, "complete_xref_census": False}


def admit():
    data = TARGET.read_bytes()
    require(hashlib.sha256(data).hexdigest() == TARGET_SHA256, "Target digest changed")
    sys.path.insert(0, str(ROOT / "tools"))
    from foundation_bsr_shift_mask import analyze
    old = analyze(data)  # Includes retained edge sanity checks; never generates these fixtures.
    return {"target_sha256": TARGET_SHA256,
            "coordinate_system": "ELF virtual addresses, no runtime rebase",
            "structure": structure(data),
            "prior_checker_result": json.loads(json.dumps(old)),
            "prior_checker_sha256": digest(ROOT / "tools/foundation_bsr_shift_mask.py"),
            "prior_evidence_sha256": digest(ROOT / "research/work-items/foundation-bsr-shift-mask-94/evidence.json"),
            "captured_binary_executed": False}


def intervals(n):
    """Equivalent arithmetic intervals, without doubling, bit scans or shifts.

    r = n mod 2**63. For r>0, rank k is the smallest k with r<=2**k;
    r=0 corresponds to the original all-ones odd operand and rank63.
    The two-bit field is a quotient of a remainder modulo four divisors.
    """
    r = n % PERIOD
    rank, capacity = 0, 1
    if r == 0:
        rank = 63
    else:
        while capacity < r:
            rank, capacity = rank + 1, capacity * 2
    divisor = 16 if rank <= 7 else 2 ** (rank - 3)
    field = ((r - 1) % (4 * divisor)) // divisor
    result = field + 4 * max(rank, 6) - 23
    require(0 <= rank <= 63 and 1 <= result <= 232, "Arithmetic interval bounds changed")
    return result, rank, divisor, field


def corpus():
    cases = dict.fromkeys(WITNESSES.values(), "witness")

    def add(n, category):
        if 0 <= n < MODULUS:
            cases.setdefault(n, category)

    def add_pair(r, category):
        if 0 <= r < PERIOD:
            add(r, category)
            add(r + PERIOD, category)

    for n in range(513):
        add_pair(n, "small_and_high_bit_pairs")
    for rank in range(64):
        low = 1 if rank == 0 else 2 ** (rank - 1) + 1
        high = min(2 ** rank, PERIOD - 1)
        divisor = 16 if rank <= 7 else 2 ** (rank - 3)
        for center in (low, high):
            for delta in (-2, -1, 0, 1, 2):
                add_pair(center + delta, "rank_edges")
        for quotient in range(low // divisor, high // divisor + 2):
            for delta in (-2, -1, 0, 1, 2):
                add_pair(quotient * divisor + 1 + delta, "field_edges")
    rng = random.Random(94_54_4390)
    for _ in range(4096):
        add_pair(rng.randrange(PERIOD), "seeded_period_pairs")
    return list(cases), Counter(cases.values())


def fixture_bytes():
    rows, categories = corpus()
    facts = [intervals(n) for n in rows]
    inputs = "".join(f"{n}\n" for n in rows).encode()
    outputs = "".join(f"{f[0]}\n" for f in facts).encode()
    ranks = Counter(f[1] for f in facts)
    require(set(ranks) == set(range(64)), "Corpus misses a bit rank")
    for n in rows:
        require(intervals(n)[0] == intervals((n + PERIOD) % MODULUS)[0], "Period relation changed")
    return inputs, outputs, {"cases": len(rows), "categories": dict(categories),
        "all_inputs_admitted": True, "ranks": {str(k): ranks[k] for k in sorted(ranks)},
        "outputs_min_max": [min(f[0] for f in facts), max(f[0] for f in facts)],
        "field_values": sorted({f[3] for f in facts}), "period": PERIOD,
        "witnesses": {name: {"row_zero_based": rows.index(n), "input": n,
                              "expected": intervals(n)[0]} for name, n in WITNESSES.items()}}


def freeze():
    require(not SOURCE.exists(), "Freeze must precede the new Rust source")
    directory = PACKET / "frozen"
    directory.mkdir()
    facts = admit()
    inputs, outputs, coverage = fixture_bytes()
    for filename, content in (("inputs.tsv.gz", inputs), ("expected.txt.gz", outputs)):
        (directory / filename).write_bytes(gzip.compress(content, mtime=0))
    record = {"method": "modulo-2^63 intervals plus quotient/remainder field extraction",
              "rust_source_existed_at_freeze": False, "oracle_source_sha256": digest(__file__),
              "inputs_sha256": hashlib.sha256(inputs).hexdigest(),
              "expected_sha256": hashlib.sha256(outputs).hexdigest(),
              "fixture_hashes_cover": "decompressed byte streams", "coverage": coverage,
              "static_facts": facts, "full_input_domain_exhausted": False}
    (directory / "ORACLE-FREEZE.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


if __name__ == "__main__":
    if sys.argv[1:] != ["--freeze"]:
        raise SystemExit("usage: oracle.py --freeze (before Rust only)")
    print(json.dumps(freeze(), indent=2))
