"""Pre-Rust, target-grounded quotient/remainder oracle; no captured execution."""
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
SOURCE = ROOT / "src/node94-bsr-normalize/lib.rs"
TARGET_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
M = 2 ** 32
MAX = M - 1
WITNESSES = {
    "bypass_absent_word_zero": (None, MAX, 1, 0),
    "bypass_absent_word_nonzero": (None, 0, 1, MAX),
    "bypass_max_word_zero": (MAX, MAX, 1, 0),
    "bypass_max_word_nonzero": (MAX, 0, 1, 2),
    "flag_two_is_main": (0, 1000, 2, 1),
    "flag_two_requires_word": (None, 0, 2, 1),
    "main_max_undefined_even_without_refinement": (MAX, 8192, 0, 0),
    "discard_before_right_shift": (2 ** 24 - 1, 8192, 0, 1),
    "subtraction_wrap": (255, 256, 0, 2),
    "saved_refinement_nonzero_bsr_zero": (0, 4096, 0, 2),
    "saved_refinement_zero_bsr_nonzero": (1, 4096, 0, 0),
    "top_word_logical_shift": (MAX - 1, 12288, 0, 1),
    "increment_crosses_power": (255, 8192, 0, 0),
    "nonzero_high_refinement": (0, 4096, 0, 2 ** 31),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def admit():
    sys.path.insert(0, str(ROOT / "tools"))
    from foundation_bsr_normalize import analyze
    from elf_index import sections
    import capstone

    data = TARGET.read_bytes()
    require(hashlib.sha256(data).hexdigest() == TARGET_SHA256, "Target digest changed")
    existing = analyze(data)  # Static bytes/FDE/call checks only; not its value model.
    secs = {s["name"]: s for s in sections(data)}
    text, eh = secs[".text"], secs[".eh_frame"]

    def code(va, size):
        offset = text["offset"] + va - text["address"]
        require(text["offset"] <= offset and offset + size <= text["offset"] + text["size"],
                "Code range outside .text")
        return data[offset:offset + size]

    cie = data[eh["offset"]:eh["offset"] + 24]
    require(cie.hex() == "1400000000000000017a5200017810011b0c070890010000", "CIE changed")
    frames = []
    for offset, start, end in ((0x2d3cec, 0x55c9800, 0x55c9830),
                               (0x2d3dfc, 0x55caf70, 0x55cc408)):
        file_offset = eh["offset"] + offset
        length = struct.unpack_from("<I", data, file_offset)[0] + 4
        raw = data[file_offset:file_offset + length]
        pc = eh["address"] + offset + 8 + struct.unpack_from("<i", raw, 8)[0]
        extent = struct.unpack_from("<I", raw, 12)[0]
        require((pc, pc + extent) == (start, end), "Decoded FDE range changed")
        require(struct.unpack_from("<I", raw, 4)[0] == offset + 4, "FDE CIE link changed")
        frames.append({"section_offset": hex(offset), "file_offset": hex(file_offset),
                       "start": hex(pc), "end_exclusive": hex(pc + extent), "raw_hex": raw.hex()})

    # Fresh linear decoding verifies the four retained sites are instruction starts.
    caller = code(0x55caf70, 0x55cc408 - 0x55caf70)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    instructions = list(decoder.disasm(caller, 0x55caf70))
    require(sum(i.size for i in instructions) == len(caller), "Incomplete caller linear decode")
    targets = [i for i in instructions if i.mnemonic == "call" and i.op_str == "0x55c9800"]
    require([i.address for i in targets] == [0x55cb6fb, 0x55cb7f0, 0x55cbde5, 0x55cc00a],
            "Caller instruction sites changed")
    return {
        "target_sha256": TARGET_SHA256,
        "coordinate_system": "ELF virtual addresses, no runtime rebase",
        "start": "0x55c9800", "end_exclusive": "0x55c9830", "body_bytes": 48,
        "body_file_offset": hex(text["offset"] + 0x55c9800 - text["address"]),
        "body_sha256": hashlib.sha256(code(0x55c9800, 48)).hexdigest(),
        "body_hex": code(0x55c9800, 48).hex(), "cie_hex": cie.hex(), "frames": frames,
        "caller_body_sha256": hashlib.sha256(caller).hexdigest(),
        "caller_bytes": len(caller), "caller_linear_instructions": len(instructions),
        "call_sites": [{"va": hex(i.address), "bytes": i.bytes.hex(), "decoded": i.mnemonic + " " + i.op_str}
                       for i in targets],
        "capstone_version": capstone.__version__, "prior_static_result": existing,
        "prior_checker_sha256": digest(ROOT / "tools/foundation_bsr_normalize.py"),
        "prior_evidence_sha256": digest(ROOT / "research/work-items/foundation-bsr-normalize-94/evidence.json"),
        "neighbor_semantics_included": False, "complete_xref_census": False,
        "captured_binary_executed": False,
    }


def mathematical_base(word, refinement):
    """Power interval plus integer quotient; no shifts or bit-scan operations.

    Multiplication by 256 in u32 discards the top byte of n. Reducing n
    modulo 2**24 BEFORE multiplication models those discarded bits.
    """
    n = (word + 1) % M
    require(n != 0, "Main-path BSR domain not admitted")
    rank, power = 0, 1
    while 2 * power <= n:
        rank, power = rank + 1, power * 2
    fraction = (256 * (n % (2 ** 24))) // power if refinement != 0 else 0
    return 256 * rank + fraction


def expected(word, value, flag, refinement):
    if flag == 1:
        return "ok\t" + str(256 * int(refinement != 0))
    if word is None:
        return "missing"
    if word == MAX:
        return "undefined"
    return "ok\t" + str((value - mathematical_base(word, refinement)) % M)


def corpus():
    cases = dict.fromkeys(WITNESSES.values(), "witness")

    def add(row, category):
        cases.setdefault(row, category)

    words = {0, 1, 2, MAX - 1, MAX}
    for exponent in range(32):
        for delta in (-2, -1, 0, 1, 2):
            n = 2 ** exponent + delta
            if 1 <= n <= MAX:
                words.add(n - 1)
    for top in (0, 1, 127, 128, 255):
        for low in (0, 1, 127, 128, 255, 256, 2 ** 23 - 1, 2 ** 23, 2 ** 24 - 1):
            n = top * 2 ** 24 + low
            if 1 <= n <= MAX:
                words.add(n - 1)
    for word in sorted(words):
        for value in (0, 255, 256, 8192, MAX):
            for flag in (0, 1, 2):
                for refinement in (0, 1, 2, MAX):
                    add((word, value, flag, refinement), "power_and_truncation_edges")
        if word != MAX:
            for refinement in (0, 1):
                base = mathematical_base(word, refinement)
                for value in (base - 1, base, base + 1):
                    add((word, value % M, 0, refinement), "subtraction_boundary")
    for word in (None, MAX):
        for value in (0, 1, 256, MAX):
            for flag in (0, 1, 2, 255, 2 ** 31, MAX):
                for refinement in (0, 1, 2, 2 ** 31, MAX):
                    add((word, value, flag, refinement), "bypass_and_refusals")
    rng = random.Random(94055_9800)
    for _ in range(4096):
        word = rng.choice((rng.randrange(M), rng.choice(sorted(words))))
        value = rng.randrange(M)
        flag = rng.choice((0, 1, 2, rng.randrange(M)))
        refinement = rng.choice((0, 1, rng.randrange(M)))
        add((word, value, flag, refinement), "seeded_mixed_inputs")
    return list(cases), Counter(cases.values())


def fixture_bytes():
    rows, categories = corpus()
    inputs = "".join("\t".join("-" if x is None else str(x) for x in row) + "\n" for row in rows).encode()
    outputs = [expected(*row) for row in rows]
    result = ("\n".join(outputs) + "\n").encode()
    coverage = {"cases": len(rows), "categories": dict(categories),
                "result_classes": dict(Counter(x.split("\t")[0] for x in outputs)),
                "bypass_cases": sum(row[2] == 1 for row in rows),
                "witnesses": {name: {"row_zero_based": rows.index(row), "input": row,
                                     "expected": expected(*row)} for name, row in WITNESSES.items()}}
    return inputs, result, coverage


def freeze():
    require(not SOURCE.exists(), "Freeze must precede the new Rust source")
    directory = PACKET / "frozen"
    directory.mkdir()
    facts = admit()
    inputs, outputs, coverage = fixture_bytes()
    for filename, content in (("inputs.tsv.gz", inputs), ("expected.txt.gz", outputs)):
        (directory / filename).write_bytes(gzip.compress(content, mtime=0))
    record = {"method": "power-interval rank, low-24-bit remainder and integer quotient",
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
