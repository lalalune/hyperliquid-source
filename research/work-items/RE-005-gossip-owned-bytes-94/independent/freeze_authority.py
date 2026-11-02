"""Seal independent byte-grammar and conditional wire/state expectations."""

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from utf8_math import python_relation, utf8_relation
from wire_math import MAX, wire_relation

HERE = Path(__file__).resolve().parent
NATIVE = HERE.parent / "source-peer/gossip-leaf-466dc10"


def digest(path):
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def prefixes(length):
    result = [bytes([length])] if length <= 250 else []
    for marker, size in [(251, 2), (252, 4), (253, 8)]:
        if length < 1 << (size * 8):
            result.append(bytes([marker]) + length.to_bytes(size, "little"))
    return result


def semantic_payloads():
    values = {b"", b"\0", b"\x7f", b"\x80", b"\xff", b"\xc0\x80", b"\xc1\xbf",
              b"\xe0\x80\x80", b"\xed\xa0\x80", b"\xf0\x80\x80\x80", b"\xf4\x90\x80\x80"}
    points = [0, 0x7F, 0x80, 0x7FF, 0x800, 0xD7FF, 0xE000, 0xFFFE, 0xFFFF,
              0x10000, 0x3FFFF, 0x40000, 0xFFFFF, 0x100000, 0x10FFFF]
    for point in points:
        raw = chr(point).encode("utf-8")
        values.add(raw)
        for cut in range(1, len(raw)):
            values.add(raw[:cut])
        for at in range(1, len(raw)):
            for wrong in [0, 0x7F, 0xC0, 0xFF]:
                values.add(raw[:at] + bytes([wrong]) + raw[at + 1:])
    return sorted(values)


def validator_cases():
    cases = {}

    def add(raw, alignment, family):
        cases.setdefault((alignment, raw), family)

    for alignment in range(8):
        add(b"", alignment, "empty-all-alignments")
    for first in range(256):
        add(bytes([first]), first % 8, "all-single-bytes")
        for second in range(256):
            add(bytes([first, second]), (first + 3 * second) % 8, "all-two-byte-inputs")
    for lead in range(0xE0, 0xF0):
        low, high = ((0xA0, 0xBF) if lead == 0xE0 else
                     (0x80, 0x9F) if lead == 0xED else (0x80, 0xBF))
        for second in range(256):
            for third in [0, 0x80, 0xBF, 0xFF]:
                add(bytes([lead, second, third]), (lead + second + third) % 8, "three-byte-second-domain")
        for second in [low, high]:
            for third in range(256):
                add(bytes([lead, second, third]), (lead + second + third) % 8, "three-byte-final-domain")
    for lead in range(0xF0, 0xF5):
        low, high = ((0x90, 0xBF) if lead == 0xF0 else
                     (0x80, 0x8F) if lead == 0xF4 else (0x80, 0xBF))
        for second in range(256):
            add(bytes([lead, second, 0x80, 0x80]), second % 8, "four-byte-second-domain")
        for second in [low, high]:
            for third in range(256):
                add(bytes([lead, second, third]), third % 8, "four-byte-truncated-or-third")
                add(bytes([lead, second, third, 0x80]), third % 8, "four-byte-third-domain")
            for third in [0x80, 0xBF]:
                for fourth in range(256):
                    add(bytes([lead, second, third, fourth]), fourth % 8, "four-byte-final-domain")
    lengths = [*range(41), 47, 48, 63, 64, 65, 127, 128, 129]
    for alignment in range(8):
        for length in lengths:
            for value in [0, 0x20, 0x7F]:
                add(bytes([value]) * length, alignment, "ascii-bulk-and-tail-all-alignments")
        for before in [0, 1, 7, 8, 15, 16, 17, 31, 32, 63]:
            for payload in semantic_payloads():
                add(b"A" * before + payload + b"Z" * 17, alignment, "scalar-offsets-all-alignments")
    return cases


def wire_cases():
    cases = {}

    def add(mode, counter, limit, raw, family):
        cases.setdefault((mode, counter, limit, raw), family)

    for marker in range(256):
        for available in range(11):
            for mode in [0, 1, 2]:
                add(mode, 0, MAX, bytes([marker]) + bytes(available), "all-header-tags-short-fast")
    modes = [0, 1, 2, 0xFFFFFFFF, 1 << 32, (1 << 32) | 1, (1 << 63) | 1, MAX]
    lengths = [0, 1, 2, 7, 8, 9, 15, 16, 31, 250, 251, 256, 65535, 65536,
               (1 << 32) - 1, 1 << 32, 0x0102030405060708, MAX]
    for mode in modes:
        base = 8 if (mode & 0xFFFFFFFF) == 1 else 0
        for counter in [0, MAX - 8, MAX - 7, MAX]:
            for length in lengths:
                limits = {0, counter, MAX}
                for edge in [counter + base, counter + base + length]:
                    limits.update(n for n in [edge - 1, edge, edge + 1] if 0 <= n <= MAX)
                payload = b"a" * length if length <= 256 else b""
                for prefix in prefixes(length):
                    for limit in sorted(limits):
                        add(mode, counter, limit, prefix + payload, "counter-mode-limit-length-boundaries")
        for limit in [0, 7, 8, MAX]:
            add(mode, 0, limit, b"", "empty-before-header-versus-charge")
    for length in lengths:
        for prefix in prefixes(length):
            for cut in range(len(prefix)):
                for mode in [0, 1, 2, 1 << 32]:
                    add(mode, 0, MAX, prefix[:cut], "all-header-prefix-shortages")
            for available in sorted({0, 1, 2, 7, 8, 9, max(0, min(length, 31) - 1)}):
                if available < length:
                    add(0, 0, MAX, prefix + b"b" * available, "payload-short-with-retained-prefix")
    for value in range(256):
        for prefix in prefixes(1):
            for tail in [b"", b"\xff\0", bytes(9)]:
                for mode in [0, 1, 1 << 32]:
                    add(mode, 0, MAX, prefix + bytes([value]) + tail, "all-payload-bytes-and-unread-tail")
    for before in [0, 7, 8, 15, 16, 31, 32]:
        for raw in semantic_payloads():
            payload = b"A" * before + raw
            for prefix in prefixes(len(payload)):
                for mode in [0, 1, 2, (1 << 32) | 1]:
                    add(mode, 0, MAX, prefix + payload + b"\xff\x80END", "utf8-positions-noncanonical-prefix-suffix")
    return cases


def seal():
    assert not (HERE / "FREEZE.json").exists(), "refuse to overwrite an independent seal"
    assert digest(NATIVE / "validation-width-table.bin")["sha256"] == "02b189407fa32e9604226dec547e4849ffaa560a3bf60c7e2cf4d48db5aa2f90"
    validator = validator_cases()
    wire = wire_cases()
    counts = {"validator": Counter(), "wire": Counter()}
    families = {"validator": Counter(), "wire": Counter()}
    alignments = Counter()
    with (HERE / "validator-input.tsv").open("w") as inputs, (HERE / "validator-expected.jsonl").open("w") as expected:
        for index, ((alignment, raw), family) in enumerate(validator.items()):
            case_id = f"v{index:06d}"
            issue = utf8_relation(raw)
            assert issue == python_relation(raw), (raw.hex(), issue, python_relation(raw))
            row = {"id": case_id, "tag": 0 if issue is None else 1,
                   "valid_up_to": None if issue is None else issue[0],
                   "error_len": None if issue is None else issue[1],
                   "validated_hex": raw.hex() if issue is None else None}
            inputs.write(f"{case_id}\t{alignment}\t{raw.hex()}\n")
            expected.write(canonical(row) + "\n")
            counts["validator"][str(row["tag"])] += 1
            families["validator"][family] += 1
            alignments[str(alignment)] += 1
    with (HERE / "wire-input.tsv").open("w") as inputs, (HERE / "wire-expected.jsonl").open("w") as expected:
        for index, ((mode, counter, limit, raw), family) in enumerate(wire.items()):
            case_id = f"w{index:06d}"
            row = wire_relation(case_id, mode, counter, limit, raw)
            inputs.write(f"{case_id}\t{mode}\t{counter}\t{limit}\t{raw.hex()}\n")
            expected.write(canonical(row) + "\n")
            counts["wire"][row["phase"]] += 1
            families["wire"][family] += 1
    native_files = ["NATIVE-INTAKE.json", "HELPER-INTAKE.json", "DATA-AND-IMPORTS.json",
                    "VALIDATOR-TABLE-IMAGE-CLOSURE.json", "NORMAL-DOMAIN.md"]
    own_files = ["UTF8-PROOF.md", "WIRE-PROOF.md", "utf8_math.py", "wire_math.py", "freeze_authority.py",
                 "validator-input.tsv", "validator-expected.jsonl", "wire-input.tsv", "wire-expected.jsonl"]
    result = {"schema": "independent-gossip-byte-grammar-wire-pre-source/1",
              "created_utc": datetime.now(timezone.utc).isoformat(),
              "target_sha256": "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f",
              "native_scopes": {"primary": ["0x466dc10", "0x466dcf4", 228, 68],
                                "vector": ["0x4589a30", "0x4589b2b", 251, 78],
                                "validator": ["0x157a200", "0x157a3f7", 503, 143]},
              "validator_cases": len(validator), "wire_cases": len(wire),
              "distinct_inputs_excluding_id": {"validator": len(validator), "wire": len(wire)},
              "counts": counts, "families": families, "validator_alignment_counts": alignments,
              "files": {name: digest(HERE / name) for name in own_files},
              "native_domain_inputs": {name: digest(NATIVE / name) for name in native_files},
              "independence": {"new_Rust_read_or_authored": False, "repository_implementation_imports": False,
                               "captured_execution_or_instruction_evaluator": False,
                               "method": "Unicode scalar byte grammar, unsigned integer inequalities and byte suffixes",
                               "secondary_validator_check": "Python strict Unicode decoder on every validator case"},
              "limits": ["Defined ordinary allocation/copy/release contract, not transitive allocator closure",
                         "Logical active fields only; excludes inactive Option payload and six padding bytes",
                         "No original ABI/pointer/type/whole-gossip/runtime/compiler/gate claim",
                         "Prefix wrapper/Readers/error-helper theorem is existing credited dependency context"]}
    (HERE / "FREEZE.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(canonical({"validator_cases": len(validator), "wire_cases": len(wire), "counts": counts,
                     "freeze": digest(HERE / "FREEZE.json")}))


if __name__ == "__main__":
    seal()
