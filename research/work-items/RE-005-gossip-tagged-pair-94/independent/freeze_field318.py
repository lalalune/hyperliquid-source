"""Seal a target-derived selector/two-scalar normal-state mathematical corpus."""

from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from field318_math import MAX, TYPE_NAME, field_relation

P = Path(__file__).resolve().parent
PEER = P.parents[1] / "source-peer/gossip-field-466c770"


def digest(path):
    raw = path.read_bytes()
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def encodings(value):
    variants = [bytes([value])] if value <= 250 else []
    for marker, size in [(251, 2), (252, 4), (253, 8)]:
        if value < 1 << (8 * size):
            variants.append(bytes([marker]) + value.to_bytes(size, "little"))
    return variants


def main():
    assert not (P / "FREEZE.json").exists(), "preserve original independent seal"
    assert (P / "invalid-variant-literal.bin").read_bytes() == TYPE_NAME.encode()
    assert digest(PEER / "NATIVE-STATE-PROOF.md")["sha256"] == "48ccd144eb560deeef80bc393599e4f0a48cccef49e3bd61eba51ff6b13697fa"
    cases = {}

    def add(mode, counter, limit, wire, family):
        cases.setdefault((mode, counter, limit, wire), family)

    modes = [0, 1, 2, 3, 0xFFFFFFFF, 1 << 32, (1 << 32) | 1, (1 << 32) | 2,
             0xFFFFFFFF00000000, 0xFFFFFFFF00000001, MAX]
    for selector in range(256):
        for mode in [0, 1, 2, 1 << 32, (1 << 32) | 1]:
            for suffix in [b"", b"\xff\0\xfd\x12\x34\x56\x78\x90\xab\xcd\xef"]:
                add(mode, 0, MAX, bytes([selector]) + suffix, "all-selector-bytes-and-ignored-tail")
    maximum = b"\xfd" + MAX.to_bytes(8, "little")
    seeds = [b"", b"\0", b"\0\xff\0", b"\x02", b"\xff", b"\x01", b"\x01\0",
             b"\x01\0\0", b"\x01\xfe", b"\x01\xff" + bytes(9), b"\x01\0\xfe",
             b"\x01\0\xff" + bytes(9), b"\x01\xfb", b"\x01\xfc\x01\x02",
             b"\x01\xfd\x01\x02\x03", b"\x01\0\xfb\x01", b"\x01" + maximum + maximum,
             b"\x01" + maximum + b"\0", b"\x01\0" + maximum]
    counters = [0, 1, MAX - 17, MAX - 16, MAX - 9, MAX - 8, MAX - 1, MAX]
    for mode in modes:
        for counter in counters:
            limits = {0, 1, 8, 9, 16, 17, MAX, counter}
            for cost in [1, 9, 17]:
                limits.update(n for n in [counter + cost - 1, counter + cost, counter + cost + 1] if 0 <= n <= MAX)
            for limit in sorted(limits):
                for wire in seeds:
                    add(mode, counter, limit, wire, "stage-charge-overflow-limit-highword-boundaries")
    values = [0, 1, 250, 251, 255, 256, 65535, 65536, (1 << 32) - 1, 1 << 32, MAX]
    for first in values:
        for second in values:
            for a in encodings(first):
                for b in encodings(second):
                    for mode in [0, 1, (1 << 32) | 1]:
                        for suffix in [b"", b"\xde\xad\xff\0EXTRA"]:
                            add(mode, 0, 17 if mode else 0, b"\x01" + a + b + suffix,
                                "all-paired-widths-nonminimal-values-and-tail")
    for marker in range(256):
        for suffix in [b"", bytes(9)]:
            for mode in [0, 1]:
                add(mode, 0, MAX, b"\x01" + bytes([marker]) + suffix, "first-header-all-tags-fast-slow")
                for first in [b"\0", b"\xfd" + bytes(8)]:
                    add(mode, 0, MAX, b"\x01" + first + bytes([marker]) + suffix,
                        "second-header-all-tags-after-different-first-widths")
    for marker in [0, 1, 250, 251, 252, 253, 254, 255]:
        for available in range(11):
            for mode in [0, 1, 1 << 32, (1 << 32) | 1]:
                for first in [b"", b"\0", b"\xfd" + bytes(8)]:
                    add(mode, 0, MAX, b"\x01" + first + bytes([marker]) + bytes(available),
                        "every-shortage-and-per-call-fast-threshold")
    phase_counts, tag_counts, families = Counter(), Counter(), Counter()
    with (P / "inputs.tsv").open("w") as inputs, (P / "expected.jsonl").open("w") as expected:
        for index, ((mode, counter, limit, wire), family) in enumerate(cases.items()):
            case_id = f"s{index:06d}"
            result = field_relation(case_id, mode, counter, limit, wire)
            assert len(result) == 16 and len(result["counter_writes"]) <= 3
            assert result["remaining"] + result["consumed"] == len(wire)
            inputs.write(f"{case_id}\t{mode}\t{counter}\t{limit}\t{wire.hex()}\n")
            expected.write(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
            phase_counts[result["phase"]] += 1
            tag_counts[str(result["tag"])] += 1
            families[family] += 1
    owned = ["field318_math.py", "freeze_field318.py", "PROOF.md", "PRIMARY-METADATA.json",
             "BINDINGS.json", "CONTEXT-16.json", "466c770.raw", "466c770.stdout", "466c770.stderr",
             "invalid-variant-literal.bin", "context-first16.bin", "CALLER-CONTEXT.json", "inputs.tsv", "expected.jsonl"]
    peer_files = ["NATIVE-INTAKE.json", "DATA-INTAKE.json", "NATIVE-STATE-PROOF.md"]
    record = {"schema": "independent-gossip-field318-pre-source/1", "created_utc": datetime.now(timezone.utc).isoformat(),
              "target_sha256": "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f",
              "new_scope": {"start": "0x466c770", "end": "0x466c8ae", "bytes": 318, "rows": 86},
              "cases": len(cases), "distinct_inputs_excluding_id": len(cases), "tag_counts": tag_counts,
              "phase_counts": phase_counts, "families": families,
              "input_protocol": "TSV id,mode_u64,counter_u64,limit_u64,wire_hex",
              "output_protocol": "canonical sorted16-key JSONL; inactive fields null; counter_writes max3; exact suffix",
              "files": {name: digest(P / name) for name in owned},
              "independent_source_peer_native_proof": {name: digest(PEER / name) for name in peer_files},
              "independence": {"new_318_Rust_or_client_read_or_authored": False, "repository_implementation_imports": False,
                               "captured_execution_or_instruction_evaluator": False,
                               "method": "unsigned arithmetic, raw byte predicates, established u64 equations and suffixes"},
              "limits": ["Only valid immutable separated ordinary-return state, no original nominal type/ABI/compiler/pointer identity.",
                         "Selector common-error extra words and scalar-forwarding padding/inactive fields excluded.",
                         "Opaque first16 context bytes bound without Location/range-layout inference.",
                         "Existing u64 wrapper/Reader/error and response selector context not counted as new recovery.",
                         "No whole gossip message, runtime execution or component gate claim."]}
    (P / "FREEZE.json").write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"cases": len(cases), "phases": phase_counts, "tags": tag_counts, "freeze": digest(P / "FREEZE.json")}, sort_keys=True))


if __name__ == "__main__":
    main()
