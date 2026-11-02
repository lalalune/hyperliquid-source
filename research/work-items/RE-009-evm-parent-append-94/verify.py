#!/usr/bin/env python3
"""Static byte binding and conditional final-buffer relation; never execute node94."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections, unwind_index  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

HERE = Path(__file__).resolve().parent
NODE = ROOT / "artifacts/node/94/hl-node"
DIGEST = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
GRAMMAR = "d1f5e3a8e7721c7537286796410f7f2d328590460a28a9560f8c19ee01dda612"
OWNER_HASHES = {
    0x1AB3D20: "93d07eae728e5ddaadc820741e5508fffe77bf2a74f50ec73d3bd448b3124d15",
    0x28546C0: "f10dde406ec27ba21c2dd1180560e96403e9c8d182130587376ce96424444ec0",
}
RANGES = ((0x1AB40D6, 0x1AB416F), (0x1AB4705, 0x1AB4725),
          (0x1AB47DF, 0x1AB488F), (0x1AB46D8, 0x1AB4705),
          (0x2854859, 0x285485E), (0x1AB3D20, 0x1AB3D31))
VARIABLE = (0x1AB4709, 0x1AB4829, 0x1AB4864, 0x1AB486F)
NOMINAL = {"count_delta": 1, "edge_displacement": 0x2D8,
           "parent_bits": 64, "index_bits": 16}
ORDER = ("parent", "new", "old", "dummy", "result")
SIZES = dict(zip(ORDER, (816, 720, 720, 720, 24)))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def plan():
    return json.loads((HERE / "PLAN.json").read_text())


def location(data, secs, address, size):
    if type(address) is not int or type(size) is not int or address < 0 or size <= 0:
        raise ValueError("invalid virtual range")
    found = [s for s in secs if s["type"] != 8 and s["address"] <= address
             and address + size <= s["address"] + s["size"]]
    if len(found) != 1:
        raise ValueError("range is not uniquely file backed")
    offset = found[0]["offset"] + address - found[0]["address"]
    if offset < 0 or offset + size > len(data):
        raise ValueError("range exceeds input")
    return offset


def span(data, secs, address, size):
    offset = location(data, secs, address, size)
    return data[offset:offset + size]


def fields(data, secs):
    """Decode only four selected operand/width fields below image authentication.

    Mutants are inert byte copies. This is not an instruction evaluator. All
    remaining 424 retained bytes must match the fixed native grammar.
    """
    fixed = bytearray()
    for a, b in RANGES:
        raw = bytearray(span(data, secs, a, b - a))
        for va in VARIABLE:
            if a <= va < b:
                raw[va - a] = 0
        fixed.extend(raw)
    if sha(fixed) != GRAMMAR:
        raise ValueError("fixed native grammar changed")
    count, edge, parent, index = (span(data, secs, va, 1)[0] for va in VARIABLE)
    if count not in (1, 2) or edge not in (0xD8, 0xD0) or parent not in (0x4C, 0x44) or index not in (0x66, 0x90):
        raise ValueError("unsupported selected field encoding")
    return {"count_delta": count,
            "edge_displacement": struct.unpack("<I", span(data, secs, 0x1AB4829, 4))[0],
            "parent_bits": 64 if parent == 0x4C else 32,
            "index_bits": 16 if index == 0x66 else 32}


def validate_fields(observed):
    if observed != NOMINAL:
        raise ValueError("native append fields changed")


def direct_target(raw, va):
    if raw[:1] == b"\xe8" and len(raw) == 5:
        return va + 5 + struct.unpack_from("<i", raw, 1)[0]
    if len(raw) == 6 and raw[0] == 0x0F and 0x80 <= raw[1] <= 0x8F:
        return va + 6 + struct.unpack_from("<i", raw, 2)[0]
    if len(raw) == 2 and (raw[0] == 0xEB or 0x70 <= raw[0] <= 0x7F):
        return va + 2 + struct.unpack_from("<b", raw, 1)[0]
    raise ValueError("unexpected direct edge form")


def authenticate(data, p):
    if len(data) != 91774280 or sha(data) != DIGEST:
        raise ValueError("node94 identity mismatch")
    secs, index = unwind_index(data)
    cies, fdes = eh_frame_records(data, secs)
    binding = p["static_binding"]
    for expected in binding["owner_and_caller"]:
        a, b = (int(expected[k], 16) for k in ("start", "end"))
        matched = [f for f in fdes if (f["start"], f["end"]) == (a, b)]
        if len(matched) != 1:
            raise ValueError("owner/caller FDE is not unique")
        f = matched[0]
        if (f["fde"] != int(expected["fde"]["va"], 16)
                or f["cie"] != int(expected["cie"]["va"], 16)
                or f["lsda"] != (None if expected["lsda"] is None else int(expected["lsda"], 16))
                or f["cie"] not in cies
                or sum(e["start"] == a and e["fde"] == f["fde"] for e in index) != 1):
            raise ValueError("FDE/CIE/index/LSDA binding changed")
        if sha(span(data, secs, a, b - a)) != OWNER_HASHES[a]:
            raise ValueError("complete owner/caller body changed")
        for name in ("fde", "cie"):
            va = f[name]
            size = int.from_bytes(span(data, secs, va, 4), "little") + 4
            raw = span(data, secs, va, size)
            if raw.hex() != expected[name]["raw"] or sha(raw) != expected[name]["sha256"]:
                raise ValueError("unwind record bytes changed")
    if len(binding["ranges"]) != len(RANGES):
        raise ValueError("selected range count changed")
    for expected, (a, b) in zip(binding["ranges"], RANGES):
        if (int(expected["start"], 16), int(expected["end"], 16), expected["bytes"]) != (a, b, b - a):
            raise ValueError("selected range metadata changed")
        if sha(span(data, secs, a, b - a)) != expected["sha256"]:
            raise ValueError("selected range bytes changed")
    for e in binding["branch_edges"]:
        va = int(e["site"], 16)
        raw = span(data, secs, va, len(bytes.fromhex(e["raw"])))
        if raw.hex() != e["raw"] or direct_target(raw, va) != int(e["target"], 16):
            raise ValueError("selected branch changed")
    if direct_target(span(data, secs, 0x2854859, 5), 0x2854859) != 0x1AB3D20:
        raise ValueError("credited caller edge changed")
    observed = fields(data, secs)
    validate_fields(observed)
    return secs, observed


def check_listing(text, data, secs, p):
    """Bind each retained decoder row, including row boundaries, to native bytes."""
    counts, expected, actual, starts = {}, {}, {}, {}
    current = None
    for r in p["static_binding"]["ranges"]:
        a, b = int(r["start"], 16), int(r["end"], 16)
        expected[r["role"]] = (a, b, r["instructions"])
    for line in text.splitlines():
        if line.startswith("# range "):
            _, _, current, aa, bb = line.split()
            if current not in expected or current in counts or tuple(map(lambda x: int(x, 16), (aa, bb))) != expected[current][:2]:
                raise ValueError("listing range header changed")
            counts[current], starts[current] = 0, []
            continue
        m = re.match(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*\S", line)
        if not m:
            continue
        if current is None:
            raise ValueError("instruction outside range header")
        a = int(m[1], 16)
        raw = bytes.fromhex(m[2])
        lo, hi, _ = expected[current]
        if not lo <= a < a + len(raw) <= hi or a != lo + sum(len(x[1]) for x in starts[current]):
            raise ValueError("listing row is noncontiguous/outside its range")
        if raw != span(data, secs, a, len(raw)):
            raise ValueError("listing bytes differ from authenticated target")
        for i, byte in enumerate(raw):
            if a + i in actual:
                raise ValueError("duplicate listing bytes")
            actual[a + i] = byte
        starts[current].append((a, raw))
        counts[current] += 1
    want = {a + i: v for a, b in RANGES for i, v in enumerate(span(data, secs, a, b - a))}
    if actual != want or set(counts) != set(expected) or any(counts[k] != expected[k][2] for k in counts):
        raise ValueError("listing coverage/row count changed")
    return {k: [[hex(a), raw.hex()] for a, raw in rows] for k, rows in starts.items()}


def fixture(n, p):
    """Input construction only; expected outputs were frozen separately in PLAN."""
    spec = p["relation_fixture"]
    addresses = dict(spec["addresses"])
    objects = {k: bytearray([spec["sentinels"][k]]) * SIZES[k] for k in ORDER}
    for j in range(11):
        objects["parent"][32*j:32*j+32] = bytes((31*j+13*i+7) % 256 for i in range(32))
        objects["parent"][0x160+32*j:0x180+32*j] = bytes((173+19*j+3*i) % 256 for i in range(32))
    for j in range(12):
        struct.pack_into("<Q", objects["parent"], 0x2D0+8*j, 0x600000060000+0x1000*j)
    struct.pack_into("<QHH", objects["parent"], 0x2C0, 0x700000070000, 0x1234, n)
    struct.pack_into("<Q", objects["parent"], 0x2D0+8*n, addresses["old"])
    struct.pack_into("<Q", objects["parent"], 0x2D8+8*n, addresses["dummy"])
    struct.pack_into("<QHH", objects["old"], 0x2C0, addresses["parent"], n, 6)
    struct.pack_into("<QHH", objects["new"], 0x2C0, 0, 0xA5A5, 5)
    struct.pack_into("<QHH", objects["dummy"], 0x2C0, 0, 0xB6B6, 7)
    key = bytes((224+7*i) % 256 for i in range(32))
    value = bytes((96-3*i) % 256 for i in range(32))
    return {k: bytes(v) for k, v in objects.items()}, addresses, key, value, tuple(spec["saved_words"])


def flatten(objects):
    return b"".join(objects[k] for k in ORDER)


def apply_relation(c, initial, addresses, key, value, saved_words, h=0):
    """Final-buffer projection under entry/alias premises, not target execution.

    Only four decoded operand fields vary in the inert controls. The selected
    native CFG fixes d=n, one scalar repair, and the raw three-word return.
    Frame stores and intermediate order are authenticated but not simulated.
    """
    if set(initial) != set(SIZES) or set(addresses) != set(SIZES):
        raise ValueError("five named objects required")
    intervals = []
    for name, size in SIZES.items():
        a = addresses[name]
        if type(a) is not int or not 0 < a < 2**64 or a+size > 2**64 or len(initial[name]) != size:
            raise ValueError("valid mapped object premise failed")
        if any(a < hi and lo < a+size for lo, hi in intervals):
            raise ValueError("nonalias premise failed")
        intervals.append((a, a+size))
    if type(h) is not int or h != 0 or len(key) != 32 or len(value) != 32:
        raise ValueError("saved-zero-word/prepared-pair premise failed")
    if len(saved_words) != 3 or any(type(x) is not int or not 0 <= x < 2**64 for x in saved_words):
        raise ValueError("three saved u64 words required")
    parent = struct.unpack_from("<Q", initial["old"], 0x2C0)[0]
    n = struct.unpack_from("<H", initial["parent"], 0x2CA)[0]
    d = struct.unpack_from("<H", initial["old"], 0x2C8)[0]
    if parent != addresses["parent"] or n >= 11 or d != n:
        raise ValueError("selected nonzero-parent append premise failed")
    if c["count_delta"] not in (1, 2) or c["edge_displacement"] not in (0x2D8, 0x2D0) or c["parent_bits"] not in (32, 64) or c["index_bits"] not in (16, 32):
        raise ValueError("unsupported operand control")
    out = {k: bytearray(v) for k, v in initial.items()}
    out["parent"][32*d:32*d+32] = key
    out["parent"][0x160+32*d:0x180+32*d] = value
    struct.pack_into("<Q", out["parent"], c["edge_displacement"]+8*d, addresses["new"])
    struct.pack_into("<H", out["parent"], 0x2CA, n+c["count_delta"])
    repair = struct.unpack_from("<Q", out["parent"], 0x2D8+8*d)[0]
    names = [name for name in ("new", "old", "dummy") if addresses[name] == repair]
    if len(names) != 1:
        raise ValueError("repair child is not a valid declared object")
    child = out[names[0]]
    struct.pack_into("<Q" if c["parent_bits"] == 64 else "<I", child, 0x2C0,
                     parent % (1 << c["parent_bits"]))
    struct.pack_into("<H" if c["index_bits"] == 16 else "<I", child, 0x2C8, d+1)
    struct.pack_into("<QQQ", out["result"], 0, *saved_words)
    return {k: bytes(v) for k, v in out.items()}, addresses["result"]


def raw_metadata(objects, n):
    return {"parent_count_hex": objects["parent"][0x2CA:0x2CC].hex(),
            "parent_edges_n_n1_hex": objects["parent"][0x2D0+8*n:0x2E0+8*n].hex(),
            "new_parent_index_count_hex": objects["new"][0x2C0:0x2CC].hex(),
            "dummy_parent_index_count_hex": objects["dummy"][0x2C0:0x2CC].hex(),
            "result_hex": objects["result"].hex()}


def control_results(data, secs, p):
    result = []
    for ctrl in p["negative_native_controls"]:
        va = int(ctrl["va"], 16)
        at = location(data, secs, va, 1)
        if data[at:at+1].hex() != ctrl["original"]:
            raise ValueError("control source byte changed")
        mutant = bytearray(data)
        mutant[at] = int(ctrl["mutation"], 16)
        c = fields(mutant, secs)
        try:
            validate_fields(c)
        except ValueError:
            rejected = True
        else:
            raise ValueError("native validator accepted control")
        cases = []
        for vector in p["independent_full_buffer_vectors"]:
            n = vector["n"]
            initial, addresses, key, value, words = fixture(n, p)
            normal, _ = apply_relation(NOMINAL, initial, addresses, key, value, words)
            changed, ret = apply_relation(c, initial, addresses, key, value, words)
            if sha(flatten(normal)) != vector["expected_sha256"]:
                raise ValueError("baseline differs from pre-model vector")
            differences = [(name, i, before, after) for name in ORDER
                           for i, (before, after) in enumerate(zip(normal[name], changed[name])) if before != after]
            if not differences:
                raise ValueError("inert control has no final-buffer witness")
            name, offset, before, after = differences[0]
            cases.append({"n": n, "different_bytes": len(differences),
                          "first_difference": {"object": name, "offset": hex(offset),
                                               "nominal_hex": f"{before:02x}", "control_hex": f"{after:02x}"},
                          "output_sha256": sha(flatten(changed)), "return_address": hex(ret),
                          "raw": raw_metadata(changed, n)})
        result.append({"site": ctrl["va"], "original": ctrl["original"],
                       "mutation": ctrl["mutation"], "inert_copy_bytes": len(mutant),
                       "changed_bytes": 1, "native_validator_rejected": rejected,
                       "decoded_fields": c, "cases": cases})
    return {"schema": "re009-parent-append-controls/1", "captured_execution": False,
            "output_kind": "conditional static final-buffer relation outputs, not native execution",
            "controls": result}


def analyze(data, p):
    secs, observed = authenticate(data, p)
    listings = [check_listing((HERE/name).read_text(), data, secs, p)
                for name in ("native-gnu.txt", "native-llvm.txt")]
    if listings[0] != listings[1]:
        raise ValueError("decoder row boundaries disagree")
    cases = []
    for vector in p["independent_full_buffer_vectors"]:
        n = vector["n"]
        initial, addresses, key, value, words = fixture(n, p)
        out, ret = apply_relation(observed, initial, addresses, key, value, words)
        if (len(flatten(initial)), sha(flatten(initial)), len(flatten(out)), sha(flatten(out)), key.hex(), value.hex()) != (
                vector["input_bytes"], vector["input_sha256"], vector["expected_bytes"], vector["expected_sha256"],
                vector["key_hex"], vector["value_hex"]):
            raise ValueError("frozen whole-buffer vector mismatch")
        cases.append({"n": n, "input_sha256": sha(flatten(initial)), "output_sha256": sha(flatten(out)),
                      "compared_bytes": len(flatten(out)), "return_address": hex(ret), "raw": raw_metadata(out, n)})
    return {"schema": "re009-parent-append-evidence/1", "target_sha256": DIGEST,
            "target_bytes": len(data), "plan_sha256": sha((HERE/"PLAN.json").read_bytes()),
            "native_binding": p["static_binding"], "native_binding_is_pre_model_snapshot": True,
            "new_conditional_python_relation": True, "decoded_fields": observed,
            "counts": {"retained_bytes": 428, "decoder_rows_each": 99, "selected_continuation_bytes": 406,
                       "credited_call_and_prologue_bytes": 22, "new_owner_byte_credit": 0,
                       "normal_cases": 4, "compared_final_bytes": 12000, "inert_controls": 4,
                       "control_case_counterexamples": 16},
            "baseline_cases": cases, "captured_execution": False,
            "limits": ["Conditional final-buffer relation, not native execution or whole insertion.",
                       "All object/source/frame alias, capacity, ownership and prior-transfer premises remain open.",
                       "No original ABI, Rust component, intermediate-store equivalence or acceptance gate."]}, control_results(data, secs, p)


def check_manifest():
    rows = (HERE/"MANIFEST.sha256").read_text().splitlines()
    expected = {f.name for f in HERE.iterdir() if f.is_file() and f.name != "MANIFEST.sha256"}
    seen = set()
    for row in rows:
        digest, name = row.split("  ", 1)
        if name not in expected or name in seen or (HERE/name).is_symlink() or sha((HERE/name).read_bytes()) != digest:
            raise ValueError("packet manifest mismatch")
        seen.add(name)
    if seen != expected:
        raise ValueError("packet manifest coverage mismatch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", type=Path, default=NODE)
    parser.add_argument("--out", type=Path, help="export deterministic evidence/control JSON to a separate directory")
    args = parser.parse_args()
    evidence, controls = analyze(args.node.read_bytes(), plan())
    generated = {"evidence.json": encode(evidence), "controls.json": encode(controls)}
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        for name, content in generated.items():
            (args.out/name).write_text(content)
    else:
        for name, content in generated.items():
            if (HERE/name).read_text() != content:
                raise ValueError(f"stale {name}")
        check_manifest()
    print("parent-append: authenticated 428 bytes/99 rows; 4 whole-buffer cases; 16 control counterexamples; no captured execution")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, struct.error) as exc:
        print(f"parent-append: {exc}", file=sys.stderr)
        sys.exit(1)
