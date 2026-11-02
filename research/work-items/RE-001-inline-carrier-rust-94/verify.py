#!/usr/bin/env python3
"""Static carrier equations and own-source builds; never evaluate captured code."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
COMPONENT = ROOT / "src/node94-alias"
NODE = ROOT / "artifacts/node/94/hl-node"
RUSTC = Path("/workspace/.tools/rust-1.94.1-x86_64-unknown-linux-gnu/bin/rustc")
PREFIX = RUSTC.parent.parent
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
DIGEST = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
VECTORS_HASH = "8f42424e6dbebe4f4d832d813f9cb88f511fa05a534556d1f8d0169fee810d68"
MASK = (1 << 64) - 1
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections, unwind_index  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402


def sha(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def span(data, secs, address, size):
    if type(address) is not int or type(size) is not int or address < 0 or size <= 0:
        raise ValueError("invalid virtual span")
    matches = [s for s in secs if s["type"] != 8 and s["address"] <= address
               and address + size <= s["address"] + s["size"]]
    if len(matches) != 1:
        raise ValueError("span is not uniquely file backed")
    offset = matches[0]["offset"] + address - matches[0]["address"]
    if offset < 0 or offset + size > len(data):
        raise ValueError("span exceeds input")
    return data[offset:offset+size]


def native_fields(data, secs):
    """Only explicit scalar fields for algebraic controls, not an interpreter."""
    grammar = bytearray()
    variables = (0x1449A9E, 0x144A022, 0x144A03C, 0x144A040, 0x144A032)
    for a, z in ((0x1449A80, 0x144A009), (0x144A010, 0x144A069)):
        raw = bytearray(span(data, secs, a, z-a))
        for va in variables:
            if a <= va < z:
                raw[va-a] = 0
        grammar.extend(raw)
    if sha(grammar) != json.loads((HERE/"native.json").read_text())["control_fixed_grammar_sha256"]:
        raise ValueError("fixed native grammar changed")
    sites = ((0x1449A9B, "4883fe10", 3), (0x144A01F, "0fb61c17", 3),
             (0x144A038, "480fa4c108", 4), (0x144A03D, "48c1e008", 3),
             (0x144A02F, "48c1ea38", 3))
    result = []
    for va, encoded, variable in sites:
        original = bytes.fromhex(encoded)
        raw = span(data, secs, va, len(original))
        if any(a != b for i, (a, b) in enumerate(zip(raw, original)) if i != variable):
            raise ValueError("native operand form changed")
        result.append(raw[variable])
    if result[0] not in (15, 16) or result[1] not in (0x17, 0x0F) or any(x not in (7, 8) for x in result[2:4]) or result[4] not in (55, 56):
        raise ValueError("unsupported algebraic control")
    return result


def equations(data, fields=(16, 0x17, 8, 8, 56)):
    """Width-explicit mathematical recurrence from the native shifts.

    None denotes leaving the selected normal inline relation. It assigns no
    behavior to the long cache or panic helpers. There is no instruction loop,
    register machine, decoded-op dispatch or captured instruction evaluator.
    """
    cap, source, high_shift, low_shift, guard = fields
    if len(data) > cap:
        return None
    low = high = 0
    for byte in reversed(data):
        if high >> guard:
            return None
        high = ((high << high_shift) | (low >> (64-high_shift))) & MASK
        low = ((low << low_shift) | (data[0] if source == 0x0F else byte)) & MASK
    return low, high


def vectors():
    raw = (COMPONENT/"evidence/inline-carrier-vectors.tsv").read_bytes()
    if sha(raw) != VECTORS_HASH:
        raise ValueError("pre-Rust fixture identity changed")
    result = []
    for line in raw.decode().splitlines():
        if line.startswith("#"):
            continue
        partition, name, encoded, lo, hi = line.split("\t")
        data = b"" if encoded == "-" else bytes.fromhex(encoded)
        expected = None if partition == "api" else (int(lo, 16), int(hi, 16))
        if partition not in ("native", "api") or (partition == "api" and len(data) <= 16):
            raise ValueError("invalid fixture partition")
        if partition == "native" and (expected != equations(data)
                or (expected[1] << 64 | expected[0]) != sum(byte << (8*i) for i, byte in enumerate(data))):
            raise ValueError("frozen native halves disagree with independent equations")
        result.append({"partition": partition, "name": name, "input": data, "expected": expected})
    if (sum(r["partition"] == "native" for r in result), sum(r["partition"] == "api" for r in result)) != (156, 2):
        raise ValueError("fixture denominators changed")
    for bit in range(128):
        r = next(r for r in result if r["name"] == f"bit-{bit}")
        if int.from_bytes(r["input"], "little") != 1 << bit:
            raise ValueError("one-bit witness changed")
    return result


def check_listing(text, data, secs, owners):
    actual = {}
    for line in text.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*\S", line)
        if m:
            va, raw = int(m[1], 16), bytes.fromhex(m[2])
            if raw != span(data, secs, va, len(raw)):
                raise ValueError("listing differs from target")
            for i, byte in enumerate(raw):
                if va+i in actual:
                    raise ValueError("duplicate native export")
                actual[va+i] = byte
    expected = {a+i: byte for r in owners for a in [int(r["start"], 16)]
                for i, byte in enumerate(span(data, secs, a, r["bytes"]))}
    if actual != expected:
        raise ValueError("incomplete native export")


def authenticate(data):
    if len(data) != 91774280 or sha(data) != DIGEST:
        raise ValueError("node94 identity mismatch")
    observed = json.loads((HERE/"native.json").read_text())
    if observed["plan_sha256"] != sha((HERE/"PLAN.json").read_bytes()):
        raise ValueError("frozen plan pin changed")
    secs, index = unwind_index(data)
    cies, fdes = eh_frame_records(data, secs)
    for r in observed["owners"]:
        a, z = int(r["start"], 16), int(r["end"], 16)
        matches = [f for f in fdes if (f["start"], f["end"]) == (a, z)]
        if len(matches) != 1:
            raise ValueError("FDE extent changed")
        f = matches[0]
        if (f["fde"] != int(r["fde"], 16) or f["cie"] != int(r["cie"], 16)
                or f["lsda"] != (None if r["lsda"] is None else int(r["lsda"], 16))
                or f["cie"] not in cies
                or sum(e["start"] == a and e["fde"] == f["fde"] for e in index) != 1):
            raise ValueError("FDE/CIE/index/LSDA changed")
        if sha(span(data, secs, a, z-a)) != r["sha256"]:
            raise ValueError("complete credited body changed")
        for key in ("fde", "cie"):
            va = f[key]
            n = int.from_bytes(span(data, secs, va, 4), "little") + 4
            if span(data, secs, va, n).hex() != r[key+"_raw"]:
                raise ValueError("raw unwind record changed")
    rela = next(s for s in secs if s["name"] == ".rela.dyn")
    rows = data[rela["offset"]:rela["offset"]+rela["size"]]
    selected = [rows[i:i+24] for i in range(0, len(rows), 24)
                if struct.unpack_from("<Q", rows, i)[0] == 0x576F5F0]
    if selected != [bytes.fromhex(observed["slot_binding"]["raw"])] or struct.unpack("<QQq", selected[0]) != (0x576F5F0, 8, 0x144A010):
        raise ValueError("recursive/tail-call relocation changed")
    for e in observed["packer_edges"]:
        va = int(e["site"], 16)
        raw = span(data, secs, va, 6)
        if raw.hex() != e["raw"] or va+6+struct.unpack_from("<i", raw, 2)[0] != 0x576F5F0:
            raise ValueError("packer edge changed")
    if native_fields(data, secs) != [16, 0x17, 8, 8, 56]:
        raise ValueError("admitted native fields changed")
    # Exact guard forms and destinations, plus inline index zero/normal RET.
    for va, encoded in ((0x1449A9F, "763e"), (0x1449ADF, "31d2"),
                        (0x144A018, "4839f27427732a"), (0x144A033, "7527"),
                        (0x144A044, "4889ca5bc3")):
        if span(data, secs, va, len(bytes.fromhex(encoded))).hex() != encoded:
            raise ValueError("admitted native guard/return changed")
    for name in ("native-gnu.txt", "native-llvm.txt"):
        check_listing((HERE/name).read_text(), data, secs, observed["owners"])
    return secs


def native_controls(data, secs, cases):
    result = []
    for c in json.loads((HERE/"PLAN.json").read_text())["native_controls"]:
        va = int(c["site"], 16)
        if span(data, secs, va, 1).hex() != c["original"]:
            raise ValueError("native control source byte changed")
        s = next(s for s in secs if s["type"] != 8 and s["address"] <= va < s["address"]+s["size"])
        at = s["offset"]+va-s["address"]
        mutant = bytearray(data)
        mutant[at] = int(c["replacement"], 16)
        fields = native_fields(mutant, secs)
        differences = []
        for row in cases:
            if row["partition"] != "native":
                continue
            actual = equations(row["input"], fields)
            if actual != row["expected"]:
                differences.append({"case": row["name"], "expected_halves": row["expected"],
                                    "control_halves": actual,
                                    "normal_inline_projection": actual is not None})
        if not differences:
            raise ValueError("inoperative native operand control")
        result.append({"site": c["site"], "original": c["original"], "replacement": c["replacement"],
                       "different_native_cases": len(differences), "first_witness": differences[0],
                       "fields": fields, "scope": "static byte/shift equations, not executed target/mutant"})
    return result


def streams(cases, partition):
    selected = [(i, r) for i, r in enumerate(cases) if r["partition"] == partition]
    header = b"IC94\x01" + struct.pack("<H", len(selected))
    inputs, expected = bytearray(header), bytearray(header)
    for i, row in selected:
        inputs.extend(struct.pack("<HB", i, len(row["input"])) + row["input"])
        lo, hi = row["expected"] or (0, 0)
        expected.extend(struct.pack("<HBQQ", i, int(row["expected"] is not None), lo, hi))
    return bytes(inputs), bytes(expected)


def source_pins():
    paths = [COMPONENT/name for name in ("Cargo.toml", "Cargo.lock", "src/lib.rs", "src/tests.rs",
                                       "evidence/contract-vectors.txt", "evidence/inline-carrier-vectors.tsv")]
    paths.append(HERE/"input-only.rs")
    return {str(p.relative_to(ROOT)): {"bytes": p.stat().st_size, "sha256": sha(p.read_bytes())} for p in paths}


def provider_pins():
    paths = {RUSTC.resolve()}
    paths.update(p.resolve() for p in (PREFIX/"lib").glob("*.so*") if p.is_file())
    paths.update(p.resolve() for p in (PREFIX/"lib/rustlib/x86_64-unknown-linux-gnu/lib").iterdir() if p.is_file())
    paths.update(Path(shutil.which(c, path=ENV["PATH"])).resolve() for c in ("cc", "ld"))
    return {str(p): {"bytes": p.stat().st_size, "sha256": sha(p.read_bytes())} for p in sorted(paths)}


def compare(actual, expected):
    if len(actual) != len(expected) or actual[:7] != expected[:7] or (len(actual)-7) % 19:
        raise ValueError("actual Rust output has invalid shape")
    different = []
    for i in range((len(actual)-7)//19):
        a, b = actual[7+19*i:26+19*i], expected[7+19*i:26+19*i]
        if a[:2] != b[:2]:
            raise ValueError("Rust driver case framing changed")
        if a != b:
            different.append({"id": int.from_bytes(a[:2], "little"), "actual_hex": a.hex(), "expected_hex": b.hex()})
    return different


RECIPES = (
    ("length16", "native", "input.len() > 16", "input.len() >= 16"),
    ("byte-order", "native", "input.iter().rev()", "input.iter()"),
    ("shift", "native", "carrier << 8", "carrier << 7"),
    ("signed-byte", "native", "u128::from(byte)", "(byte as i8 as i128) as u128"),
    ("halves", "native", "Some(carrier)", "Some(carrier.rotate_left(64))"),
    ("api-only", "api", "return None;", "return Some(0);"),
)


def qualify(output, cases, controls):
    if output.exists():
        raise ValueError("refuse to reuse qualification output directory")
    output.mkdir(parents=True)
    snapshot = output/"snapshot"
    snapshot.mkdir()
    payload = {"lib.rs": (COMPONENT/"src/lib.rs").read_bytes(),
               "input-only.rs": (HERE/"input-only.rs").read_bytes(),
               "vectors.tsv": (COMPONENT/"evidence/inline-carrier-vectors.tsv").read_bytes(),
               "PLAN.json": (HERE/"PLAN.json").read_bytes(), "native.json": (HERE/"native.json").read_bytes(),
               "recipes.json": json_bytes(RECIPES)}
    for part in ("native", "api"):
        inputs, expected = streams(cases, part)
        payload[part+".inputs.bin"], payload[part+".expected.bin"] = inputs, expected
    manifest = {name: {"bytes": len(raw), "sha256": sha(raw)} for name, raw in payload.items()}
    for name, raw in payload.items():
        (snapshot/name).write_bytes(raw)
        (snapshot/name).chmod(0o444)
    manifest_raw = json_bytes(manifest)
    (snapshot/"SNAPSHOT.json").write_bytes(manifest_raw)
    (snapshot/"SNAPSHOT.json").chmod(0o444)
    snapshot_pin = sha(manifest_raw)
    pins, providers = source_pins(), provider_pins()
    version = subprocess.run([str(RUSTC), "-vV"], capture_output=True, env=ENV, check=True)
    if b"release: 1.94.1\n" not in version.stdout or b"host: x86_64-unknown-linux-gnu\n" not in version.stdout:
        raise ValueError("approved compiler identity changed")
    receipt = {"schema": "re001-inline-carrier-compiled/1", "snapshot_sha256": snapshot_pin,
               "snapshot_files": manifest, "source_input_pins": pins, "providers": providers,
               "runner_sha256": sha(Path(__file__).read_bytes()), "compiler_version": version.stdout.decode(),
               "native_controls": controls, "builds": [], "captured_execution": False}
    variants = [("baseline", None, payload["lib.rs"])]
    for name, partition, old, new in RECIPES:
        source = payload["lib.rs"].decode()
        if source.count(old) != 1:
            raise ValueError(f"source control does not bind once: {name}")
        variants.append((name, partition, source.replace(old, new).encode()))
    jobs = [(v, opt, 0) for v in variants for opt in (0, 3)] + [(variants[0], 3, 1)]
    for (name, partition, source), opt, repeat in jobs:
        for filename, raw in payload.items():
            if (snapshot/filename).read_bytes() != raw:
                raise ValueError("immutable source/input snapshot changed")
        build = output/f"{name}-opt{opt}-repeat{repeat}"
        build.mkdir()
        src = build/"lib.rs"
        src.write_bytes(source)
        src.chmod(0o444)
        library, binary = build/"libnode94_alias.rlib", build/"input-only"
        common = [str(RUSTC), "--edition=2021", "--target=x86_64-unknown-linux-gnu", "--sysroot", str(PREFIX),
                  "-D", "warnings", "-C", "overflow-checks=on", "-C", f"opt-level={opt}", "-C", "debuginfo=0"]
        # A stable remap root removes only authored build-directory variation;
        # no captured or generated machine-code bytes are normalized.
        common += ["--remap-path-prefix", f"{build}=/inline-carrier-build"]
        commands = [common + ["--crate-name", "node94_alias", "--crate-type=rlib", f"--emit=dep-info={build/'library.d'},link", str(src), "-o", str(library)],
                    common + ["--crate-name", "inline_carrier_input_only", f"--emit=dep-info={build/'driver.d'},link", "--extern", f"node94_alias={library}", str(snapshot/"input-only.rs"), "-o", str(binary)]]
        command_records = []
        for ordinal, command in enumerate(commands):
            if src.read_bytes() != source or any((snapshot/n).read_bytes() != b for n, b in payload.items()):
                raise ValueError("compiler-read source/input bytes changed")
            cp = subprocess.run(command, capture_output=True, cwd=build, env=ENV)
            (build/f"compile-{ordinal}.stdout").write_bytes(cp.stdout)
            (build/f"compile-{ordinal}.stderr").write_bytes(cp.stderr)
            command_records.append({"argv": command, "exit": cp.returncode, "stdout_sha256": sha(cp.stdout), "stderr_sha256": sha(cp.stderr), "diagnostic_bytes": len(cp.stderr)})
            if cp.returncode or cp.stderr:
                raise ValueError(f"compiler failure/diagnostics: {name}: {cp.stderr.decode()}")
            if src.read_bytes() != source or any((snapshot/n).read_bytes() != b for n, b in payload.items()):
                raise ValueError("compiler-read source/input bytes changed")
        for dep, wanted in (("library.d", str(src)), ("driver.d", str(snapshot/"input-only.rs"))):
            tokens = (build/dep).read_text().replace("\\\n", " ").split()
            observed = {t.rstrip(":") for t in tokens if t.rstrip(":").endswith(".rs")}
            if observed != {wanted}:
                raise ValueError("unexpected compiler-read project source")
        run = build/"run"
        run.mkdir()
        groups = []
        for part in ("native", "api"):
            cp = subprocess.run([str(binary)], input=payload[part+".inputs.bin"], capture_output=True, cwd=run, env=ENV)
            (build/(part+".actual.bin")).write_bytes(cp.stdout)
            (build/(part+".stderr")).write_bytes(cp.stderr)
            if cp.returncode or cp.stderr:
                raise ValueError("input-only Rust driver failed")
            mismatches = compare(cp.stdout, payload[part+".expected.bin"])
            if bool(mismatches) != (partition == part):
                raise ValueError(f"compiled control outcome wrong: {name}/{part}")
            groups.append({"partition": part, "input_sha256": sha(payload[part+".inputs.bin"]), "stdout_sha256": sha(cp.stdout),
                           "stdout_bytes": len(cp.stdout), "exit": cp.returncode, "different_cases": len(mismatches),
                           "first_witness": mismatches[0] if mismatches else None})
        if src.read_bytes() != source or any((snapshot/n).read_bytes() != b for n, b in payload.items()):
            raise ValueError("compiled source/input snapshot changed")
        framing = []
        if name == "baseline":
            for label, raw, message in (("empty", b"", "header"), ("truncated", b"IC94\x01\x01\x00", "record"),
                                        ("payload", b"IC94\x01\x01\x00\x00\x00\x01", "payload"),
                                        ("trailing", b"IC94\x01\x00\x00x", "trailing")):
                cp = subprocess.run([str(binary)], input=raw, capture_output=True, cwd=run, env=ENV)
                if (cp.returncode, cp.stdout, cp.stderr) != (1, b"", f"inline-carrier driver: {message}\n".encode()):
                    raise ValueError("driver framing control failed")
                framing.append({"id": label, "input_hex": raw.hex(), "exit": cp.returncode, "stderr": cp.stderr.decode()})
        receipt["builds"].append({"variant": name, "partition": partition, "opt": opt, "repeat": repeat,
                                  "source_sha256": sha(source), "commands": command_records, "groups": groups,
                                  "framing_controls": framing, "library_sha256": sha(library.read_bytes()),
                                  "executable_sha256": sha(binary.read_bytes()),
                                  "depinfo": {n: (build/n).read_text() for n in ("library.d", "driver.d")}})
        print(f"{name} opt{opt} repeat{repeat}: compiler0; partitioned comparisons as required", flush=True)
    if source_pins() != pins or provider_pins() != providers:
        raise ValueError("source/input or compiler providers changed during qualification")
    repeated = [r for r in receipt["builds"] if r["variant"] == "baseline" and r["opt"] == 3]
    receipt["repeat_library_equal"] = repeated[0]["library_sha256"] == repeated[1]["library_sha256"]
    receipt["repeat_executable_equal"] = repeated[0]["executable_sha256"] == repeated[1]["executable_sha256"]
    if not receipt["repeat_library_equal"] or not receipt["repeat_executable_equal"]:
        raise ValueError("clean repeated authored products differ")
    receipt["status"] = "all compiled comparisons and controls passed"
    (output/"receipt.json").write_bytes(json_bytes(receipt))
    # Retain exact small sources/fixtures/streams/logs; compiled products stay
    # ignored with their hashes. No output is replaced by an expected file.
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tar:
        files = [p for p in output.rglob("*") if p.is_file() and (p.parent == snapshot
                 or p.name == "receipt.json" or p.suffix in (".stdout", ".stderr", ".d") or p.name.endswith(".actual.bin") or p.name == "lib.rs")]
        for p in sorted(files):
            raw = p.read_bytes()
            info = tarfile.TarInfo(str(p.relative_to(output)))
            info.size, info.mode, info.mtime = len(raw), 0o444, 0
            tar.addfile(info, io.BytesIO(raw))
    (output/"raw-evidence.tar.gz").write_bytes(gzip.compress(archive.getvalue(), mtime=0))
    print(f"snapshot {snapshot_pin}; receipt {sha((output/'receipt.json').read_bytes())}")
    return receipt


def manifest_check():
    files = {p.name for p in HERE.iterdir() if p.is_file() and p.name != "MANIFEST.sha256"}
    seen = set()
    for line in (HERE/"MANIFEST.sha256").read_text().splitlines():
        expected, name = line.split("  ", 1)
        if name not in files or name in seen or (HERE/name).is_symlink() or sha((HERE/name).read_bytes()) != expected:
            raise ValueError("packet manifest mismatch")
        seen.add(name)
    if seen != files:
        raise ValueError("packet manifest coverage changed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qualify", type=Path, help="fresh ignored output directory; compile authored Rust only")
    parser.add_argument("--write-controls", action="store_true")
    args = parser.parse_args()
    data = NODE.read_bytes()
    secs = authenticate(data)
    cases = vectors()
    controls = native_controls(data, secs, cases)
    if args.write_controls:
        (HERE/"native-controls.json").write_bytes(json_bytes(controls))
    elif (HERE/"native-controls.json").read_bytes() != json_bytes(controls):
        raise ValueError("stale native control equations")
    if args.qualify:
        qualify(args.qualify.resolve(), cases, controls)
    elif not args.write_controls:
        manifest_check()
    print("inline carrier: complete native identity;156 native rows/2 API rows;5 operative native controls;no captured execution")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, struct.error, subprocess.CalledProcessError) as error:
        print(f"inline carrier: {error}", file=sys.stderr)
        raise SystemExit(1)
