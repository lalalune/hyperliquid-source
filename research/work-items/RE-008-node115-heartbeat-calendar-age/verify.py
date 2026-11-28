#!/usr/bin/env python3
"""Verify the selected #115 heartbeat call and compare the owned Rust path with Chrono."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import entry_start_static as elf
from fde_extents import eh_frame_records
import re008_heartbeat_classification115 as prior

NS = 1_000_000_000
DAY = 86_400
HELPER = 0x162A290


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def static_evidence():
    data = prior.TARGET.read_bytes()
    prior.verify_binary(data)
    prior.verify_windows(data)
    windows = json.loads((ROOT / "research/byte-windows.json").read_text())["windows"]
    vendor, = [w for w in windows if w["id"] == "node115-ovf-vendor-162a290"]
    source = vendor["source"]
    source_offset = source["offset"]
    start, end = vendor["start"], vendor["end"]
    require(start == HELPER and (start, end) in {(f["start"], f["end"]) for f in eh_frame_records(data)[1]},
            "source comparison not at the captured difference FDE")
    compiled = (ROOT / source["path"]).read_bytes()[source_offset:source_offset + end - start]
    _, actual = elf.read(data, start, end - start)
    require(digest(compiled) == source["body_sha256"] and digest(actual) == vendor["target_body_sha256"],
            "helper body identity changed")
    census = json.loads((ROOT / vendor["evidence"]).read_text())
    reference, = [r for r in census["records"] if r["start"] == start]
    require("NaiveDateTime21signed_duration_since" in reference["symbol"], "different public symbol")
    fields = set()
    for row in reference["relocations"]:
        require(row["width"] == 4 and row["kind"] in (2, 9) and row["addend"] == -4, "different relocation")
        fields.update(range(row["offset"], row["offset"] + 4))
    require(len(fields) == 12 and all(compiled[i] == actual[i] for i in range(len(actual)) if i not in fields),
            "fixed helper bytes differ")
    bindings = elf.relocations(data)
    for site, slot, dest in [(0x5A71E54, 0x64E0990, 0x1629690), (0x5A3047D, 0x64E0FC0, HELPER)]:
        elf.anchors_ok(data, [(site, "ff15")])
        require(elf.rip_target(data, site, 2) == slot and bindings[slot] == (8, dest), "changed provider")
    # r15 holds the current tuple. The two loads from entry+0x58/+0x60 form
    # the earlier tuple. RDI and RSI point to their respective 12-byte copies.
    elf.anchors_ok(data, [
        (0x5A30450, "418b470889442410498b074889442408418b44246089442430498b4424584889442428"),
        (0x5A30473, "488d7c2408488d742428"),
        (0x162A34B, "448b77048b4f08"), (0x162A35C, "8b7e048b5608"),
        (0x162A383, "4139fe480f46f0"), (0x5A30492, "400fb6ce4801c8"),
        (0x5A304C3, "f20f5fc8"), (0x5A304DD, "0f87"),
    ])
    table_va = elf.rip_target(data, 0x162A2E0, 3)
    table = elf.read(data, table_va, 400)[1]
    leap_prefix = bytes((y + 3) // 4 - (y + 99) // 100 + (y + 399) // 400 for y in range(400))
    require(table == leap_prefix, "Gregorian cycle offsets changed")
    for site, size, value in [(0x5A304B3, 4, float(NS)), (0x5A304C7, 4, float("inf")), (0x5A304D5, 4, 180.0)]:
        address = elf.rip_target(data, site, size)
        require(struct.unpack("<d", elf.read(data, address, 8)[1])[0] == value, "changed age constant")
    return {"node115_sha256": digest(data), "clock_provider": "0x1629690", "difference_provider": hex(start),
            "helper_bytes": len(actual), "target_helper_sha256": digest(actual),
            "fixed_source_bytes": len(actual) - len(fields), "source_helper_sha256": digest(compiled),
            "candidate_chrono_versions": reference["candidate_versions"], "cycle_table_va": hex(table_va),
            "cycle_table_sha256": digest(table), "captured_code_executed": False}


def jan1(year):
    prev = year - 1
    return 365 * prev + prev // 4 - prev // 100 + prev // 400 + 1


def cases():
    minimum, maximum = jan1(-262143), jan1(262143) - 1
    epoch = jan1(1970)
    rows = set()
    for n in [0, 1, 500_000_000, 999_999_999]:
        for elapsed in [179 * NS, 180 * NS - 1, 180 * NS, 180 * NS + 1, 181 * NS]:
            s, ns = divmod(59 * NS + n + elapsed, NS)
            for mode in range(6):
                rows.add((epoch, s, ns, epoch, 59, n, mode))
                rows.add((epoch, 59, n, epoch, s, ns, mode))
    for y in range(1800, 2200):
        d = jan1(y)
        for frac in [0, NS - 1, NS, NS + 500_000_000, 2 * NS - 1]:
            rows.add((d, 240, 0, d, 59, frac, 0))
            rows.add((d, 59, frac, d - 1, 23 * 3600 + 59, NS + 17, 0))
            rows.add((d, 181, 1, d - 1, DAY - 1, frac, 3))
            rows.add((d - 1, DAY - 1, frac, d, 181, 1, 5))
    for i in range(2048):
        one = minimum + (i * 52_866_391) % (maximum - minimum + 1)
        two = maximum - (i * 7_919_147) % (maximum - minimum + 1)
        rows.add((one, (86399 - i) % DAY, (999_999_937 * i) % NS,
                  two, (17 * i) % DAY, (314_159_269 * i) % NS, 0))
        rows.add((maximum, DAY - 1, 2 * NS - 1, minimum, 59, NS + i, 0))
    return sorted(rows)


def bits(value):
    return int.from_bytes(struct.pack(">d", value), "big")


def elapsed_float(total_nanos):
    whole, part = divmod(max(0, total_nanos), NS)
    return float(whole) + float(part) / NS


def result(age):
    return ("age", bits(age)) if age > 180.0 else ("skip", 0)


def checked_outputs(rows, output):
    lines = output.splitlines()
    require(len(rows) == len(lines), "reference row count")
    tags, controls = Counter(), Counter()
    for row, line in zip(rows, lines):
        cd, cs, cn, pd, ps, pn, mode = row
        tag, payload, secs, frac = line.split()
        leap = int(cs > ps and pn >= NS) - int(cs < ps and cn >= NS)
        wall = ((cd - pd) * DAY + cs - ps) * NS + cn - pn
        total = wall + leap * NS
        require(int(secs) * NS + int(frac) == total, f"calendar source disagreement for {row}")
        tags[tag.decode()] += 1
        if mode not in (0, 3, 5):
            continue
        age = elapsed_float(total)
        actual = (tag.decode(), int(payload))
        require(result(age) == actual, f"captured consumer relation differs for {row}")
        alt = {
            "omit_leap_adjustment": elapsed_float(wall),
            "drop_fraction": float(max(0, total) // NS), "swap_operands": elapsed_float(-total),
            "convert_total_nanoseconds_first": float(max(0, total)) / NS,
        }
        for name, value in alt.items():
            controls[name] += int(result(value) != actual)
        controls["inclusive_threshold"] += int(age == 180.0 and actual[0] == "skip")
    require(all(v > 0 for v in controls.values()), "a semantic counterexample is missing")
    return {"rows": len(rows), "tag_counts": dict(tags), "distinguished_outputs": dict(controls),
            "output_sha256": digest(output)}


def replay():
    rows = cases()
    inputs = "".join(" ".join(map(str, row)) + "\n" for row in rows).encode("ascii")
    rustc = subprocess.check_output(["rustup", "which", "--toolchain", "1.95.0", "rustc"], text=True).strip()
    cargo = subprocess.check_output(["rustup", "which", "--toolchain", "1.95.0", "cargo"], text=True).strip()
    manifest = HERE / "reference/Cargo.toml"
    with tempfile.TemporaryDirectory(prefix="heartbeat-calendar-") as tmp:
        env = dict(os.environ, RUSTC=rustc, CARGO_TARGET_DIR=tmp)
        outputs = []
        for profile in [[], ["--release"]]:
            outputs.append(subprocess.check_output([cargo, "run", "--frozen", "--quiet", *profile,
                                                    "--manifest-path", manifest], input=inputs, env=env))
        require(outputs[0] == outputs[1], "debug and release outputs differ")
        return dict(checked_outputs(rows, outputs[0]), input_sha256=digest(inputs),
                    profiles=["debug", "release"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--static-only", action="store_true")
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()
    report = {"static": static_evidence()}
    if not args.static_only:
        report["comparison"] = replay()
    if args.record:
        print(json.dumps(report, indent=2, sort_keys=True))
        return
    saved = json.loads((HERE / "results.json").read_text())
    require(all(value == saved[key] for key, value in report.items()), "recorded evidence differs")
    print("Verified heartbeat caller, clock and calendar helper, 399 fixed source bytes, and 400 calendar offsets.")
    if not args.static_only:
        print(f"Both build profiles agreed with Chrono on {report['comparison']['rows']} inputs.")


if __name__ == "__main__":
    main()
