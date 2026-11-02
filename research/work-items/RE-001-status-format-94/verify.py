"""Packet checker for RE-001-status-format-94.

Checks, all against the digest-verified binary:
1. Every excerpt file matches a fresh objdump run (from the repo root,
   with the repo-relative binary path, so the header spelling matches).
2. records.json parses and carries the required semantic sections.
3. The code prefixes, subcode names, and jump-table arms in records.json
   match the binary's rodata, relocations, and jump table.
4. Three sampled instructions match the raw binary byte-for-byte.
5. callers.tsv lists 178 direct call sites including the replay site,
   and three sampled sites encode an e8 call to the window.

Usage:
    python3 research/work-items/RE-001-status-format-94/verify.py
    python3 .../verify.py --packet-dir <dir> [--binary <path>]
"""
import argparse
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

WINDOWS = {
    "window.txt": (0x542F8A0, 0x542FE90),
    "caller-replay.txt": (0x520B56E, 0x520B630),
}

SAMPLES = {
    0x542F8A0: bytes.fromhex("f30f1efa"),       # endbr64
    0x542F8CC: bytes.fromhex("4180f90f"),       # cmp $0xf, %r9b
    0x542FA08: bytes.fromhex("488d15f16c3300"),  # lea subcode table
}

REQUIRED_RECORD_KEYS = [
    "artifact", "window", "arguments", "code_table", "jump_table",
    "unknown_fallback", "subcode_table", "assembly_rules", "callers",
    "consumers", "unknowns", "not_claimed",
]

TEXT_BASE = 0x1343C80


def file_offset(vaddr):
    return vaddr - 0x1000 if vaddr >= TEXT_BASE else vaddr


def cstr(data, vaddr):
    end = data.index(b"\x00", file_offset(vaddr))
    return data[file_offset(vaddr):end].decode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--packet-dir", default=None)
    parser.add_argument("--binary", default="work/hl-node-94.bin")
    args = parser.parse_args()
    packet = Path(args.packet_dir) if args.packet_dir else Path(
        __file__).resolve().parent
    repo = packet.parent.parent.parent
    binary = Path(args.binary)
    if not binary.is_absolute():
        binary = repo / binary
    data = binary.read_bytes()
    failures = []

    if hashlib.sha256(data).hexdigest() != (
            "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575"
            "eff1c0459f"):
        failures.append("binary digest mismatch")

    for name, (start, stop) in WINDOWS.items():
        fresh = subprocess.run(
            ["objdump", "-d", f"--start-address={start:#x}",
             f"--stop-address={stop:#x}", "work/hl-node-94.bin"],
            cwd=repo, capture_output=True, text=True).stdout
        if fresh != (packet / name).read_text():
            failures.append(f"excerpt mismatch: {name}")

    try:
        records = json.loads((packet / "records.json").read_text())
    except json.JSONDecodeError as exc:
        print(f"FAIL: records.json does not parse: {exc}")
        return 1
    for key in REQUIRED_RECORD_KEYS:
        if key not in records:
            failures.append(f"records.json missing key: {key}")

    # Code prefixes: jump-table arm order and prefix bytes.
    arms = []
    for i in range(16):
        off = struct.unpack_from("<i", data, file_offset(0x7FC298) + i * 4)[0]
        arms.append(0x7FC298 + off)
    if [hex(a) for a in arms] != records["jump_table"]["arms"]:
        failures.append("jump-table arms mismatch")
    prefix_addr = {
        1: 0x1E21C0, 2: 0x1E9021, 3: 0x1EC90A, 4: 0x202D33,
        5: 0x1E4A1C, 6: 0x1E706D, 7: 0x1F2B1C, 8: 0x1F396B,
        9: 0x1F1A2C, 10: 0x1F01DA, 11: 0x1EC91C, 12: 0x1FCC78,
        13: 0x7DC490, 14: 0x1DE388, 15: 0x1F1A14,
    }
    for entry in records["code_table"]:
        code = entry["code"]
        if code == 0:
            if entry["prefix"] != "OK" or entry["length"] != 2:
                failures.append("code 0 prefix mismatch")
            continue
        if cstr(data, prefix_addr[code]) != entry["prefix"]:
            failures.append(f"code {code} prefix mismatch")
        if len(entry["prefix"]) != entry["length"]:
            failures.append(f"code {code} length mismatch")
        if entry["arm"] != hex(arms[code]):
            failures.append(f"code {code} arm mismatch")

    # Subcode names via relocation addends.
    for entry in records["subcode_table"]["entries"]:
        if cstr(data, int(entry["addend"], 16)) != entry["name"]:
            failures.append(f"subcode {entry['subcode']} name mismatch")
        if int(entry["relocation_slot"], 16) != 0x5766700 + entry["subcode"] * 8:
            failures.append(f"subcode {entry['subcode']} slot mismatch")
    if cstr(data, 0x1E81F5) != "Unknown code(%d): ":
        failures.append("unknown fallback format mismatch")

    # Sampled instructions byte-for-byte against the raw binary.
    for addr, raw in SAMPLES.items():
        if data[file_offset(addr):file_offset(addr) + len(raw)] != raw:
            failures.append(f"sample mismatch at {addr:#x}")

    # Caller census: row count, replay site, sampled e8 encodings.
    rows = (packet / "callers.tsv").read_text().splitlines()[1:]
    if len(rows) != 178:
        failures.append(f"callers.tsv row count {len(rows)}, expected 178")
    sites = [r.split("\t")[0] for r in rows]
    if "0x520b5e2" not in sites:
        failures.append("replay call site 0x520b5e2 missing from callers.tsv")
    for site in sites[:3] + sites[-1:]:
        v = int(site, 16)
        off = file_offset(v)
        if data[off] != 0xE8:
            failures.append(f"call site {site} is not an e8 call")
        elif v + 5 + struct.unpack_from("<i", data, off + 1)[0] != 0x542F8A0:
            failures.append(f"call site {site} does not target the window")

    # MANIFEST hashes.
    manifest = (packet / "MANIFEST.sha256").read_text().splitlines()
    for line in manifest:
        digest, name = line.split("  ", 1)
        if hashlib.sha256((packet / name).read_bytes()).hexdigest() != digest:
            failures.append(f"MANIFEST mismatch: {name}")

    if failures:
        print("FAIL:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
