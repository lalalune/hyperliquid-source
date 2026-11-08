#!/usr/bin/env python3
"""Verify one digest-bound #115 FDE census packet without executing the target."""
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
TARGET = ROOT / "artifacts/node/115/hl-node"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105_896_032
BAND_START = 0x3A40000
BAND_END = 0x3A80000


def run(args):
    result = subprocess.run(args, check=False, text=True, capture_output=True)
    if result.returncode:
        raise SystemExit(f"command failed ({result.returncode}): {' '.join(args)}\n{result.stderr}")
    return result.stdout


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def text_section():
    for line in run(["readelf", "--wide", "--section-headers", str(TARGET)]).splitlines():
        fields = line.split()
        if ".text" in fields:
            index = fields.index(".text")
            return tuple(int(fields[index + offset], 16) for offset in (2, 3, 4))
    raise AssertionError(".text section is missing")


def fde_rows():
    rows = []
    for line in run(["readelf", "--wide", "--debug-dump=frames", str(TARGET)]).splitlines():
        marker = line.find("pc=")
        if "FDE cie=" not in line or marker < 0:
            continue
        bounds = line[marker + 3 :].split()[0]
        start_text, separator, end_text = bounds.partition("..")
        if not separator:
            raise AssertionError(f"malformed FDE range: {line}")
        start, end = int(start_text, 16), int(end_text, 16)
        if BAND_START <= start < BAND_END:
            if end <= start:
                raise AssertionError(f"empty FDE: {line}")
            rows.append((start, end, line.rstrip()))
    rows.sort()
    if not rows:
        raise AssertionError("no FDE starts in the band")
    for previous, current in zip(rows, rows[1:]):
        if current[0] == previous[0] or current[0] < previous[1]:
            raise AssertionError(f"duplicate or overlapping FDEs: {previous}, {current}")
    return rows


def instruction_count(start, end):
    text = run(["objdump", "-d", f"--start-address=0x{start:x}", f"--stop-address=0x{end:x}", str(TARGET)])
    total = 0
    for line in text.splitlines():
        address, separator, rest = line.strip().partition(":")
        columns = rest.split("\t")
        if (
            separator
            and address
            and all(char in "0123456789abcdefABCDEF" for char in address)
            and len(columns) >= 3
            and columns[2].strip()
        ):
            total += 1
    return total


def records(rows, section_address, section_offset, section_size):
    result = []
    with TARGET.open("rb") as source:
        for start, end, _ in rows:
            if start < section_address or end > section_address + section_size:
                raise AssertionError(f"FDE outside .text: {start:x}..{end:x}")
            source.seek(section_offset + start - section_address)
            body = source.read(end - start)
            if len(body) != end - start:
                raise AssertionError(f"short target read: {start:x}..{end:x}")
            result.append([hex(start), hex(end), len(body), hashlib.sha256(body).hexdigest(), instruction_count(start, end)])
    return result


def verify_window(saved, smallest, section_address, section_offset):
    start = int(smallest[0], 16)
    expected = []
    with TARGET.open("rb") as source:
        source.seek(section_offset + start - section_address)
        expected = list(source.read(6))
    seen_start = False
    observed = []
    for line in saved.splitlines():
        address_text, separator, remainder = line.strip().partition(":")
        if not separator or not address_text or any(c not in "0123456789abcdefABCDEF" for c in address_text):
            continue
        address = int(address_text, 16)
        if address == start:
            seen_start = True
        if seen_start:
            parts = remainder.split("\t")
            if len(parts) < 2:
                continue
            observed.extend(int(token, 16) for token in parts[1].split() if len(token) == 2 and all(c in "0123456789abcdefABCDEF" for c in token))
            if len(observed) >= len(expected):
                break
    if len(expected) != 6 or observed[:6] != expected:
        raise AssertionError(f"window does not preserve six target prologue bytes at {start:x}")


def verify_manifest():
    manifest = (PACKET / "MANIFEST.sha256").read_text(encoding="utf-8")
    listed = {}
    for line in manifest.splitlines():
        digest, separator, name = line.partition("  ")
        if not separator or len(digest) != 64 or not name or name in listed:
            raise AssertionError(f"malformed or duplicate manifest entry: {line!r}")
        listed[name] = digest
    actual = sorted(path.name for path in PACKET.iterdir() if path.is_file() and path.name != "MANIFEST.sha256")
    if actual != sorted(listed):
        raise AssertionError(f"manifest file set differs: {sorted(listed)} != {actual}")
    for name, digest in listed.items():
        if sha256(PACKET / name) != digest:
            raise AssertionError(f"manifest digest mismatch: {name}")


def main():
    if TARGET.stat().st_size != TARGET_SIZE or sha256(TARGET) != TARGET_SHA256:
        raise SystemExit("target identity mismatch")
    address, offset, size = text_section()
    if (address, offset, size) != (0x1419300, 0x1418300, 0x4FD7700):
        raise SystemExit(".text coordinates differ from the recorded target")
    rows = fde_rows()
    actual = records(rows, address, offset, size)
    saved = json.loads((PACKET / "evidence.json").read_text(encoding="utf-8"))
    expected = {
        "target_sha256": TARGET_SHA256,
        "target_size": TARGET_SIZE,
        "packet": PACKET.name,
        "band": {"start": hex(BAND_START), "end": hex(BAND_END)},
        "fde_count": len(actual),
        "fdes": actual,
    }
    if saved != expected:
        raise AssertionError("saved evidence differs from target-derived records")
    frames = "\n".join(line for _, _, line in rows) + "\n"
    if (PACKET / "frames.txt").read_text(encoding="utf-8") != frames:
        raise AssertionError("saved FDE lines differ from readelf output")
    smallest = min(actual, key=lambda item: item[2])
    verify_window((PACKET / "window.txt").read_text(encoding="utf-8"), smallest, address, offset)
    verify_manifest()
    print(f"verified fdes={len(actual)} band={BAND_START:#x}..{BAND_END:#x} smallest={smallest[0]}..{smallest[1]}")


if __name__ == "__main__":
    main()
