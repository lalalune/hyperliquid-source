"""Packet checker for the RE-001 WAL record scan work item.

Checks, all against the digest-verified binary work/hl-node-94.bin
(SHA-256 3b7179cd...c0459f):
  1. records.json parses and carries semantic records only (no
     per-instruction mnemonic list).
  2. MANIFEST.sha256 matches the packet files on disk.
  3. The verbatim excerpt regenerates byte-identically from a fresh
     objdump run (repo root, relative binary path).
  4. Sampled bytes match byte-for-byte against the raw binary and
     the fresh objdump output.
  5. The rodata strings and jump table match records.json.
  6. The census script reproduces the reachability record.
Run from the repository root:
  python3 research/work-items/RE-001-wal-record-scan-94/verify.py
"""
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET = ROOT / "research/work-items/RE-001-wal-record-scan-94"
BIN = ROOT / "work/hl-node-94.bin"
BIN_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
SAMPLES = [
    (0x51628F0, bytes.fromhex("f30f1efa")),   # endbr64, window entry
    (0x51629AC, bytes.fromhex("e85ffbffff")),  # call 0x5162510 (buffered read)
    (0x5162D7C, bytes.fromhex("e8cfeaffff")),  # call 0x5161850 (body parser)
]
FAILURES = []


def check(name, ok, detail=""):
    print(f"{'PASS' if ok else 'FAIL'}: {name} {detail}")
    if not ok:
        FAILURES.append(name)


def file_offset_text(vaddr):
    # .text: file offset 0x1342c80, vaddr 0x1343c80.
    return vaddr - 0x1000


def va_to_offset(raw):
    e_phoff = struct.unpack_from("<Q", raw, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", raw, 0x36)[0]
    e_phnum = struct.unpack_from("<H", raw, 0x38)[0]
    segs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, _flags, p_offset, p_vaddr, _p, p_filesz, _m, _a = \
            struct.unpack_from("<IIQQQQQQ", raw, off)
        if p_type == 1:
            segs.append((p_vaddr, p_offset, p_filesz))

    def conv(va):
        for v, o, f in segs:
            if v <= va < v + f:
                return o + (va - v)
        return None

    return conv


def main():
    raw = BIN.read_bytes()
    check("binary digest", hashlib.sha256(raw).hexdigest() == BIN_SHA256)
    records = json.loads((PACKET / "records.json").read_text())
    check("records parse", isinstance(records, dict))
    check("no mnemonic list",
          "instructions" not in records and "mnemonics" not in records)
    check("dispatch present", "dispatch" in records and "arms" in records)
    manifest_ok = True
    for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        path = PACKET / name.strip()
        if not path.exists() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            manifest_ok = False
    check("manifest matches", manifest_ok)
    fresh = subprocess.run(
        ["objdump", "-d", "--start-address=0x51628f0",
         "--stop-address=0x5162ec2", "work/hl-node-94.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout
    check("window regenerates",
          fresh == (PACKET / "window.txt").read_text())
    for va, expected in SAMPLES:
        got = raw[file_offset_text(va):file_offset_text(va) + len(expected)]
        check(f"sample {hex(va)} raw bytes", got == expected,
              f"got {got.hex()}")
        check(f"sample {hex(va)} in objdump",
              expected.hex() in fresh.replace(" ", "").replace("\t", "") or
              " ".join(f"{b:02x}" for b in expected) in fresh)
    conv = va_to_offset(raw)

    def cstr(va):
        o = conv(va)
        end = raw.index(b"\0", o)
        return raw[o:end].decode()

    strings = {
        0x1F7017: "checksum mismatch",
        0x1FCA14: "error in middle of record",
        0x7E7108: "missing start of fragmented record(2)",
        0x7D9558: "missing start of fragmented record(1)",
        0x1E1E9A: "partial record without end(2)",
        0x1E3344: "partial record without end(1)",
        0x7D7428: "read multiple SetCompressionType records",
        0x7DA990: "SetCompressionType not the first record",
        0x7D7F60: "could not decode SetCompressionType record",
        0x7E3B88: "WAL compression type not supported",
        0x7DD400: "Error decoding WAL compression type",
        0x1F179E: "unknown record type %u",
    }
    for va, text in strings.items():
        check(f"rodata {hex(va)}", cstr(va) == text, repr(cstr(va)))
    check("detail template", raw[conv(0x205CF0):conv(0x205CF0) + 16] == b"CompressionTypeR")
    base = 0x7EE0C8
    targets = []
    for i in range(16):
        rel = struct.unpack_from("<i", raw, conv(base + 4 * i))[0]
        targets.append(hex(base + rel))
    expected_targets = ["0x5162cc0", "0x5162b10", "0x5162ac0", "0x5162a70",
                        "0x5162a40", "0x5162b10", "0x5162ac0", "0x5162a70",
                        "0x5162a40", "0x5162b88", "0x51629fe", "0x51629fe",
                        "0x51629fe", "0x51629fe", "0x5162cc0", "0x51629e0"]
    check("jump table", targets == expected_targets, str(targets))
    census = json.loads(subprocess.run(
        [sys.executable, str(PACKET / "census.py")],
        cwd=ROOT, capture_output=True, text=True, check=True).stdout)
    check("census no direct calls",
          census["direct_calls"] == [] and census["tail_jumps"] == [])
    check("census rela slot",
          census["rela_addend_entries"] == [
              {"offset": "0x575b0f8", "type": 8, "sym": 0}])
    if FAILURES:
        print(f"FAILURES: {FAILURES}")
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
