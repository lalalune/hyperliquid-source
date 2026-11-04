#!/usr/bin/env python3
"""RE-005 packet checker: the node #115 rmp_signable .rodata window.

Packet: research/work-items/RE-005-node115-rmp-signable-window/

Bounded question: which action-signing source-path run does the pinned node
#115 image carry in .rodata, at which virtual address, and what are the
distinct printable-run counts for the l1/, bincode and rmp_signable needles?

Every value is re-derived from artifacts/node/115/hl-node in place:

* SHA-256 and size before and after the analysis;
* .rodata and .data.rel.ro coordinates from the real ELF section headers;
* the printable-run census over both data sections;
* the 29-byte string l1/src/action/rmp_signable.rs at .rodata 0x4470c4.

The target is never executed and no copy of it is written. Corruption
controls mutate an in-memory byte image only. MANIFEST.sha256 is written by
the host, never by this checker.

Exit status: 0 when every recorded value matches the saved packet evidence,
1 with an AssertionError otherwise (including a not-yet-written packet file).
"""
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts" / "node" / "115" / "hl-node"
PACKET = ROOT / "research" / "work-items" / "RE-005-node115-rmp-signable-window"
EVIDENCE = PACKET / "evidence.json"

TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_BYTES = 105896032

RODATA = {"name": ".rodata", "addr": 0x430400, "offset": 0x430400, "size": 7792192}
DATAREL = {"name": ".data.rel.ro", "addr": 0x63F3C20, "offset": 0x63F1C20, "size": 964136}

PATH_VA = 0x4470C4
PATH_TEXT = b"l1/src/action/rmp_signable.rs"
PATH_LENGTH = 29

NEEDLES = (b"l1/", b"bincode", b"rmp_signable")
EXPECTED_COUNTS = {b"l1/": 77, b"bincode": 6, b"rmp_signable": 1}
EXPECTED_RUNS = {".rodata": 1536525, ".data.rel.ro": 18683}
EXPECTED_TOTAL_RUNS = 1555208

ELF_MAGIC = b"\x7fELF"
SHDR = struct.Struct("<IIQQQQIIQQ")


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def authenticate(stage, expected_sha256=TARGET_SHA256, expected_bytes=TARGET_BYTES):
    if not TARGET.is_file():
        raise AssertionError("missing pinned target: " + str(TARGET))
    size = TARGET.stat().st_size
    digest = sha256_file(TARGET)
    print("AUTH " + stage + " sha256=" + digest + " bytes=" + str(size))
    if digest != expected_sha256:
        raise AssertionError("digest mismatch at " + stage + ": " + digest)
    if size != expected_bytes:
        raise AssertionError("size mismatch at " + stage + ": " + str(size))
    return digest


def section_table(blob):
    if len(blob) < 0x40 or blob[:4] != ELF_MAGIC:
        raise AssertionError("not an ELF file")
    shoff = struct.unpack_from("<Q", blob, 0x28)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", blob, 0x3A)
    if shoff == 0 or shnum == 0 or shstrndx >= shnum:
        raise AssertionError("missing ELF section table")
    if shentsize != SHDR.size:
        raise AssertionError("unexpected section header size: " + str(shentsize))
    if shoff + shnum * shentsize > len(blob):
        raise AssertionError("section table extends past end of file")
    rows = [SHDR.unpack_from(blob, shoff + index * shentsize) for index in range(shnum)]
    name_off = rows[shstrndx][4]
    name_size = rows[shstrndx][5]
    if name_off + name_size > len(blob):
        raise AssertionError("section name table extends past end of file")
    names = blob[name_off:name_off + name_size]
    table = {}
    for row in rows:
        stop = names.find(b"\x00", row[0])
        if stop < 0:
            continue
        label = names[row[0]:stop].decode("utf-8", "replace")
        if not label:
            continue
        if label in table:
            raise AssertionError("duplicate section name: " + label)
        table[label] = {"addr": row[3], "offset": row[4], "size": row[5]}
    print("SECTIONS count=" + str(shnum) + " shstrndx=" + str(shstrndx))
    return table


def section_bytes(blob, table, name):
    sec = table.get(name)
    if sec is None:
        raise AssertionError("missing section " + name)
    if sec["offset"] + sec["size"] > len(blob):
        raise AssertionError("section " + name + " extends past end of file")
    return sec, blob[sec["offset"]:sec["offset"] + sec["size"]]


def printable_runs(body):
    runs = []
    pos = 0
    size = len(body)
    while pos < size:
        if 0x20 <= body[pos] <= 0x7E:
            begin = pos
            while pos < size and 0x20 <= body[pos] <= 0x7E:
                pos += 1
            runs.append((begin, pos))
            continue
        pos += 1
    return runs


def run_counts(blob, table):
    counts = dict((needle, 0) for needle in NEEDLES)
    rmp_vas = []
    per_section = {}
    total = 0
    for spec in (RODATA, DATAREL):
        sec, body = section_bytes(blob, table, spec["name"])
        if (sec["addr"], sec["offset"], sec["size"]) != (spec["addr"], spec["offset"], spec["size"]):
            raise AssertionError(spec["name"] + " coordinates differ: " + repr(sec))
        runs = printable_runs(body)
        per_section[spec["name"]] = len(runs)
        total += len(runs)
        print("SECTION " + spec["name"] + " addr=0x{:x} offset=0x{:x} size={}".format(sec["addr"], sec["offset"], sec["size"]))
        print("RUNS " + spec["name"] + " printable=" + str(len(runs)))
        for begin, stop in runs:
            text = body[begin:stop]
            for needle in NEEDLES:
                if needle in text:
                    counts[needle] += 1
            if b"rmp_signable" in text:
                rmp_vas.append(sec["addr"] + begin)
    print("TOTAL printable_runs=" + str(total))
    for needle in NEEDLES:
        print("COUNT " + needle.decode("ascii") + " distinct_runs=" + str(counts[needle]))
    for needle in NEEDLES:
        want = EXPECTED_COUNTS[needle]
        if counts[needle] != want:
            raise AssertionError("run count for " + needle.decode("ascii") + " is " + str(counts[needle]) + ", recorded " + str(want))
    for name in sorted(EXPECTED_RUNS):
        if per_section[name] != EXPECTED_RUNS[name]:
            raise AssertionError("printable runs in " + name + " is " + str(per_section[name]) + ", recorded " + str(EXPECTED_RUNS[name]))
    if total != EXPECTED_TOTAL_RUNS:
        raise AssertionError("total printable runs is " + str(total) + ", recorded " + str(EXPECTED_TOTAL_RUNS))
    if rmp_vas != [PATH_VA]:
        raise AssertionError("rmp_signable runs at " + repr([hex(va) for va in rmp_vas]) + ", recorded [0x4470c4]")
    print("RMP_RUNS va=" + ",".join("0x{:x}".format(va) for va in rmp_vas))
    return counts, per_section, total


def path_record(body, base_va, base_offset):
    rel = PATH_VA - base_va
    if not 0 <= rel < len(body):
        raise AssertionError("path va lies outside .rodata")
    stop = body.find(b"\x00", rel)
    if stop < 0:
        raise AssertionError("path record is not NUL terminated")
    text = bytes(body[rel:stop])
    print("PATH va=0x{:x} file_offset=0x{:x} length={} text={}".format(PATH_VA, base_offset + rel, len(text), text.decode("utf-8", "replace")))
    if text != PATH_TEXT:
        raise AssertionError("path bytes differ: " + text.decode("utf-8", "replace"))
    if len(text) != PATH_LENGTH:
        raise AssertionError("path length is " + str(len(text)) + ", recorded " + str(PATH_LENGTH))
    if rel > 0 and 0x20 <= body[rel - 1] <= 0x7E:
        raise AssertionError("path does not start a printable run")
    return {"va": hex(PATH_VA), "file_offset": hex(base_offset + rel), "length": len(text), "text": text.decode("ascii")}


def derive(blob, table):
    counts, per_section, total = run_counts(blob, table)
    rodata_sec, rodata_body = section_bytes(blob, table, ".rodata")
    record = path_record(rodata_body, rodata_sec["addr"], rodata_sec["offset"])
    observed = {
        "target": {"sha256": TARGET_SHA256, "bytes": TARGET_BYTES},
        "sections": {
            ".rodata": {"addr": hex(RODATA["addr"]), "offset": hex(RODATA["offset"]), "size": RODATA["size"]},
            ".data.rel.ro": {"addr": hex(DATAREL["addr"]), "offset": hex(DATAREL["offset"]), "size": DATAREL["size"]},
        },
        "printable_runs": {
            ".rodata": per_section[".rodata"],
            ".data.rel.ro": per_section[".data.rel.ro"],
            "total": total,
        },
        "run_counts": dict((needle.decode("ascii"), counts[needle]) for needle in NEEDLES),
        "path_record": record,
    }
    return observed


def expect_error(label, func, needle):
    try:
        func()
    except AssertionError as exc:
        message = str(exc)
        print("CONTROL " + label + " rejected: " + message[:120])
        if needle not in message:
            raise AssertionError("control " + label + " raised unexpected message: " + message[:200])
        return
    raise AssertionError("control " + label + " was accepted")


def controls(blob, table):
    expect_error(
        "wrong digest",
        lambda: authenticate("control", expected_sha256="00" * 32),
        "digest mismatch",
    )
    expect_error("truncated image", lambda: section_table(blob[:0x800]), "extends past end of file")
    sec, body = section_bytes(blob, table, ".rodata")
    mutated = bytearray(body)
    mutated[PATH_VA - sec["addr"]] = 0x6D
    expect_error("altered path byte", lambda: path_record(mutated, sec["addr"], sec["offset"]), "path bytes differ")
    del mutated
    print("CONTROLS rejected=3")


def flatten(node, prefix, out):
    for key in sorted(node):
        value = node[key]
        path = prefix + (key,)
        if isinstance(value, dict):
            flatten(value, path, out)
        else:
            out.append((path, value))


def compare_evidence(observed):
    if not EVIDENCE.is_file():
        raise AssertionError("missing packet evidence file: " + str(EVIDENCE))
    data = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    if data.get("schema_version") != 1:
        raise AssertionError("unexpected evidence schema_version: " + repr(data.get("schema_version")))
    if data.get("task") != "RE-005":
        raise AssertionError("unexpected evidence task: " + repr(data.get("task")))
    flat = []
    flatten(observed, (), flat)
    for path, value in flat:
        node = data
        for key in path:
            if not isinstance(node, dict) or key not in node:
                raise AssertionError("evidence missing field " + ".".join(path))
            node = node[key]
        if node != value:
            raise AssertionError("evidence " + ".".join(path) + " mismatch: recorded=" + repr(node) + " observed=" + repr(value))
        print("EVIDENCE " + ".".join(path) + " = " + repr(value))


def main():
    authenticate("before")
    blob = TARGET.read_bytes()
    table = section_table(blob)
    observed = derive(blob, table)
    controls(blob, table)
    del blob
    authenticate("after")
    compare_evidence(observed)
    print("RESULT question=RE-005 node115 rmp_signable .rodata window")
    print("RESULT packet=RE-005-node115-rmp-signable-window")
    print("RESULT path_va=0x4470c4 length=29")
    print("RESULT target_executed=false target_copied=false")
    return 0


if __name__ == "__main__":
    sys.exit(main())
