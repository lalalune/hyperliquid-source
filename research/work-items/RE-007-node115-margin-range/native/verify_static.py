#!/usr/bin/env python3
"""MIT. Authenticate retained static data; never run or interpret the capture."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_BYTES = 105896032
BINDINGS_SHA = "b33925a6edcaa1c21606c94f6631a716ce071175f371d380da0765aa496ae99c"
DATA_FILES = {"3cd80d0.gnu.txt", "4550ee0.gnu.txt", "3cd80d0.fde.txt", "4550ee0.fde.txt"}


class Rejection(Exception):
    pass


def need(condition, label):
    if not condition:
        raise Rejection(label)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pinned(path, expected, size=None):
    need(path.is_file() and not path.is_symlink(), "regular file required")
    data = path.read_bytes()
    need(digest(data) == expected, "file hash mismatch")
    need(size is None or len(data) == size, "file size mismatch")
    return data


def load_segments(image):
    need(image[:6] == b"\x7fELF\x02\x01", "ELF64 little endian required")
    need(struct.unpack_from("<H", image, 18)[0] == 62, "x86-64 required")
    offset = struct.unpack_from("<Q", image, 32)[0]
    width, count = struct.unpack_from("<HH", image, 54)
    need(width == 56 and offset + count * width <= len(image), "program header bounds")
    segments = []
    for index in range(count):
        kind, flags, file_offset, va, _, size, memory_size, _ = struct.unpack_from(
            "<IIQQQQQQ", image, offset + index * width
        )
        if kind == 1:
            need(size <= memory_size and file_offset + size <= len(image), "load span bounds")
            segments.append((va, file_offset, size, flags))
    return segments


def file_offset(segments, va, size):
    matches = [offset + va - start for start, offset, length, _ in segments
               if start <= va and va + size <= start + length]
    need(len(matches) == 1, "unique file-backed load span")
    return matches[0]


def exported_bytes(text, start, end):
    cursor = start
    raw = bytearray()
    starts = []
    for line in text.decode("utf-8").splitlines():
        fields = line.split("\t")
        if len(fields) < 2 or re.fullmatch(r"\s*[0-9a-f]+:", fields[0]) is None:
            continue
        address = int(fields[0].strip()[:-1], 16)
        chunk = bytes.fromhex(fields[1].strip())
        need(chunk and address == cursor, "contiguous GNU byte partition")
        raw.extend(chunk)
        cursor += len(chunk)
        if len(fields) > 2 and "".join(fields[2:]).strip():
            starts.append(address)
    need(cursor == end and starts and starts[0] == start, "complete GNU extent")
    return bytes(raw), starts


def verify(image, bindings, files):
    need(bindings["schema"] == "node115-margin-range-static-bindings-v1", "bindings schema")
    need(bindings["target"]["sha256"] == TARGET_SHA
         and bindings["target"]["bytes"] == TARGET_BYTES, "target metadata")
    segments = load_segments(image)
    need({body["start"] for body in bindings["bodies"]} == {"0x3cd80d0", "0x4550ee0"}
         and len(bindings["bodies"]) == 2, "exact two-body scope")
    result = []
    all_starts = set()
    for body in bindings["bodies"]:
        start, end = int(body["start"], 16), int(body["end"], 16)
        offset = file_offset(segments, start, end - start)
        need(end > start and offset == body["file_offset"], "body mapping")
        raw = image[offset:offset + end - start]
        need(len(raw) == body["bytes"] and digest(raw) == body["body_sha256"], "body identity")
        exported, starts = exported_bytes(files[body["export"]["path"]], start, end)
        need(exported == raw and len(starts) == body["instructions"], "export equals target")
        all_starts.update(starts)
        fde, cie = body["fde"], body["cie"]
        fraw, craw = bytes.fromhex(fde["raw"]), bytes.fromhex(cie["raw"])
        fva, cva = int(fde["va"], 16), int(cie["va"], 16)
        for record, record_va, data in ((fde, fva, fraw), (cie, cva, craw)):
            location = file_offset(segments, record_va, len(data))
            need(location == record["file_offset"] and image[location:location + len(data)] == data,
                 "raw unwind record identity")
            need(struct.unpack_from("<I", data)[0] + 4 == len(data), "unwind record length")
        need(fva + 4 - struct.unpack_from("<I", fraw, 4)[0] == cva, "FDE CIE back-reference")
        need(fva + 8 + struct.unpack_from("<i", fraw, 8)[0] == start
             and struct.unpack_from("<I", fraw, 12)[0] == end - start, "FDE PC and range")
        pattern = f"pc={start:016x}..{end:016x}"
        need(pattern in files[body["fde_text"]["path"]].decode("ascii"), "retained FDE text range")
        result.append({"start": body["start"], "end": body["end"], "bytes": len(raw),
                       "instructions": len(starts), "body_sha256": digest(raw)})
    call = bindings["selected_direct_call"]
    site, target = int(call["site"], 16), int(call["target"], 16)
    offset = file_offset(segments, site, 5)
    instruction = image[offset:offset + 5]
    need(instruction.hex() == call["raw"] and instruction[0] == 0xE8, "selected call encoding")
    need(site in all_starts and target in all_starts, "selected call boundaries")
    need(site + 5 + struct.unpack_from("<i", instruction, 1)[0] == target, "selected call target")
    relocation = bindings["bounds_diagnostic_relocation"]
    location = relocation["file_offset"]
    raw = bytes.fromhex(relocation["raw"])
    need(len(raw) == 24 and image[location:location + 24] == raw, "raw RELA identity")
    slot, info, addend = struct.unpack("<QQq", raw)
    need(slot == int(relocation["slot"], 16) and info == relocation["info"] == 8
         and addend == int(relocation["addend"], 16), "RELATIVE zero-symbol binding")
    need(sum(item["bytes"] for item in result) == bindings["selected_bytes"] == 678
         and sum(item["instructions"] for item in result) == bindings["selected_instruction_rows"] == 210,
         "selected denominator")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    source = Path(__file__).resolve()
    evidence = source.parent
    source_sha = digest(source.read_bytes())
    need(args.out.is_absolute() and args.out.parent.is_dir()
         and not args.out.exists() and not args.out.is_symlink(), "fresh absolute output required")
    out = args.out.resolve()
    need(out != evidence and evidence not in out.parents, "output outside sealed evidence required")
    # Full capture authentication precedes ELF parsing or output creation.
    image = pinned(args.target, TARGET_SHA, TARGET_BYTES)
    bindings = json.loads(pinned(evidence / "BINDINGS.json", BINDINGS_SHA))
    files = {}
    for body in bindings["bodies"]:
        for field in ("export", "fde_text"):
            entry = body[field]
            name = entry["path"]
            need(name in DATA_FILES and name not in files, "fixed unique evidence filename")
            files[name] = pinned(evidence / name, entry["sha256"], entry["bytes"])
    need(set(files) == DATA_FILES, "complete evidence set")
    bodies = verify(image, bindings, files)
    need(digest(source.read_bytes()) == source_sha, "verifier source changed")
    result = {"schema": "margin-range-static-result-v1", "target_sha256": TARGET_SHA,
              "bindings_sha256": BINDINGS_SHA, "verifier_sha256": source_sha,
              "bodies": bodies, "selected_call_target": "0x4550ee0",
              "captured_execution_or_instruction_evaluation": False,
              "limit": "Static data identity only; no runtime, arithmetic, tree, source-built byte or first-byte claim."}
    out.mkdir()
    raw = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode("utf-8")
    (out / "RESULT.json").write_bytes(raw)
    print(json.dumps({"passed": True, "result_sha256": digest(raw)}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, Rejection, ValueError, KeyError, struct.error) as error:
        detail = str(error) if isinstance(error, Rejection) else type(error).__name__
        print(json.dumps({"passed": False, "reason": detail}, sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
