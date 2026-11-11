"""Recheck the two recorded node #115 call edges and their stride as static data."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys


PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[3]
TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032
CALLER = (0x250ECD0, 0x250EE44)
CALLEE = (0x298AF40, 0x298B04D)
SITES = (0x250ED83, 0x250EDD0)
STRIDES = {
    0x250ED91: (b"\x49\x81\xc6", 0x20000),
    0x250ED98: (b"\x49\x81\xc5", -0x20000),
    0x250EDD5: (b"\x49\x81\xc6", 0x20000),
    0x250EDDC: (b"\x49\x81\xc5", -0x20000),
}
ROW = re.compile(r"^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s+)+)")


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def rows(log):
    result = []
    for line in log.splitlines():
        match = ROW.match(line)
        if match:
            result.append((int(match[1], 16), bytes.fromhex(match[2])))
    return result


def partition(native, bounds):
    start, end = bounds
    position = start
    for address, raw in native:
        require(address == position and 1 <= len(raw) <= 15, "native partition")
        position += len(raw)
    require(position == end, "native partition")
    return b"".join(raw for _, raw in native)


def observations(native):
    by_site = dict(native)
    for site in SITES:
        raw = by_site.get(site, b"")
        require(len(raw) == 5 and raw[:1] == b"\xe8"
                and site + len(raw) + int.from_bytes(raw[1:], "little", signed=True) == CALLEE[0],
                f"call destination {site:#x}")
    for site, (opcode, stride) in STRIDES.items():
        raw = by_site.get(site, b"")
        require(len(raw) == 7 and raw[:3] == opcode
                and int.from_bytes(raw[3:], "little", signed=True) == stride,
                f"stride {site:#x}")
    require(by_site.get(0x250ED8D) == bytes.fromhex("49c1e511"), "shift amount")


def extent(matches, expected):
    require(len(matches) == 1 and (matches[0]["start"], matches[0]["end"]) == expected, "FDE extent")
    return matches[0]


def identity(raw, expected):
    require(sha(raw) == expected, "body digest")


def controls(native, caller_body, caller_sha, fde):
    results = {}

    def reject(label, reason, call, *args):
        try:
            call(*args)
        except ValueError as error:
            require(str(error) == reason, f"{label} rejected for the wrong reason")
            results[label] = reason
        else:
            raise ValueError(f"{label} passed")

    for site, byte, reason in [
        *((site, 1, f"call destination {site:#x}") for site in SITES),
        (0x250ED91, 5, "stride 0x250ed91"),
        (0x250EDDC, 5, "stride 0x250eddc"),
        (0x250ED8D, 3, "shift amount"),
    ]:
        altered = [(address, raw[:byte] + bytes([raw[byte] ^ 1]) + raw[byte + 1:]
                    if address == site else raw) for address, raw in native]
        reject(reason, reason, observations, altered)
    reject("gap", "native partition", partition, native[:1] + native[2:], CALLER)
    reject("extent", "FDE extent", extent, [dict(fde, end=fde["end"] - 1)], CALLER)
    reject("body", "body digest", identity, bytes([caller_body[0] ^ 1]) + caller_body[1:], caller_sha)
    return results


def file_window(image, section, start, end):
    require(section["address"] <= start < end <= section["address"] + section["size"], "section bounds")
    offset = section["offset"] + start - section["address"]
    return offset, image[offset:offset + end - start]


def frame_record(image, section, address):
    offset, length_bytes = file_window(image, section, address, address + 4)
    length = struct.unpack("<I", length_bytes)[0]
    require(4 <= length <= 4096, "frame record size")
    _, raw = file_window(image, section, address, address + length + 4)
    return {"va": hex(address), "file_offset": hex(offset), "hex": raw.hex(), "sha256": sha(raw)}


def reproduce(binary, output):
    require(binary.stat().st_size == TARGET_SIZE, "capture size")
    image = binary.read_bytes()
    require(len(image) == TARGET_SIZE and sha(image) == TARGET_SHA, "capture digest")
    sys.path.insert(0, str(ROOT / "tools"))
    from elf_index import sections
    from fde_extents import eh_frame_records

    evidence = json.loads((PACKET / "evidence.json").read_text())
    require(evidence["target"]["sha256"] == TARGET_SHA, "evidence target identity")
    receipt_index = json.loads((PACKET / "receipt-index.json").read_text())["files"]
    receipts = PACKET / "receipts"
    require({path.name: sha(path.read_bytes()) for path in receipts.iterdir()} == receipt_index,
            "original receipt identity")
    section_rows = sections(image)
    frames = [item for item in section_rows if item["name"] == ".eh_frame" and item["type"] != 8]
    require(len(frames) == 1, "unique file-backed .eh_frame")
    frame_section, = frames
    _, fdes = eh_frame_records(image, section_rows)
    output.mkdir(parents=True, exist_ok=False)
    result = {"target_sha256": TARGET_SHA, "target_bytes": TARGET_SIZE, "intervals": {}, "tool_versions": {}}
    tools = {"gnu": ("objdump", "-d", "-z", "--insn-width=16"),
             "llvm": ("llvm-objdump", "-d", "--disassemble-zeroes")}
    for label, (tool, *_) in tools.items():
        result["tool_versions"][label] = subprocess.check_output(
            [tool, "--version"], text=True, timeout=10).splitlines()[0]

    for label, bounds, receipt, key in [
        ("caller", CALLER, "caller-0x250ecd0", "caller"),
        ("callee", CALLEE, "selected", "selected_callee"),
    ]:
        start, end = bounds
        meta = evidence[key]
        require((int(meta["start_va"], 16), int(meta["end_va"], 16)) == bounds, "evidence interval")
        fde = extent([item for item in fdes if item["start"] == start], bounds)
        owners = [item for item in section_rows if item["type"] != 8 and item["flags"] & 4
                  and item["address"] <= start < end <= item["address"] + item["size"]]
        require(len(owners) == 1, "unique executable section")
        offset, body = file_window(image, owners[0], start, end)
        identity(body, meta["body_sha256"])
        require(len(body) == meta["bytes"], "evidence body size")
        command_records = {}
        native = None
        for flavor, command in tools.items():
            argv = [*command, f"--start-address={start:#x}", f"--stop-address={end:#x}", str(binary)]
            run = subprocess.run(argv, check=True, capture_output=True, timeout=30)
            require(len(run.stdout) <= 65536 and not run.stderr, "unexpected native output")
            current = rows(run.stdout.decode("utf-8"))
            retained = rows((receipts / f"{receipt}-{flavor}.log").read_text())
            require(current == retained and partition(current, bounds) == body, "native byte agreement")
            require(len(current) == meta["instructions"], "native row count")
            require(native is None or native == current, "GNU/LLVM agreement")
            native = current
            (output / f"{label}-{flavor}.log").write_bytes(run.stdout)
            command_records[flavor] = {"argv": argv, "exit_code": run.returncode, "sha256": sha(run.stdout)}
        result["intervals"][label] = {
            "start": hex(start), "end": hex(end), "file_offset": hex(offset), "bytes": len(body),
            "body_sha256": sha(body), "instruction_rows": len(native),
            "fde": frame_record(image, frame_section, fde["fde"]),
            "cie": frame_record(image, frame_section, fde["cie"]), "commands": command_records,
        }
        if label == "caller":
            observations(native)
            by_site = dict(native)
            for observation in evidence["observations"]:
                site = int(observation["site_va"], 16)
                require(by_site.get(site) == bytes.fromhex(observation["bytes"]), "observation bytes")
            result["controls"] = controls(native, body, meta["body_sha256"], fde)
    result["direct_call_sites"] = [hex(site) for site in SITES]
    result["direct_call_destination"] = hex(CALLEE[0])
    result["observed_stride_bytes"] = 0x20000
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"intervals_checked": 2, "direct_calls_checked": len(SITES),
                      "controls_rejected": len(result["controls"]), "result": str(output / "result.json")}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    options = parser.parse_args()
    reproduce(options.binary.resolve(), options.out.resolve())
