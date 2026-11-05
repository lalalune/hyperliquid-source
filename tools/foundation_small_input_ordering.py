#!/usr/bin/env python3
"""Re-derive the node #115 RE-011 small-input ordering evidence from bytes.

The helper window 0x26ce540..0x26ce5ec is read from the pinned target
artifacts/node/115/hl-node in place. This checker never executes or copies the
target and never writes to artifacts/. It re-derives the caller call site, the
window digest, the comparison instruction bytes, the 32-byte record stride and
an independent unsigned 128-bit comparison/sort model. The byte-backed
values derived from the target are compared with the recorded evidence; fixed
values (the FDE pc limits and the 24/32-byte movement widths) are checked
against the recorded constants.

Limit: the recorded FDE pc_start/pc_end are compared with the window constants
and are not re-parsed from .eh_frame here. This packet retains no frames.txt, so
the FDE extent is a recorded readelf value and is not re-derived by this checker.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

TARGET_REL = "artifacts/node/115/hl-node"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105896032
PACKET_REL = "research/work-items/RE-011-node115-small-input-ordering"
HELPER_ENTRY = 0x26CE540
HELPER_END = 0x26CE5EC
WINDOW_START = HELPER_ENTRY
WINDOW_END = HELPER_END
CALLER_CALL = 0x2A2121D
CALL_TARGET = HELPER_ENTRY
STRIDE_BYTES = 32
HELD_WRITE_BYTES = 24
CMP_FAMILY = (0x38, 0x39, 0x3A, 0x3B)
SBB_FAMILY = (0x18, 0x19, 0x1A, 0x1B)
PREFIXES = (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3)
SITE_KINDS = ("read", "write", "step")
FDE_LIMIT = (
    "FDE pc limits are compared with the recorded window constants; this checker "
    "does not re-parse .eh_frame. No frames.txt is retained in this packet."
)


class CheckError(AssertionError):
    """Raised when a recorded value disagrees with the pinned target bytes."""


def require(condition, message):
    if not condition:
        raise CheckError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def as_int(value):
    if isinstance(value, int):
        return value
    return int(value, 16)


def hexdump(label, base, buf, width=16):
    lines = []
    for offset in range(0, len(buf), width):
        chunk = buf[offset:offset + width]
        text = " ".join("%02x" % byte for byte in chunk)
        lines.append("%s 0x%08x  %s" % (label, base + offset, text))
    return lines


def load_segments(data):
    require(data[:4] == b"\x7fELF", "target is not an ELF image")
    require(data[4] == 2 and data[5] == 1, "target is not ELF64 little-endian")
    phoff = struct.unpack_from("<Q", data, 0x20)[0]
    phentsize = struct.unpack_from("<H", data, 0x36)[0]
    phnum = struct.unpack_from("<H", data, 0x38)[0]
    require(phentsize >= 56 and phnum > 0, "unexpected program header table")
    segments = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        fields = struct.unpack_from("<IIQQQQQQ", data, offset)
        p_type, _flags, p_offset, p_vaddr, _paddr, p_filesz, _memsz, _align = fields
        if p_type == 1:
            segments.append((p_offset, p_vaddr, p_filesz))
    require(segments, "target has no file-backed PT_LOAD segment")
    return segments


def read_va(data, segments, va, length):
    for p_offset, p_vaddr, p_filesz in segments:
        if p_vaddr <= va and va + length <= p_vaddr + p_filesz:
            start = p_offset + (va - p_vaddr)
            return data[start:start + length]
    raise CheckError("VA 0x%x..0x%x is not file-backed" % (va, va + length))


def skip_prefixes(buf, offset):
    index = offset
    rex = None
    while index < len(buf):
        byte = buf[index]
        if byte in PREFIXES:
            index += 1
            continue
        if 0x40 <= byte <= 0x4F:
            rex = byte
            index += 1
            continue
        break
    require(index < len(buf), "truncated instruction at window offset 0x%x" % offset)
    return rex, index


def operand_bits(rex):
    if rex is not None and (rex & 0x08):
        return 64
    return 32


def inspect_comparison(window, base_va, cmp_va, sbb_va, jae_va):
    """Derive the cmp/sbb/jae comparison pattern from the window bytes."""
    cmp_off = cmp_va - base_va
    sbb_off = sbb_va - base_va
    jae_off = jae_va - base_va
    for name, value in (("cmp", cmp_off), ("sbb", sbb_off), ("jae", jae_off)):
        require(0 <= value < len(window), "%s site is outside the window" % name)
    rex_cmp, cmp_index = skip_prefixes(window, cmp_off)
    rex_sbb, sbb_index = skip_prefixes(window, sbb_off)
    rex_jae, jae_index = skip_prefixes(window, jae_off)
    cmp_opcode = window[cmp_index]
    sbb_opcode = window[sbb_index]
    jae_opcode = window[jae_index]
    require(cmp_opcode in CMP_FAMILY, "cmp site opcode 0x%02x is not CMP r/m" % cmp_opcode)
    require(sbb_opcode in SBB_FAMILY, "sbb site opcode 0x%02x is not SBB r/m" % sbb_opcode)
    width_bits = operand_bits(rex_cmp)
    require(operand_bits(rex_sbb) == width_bits,
            "cmp and sbb do not use the same operand width")
    if jae_opcode == 0x73:
        require(jae_index + 1 < len(window), "truncated short jae")
        displacement = struct.unpack_from("<b", window, jae_index + 1)[0]
        size = 2
    elif jae_opcode == 0x0F and jae_index + 1 < len(window) and window[jae_index + 1] == 0x83:
        require(jae_index + 5 < len(window), "truncated near jae")
        displacement = struct.unpack_from("<i", window, jae_index + 2)[0]
        size = 6
    else:
        raise CheckError("jae site opcode 0x%02x is not JAE/JNB" % jae_opcode)
    target = jae_va + (jae_index - jae_off) + size + displacement
    return {
        "cmp_index": cmp_index,
        "sbb_index": sbb_index,
        "jae_index": jae_index,
        "cmp_opcode": cmp_opcode,
        "sbb_opcode": sbb_opcode,
        "jae_opcode": jae_opcode,
        "operand_width_bits": width_bits * 2,
        "jae_target": target,
    }


def inspect_back_edge(window, base_va, va):
    offset = va - base_va
    require(0 <= offset < len(window), "back edge is outside the window")
    _rex, index = skip_prefixes(window, offset)
    opcode = window[index]
    require(opcode in (0x72, 0x73, 0x74, 0x75, 0x76, 0x7C, 0x7D, 0x7E, 0x7F, 0xEB),
            "back edge opcode 0x%02x is not a short backward branch" % opcode)
    require(index + 1 < len(window), "truncated short branch")
    displacement = struct.unpack_from("<b", window, index + 1)[0]
    target = va + (index - offset) + 2 + displacement
    require(target < va, "branch at 0x%x does not point backward" % va)
    return target


def decode_stride_shift(raw):
    """Decode a `shl r64, imm8` instruction and return its byte stride."""
    require(len(raw) == 4, "stride site is not a four-byte shift instruction")
    require(raw[0] == 0x48, "stride site does not carry the REX.W prefix")
    require(raw[1] == 0xC1, "stride site is not a shift with an 8-bit immediate")
    modrm = raw[2]
    require((modrm >> 6) == 3, "stride shift does not use a register operand")
    require(((modrm >> 3) & 7) == 4, "stride shift is not SHL")
    shift = raw[3]
    require(shift < 64, "stride shift amount is outside the 64-bit range")
    return 1 << shift


def validate_stride(window, base_va, sites):
    seen = []
    for site in sites:
        va = as_int(site["va"])
        raw = bytes.fromhex(site["bytes_hex"])
        offset = va - base_va
        require(0 <= offset and offset + len(raw) <= len(window),
                "stride site 0x%x is outside the window" % va)
        require(window[offset:offset + len(raw)] == raw,
                "stride site 0x%x bytes differ from the target" % va)
        stride = decode_stride_shift(raw)
        require(stride == STRIDE_BYTES,
                "stride site 0x%x shifts by %d bytes, not %d" % (va, stride, STRIDE_BYTES))
        seen.append(va)
    require(seen, "no stride site is recorded")
    return seen


def validate_record_sites(window, base_va, sites):
    spans = []
    for site in sites:
        va = as_int(site["va"])
        raw = bytes.fromhex(site["bytes_hex"])
        offset = va - base_va
        require(0 <= offset and offset + len(raw) <= len(window),
                "record site 0x%x is outside the window" % va)
        require(window[offset:offset + len(raw)] == raw,
                "record site 0x%x bytes differ from the target" % va)
        require(site["kind"] in SITE_KINDS,
                "record site 0x%x kind is not read/write/step" % va)
        spans.append((va, va + len(raw)))
    require(spans, "no record site is recorded")
    return spans


def compare_u128(hi_a, lo_a, hi_b, lo_b):
    left = (hi_a << 64) | lo_a
    right = (hi_b << 64) | lo_b
    if left < right:
        return -1
    if left > right:
        return 1
    return 0


def stable_insertion_order(records):
    ordered = []
    for record in records:
        position = len(ordered)
        while position > 0:
            previous = ordered[position - 1]
            if compare_u128(previous[0], previous[1], record[0], record[1]) <= 0:
                break
            position -= 1
        ordered.insert(position, record)
    return [record[2] for record in ordered]


def expect_rejected(label, func):
    try:
        func()
    except CheckError:
        return
    raise CheckError("corruption control not detected: %s" % label)


def check(root, evidence_path, out=print):
    target_path = root / TARGET_REL
    require(target_path.is_file(), "pinned target is missing: %s" % target_path)
    data = target_path.read_bytes()
    require(len(data) == TARGET_SIZE, "target size %d is not %d" % (len(data), TARGET_SIZE))
    require(digest(data) == TARGET_SHA256, "target SHA-256 is not the pinned node #115 digest")
    segments = load_segments(data)
    window = read_va(data, segments, WINDOW_START, WINDOW_END - WINDOW_START)
    callsite = read_va(data, segments, CALLER_CALL, 5)
    for line in hexdump("window", WINDOW_START, window):
        out(line)
    out("caller 0x%08x  %s" % (CALLER_CALL, " ".join("%02x" % byte for byte in callsite)))
    out("window length %d, sha256 %s" % (len(window), digest(window)))
    out("LIMIT: " + FDE_LIMIT)

    require(evidence_path.is_file(), "packet evidence file is missing: %s" % evidence_path)
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))

    identity = evidence["target"]
    require(as_int(identity["sha256"]) if False else identity["sha256"] == TARGET_SHA256,
            "recorded target digest differs from the pinned digest")
    require(identity["size"] == TARGET_SIZE, "recorded target size differs")

    fde = evidence["fde"]
    require(as_int(fde["pc_start"]) == WINDOW_START, "recorded FDE start differs")
    require(as_int(fde["pc_end"]) == WINDOW_END, "recorded FDE end differs")
    require(fde["index"] == "0009c51c", "recorded FDE index differs")
    require(fde.get("derivation") == "recorded-readelf",
            "recorded FDE derivation is not the explicit recorded-readelf limitation")
    out("FDE limits 0x%x..0x%x from recorded readelf decode (not re-parsed here)" % (WINDOW_START, WINDOW_END))

    caller = evidence["caller"]
    require(as_int(caller["call_va"]) == CALLER_CALL, "recorded call site differs")
    require(bytes.fromhex(caller["bytes_hex"]) == callsite, "call site bytes differ")
    require(callsite[0] == 0xE8, "call site is not a direct relative call")
    relative = struct.unpack_from("<i", callsite, 1)[0]
    target_va = CALLER_CALL + 5 + relative
    require(target_va == CALL_TARGET, "call target 0x%x is not the helper entry" % target_va)
    require(as_int(caller["call_target"]) == target_va, "recorded call target differs")

    recorded_window = evidence["window"]
    require(as_int(recorded_window["start"]) == WINDOW_START, "recorded window start differs")
    require(as_int(recorded_window["end"]) == WINDOW_END, "recorded window end differs")
    require(recorded_window["length"] == len(window), "recorded window length differs")
    require(recorded_window["sha256"] == digest(window), "recorded window digest differs")
    require(recorded_window["stride_bytes"] == STRIDE_BYTES, "recorded stride is not 32")

    comparison = evidence["comparison"]
    cmp_va = as_int(comparison["cmp"]["va"])
    sbb_va = as_int(comparison["sbb"]["va"])
    jae_va = as_int(comparison["jae"]["va"])
    for name, va in (("cmp", cmp_va), ("sbb", sbb_va), ("jae", jae_va)):
        raw = bytes.fromhex(comparison[name]["bytes_hex"])
        offset = va - WINDOW_START
        require(0 <= offset and offset + len(raw) <= len(window),
                "%s site 0x%x is outside the window" % (name, va))
        require(window[offset:offset + len(raw)] == raw,
                "%s site 0x%x bytes differ from the target" % (name, va))
    derived = inspect_comparison(window, WINDOW_START, cmp_va, sbb_va, jae_va)
    require(derived["operand_width_bits"] == comparison["operand_width_bits"],
            "derived operand width %d differs from the record" % derived["operand_width_bits"])
    require(as_int(comparison["jae"]["target"]) == derived["jae_target"],
            "derived jae target 0x%x differs from the record" % derived["jae_target"])
    require(derived["jae_target"] < jae_va,
            "jae does not branch backward to the outer loop head")
    require(WINDOW_START <= derived["jae_target"] < WINDOW_END,
            "jae target leaves the helper")
    require(derived["jae_target"] < cmp_va,
            "jae target does not precede the comparison")

    back = evidence["loop"]["back_branch"]
    back_va = as_int(back["va"])
    back_raw = bytes.fromhex(back["bytes_hex"])
    back_offset = back_va - WINDOW_START
    require(0 <= back_offset and back_offset + len(back_raw) <= len(window),
            "back branch is outside the window")
    require(window[back_offset:back_offset + len(back_raw)] == back_raw,
            "back branch bytes differ from the target")
    back_target = inspect_back_edge(window, WINDOW_START, back_va)
    require(back_target == as_int(back["target"]), "derived back edge target differs")
    require(cmp_va < back_target < back_va,
            "back edge does not return to the inner insertion loop after the outer comparison")
    inner = evidence["loop"]["inner_comparison"]
    for name, family in (("cmp", CMP_FAMILY), ("sbb", SBB_FAMILY)):
        site = inner[name]
        site_va = as_int(site["va"])
        site_raw = bytes.fromhex(site["bytes_hex"])
        site_offset = site_va - WINDOW_START
        require(0 <= site_offset and site_offset + len(site_raw) <= len(window),
                "inner %s site 0x%x is outside the window" % (name, site_va))
        require(window[site_offset:site_offset + len(site_raw)] == site_raw,
                "inner %s site 0x%x bytes differ from the target" % (name, site_va))
        require(back_target <= site_va < back_va,
                "inner %s site 0x%x is outside the inner insertion loop" % (name, site_va))
        _site_rex, site_index = skip_prefixes(window, site_offset)
        site_opcode = window[site_index]
        require(site_opcode in family,
                "inner %s site 0x%x opcode 0x%02x is not a %s" %
                (name, site_va, site_opcode, name.upper()))

    records = evidence["records"]
    require(records["stride_bytes"] == STRIDE_BYTES, "record stride is not 32")
    require(records["moved_span_bytes"] == STRIDE_BYTES,
            "vector move span is not one complete 32-byte record")
    require(records["held_write_bytes"] == HELD_WRITE_BYTES,
            "final held-record write is not the three qwords (24 bytes)")
    require(records["held_write_bytes"] < records["moved_span_bytes"],
            "held-record write does not leave the fourth qword unwritten")
    validate_stride(window, WINDOW_START, evidence["stride"]["sites"])
    validate_record_sites(window, WINDOW_START, records["sites"])

    model = evidence["model"]
    pairs = model["pairs"]
    require(len(pairs) >= 5, "fewer than five boundary pairs are recorded")
    for pair in pairs:
        hi_a, lo_a, hi_b, lo_b, relation = pair
        derived_relation = compare_u128(hi_a, lo_a, hi_b, lo_b)
        require(derived_relation == relation,
                "model relation for (%d,%d)/(%d,%d) is not %d" % (hi_a, lo_a, hi_b, lo_b, relation))
    stability = model["stability"]
    derived_order = stable_insertion_order([tuple(item) for item in stability["records"]])
    require(derived_order == stability["order"],
            "stable insertion order %r differs from the record" % (derived_order,))

    mutated = bytearray(window)
    mutated[derived["cmp_index"]] ^= 0xFF
    expect_rejected("cmp opcode",
                    lambda: inspect_comparison(bytes(mutated), WINDOW_START, cmp_va, sbb_va, jae_va))
    mutated = bytearray(window)
    mutated[derived["sbb_index"]] ^= 0xFF
    expect_rejected("sbb opcode",
                    lambda: inspect_comparison(bytes(mutated), WINDOW_START, cmp_va, sbb_va, jae_va))
    mutated = bytearray(window)
    mutated[derived["jae_index"]] = 0x90
    expect_rejected("jae opcode",
                    lambda: inspect_comparison(bytes(mutated), WINDOW_START, cmp_va, sbb_va, jae_va))
    first_stride = evidence["stride"]["sites"][0]
    stride_offset = as_int(first_stride["va"]) - WINDOW_START
    mutated = bytearray(window)
    mutated[stride_offset + len(bytes.fromhex(first_stride["bytes_hex"])) - 1] = 0x21
    expect_rejected("stride immediate",
                    lambda: validate_stride(bytes(mutated), WINDOW_START, evidence["stride"]["sites"]))
    bad_stride = bytearray(bytes.fromhex(first_stride["bytes_hex"]))
    bad_stride[-1] = 0x21
    expect_rejected("stride shift amount",
                    lambda: require(decode_stride_shift(bytes(bad_stride)) == STRIDE_BYTES,
                                    "mutated stride shift still yields 32 bytes"))
    mutated_call = bytearray(callsite)
    mutated_call[1] ^= 0x01
    mutated_relative = struct.unpack_from("<i", mutated_call, 1)[0]
    expect_rejected("call displacement",
                    lambda: require(CALLER_CALL + 5 + mutated_relative == CALL_TARGET,
                                    "mutated call displacement still resolves to the helper"))

    require(digest(data) == TARGET_SHA256, "target bytes changed during the check")
    out("comparison width %d bits, jae target 0x%08x" % (derived["operand_width_bits"], derived["jae_target"]))
    return derived


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--evidence", default=None)
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    evidence_path = Path(args.evidence) if args.evidence else root / PACKET_REL / "evidence.json"
    try:
        check(root, evidence_path)
    except CheckError as exc:
        print("FAIL: %s" % exc, file=sys.stderr)
        return 1
    print("PASS: small-input ordering packet re-derived from the pinned target")
    return 0


if __name__ == "__main__":
    sys.exit(main())
