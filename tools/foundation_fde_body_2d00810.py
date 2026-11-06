#!/usr/bin/env python3
"""RE-001 node #115: FDE body extent and direct-call edge for 0x2d00810..0x2d009ef.

Reads the pinned target in place. Never executes or copies it.
Re-derives the target digest, .text section, window bounds, file offset, body
digest and FDE presence from the target bytes, then compares the recorded
window fields in the saved packet with those derived values. Also re-derives
the direct call edge at 0x2d00849 from its five pinned instruction bytes and
compares each recorded numeric and byte field of that edge.

Limits: this checker does not verify evidence.json target_size_bytes or the
text_section object, does not recount objdump lines, and does not re-derive the
full FDE record text; those are recorded observations. It does not validate
explanatory strings (derivation, callee_label) or any prior-research label. The
callee identity is prior RE-011 interpretation only, not a recovered symbol.
"""
import hashlib
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
PACKET = os.environ.get(
    "FDE_BODY_PACKET_DIR",
    os.path.join(ROOT, "research", "work-items", "RE-001-node115-fde-body-2d00810"),
)
EVIDENCE = os.path.join(PACKET, "evidence.json")

PINNED_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
WINDOW_START = 0x2d00810
WINDOW_END = 0x2d009ef
WINDOW_SIZE = WINDOW_END - WINDOW_START
FILE_OFFSET = 0x2cff810
BODY_SHA256 = "743cdc0425af36017af36e8e2882b9896eeb29ebe547eb3600368ef4118d99d3"
TEXT_VA = 0x1419300
TEXT_OFF = 0x1418300
TEXT_SIZE = 0x4fd7700
CALL_VA = 0x2d00849
CALL_NEXT_VA = 0x2d0084e
CALL_FILE_OFFSET = 0x2cff849
CALL_BYTES = bytes.fromhex("e82214d2ff")
CALL_INSTRUCTION_BYTES_STR = "e8 22 14 d2 ff"
CALL_OPCODE_STR = "e8 (call rel32)"
CALL_DISP_BYTES_STR = "22 14 d2 ff"
CALL_DISP_SIGNED_STR = "-0x2debde"
CALL_DISP_DECIMAL = -3009502
CALL_TARGET_VA = 0x2a21c70
CALL_CALLEE_LABEL = (
    "prior RE-011 interpretation only: role=block_number_resolver in "
    "research/work-items/RE-011-evm-fee-history-115/functions.json "
    "(start_va 0x2a21c70, end_va_exclusive 0x2a225bd); not a recovered symbol"
)


def fail(message):
    sys.stderr.write("FAIL: " + message + "\n")
    return 1


def signed_hex(value):
    if value < 0:
        return "-0x%x" % (-value)
    return "0x%x" % value


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_body(path, offset, size):
    with open(path, "rb") as handle:
        handle.seek(offset)
        return handle.read(size)


def text_section():
    proc = subprocess.run(
        ["readelf", "-S", "--wide", TARGET],
        capture_output=True,
        text=True,
        errors="replace",
    )
    if proc.returncode != 0:
        return None
    pattern = re.compile(
        r"\]\s+\.text\s+\S+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)"
    )
    match = pattern.search(proc.stdout)
    if match is None:
        return None
    return int(match.group(1), 16), int(match.group(2), 16), int(match.group(3), 16)


def fde_line():
    proc = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", TARGET],
        capture_output=True,
        text=True,
        errors="replace",
    )
    if proc.returncode != 0:
        return None
    needle = "pc=%016x..%016x" % (WINDOW_START, WINDOW_END)
    for line in proc.stdout.splitlines():
        if " FDE " in line and needle in line:
            return line.strip()
    return None


def load_evidence():
    if not os.path.isfile(EVIDENCE):
        return None, "missing packet evidence %s" % EVIDENCE
    try:
        with open(EVIDENCE, "r", encoding="utf-8") as handle:
            return json.load(handle), None
    except (OSError, ValueError, UnicodeDecodeError) as exc:
        return None, "cannot read packet evidence: %s" % exc


def check_target():
    if not os.path.isfile(TARGET):
        return fail("missing target " + TARGET)
    digest = sha256_file(TARGET)
    if digest != PINNED_SHA256:
        return fail("target digest %s does not match pinned %s" % (digest, PINNED_SHA256))
    return 0


def check_window():
    section = text_section()
    if section is None:
        return fail("cannot resolve .text from readelf -S")
    va, off, size = section
    if (va, off, size) != (TEXT_VA, TEXT_OFF, TEXT_SIZE):
        return fail(
            ".text section mismatch: got va=0x%x off=0x%x size=0x%x" % (va, off, size)
        )
    if WINDOW_START < va or WINDOW_END > va + size:
        return fail("window 0x%x..0x%x is outside .text" % (WINDOW_START, WINDOW_END))
    if WINDOW_SIZE != 479:
        return fail("window size %d != 479" % WINDOW_SIZE)
    expected_offset = off + (WINDOW_START - va)
    if expected_offset != FILE_OFFSET:
        return fail("file offset 0x%x != recorded 0x%x" % (expected_offset, FILE_OFFSET))
    body = read_body(TARGET, FILE_OFFSET, WINDOW_SIZE)
    if len(body) != WINDOW_SIZE:
        return fail("short read: %d bytes, expected %d" % (len(body), WINDOW_SIZE))
    digest = hashlib.sha256(body).hexdigest()
    if digest != BODY_SHA256:
        return fail("body digest %s != recorded %s" % (digest, BODY_SHA256))
    line = fde_line()
    if line is None:
        return fail("no FDE record for the recorded window")
    return 0


def check_call_edge():
    if CALL_VA < WINDOW_START or CALL_VA + 5 > WINDOW_END:
        return fail("call site 0x%x is outside the recorded window" % CALL_VA)
    offset = FILE_OFFSET + (CALL_VA - WINDOW_START)
    if offset != CALL_FILE_OFFSET:
        return fail(
            "call site file offset 0x%x != recorded 0x%x" % (offset, CALL_FILE_OFFSET)
        )
    raw = read_body(TARGET, offset, 5)
    if len(raw) != 5:
        return fail("short read at call site: %d bytes, expected 5" % len(raw))
    print("call_site: va=0x%x file_offset=0x%x bytes=%s" % (CALL_VA, offset, raw.hex(" ")))
    if raw != CALL_BYTES:
        return fail("call bytes %s != recorded %s" % (raw.hex(), CALL_BYTES.hex()))
    if raw[0] != 0xE8:
        return fail("call opcode 0x%02x is not e8 (call rel32)" % raw[0])
    disp_bytes = raw[1:5]
    displacement = int.from_bytes(disp_bytes, "little", signed=True)
    next_va = CALL_VA + 5
    print(
        "call_displacement: bytes=%s signed=%s decimal=%d"
        % (disp_bytes.hex(" "), signed_hex(displacement), displacement)
    )
    if displacement != CALL_DISP_DECIMAL:
        return fail(
            "derived displacement %d (%s) != recorded %d (%s)"
            % (
                displacement,
                signed_hex(displacement),
                CALL_DISP_DECIMAL,
                CALL_DISP_SIGNED_STR,
            )
        )
    if next_va != CALL_NEXT_VA:
        return fail(
            "derived next-instruction va 0x%x != recorded 0x%x" % (next_va, CALL_NEXT_VA)
        )
    target = next_va + displacement
    print(
        "call_target: next_va=0x%x + %s = 0x%x"
        % (next_va, signed_hex(displacement), target)
    )
    if target != CALL_TARGET_VA:
        return fail(
            "derived call target 0x%x != recorded 0x%x (displacement %d)"
            % (target, CALL_TARGET_VA, displacement)
        )
    return 0


EDGE_FIELDS = (
    ("instruction_va", "0x%x" % CALL_VA),
    ("instruction_bytes", CALL_INSTRUCTION_BYTES_STR),
    ("opcode", CALL_OPCODE_STR),
    ("displacement_bytes_le", CALL_DISP_BYTES_STR),
    ("displacement_signed_le", CALL_DISP_SIGNED_STR),
    ("displacement_decimal", CALL_DISP_DECIMAL),
    ("next_instruction_va", "0x%x" % CALL_NEXT_VA),
    ("target_va", "0x%x" % CALL_TARGET_VA),
)


def check_evidence(data):
    if not isinstance(data, dict):
        return fail("evidence.json is not an object")
    if data.get("target_sha256") != PINNED_SHA256:
        return fail("evidence target_sha256 mismatch")
    window = data.get("window")
    if not isinstance(window, dict):
        return fail("evidence window missing")
    if window.get("start") != "0x%x" % WINDOW_START:
        return fail("evidence window start mismatch")
    if window.get("end") != "0x%x" % WINDOW_END:
        return fail("evidence window end mismatch")
    if window.get("size_bytes") != WINDOW_SIZE:
        return fail("evidence window size mismatch")
    if window.get("file_offset") != "0x%x" % FILE_OFFSET:
        return fail("evidence file_offset mismatch")
    if window.get("body_sha256") != BODY_SHA256:
        return fail("evidence body_sha256 mismatch")
    edge = data.get("call_edge")
    if not isinstance(edge, dict):
        return fail("evidence call_edge missing")
    for field, expected in EDGE_FIELDS:
        if edge.get(field) != expected:
            return fail("evidence call_edge %s mismatch" % field)
    return 0


def main():
    code = check_target()
    if code:
        return code
    code = check_window()
    if code:
        return code
    code = check_call_edge()
    if code:
        return code
    data, error = load_evidence()
    if data is None:
        return fail(error)
    code = check_evidence(data)
    if code:
        return code
    print(
        "ok: window 0x%x..0x%x size=%d body_sha256=%s"
        % (WINDOW_START, WINDOW_END, WINDOW_SIZE, BODY_SHA256)
    )
    print("ok: call edge 0x%x -> 0x%x (%s)" % (CALL_VA, CALL_TARGET_VA, CALL_CALLEE_LABEL))
    return 0


if __name__ == "__main__":
    sys.exit(main())
