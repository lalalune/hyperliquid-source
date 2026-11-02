"""Tests for tools/wal_physical_record.py (node #94 0x5161400).

Fixtures are built with the same framing the model pins: 7-byte
plain headers, 11-byte recyclable headers, CRC-32C masked with
the binary's delta. The tests exercise the behavior end to end:
bytes in, (code, fragment, out) out, including the refill
helper's block-source rounds.
"""

import hashlib
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tools"))

from wal_physical_record import (  # noqa: E402
    CODE_BAD_CRC, CODE_EOF, CODE_LEFTOVER, CODE_LOG_NUMBER,
    CODE_TRAILER_OR_STREAM_FAIL, CODE_TRUNCATED,
    InconsistentReader, Reader, crc32c_extend, mask_crc,
    read_physical_record, unmask_crc,
)

PACKET = os.path.join(os.path.dirname(__file__), "..", "research",
                      "work-items", "RE-001-wal-physical-record-94")
BINARY = os.path.join(os.path.dirname(__file__), "..", "work",
                      "hl-node-94.bin")


def build_record(rtype, payload, log_number=None, checksum=True,
                 corrupt_crc=False):
    """One physical record. ``rtype`` is the signed type byte;
    recyclable types (5..8) carry a log number and use the
    11-byte header."""
    recyclable = 5 <= rtype <= 8
    header_len = 11 if recyclable else 7
    covered = bytes([rtype & 0xFF])
    if recyclable:
        covered += int(log_number).to_bytes(4, "little")
    covered += payload
    stored = mask_crc(crc32c_extend(0, covered))
    if corrupt_crc:
        stored ^= 0x1
    if not checksum:
        stored = 0
    out = bytearray()
    out += stored.to_bytes(4, "little")
    out += len(payload).to_bytes(2, "little")
    out += bytes([rtype & 0xFF])
    if recyclable:
        out += int(log_number).to_bytes(4, "little")
    out += payload
    assert len(out) == header_len + len(payload)
    return bytes(out)


def never_block():
    raise AssertionError("block source must not be called")


def eof_block_source():
    """A block source with nothing left: ok status, empty chunk."""
    def source():
        return 0, b""
    return source


def test_crc32c_check_value():
    # Published CRC-32C check value, pinning the algorithm the
    # PLT import stands for.
    assert crc32c_extend(0, b"123456789") == 0xE3069283


def test_mask_roundtrip():
    for crc in (0, 1, 0xDEADBEEF, 0xFFFFFFFF):
        assert unmask_crc(mask_crc(crc)) == crc


def test_full_record_and_advance():
    rec = build_record(1, b"hello")
    reader = Reader(buffer=rec + build_record(2, b"xy"))
    code, frag, out = read_physical_record(reader, never_block)
    assert (code, frag, out) == (1, b"hello", None)
    code, frag, out = read_physical_record(reader, never_block)
    assert (code, frag, out) == (2, b"xy", None)
    assert reader.buffer == b""


def test_all_plain_types():
    for rtype in (1, 2, 3, 4, 9):
        rec = build_record(rtype, b"p")
        reader = Reader(buffer=rec)
        code, frag, _ = read_physical_record(reader, never_block)
        assert code == rtype and frag == b"p"


def test_zero_type_trailer_returns_11_and_clears():
    rec = build_record(0, b"")
    reader = Reader(buffer=rec + build_record(1, b"z"))
    code, frag, out = read_physical_record(reader, never_block)
    assert code == CODE_TRAILER_OR_STREAM_FAIL and frag is None
    assert reader.buffer == b""


def test_zero_type_with_payload_is_not_a_trailer():
    rec = build_record(0, b"ab")
    reader = Reader(buffer=rec)
    code, frag, _ = read_physical_record(reader, never_block)
    assert (code, frag) == (0, b"ab")


def test_recyclable_match_and_log_number_mismatch():
    rec = build_record(6, b"data", log_number=42)
    reader = Reader(buffer=rec, expected_log=42)
    code, frag, _ = read_physical_record(reader, never_block)
    assert (code, frag) == (6, b"data")
    reader = Reader(buffer=rec, expected_log=43)
    code, frag, out = read_physical_record(reader, never_block)
    assert code == CODE_LOG_NUMBER and frag is None
    # The buffer is left untouched on the log-number path.
    assert reader.buffer == rec


def test_truncated_header_and_payload_return_14():
    rec = build_record(1, b"hello")
    reader = Reader(buffer=rec[:9])
    code, frag, out = read_physical_record(reader, never_block)
    assert code == CODE_TRUNCATED and out == 9 and reader.buffer == b""
    rec = build_record(6, b"hello", log_number=7)
    reader = Reader(buffer=rec[:13], expected_log=7)
    code, frag, out = read_physical_record(reader, never_block)
    assert code == CODE_TRUNCATED and out == 13


def test_bad_crc_returns_15_and_good_crc_passes():
    rec = build_record(1, b"hello", corrupt_crc=True)
    reader = Reader(buffer=rec)
    code, frag, out = read_physical_record(reader, never_block)
    assert code == CODE_BAD_CRC and out == len(rec)
    assert reader.buffer == b""
    rec = build_record(6, b"hello", log_number=3, corrupt_crc=True)
    reader = Reader(buffer=rec, expected_log=3)
    code, frag, _ = read_physical_record(reader, never_block)
    assert code == CODE_BAD_CRC


def test_checksum_disabled_skips_crc_gate():
    rec = build_record(1, b"hello", corrupt_crc=True)
    reader = Reader(buffer=rec, checksum=False)
    code, frag, _ = read_physical_record(reader, never_block)
    assert (code, frag) == (1, b"hello")


def test_eof_on_empty_and_leftover_code_12():
    reader = Reader(buffer=b"")
    code, frag, out = read_physical_record(reader, eof_block_source())
    assert (code, frag, out) == (CODE_EOF, None, None)
    # Final short block seen, then a 5-byte leftover fragment.
    reader = Reader(buffer=b"\x00\x01\x02\x03\x04")
    reader.flag48 = True
    code, frag, out = read_physical_record(reader, never_block)
    assert (code, frag, out) == (CODE_LEFTOVER, None, 5)
    assert reader.buffer == b""


def test_refill_supplies_next_block_and_short_block_sets_flag():
    rec = build_record(1, b"hi")
    blocks = iter([rec])
    reader = Reader(buffer=b"")

    def source():
        try:
            return 0, next(blocks)
        except StopIteration:
            return 0, b""

    code, frag, _ = read_physical_record(reader, source)
    assert (code, frag) == (1, b"hi")
    assert reader.flag48 is True  # short block: final-block flag
    assert reader.total_buffered == len(rec)


def test_refill_error_then_eof():
    calls = []

    def source():
        calls.append(1)
        return 1, b""  # nonzero status: latched error

    reader = Reader(buffer=b"")
    code, frag, out = read_physical_record(reader, source)
    assert (code, frag, out) == (CODE_EOF, None, None)
    assert reader.flag49 is True
    assert len(calls) == 1  # one read attempt, then the flag path


def test_flag70_set_only_while_nothing_consumed():
    rec = build_record(5, b"a", log_number=1)
    reader = Reader(buffer=rec, expected_log=1)
    reader.total_buffered = len(rec)  # first block, unconsumed
    code, _, _ = read_physical_record(reader, never_block)
    assert code == 5 and reader.flag70 is True
    rec2 = build_record(5, b"b", log_number=1)
    reader2 = Reader(buffer=rec2, expected_log=1)
    reader2.total_buffered = len(rec2) + 100  # already consumed
    code, _, _ = read_physical_record(reader2, never_block)
    assert code == 5 and reader2.flag70 is False


def test_transform_path_redirects_fragment_to_scratch():
    rec = build_record(1, b"raw")
    reader = Reader(buffer=rec, stream=object(), out_pointer="ptr")
    steps = iter([(0, b"cooked")])

    def transform(payload, length):
        assert payload == b"raw" and length == 3
        return next(steps)

    code, frag, out = read_physical_record(
        reader, never_block, transform_step=transform)
    assert (code, frag) == (1, b"cooked")
    assert reader.scratch == b"cooked" and out == "cleanup"
    assert reader.helper_created is True


def test_transform_negative_status_returns_11():
    rec = build_record(2, b"raw")
    reader = Reader(buffer=rec, stream=object(), out_pointer="ptr")

    def transform(payload, length):
        return -1, b""

    code, frag, _ = read_physical_record(
        reader, never_block, transform_step=transform)
    assert code == CODE_TRAILER_OR_STREAM_FAIL and frag is None
    assert reader.buffer == b""


def test_transform_full_block_chunk_loops():
    rec = build_record(1, b"raw")
    reader = Reader(buffer=rec, stream=object(), out_pointer="ptr")
    steps = iter([(0, b"x" * 0x8000), (0, b"tail")])

    def transform(payload, length):
        return next(steps)

    code, frag, _ = read_physical_record(
        reader, never_block, transform_step=transform)
    assert code == 1 and frag == b"x" * 0x8000 + b"tail"


def test_stream_read_path_assembles_chunks():
    rec = build_record(3, b"raw")
    reader = Reader(buffer=rec, stream=object(), out_pointer=None)
    steps = iter([(1, b"mid"), (0, b"dle")])

    def stream_read(length):
        return next(steps)

    code, frag, _ = read_physical_record(
        reader, never_block, stream_read=stream_read)
    assert (code, frag) == (3, b"middle")


def test_set_compression_bypasses_transform():
    rec = build_record(9, b"ct")
    reader = Reader(buffer=rec, stream=object(), out_pointer="ptr")

    def transform(payload, length):
        raise AssertionError("type 9 must not reach the transform")

    code, frag, _ = read_physical_record(
        reader, never_block, transform_step=transform)
    assert (code, frag) == (9, b"ct")


def test_packet_manifest_and_excerpts():
    manifest = {}
    for line in open(os.path.join(PACKET, "MANIFEST.sha256")):
        digest, name = line.split(None, 1)
        manifest[name.strip()] = digest
    for name, digest in manifest.items():
        path = os.path.join(PACKET, name)
        assert os.path.isfile(path), name
        actual = hashlib.sha256(open(path, "rb").read()).hexdigest()
        assert actual == digest, name
    records = json.load(open(os.path.join(PACKET, "records.json")))
    assert records["artifact_sha256"] == (
        "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f")
    assert "instructions" not in json.dumps(records)
    assert "mnemonic" not in json.dumps(records)


def test_excerpt_regeneration_and_sampled_bytes():
    # objdump prints the binary path as given in its header, so
    # regenerate with the same repo-relative spelling the packet
    # was built with, from the repo root.
    repo = os.path.join(os.path.dirname(__file__), "..")
    outdir = "/tmp/hl-fde/regen"
    result = subprocess.run(
        [sys.executable, os.path.join(PACKET, "export_excerpts.py"),
         "--binary", "work/hl-node-94.bin", "--out", outdir],
        capture_output=True, text=True, cwd=repo)
    assert result.returncode == 0, result.stderr
    for name in ("window.objdump.txt", "refill.objdump.txt",
                 "caller-site-1.objdump.txt", "caller-site-2.objdump.txt"):
        assert open(os.path.join(outdir, name)).read() == (
            open(os.path.join(PACKET, name)).read()), name
    # Byte-for-byte self-check: three sampled instructions against
    # a fresh objdump run and the raw binary bytes.
    fresh = subprocess.run(
        ["objdump", "-d", "--start-address=0x5161400",
         "--stop-address=0x516184d", BINARY],
        capture_output=True, text=True).stdout
    assert "5161400:\tf3 0f 1e fa" in fresh  # endbr64
    assert "5161441:\t44 0f be 79 06" in fresh  # type byte load
    assert "51616ef:\t41 c1 c6 0f" in fresh  # rol 15 (CRC unmask)
    raw = open(BINARY, "rb").read()
    # .text file offset 0x1342c80, vaddr 0x1343c80: delta 0x1000.
    assert raw[0x5161400 - 0x1000:0x5161400 - 0x1000 + 4] == bytes(
        [0xF3, 0x0F, 0x1E, 0xFA])


def test_packet_corruption_controls():
    # A tampered record must fail the packet's own verify script.
    import shutil
    import tempfile
    tmp = tempfile.mkdtemp()
    shutil.copytree(PACKET, os.path.join(tmp, "packet"))
    pkt = os.path.join(tmp, "packet")
    with open(os.path.join(pkt, "records.json"), "a") as fh:
        fh.write(" ")
    result = subprocess.run(
        [sys.executable, os.path.join(pkt, "verify.py"), "--packet", pkt],
        capture_output=True, text=True)
    assert result.returncode != 0
    with open(os.path.join(pkt, "window.objdump.txt"), "a") as fh:
        fh.write("tampered\n")
    result = subprocess.run(
        [sys.executable, os.path.join(pkt, "verify.py"), "--packet", pkt],
        capture_output=True, text=True)
    assert result.returncode != 0
