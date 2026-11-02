"""Tests for tools/wal_writer.py (node #94 WAL writer AddRecord).

Runs under pytest and under plain python3 (no pytest import needed).
Packet files are located relative to this file, so the tests pass from
any working directory.
"""

import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.wal_writer import (BLOCK_SIZE, ResultRecord, Writer, add_record,
                              build_header, crc32c, crc32c_combine,
                              emit_compression_record, emit_fragment,
                              mask_crc, unmask_crc)

TYPE_CRC = {t: crc32c(bytes([t])) for t in range(1, 10)}
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class RecordingAppend:
    def __init__(self, fail_on=None):
        self.calls = []
        self.fail_on = fail_on  # call index that returns a terminal record

    def __call__(self, payload):
        self.calls.append(bytes(payload))
        if self.fail_on is not None and len(self.calls) - 1 == self.fail_on:
            return ResultRecord.previous_error()
        return ResultRecord.ok()


class FakeComplete:
    def __init__(self):
        self.calls = []

    def __call__(self, writer, aux):
        self.calls.append(aux)
        return ResultRecord.ok()


class FakeCompressor:
    """Chunks: list of (bytes, status). status 0 = final, >0 = more."""

    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.begin_calls = 0
        self.step_calls = 0

    def begin(self):
        self.begin_calls += 1

    def step(self, data, scratch):
        self.step_calls += 1
        chunk, status = self.chunks.pop(0)
        scratch[:len(chunk)] = chunk
        return len(chunk), status


def make_writer(append=None, complete=None, **kwargs):
    kwargs.setdefault("type_crc", TYPE_CRC)
    return Writer(append or RecordingAppend(), complete or FakeComplete(),
                  **kwargs)


def parse_header(raw):
    crc, length, ftype = struct.unpack_from("<IHB", raw, 0)
    log_number = None
    if len(raw) == 11:
        (log_number,) = struct.unpack_from("<I", raw, 7)
    return crc, length, ftype, log_number


def test_crc32c_check_value():
    assert crc32c(b"123456789") == 0xE3069283


def test_crc32c_combine_matches_direct():
    cases = [(b"", b"abc"), (b"x", b"hello world"), (bytes(range(20)), b"z")]
    for a, b in cases:
        combined = crc32c_combine(crc32c(a), crc32c(b), len(b))
        assert combined == crc32c(a + b)


def test_mask_unmask_roundtrip_matches_reader_rule():
    data = b"record-payload"
    header = build_header(1, data, make_writer())
    crc, length, ftype, _ = parse_header(header)
    assert length == len(data) and ftype == 1
    assert unmask_crc(crc) == crc32c(bytes([1]) + data)
    assert mask_crc(unmask_crc(crc)) == crc


def test_header_layout_plain_and_recyclable():
    plain = build_header(2, b"ab", make_writer())
    assert len(plain) == 7
    rec = build_header(6, b"ab", make_writer(log_number=0x12345678))
    assert len(rec) == 11
    _, _, ftype, log_number = parse_header(rec)
    assert ftype == 6 and log_number == 0x12345678
    comp = build_header(9, b"\x03\x00\x00\x00", make_writer())
    assert len(comp) == 7


def test_corruption_control_header_mismatch():
    header = build_header(1, b"payload", make_writer())
    crc, _, _, _ = parse_header(header)
    assert unmask_crc(crc) != crc32c(bytes([1]) + b"payloax")
    assert unmask_crc(crc ^ 0xFF) != crc32c(bytes([1]) + b"payload")


def test_emit_fragment_appends_header_then_data():
    append = RecordingAppend()
    writer = make_writer(append=append)
    out = emit_fragment(writer, 1, b"hello", 0)
    assert not out.terminal
    assert len(append.calls) == 2
    assert len(append.calls[0]) == 7
    assert append.calls[1] == b"hello"
    assert writer.block_offset == 7 + 5


def test_emit_fragment_header_failure_skips_data():
    append = RecordingAppend(fail_on=0)
    writer = make_writer(append=append)
    out = emit_fragment(writer, 1, b"hello", 0)
    assert out.terminal and out.message == "Writer has previous error."
    assert len(append.calls) == 1
    assert writer.block_offset == 7 + 5  # offset still advances, writer is done


def test_add_record_single_fragment_and_completion():
    append = RecordingAppend()
    complete = FakeComplete()
    writer = make_writer(append=append, complete=complete)
    out = add_record(writer, b"x" * 100, 0)
    assert not out.terminal
    assert [len(c) for c in append.calls] == [7, 100]
    _, _, ftype, _ = parse_header(append.calls[0])
    assert ftype == 1  # full
    assert complete.calls == [0]


def test_add_record_completion_skipped_when_finalize_flag_set():
    append = RecordingAppend()
    complete = FakeComplete()
    writer = make_writer(append=append, complete=complete, finalize_flag=True)
    add_record(writer, b"hi", 0)
    assert complete.calls == []


def test_add_record_multi_block_types():
    append = RecordingAppend()
    writer = make_writer(append=append, complete=FakeComplete(),
                         finalize_flag=True)
    add_record(writer, b"a" * 70000, 0)
    headers = [parse_header(c) for c in append.calls[::2]]
    assert [h[2] for h in headers] == [2, 3, 4]  # first, middle, last
    assert [h[1] for h in headers] == [32761, 32761, 4478]


def test_add_record_trailer_zero_padding():
    append = RecordingAppend()
    writer = make_writer(append=append, complete=FakeComplete(),
                         finalize_flag=True, block_offset=32765)
    add_record(writer, b"0123456789", 0)
    assert append.calls[0] == b"\x00" * 3
    _, _, ftype, _ = parse_header(append.calls[1])
    assert ftype == 1
    assert writer.block_offset == 7 + 10


def test_add_record_recyclable_types_and_headers():
    append = RecordingAppend()
    writer = make_writer(append=append, complete=FakeComplete(),
                         finalize_flag=True, recycle=True, log_number=42)
    add_record(writer, b"b" * 70000, 0)
    headers = [parse_header(c) for c in append.calls[::2]]
    assert [h[2] for h in headers] == [6, 7, 8]
    assert all(len(c) == 11 for c in append.calls[::2])
    assert all(h[3] == 42 for h in headers)


def test_add_record_empty_is_one_empty_full_fragment():
    append = RecordingAppend()
    writer = make_writer(append=append, complete=FakeComplete(),
                         finalize_flag=True)
    add_record(writer, b"", 0)
    assert len(append.calls) == 2
    crc, length, ftype, _ = parse_header(append.calls[0])
    assert (length, ftype) == (0, 1)


def test_add_record_with_compressor_two_chunks():
    append = RecordingAppend()
    comp = FakeCompressor([(b"A" * 100, 1), (b"B" * 50, 0)])
    writer = make_writer(append=append, complete=FakeComplete(),
                         finalize_flag=True, compressor=comp)
    writer.scratch = bytearray(BLOCK_SIZE)
    out = add_record(writer, b"ignored-input", 0)
    assert not out.terminal
    assert comp.begin_calls == 1 and comp.step_calls == 2
    headers = [parse_header(c) for c in append.calls[::2]]
    assert [h[2] for h in headers] == [2, 4]  # first, last
    assert append.calls[1] == b"A" * 100
    assert append.calls[3] == b"B" * 50


def test_add_record_compressor_chunk_spanning_blocks():
    append = RecordingAppend()
    comp = FakeCompressor([(b"C" * 40000, 0)])
    writer = make_writer(append=append, complete=FakeComplete(),
                         finalize_flag=True, compressor=comp)
    writer.scratch = bytearray(BLOCK_SIZE)
    add_record(writer, b"in", 0)
    headers = [parse_header(c) for c in append.calls[::2]]
    assert [h[2] for h in headers] == [2, 4]
    assert comp.step_calls == 1


def test_add_record_compressor_error_record():
    append = RecordingAppend()
    complete = FakeComplete()
    comp = FakeCompressor([(b"", -1)])
    writer = make_writer(append=append, complete=complete, compressor=comp)
    writer.scratch = bytearray(BLOCK_SIZE)
    out = add_record(writer, b"in", 0)
    assert out.terminal and out.code == 5 and out.field4 == 1
    assert out.message == "Unexpected WAL compression error"
    assert complete.calls == []  # no completion step on the error path
    assert append.calls == []


def test_add_record_empty_second_chunk_ends_without_fragment():
    append = RecordingAppend()
    comp = FakeCompressor([(b"X" * 10, 1), (b"", 0)])
    writer = make_writer(append=append, complete=FakeComplete(),
                         finalize_flag=True, compressor=comp)
    writer.scratch = bytearray(BLOCK_SIZE)
    add_record(writer, b"in", 0)
    assert len(append.calls) == 2  # only the first chunk was emitted
    assert comp.step_calls == 2


def test_add_record_append_failure_stops_loop():
    append = RecordingAppend(fail_on=0)
    writer = make_writer(append=append, complete=FakeComplete(),
                         finalize_flag=True)
    out = add_record(writer, b"z" * 70000, 0)
    assert out.terminal
    assert len(append.calls) == 1


def test_emit_compression_record_disabled_is_empty():
    append = RecordingAppend()
    writer = make_writer(append=append, compression_type=0)
    out = emit_compression_record(writer)
    assert not out.terminal
    assert append.calls == [] and writer.compressor is None


def test_emit_compression_record_installs_compressor():
    append = RecordingAppend()
    complete = FakeComplete()
    writer = make_writer(append=append, complete=complete,
                         compression_type=3, finalize_flag=True)
    comp = FakeCompressor([])
    out = emit_compression_record(writer, 4, lambda size: comp)
    assert not out.terminal
    _, _, ftype, _ = parse_header(append.calls[0])
    assert ftype == 9
    assert append.calls[1] == b"\x03\x00\x00\x00"
    assert writer.compressor is comp
    assert len(writer.scratch) == BLOCK_SIZE - 7


def test_emit_compression_record_terminal_clears_type():
    append = RecordingAppend(fail_on=0)
    writer = make_writer(append=append, compression_type=3)
    out = emit_compression_record(writer, 4, lambda size: FakeCompressor([]))
    assert out.terminal
    assert writer.compression_type == 0
    assert writer.compressor is None


def test_emit_compression_record_completion_replaces_result():
    append = RecordingAppend()
    sentinel = ResultRecord(0, 0, None)
    complete = FakeComplete()
    complete.calls = []
    writer = make_writer(append=append, complete=complete,
                         compression_type=2, finalize_flag=False)
    writer.complete = lambda w, aux: (complete.calls.append(aux), sentinel)[1]
    out = emit_compression_record(writer, 4, lambda size: FakeCompressor([]))
    assert out is sentinel and complete.calls == [4]


def test_packet_records_and_excerpts_exist():
    packet = os.path.join(ROOT, "research", "work-items", "RE-001-wal-writer-94")
    with open(os.path.join(packet, "records.json")) as handle:
        records = json.load(handle)
    assert records["task"] == "RE-001"
    assert records["target"]["sha256"].startswith("3b7179cd")
    for name in ("window-5163730.txt", "window-5163550.txt",
                 "window-5163ba0.txt"):
        assert os.path.getsize(os.path.join(packet, name)) > 1000


if __name__ == "__main__":
    tests = [(name, fn) for name, fn in sorted(globals().items())
             if name.startswith("test_") and callable(fn)]
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print("PASS", name)
        except Exception as exc:  # noqa: BLE001 - report and continue
            failed += 1
            print("FAIL", name, ":", exc)
    print(f"{len(tests) - failed}/{len(tests)} tests passed")
    raise SystemExit(1 if failed else 0)
