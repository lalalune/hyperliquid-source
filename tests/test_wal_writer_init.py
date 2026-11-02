"""Tests for tools/wal_writer_init.py (node #94 WAL writer initializer).

Runs under pytest and under plain python3 (no pytest import needed).
Packet files are located relative to this file, so the tests pass from
any working directory.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tools.wal_writer_init import (OBJECT_SIZE, Writer, construct_replace_site,
                                   construct_setup_site, construct_zero_site,
                                   crc32c, initialize, type_crc_table)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research", "work-items", "RE-001-wal-writer-init-94")


def test_crc_check_value():
    assert crc32c(b"123456789") == 0xE3069283


def test_crc_empty_and_single_bytes():
    assert crc32c(b"") == 0
    assert crc32c(bytes([0])) == 0x527D5351
    assert crc32c(bytes([9])) == 0x2ACF889D


def test_type_crc_table_matches_packet():
    with open(os.path.join(PACKET, "records.json")) as handle:
        records = json.load(handle)
    table = type_crc_table()
    assert len(table) == 10
    assert {str(k): "0x%08x" % v for k, v in table.items()} == records["type_crc_table"]
    # Every entry differs from its neighbours: the loop really varies
    # with the type byte instead of repeating one value.
    assert len(set(table.values())) == 10


def test_initialize_moves_and_zeroes():
    slot = [0xDEADBEEF12345678]
    writer = initialize(slot, 0x1122334455667788, 1, 1, 7)
    assert slot[0] == 0
    assert writer.moved_qword == 0xDEADBEEF12345678
    assert writer.block_offset == 0
    assert writer.log_number == 0x1122334455667788
    assert writer.recycle_flag == 1
    assert writer.finalize_flag == 1
    assert writer.compression_type == 7
    assert writer.compressor is None
    assert writer.scratch is None
    assert writer.type_crc == type_crc_table()
    fields = writer.as_fields()
    assert fields[0x1C] == 0x527D5351  # type 0
    assert fields[0x1C + 4 * 9] == 0x2ACF889D  # type 9
    assert fields[0x44] == 1
    assert fields[0x45] == 7


def test_initialize_masks_flag_bytes():
    writer = initialize([0], 0, 0x1FF, 0x100, 0x1FE)
    assert writer.recycle_flag == 0xFF
    assert writer.finalize_flag == 0
    assert writer.compression_type == 0xFE


def test_zero_site():
    writer = construct_zero_site(0xABC)
    assert writer.moved_qword == 0xABC
    assert writer.log_number == 0
    assert writer.recycle_flag == 0
    assert writer.finalize_flag == 0
    assert writer.compression_type == 0
    assert writer.compressor is None and writer.scratch is None


def test_setup_site_calls_setup_with_new_writer():
    seen = []

    def setup(writer):
        seen.append(writer)
        return "setup-result"

    writer, result = construct_setup_site(0x55, 42, 1, 0, 3, setup)
    assert result == "setup-result"
    assert seen == [writer]
    assert writer.log_number == 42
    assert writer.compression_type == 3


def test_replace_site_with_old_writer():
    events = []

    def release(writer):
        events.append(("release", writer))

    def free(writer, size):
        events.append(("free", writer, size))

    old = Writer()
    slot = [old]
    writer = construct_replace_site(slot, 0x77, release, free)
    assert slot[0] is writer
    assert events == [("release", old), ("free", old, OBJECT_SIZE)]
    assert OBJECT_SIZE == 0x58


def test_replace_site_without_old_writer():
    events = []

    def release(writer):
        events.append(("release", writer))

    def free(writer, size):
        events.append(("free", writer, size))

    slot = [None]
    writer = construct_replace_site(slot, 0x77, release, free)
    assert slot[0] is writer
    assert events == []


def test_packet_excerpts_present():
    for name in ("window-51645d0.txt", "callsite-50bbf5a.txt",
                 "callsite-50be17b.txt", "callsite-51f7c20.txt",
                 "frames.txt", "relocations.txt", "records.json",
                 "verify.py", "export_excerpts.py", "census.py"):
        path = os.path.join(PACKET, name)
        assert os.path.isfile(path), name
        assert os.path.getsize(path) > 0, name


def test_window_excerpt_is_whole_function():
    with open(os.path.join(PACKET, "window-51645d0.txt")) as handle:
        text = handle.read()
    assert "51645d0:" in text
    assert "endbr64" in text
    assert "516462e:" in text  # CRC import call
    assert "5164659:" in text  # ret
    # The cleanup stub follows the ret inside the same FDE.
    assert "516465f:" in text


def test_callsite_excerpts_pin_the_protocol():
    with open(os.path.join(PACKET, "callsite-50bbf5a.txt")) as handle:
        setup_site = handle.read()
    assert "50bbf5a:" in setup_site and "51645d0" in setup_site
    assert "50bbf73:" in setup_site and "5163ba0" in setup_site
    with open(os.path.join(PACKET, "callsite-51f7c20.txt")) as handle:
        replace_site = handle.read()
    assert "51f7c20:" in replace_site and "51645d0" in replace_site
    assert "51f7c42:" in replace_site and "51641d0" in replace_site
    assert "51f7c47:" in replace_site  # sized delete size 0x58


def test_corruption_control_table_tamper_detected():
    table = type_crc_table()
    table[5] ^= 0xFFFFFFFF
    with open(os.path.join(PACKET, "records.json")) as handle:
        records = json.load(handle)
    assert {str(k): "0x%08x" % v for k, v in table.items()} != records["type_crc_table"]


def _run():
    tests = [(name, fn) for name, fn in sorted(list(globals().items()))
             if name.startswith("test_") and callable(fn)]
    failed = []
    for name, fn in tests:
        try:
            fn()
            print("PASS", name)
        except Exception as exc:  # noqa: BLE001 - report and continue
            failed.append(name)
            print("FAIL", name, exc)
    print("%d tests, %d failed" % (len(tests), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_run())
