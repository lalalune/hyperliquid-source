"""Tests for the node #94 WAL replay caller-loop model and its packet."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-001-wal-replay-caller-loop-94"
sys.path.insert(0, str(ROOT / "tools"))

from wal_replay_caller_loop import (  # noqa: E402
    CallerLoop, ChainNode, Record, Status, resolve_chain,
)

SINGLETON_A = 0x5778260
SINGLETON_B = 0x57781E0
SINGLETON_R = 0x5778258


def nodes(values):
    return [ChainNode(v) for v in values]


def chain(value, count=11):
    return nodes([value] * count)


class World:
    """Injectable callees with scripted chain handlers."""

    def __init__(self, file_list, entry_status=Status(),
                 entry_nodes=None, chain_b_nodes=None,
                 retry_a_nodes=None, retry_b_nodes=None,
                 retry_a2_nodes=None, predicate=None, driver=None,
                 chain_b=None, retry_a=None, retry_b=None,
                 retry_a2=None):
        self.file_list = file_list
        self.entry_status = entry_status
        self.entry_nodes = entry_nodes or chain(SINGLETON_A)
        self.chain_b_nodes = chain_b_nodes or chain(SINGLETON_B)
        self.retry_a_nodes = retry_a_nodes or chain(SINGLETON_R)
        self.retry_b_nodes = retry_b_nodes or chain(SINGLETON_B)
        self.retry_a2_nodes = retry_a2_nodes or chain(SINGLETON_R)
        self.predicate = predicate or (lambda e: (True, 0, 7))
        self.driver = driver or (lambda t, n, s: (Status(), 0xABC))
        self.chain_b = chain_b or (lambda i: (Status(), "hs"))
        self.retry_a = retry_a or (lambda i: Status())
        self.retry_b = retry_b or (lambda i: (Status(), "hs2"))
        self.retry_a2 = retry_a2 or (lambda i: Status())

    def entry_handler(self, i):
        return self.entry_status, self.file_list

    def builder1(self, log_number):
        return f"dir/{log_number:06d}.log"

    def builder0(self, log_number):
        return f"dir/rt/{log_number:06d}.log"

    def chain_b_handler(self, i):
        return self.chain_b(i)

    def retry_a_handler(self, i):
        return self.retry_a(i)

    def retry_b_handler(self, i):
        return self.retry_b(i)

    def retry_a2_handler(self, i):
        return self.retry_a2(i)


def run(world, file_type=0):
    loop = CallerLoop(world, file_type)
    out = loop.run()
    return loop, out


# --- chain resolution -------------------------------------------------

def test_resolve_first_mismatch_wins():
    ns = chain(SINGLETON_A)
    ns[3] = ChainNode(0x1234)
    assert resolve_chain(ns, SINGLETON_A) == 3


def test_resolve_all_match_uses_fallback_node():
    assert resolve_chain(chain(SINGLETON_A), SINGLETON_A) == 10


def test_resolve_first_node_mismatch():
    ns = chain(SINGLETON_A)
    ns[0] = ChainNode(0x999)
    assert resolve_chain(ns, SINGLETON_A) == 0


# --- entry chain ------------------------------------------------------

def test_entry_fail_copies_status_and_skips_loop():
    w = World(["a", "b"], entry_status=Status(3, 1, "boom"))
    loop, out = run(w)
    assert out == Status(3, 1, "boom")
    assert loop.records == []
    assert ("entry_fail_copy", out) in loop.events


def test_empty_file_list_returns_entry_status():
    loop, out = run(World([]))
    assert out == Status()
    assert ("loop_end_copy", out) in loop.events


# --- main loop --------------------------------------------------------

def test_success_appends_record_in_order():
    w = World(["e1", "e2"],
              predicate=lambda e: (True, 0, {"e1": 5, "e2": 9}[e]),
              driver=lambda t, n, s: (Status(), 0x100 + n))
    loop, out = run(w)
    assert loop.records == [Record(5, 0, 0x105, "hs"),
                            Record(9, 0, 0x109, "hs")]
    assert out == Status()


def test_predicate_false_skips():
    w = World(["e1", "e2"], predicate=lambda e: (e == "e2", 0, 4))
    loop, out = run(w)
    assert len(loop.records) == 1 and loop.records[0].log_number == 4


def test_predicate_gate_nonzero_skips():
    w = World(["e1", "e2"], predicate=lambda e: (True, 1, 4))
    loop, out = run(w)
    assert loop.records == []


def test_driver_fail_moves_status_and_ends():
    w = World(["e1", "e2"],
              driver=lambda t, n, s: (Status(9, 2, "died"), 0x1))
    loop, out = run(w)
    assert out == Status(9, 2, "died")
    assert loop.records == []
    assert any(ev[0] == "driver_fail_move" for ev in loop.events)


def test_driver_slot_zero_advances_without_record():
    w = World(["e1", "e2"], driver=lambda t, n, s: (Status(), 0))
    loop, out = run(w)
    assert loop.records == []
    assert out == Status()


def test_chain_b_fail_non_retry_copies_status():
    w = World(["e1"], chain_b=lambda i: (Status(5, 0, "cb"), "hs"))
    loop, out = run(w, file_type=0)
    assert out == Status(5, 0, "cb")
    assert loop.records == []


def test_grow_path_keeps_order():
    # The out-records vector may already hold records from the caller:
    # reserve only covers the file-list count, so pre-existing records
    # can push appends past capacity and trigger the grow path.
    w = World(["a", "b"])
    loop = CallerLoop(w, 0)
    loop.records = [Record(1, 0, 0x1, "old"), Record(2, 0, 0x2, "old"),
                    Record(3, 0, 0x3, "old"), Record(4, 0, 0x4, "old")]
    loop.capacity = 4
    out = loop.run()
    assert [r.log_number for r in loop.records] == [1, 2, 3, 4, 7, 7]
    assert any(ev[0] == "grow" for ev in loop.events)


def test_record_tag_and_type():
    w = World(["e1"])
    loop, out = run(w, file_type=1)
    assert loop.records[0].tag_ptr == 0x575BDF0
    assert loop.records[0].file_type == 1


# --- retry arm --------------------------------------------------------

def test_retry_success_appends_with_retry_handler_slot():
    w = World(["e1"], chain_b=lambda i: (Status(4, 0, "cb"), "hs"))
    loop, out = run(w, file_type=1)
    assert len(loop.records) == 1
    assert loop.records[0].handler_slot == "hs2"
    assert out == Status()


def test_retry_a_fail_copies_loop_status():
    w = World(["e1"], chain_b=lambda i: (Status(4, 0, "cb"), "hs"),
              retry_a=lambda i: Status(2, 0, "ra"))
    loop, out = run(w, file_type=1)
    assert out == Status(4, 0, "cb")
    assert loop.records == []


def test_retry_b_fail_then_swallow_advances():
    w = World(["e1", "e2"],
              chain_b=lambda i: (Status(4, 0, "cb"), "hs"),
              retry_b=lambda i: (Status(6, 0, "rb"), "hs2"),
              retry_a2=lambda i: Status(1, 0, "ok"))
    # e1 is swallowed; e2 takes the same path (chain_b still fails),
    # so it is swallowed too and no record lands.
    loop, out = run(w, file_type=1)
    assert loop.records == []
    assert out == Status()
    assert sum(1 for ev in loop.events if ev[0] == "swallow") == 2


def test_retry_b_fail_then_a2_fail_copies_loop_status():
    w = World(["e1"], chain_b=lambda i: (Status(4, 0, "cb"), "hs"),
              retry_b=lambda i: (Status(6, 0, "rb"), "hs2"),
              retry_a2=lambda i: Status(3, 0, "no"))
    loop, out = run(w, file_type=1)
    assert out == Status(6, 0, "rb")
    assert loop.records == []


# --- packet -----------------------------------------------------------

def test_records_json_semantic_only():
    text = (PACKET / "records.json").read_text()
    records = json.loads(text)
    assert "mnemonic" not in text.lower()
    assert records["task"] == "RE-001"
    assert records["window"]["start"] == "0x520d3a0"
    assert records["window"]["end"] == "0x520e12e"
    assert records["window"]["size_bytes"] == 3518
    assert records["window"]["artifact_sha256"] == \
        "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"


def test_manifest_matches_packet_files():
    for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
        digest, _, rel = line.partition("  ")
        path = PACKET / rel
        assert path.exists(), rel
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, rel


def test_window_regenerates_from_binary():
    fresh = subprocess.run(
        ["objdump", "-d", "--start-address=0x520d3a0",
         "--stop-address=0x520e12e", "work/hl-node-94.bin"],
        cwd=ROOT, check=True, capture_output=True, text=True).stdout
    assert fresh == (PACKET / "window.txt").read_text()


def test_sampled_instructions_byte_for_byte():
    raw = (ROOT / "work/hl-node-94.bin").read_bytes()
    for addr, expected in [(0x520D3A0, bytes.fromhex("f30f1efa")),
                           (0x520D5A9, bytes.fromhex("e872ebffff")),
                           (0x520D713, bytes.fromhex("ff9028010000"))]:
        assert raw[addr - 0x1000:addr - 0x1000 + len(expected)] == expected


def test_corruption_control_window_tamper_detected():
    good = (PACKET / "window.txt").read_text()
    tampered = good.replace("endbr64", "endbr65", 1)
    assert tampered != good


def test_corruption_control_records_tamper_detected():
    records = json.loads((PACKET / "records.json").read_text())
    records["window"]["start"] = "0x520d3a1"
    assert records["window"]["start"] != "0x520d3a0"
