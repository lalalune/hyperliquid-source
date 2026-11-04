"""Tests for the node #115 sentinel chain dispatch (tools/sentinel_chain_dispatch_115.py).

Run with pytest, or directly: python3 tests/test_sentinel_chain_dispatch_115.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from sentinel_chain_dispatch_115 import SENTINELS, run_sentinel

SENT70, SENT78, SENT98 = SENTINELS[0x70], SENTINELS[0x78], SENTINELS[0x98]


def node(slot_id, result=None, nxt=None):
    return {"slot_id": slot_id, "handler": lambda n, r=result: r, "next": nxt}


def chain(slot_ids, results=None):
    """Build a receiver followed by nodes with the given slot ids."""
    results = results or [f"r{i}" for i in range(len(slot_ids))]
    head = None
    for slot_id, result in reversed(list(zip(slot_ids, results))):
        head = node(slot_id, result, head)
    return node(0, "receiver-never-dispatched", head)


def test_first_node_differs():
    recv = chain([0x1111])
    assert run_sentinel(recv, 0x70) == "r0"


def test_differ_at_each_level():
    for level in range(2, 9):
        slots = [SENT70] * (level - 1) + [0x2222]
        recv = chain(slots)
        assert run_sentinel(recv, 0x70) == f"r{level - 1}"


def test_ninth_node_fallthrough_matching_and_differing():
    recv = chain([SENT70] * 8 + [SENT70])
    assert run_sentinel(recv, 0x70) == "r8"
    recv = chain([SENT70] * 8 + [0x3333])
    assert run_sentinel(recv, 0x70) == "r8"


def test_receiver_slot_never_read():
    recv = chain([SENT78, 0x5555])
    recv["slot_id"] = 0x9999  # receiver slot is irrelevant to the walk
    assert run_sentinel(recv, 0x78) == "r1"


def test_all_three_slots():
    for slot, sentinel in ((0x70, SENT70), (0x78, SENT78), (0x98, SENT98)):
        recv = chain([sentinel, 0x4444])
        assert run_sentinel(recv, slot) == "r1"


def test_chain_exhaustion_refused():
    recv = chain([SENT70, SENT70])
    try:
        run_sentinel(recv, 0x70)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError on an exhausted chain")


def test_missing_field_guards():
    try:
        run_sentinel({}, 0x70)
    except KeyError:
        pass
    else:
        raise AssertionError("expected KeyError for a missing next field")


def test_packet_checks():
    packet = Path(__file__).resolve().parents[1] / "research" / "work-items" / "RE-001-sentinel-chain-dispatch-115"
    assert (packet / "records.json").exists()
    assert (packet / "MANIFEST.sha256").exists()
    for name in ("sentinel70_0x5d2efc0.objdump", "sentinel78_0x5d2ef10.objdump",
                 "sentinel98_0x5d2f070.objdump"):
        assert (packet / name).exists()


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for test in tests:
        test()
    print(f"{len(tests)} tests passed")
