"""Tests for node #115 chain-walk getters 0x5eee5d0/0x5eee660/0x5eee6f0
with head helper 0x5eee5b0.

Run under pytest when available, or directly: python3 tests/test_chain_walk_getters_115.py
(pytest is not installed on this VM, so the __main__ runner below is the honest path.)
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from chain_walk_getters_115 import SENTINELS, head_value, run_getter

SENT = 0x5D2EFC0  # the slot-0x70 sentinel value; other slots use their own


def node(slot_id, value, nxt=None):
    return {"slot_id": slot_id, "handler": lambda n, v=value: v, "next": nxt}


def chain(slots, values):
    head = None
    for slot_id, value in reversed(list(zip(slots, values))):
        head = node(slot_id, value, head)
    return head


def outer(head):
    return {"member788": {"head6b0": head}}


def run(head, slot_offset=0x70):
    out = ["untouched"]
    ret = run_getter(outer(head), slot_offset, out)
    return ret, out[0]


def test_head_projection():
    assert head_value(outer(None)) is None
    n = node(1, "x")
    assert head_value(outer(n)) is n


def test_null_head_returns_zero_without_writing():
    assert run(None) == (0, "untouched")


def test_head_slot_differs_from_sentinel_invoked_immediately():
    assert run(node(0x1111, "first")) == (1, "first")


def test_differ_at_second_node():
    head = chain([SENT, 0x2222], ["default", "second"])
    assert run(head) == (1, "second")


def test_differ_at_third_node():
    head = chain([SENT, SENT, 0x3333], ["a", "b", "third"])
    assert run(head) == (1, "third")


def test_differ_at_fourth_node():
    head = chain([SENT, SENT, SENT, 0x4444], ["a", "b", "c", "fourth"])
    assert run(head) == (1, "fourth")


def test_all_equal_falls_through_to_fifth_node():
    head = chain([SENT, SENT, SENT, SENT, 0x5555], ["a", "b", "c", "d", "fifth"])
    assert run(head) == (1, "fifth")


def test_fifth_node_called_even_when_it_matches():
    head = chain([SENT, SENT, SENT, SENT, SENT], ["a", "b", "c", "d", "fifth"])
    assert run(head) == (1, "fifth")


def test_handler_receives_the_invoked_node():
    seen = []
    n1 = {"slot_id": SENT, "handler": lambda n: seen.append("n1"), "next": None}
    n2 = {"slot_id": 0x7777, "handler": lambda n: seen.append("n2"), "next": None}
    n1["next"] = n2
    assert run(n1) == (1, None)
    assert seen == ["n2"]


def test_other_slots_use_their_own_sentinels():
    assert SENTINELS == {0x70: 0x5D2EFC0, 0x78: 0x5D2EF10, 0x98: 0x5D2F070}
    # Slot 0x78: head slot equal to the 0x78 sentinel, second differs.
    head = chain([0x5D2EF10, 0x8888], ["a", "second78"])
    assert run(head, 0x78) == (1, "second78")
    # Slot 0x98: head slot differs from the 0x98 sentinel at once.
    assert run(node(0x9999, "first98"), 0x98) == (1, "first98")


def test_chain_exhaustion_refuses():
    head = chain([SENT, SENT], ["a", "b"])
    try:
        run(head)
    except ValueError:
        pass
    else:
        raise AssertionError("exhausted chain should raise ValueError")


def test_missing_fields_raise():
    try:
        head_value({})
    except KeyError:
        pass
    else:
        raise AssertionError("head_value should raise KeyError")
    try:
        run_getter({}, 0x70, ["x"])
    except KeyError:
        pass
    else:
        raise AssertionError("run_getter should raise KeyError")


def test_packet_files_exist():
    root = Path(__file__).resolve().parents[1]
    packet = root / "research" / "work-items" / "RE-001-chain-walk-getters-115"
    for name in ("records.json", "README.md", "MANIFEST.sha256", "frames.txt",
                 "relocations.txt", "verify.py", "export_excerpts.py", "census.py",
                 "head_0x5eee5b0.objdump", "getter70_0x5eee5d0.objdump",
                 "getter78_0x5eee660.objdump", "getter98_0x5eee6f0.objdump"):
        assert (packet / name).is_file(), f"missing packet file {name}"
    assert (root / "tools" / "chain_walk_getters_115.py").is_file()


def main():
    tests = [(k, v) for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    for name, fn in tests:
        fn()
        print(f"PASS {name}")
    print(f"{len(tests)} tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
