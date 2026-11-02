"""Tests for the node #94 WAL replay caller model and its packet.

Plain assert functions so they run without pytest installed:
  python3 tests/test_wal_replay_caller.py
They are also collectable by pytest when it is available.
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-001-wal-replay-caller-94"
sys.path.insert(0, str(ROOT / "tools"))

from wal_replay_caller import (  # noqa: E402
    Ctx, Elem, Obj, Slot, Status, replay_caller,
)

BIN_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"


class CByte:
    def __init__(self, byte):
        self.byte = byte


def scripted(first=None, second=None):
    """Orchestrator/helper pair returning the given statuses."""
    first = first if first is not None else Status()
    second = second if second is not None else Status()

    def orchestrator(status_out, ctx, vec, events):
        events.append(("orchestrator",))
        status_out.code, status_out.flags, status_out.message = (
            first.code, first.flags, first.message)

    def helper(status_out, ctx, vec, a, events):
        events.append(("helper", a))
        status_out.code, status_out.flags, status_out.message = (
            second.code, second.flags, second.message)

    return orchestrator, helper


def recording_constructor(name="new", finish_status=None):
    seen = {}

    def constructor(args, events):
        events.append(("constructor",))
        seen.update(args)
        return Obj(name, finish_status)

    constructor.seen = seen
    return constructor


def run(first=None, second=None, flag=0, old=None, finish=None,
        out=None):
    out = out if out is not None else Status()
    ctx = Ctx(flag=flag, field08="ctx08", field158="ctx158")
    slot = Slot(old)
    events = []
    orchestrator, helper = scripted(first, second)
    constructor = recording_constructor(finish_status=finish)
    result = replay_caller(out, ctx, "A", slot, CByte(0x41), "D",
                           orchestrator, helper, constructor, events)
    return result, slot, events, constructor.seen


def test_gate_nonzero_returns_code3_without_calls():
    out, slot, events, _ = run(flag=1)
    assert out.code == 3 and out.flags == 0 and out.message is None
    assert events == []
    assert slot.obj is None


def test_gate_does_not_free_preexisting_out_message():
    prior = Status(9, 9, "old-msg")
    out, _, events, _ = run(flag=7, out=prior)
    assert out.code == 3 and out.message is None
    assert ("free_msg", "old-msg") not in events


def test_nonzero_orchestrator_status_copies_and_teardowns():
    out, slot, events, _ = run(first=Status(0x201, 5, "msg"))
    assert (out.code, out.flags, out.message) == (0x201, 5, "msg")
    assert events == [("orchestrator",), ("free_vec_struct",)]
    assert slot.obj is None


def test_low_byte_gate_only_orchestrator():
    # Code 0x100 has byte0 == 0, so it proceeds to the helper.
    out, _, events, _ = run(first=Status(0x100, 0, None),
                            second=Status(0x77, 0, "h"))
    assert ("helper", "A") in events
    assert (out.code, out.message) == (0x77, "h")


def test_helper_status_moves_and_copies():
    out, _, events, _ = run(first=Status(0, 0, "first-msg"),
                            second=Status(2, 3, "second-msg"))
    assert (out.code, out.flags, out.message) == (2, 3, "second-msg")
    # The move frees the old first message; the copy does not free.
    assert ("free_msg", "first-msg") in events
    assert events.count(("free_vec_struct",)) == 1


def test_full_path_constructor_args_and_replacement():
    old = Obj("old")
    finish = Status(0, 0, "done")
    out, slot, events, seen = run(old=old, finish=finish)
    assert seen["a"] == "A"
    assert seen["c_byte"] == 0x41
    assert seen["ctx08"] == "ctx08"
    assert seen["ctx158"] == "ctx158"
    assert seen["d"] == "D"
    assert seen["flag"] == 0
    assert seen["slot_ptr"].content is seen["heap_vec"]
    assert slot.obj is not None and slot.obj.name == "new"
    assert ("destroy_obj", "old") in events
    assert ("finish_obj", "new") in events
    assert (out.code, out.message) == (0, "done")


def test_full_path_old_null_skips_destroy():
    _, _, events, _ = run(old=None)
    assert ("destroy_obj",) not in [e[:1] for e in events]
    assert not any(e[0] == "destroy_obj" for e in events)


def test_full_path_frees_status1_message_at_end():
    out, _, events, _ = run(first=Status(0, 0, "first-msg"),
                            second=Status(0, 0, None))
    assert ("free_msg", "first-msg") in events
    # The message is freed after the finish call, not transferred.
    assert out.message != "first-msg"


def test_teardown_skips_null_elements_and_orders():
    # Drive the teardown through the nonzero-orchestrator path with a
    # vector the orchestrator fills.
    def orchestrator(status_out, ctx, vec, events):
        vec.items = [Elem("e1"), None, Elem("e2")]
        vec.has_array = True
        status_out.code = 4

    def helper(status_out, ctx, vec, a, events):
        raise AssertionError("helper must not run")

    out = Status()
    events = []
    replay_caller(out, Ctx(), "A", Slot(), CByte(0), "D",
                  orchestrator, helper,
                  recording_constructor(), events)
    assert out.code == 4
    assert events == [("destroy_elem", "e1"), ("destroy_elem", "e2"),
                      ("free_array",), ("free_vec_struct",)]


def test_packet_checker_passes():
    proc = subprocess.run(
        [sys.executable, str(PACKET / "verify.py")],
        cwd=ROOT, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "ALL CHECKS PASSED" in proc.stdout


def test_sampled_instructions_byte_for_byte():
    raw = (ROOT / "work/hl-node-94.bin").read_bytes()
    assert hashlib.sha256(raw).hexdigest() == BIN_SHA256
    samples = [
        (0x520E830, bytes.fromhex("f30f1efa")),  # endbr64, window entry
        (0x520E8DC, bytes.fromhex("e8cff8ffff")),  # call orchestrator
        (0x520EA49, bytes.fromhex("e8725a0000")),  # call constructor
    ]
    for addr, expected in samples:
        assert raw[addr - 0x1000:addr - 0x1000 + len(expected)] == expected


def test_corruption_control_manifest():
    manifest = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    names = [line.split("  ", 1)[1] for line in manifest]
    target = PACKET / "records.json"
    original = target.read_bytes()
    try:
        target.write_bytes(original + b" ")
        proc = subprocess.run(
            [sys.executable, str(PACKET / "verify.py")],
            cwd=ROOT, capture_output=True, text=True)
        assert proc.returncode != 0
    finally:
        target.write_bytes(original)
    assert "records.json" in names


def test_corruption_control_records():
    records = json.loads((PACKET / "records.json").read_text())
    assert records["task"] == "RE-001"
    assert records["window"]["start"] == "0x520e830"
    assert records["window"]["end"] == "0x520eb1c"
    assert records["window"]["artifact_sha256"] == BIN_SHA256
    assert records["caller_census"]["direct_callers"][0]["site"] == "0x4fa88cf"


TESTS = [v for k, v in sorted(globals().items())
         if k.startswith("test_") and callable(v)]


if __name__ == "__main__":
    for test in TESTS:
        test()
        print(f"PASS: {test.__name__}")
    print(f"{len(TESTS)} tests passed")
