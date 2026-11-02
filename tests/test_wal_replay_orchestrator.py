"""Tests for the node #94 WAL replay orchestrator model and its packet.

Plain assert functions so they run without pytest installed:
  python3 tests/test_wal_replay_orchestrator.py
They are also collectable by pytest when it is available.
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research/work-items/RE-001-wal-replay-orchestrator-94"
sys.path.insert(0, str(ROOT / "tools"))

from wal_replay_orchestrator import (  # noqa: E402
    KNOWN_10, KNOWN_18, KNOWN_E8, Callbacks, ChainObj, Ctx, Elem,
    HandlerResult, Link, Status, Vec, orchestrate,
)

BIN_SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"


def chain_of(hooks):
    """Build a chain from a hook list; hooks[0] is link 1."""
    head = None
    for hook in reversed(hooks):
        head = Link(ChainObj(hook), head)
    return head


def matching_chain(handler, count=11):
    """A chain whose first ten hooks match, so link 11's handler runs."""
    return chain_of([KNOWN_E8] * 10 + [handler])


class World(Callbacks):
    """Scripted callees: replay statuses and appended records per call."""

    def __init__(self, first=None, second=None, first_records=(),
                 second_records=()):
        super().__init__()
        self.first = first or Status()
        self.second = second or Status()
        self.first_records = list(first_records)
        self.second_records = list(second_records)

    def caller_loop(self, status_out, ctx, arg3, records, file_type):
        self.events.append(("caller_loop", file_type, arg3))
        if file_type == 1:
            status_out.code, status_out.flags, status_out.message = (
                self.first.code, self.first.flags, self.first.message)
            records.items.extend(self.first_records)
        else:
            status_out.code, status_out.flags, status_out.message = (
                self.second.code, self.second.flags, self.second.message)
            records.items.extend(self.second_records)


def run(world, ctx, pending):
    out = Status()
    orchestrate(out, ctx, pending, world)
    return out


def test_early_return_on_nonzero_out_byte():
    rec = Elem(9)
    ctx = Ctx(chain_head=matching_chain(lambda g: HandlerResult(1)))
    world = World(first=Status(5, 0, "boom"), first_records=[rec])
    out = run(world, ctx, Vec())
    assert out.code == 5
    assert ("destroy", rec) in world.events
    assert not any(e[0] == "getter" for e in world.events)
    assert not any(e[0] == "log" for e in world.events)


def test_low_byte_gate_only():
    # Code 0x100 has low byte 0, so the gate passes.
    ctx = Ctx(chain_head=matching_chain(lambda g: HandlerResult(1)))
    world = World(first=Status(0x100, 0, None))
    out = run(world, ctx, Vec())
    assert out.code == 0x100
    assert any(e[0] == "getter" for e in world.events)


def test_pending_drain_skips_nulls_and_resets_end():
    e1, e2 = Elem(1), Elem(2)
    ctx = Ctx(chain_head=matching_chain(lambda g: HandlerResult(1)))
    world = World()
    pending = Vec([e1, None, e2], capacity=3)
    run(world, ctx, pending)
    destroys = [e for e in world.events if e[0] == "destroy"]
    assert destroys == [("destroy", e1), ("destroy", e2)]
    assert pending.items == []


def test_chain_all_match_invokes_link_11():
    seen = []
    handler = lambda g: seen.append(g) or HandlerResult(1)
    ctx = Ctx(chain_head=matching_chain(handler), f148="ctx148")
    world = World()
    run(world, ctx, Vec())
    assert seen == [""]  # getter default returns ""


def test_chain_first_mismatch_wins():
    seen = []
    bad = lambda g: seen.append("bad") or HandlerResult(1)
    good = lambda g: seen.append("good") or HandlerResult(1)
    hooks = [KNOWN_E8, KNOWN_E8, bad] + [KNOWN_E8] * 7 + [good]
    ctx = Ctx(chain_head=chain_of(hooks))
    run(World(), ctx, Vec())
    assert seen == ["bad"]


def test_chain_first_link_mismatch():
    seen = []
    bad = lambda g: seen.append("bad") or HandlerResult(1)
    hooks = [bad] + [KNOWN_E8] * 10
    ctx = Ctx(chain_head=chain_of(hooks))
    run(World(), ctx, Vec())
    assert seen == ["bad"]


def test_predicate_code_1_proceeds_without_second_replay():
    ctx = Ctx(chain_head=matching_chain(lambda g: HandlerResult(1)))
    world = World(first=Status(0, 0, "first"))
    out = run(world, ctx, Vec())
    assert out.message == "first"
    assert [e for e in world.events if e[0] == "caller_loop"] == [
        ("caller_loop", 1, None)]


def test_predicate_code_0_second_replay_and_move_frees_old():
    ctx = Ctx(chain_head=matching_chain(lambda g: HandlerResult(0, "det")),
              f148="ctx148")
    world = World(first=Status(0, 0, "first"),
                  second=Status(0, 0, "second"))
    out = run(world, ctx, Vec())
    assert out.message == "second"
    assert ("free_msg", "first") in world.events
    assert ("free_detail", "det") in world.events
    calls = [e for e in world.events if e[0] == "caller_loop"]
    assert calls[1][1] == 0  # second call has file_type 0


def test_predicate_code_0_second_replay_nonzero_aborts():
    rec = Elem(4)
    ctx = Ctx(chain_head=matching_chain(lambda g: HandlerResult(0, "det")))
    world = World(first=Status(0, 0, None),
                  second=Status(3, 0, "fail"), first_records=[rec])
    out = run(world, ctx, Vec())
    assert out.code == 3
    assert ("free_detail", "det") in world.events
    assert ("destroy", rec) in world.events
    assert not any(e[0] == "log" for e in world.events)


def test_predicate_other_code_aborts():
    rec = Elem(4)
    ctx = Ctx(chain_head=matching_chain(lambda g: HandlerResult(7, "det")))
    world = World(first_records=[rec])
    out = run(world, ctx, Vec())
    assert out.code == 0
    assert ("free_detail", "det") in world.events
    assert ("destroy", rec) in world.events


def test_empty_pending_threshold_zero_no_latest_log():
    rec = Elem(0)
    ctx = Ctx(chain_head=matching_chain(lambda g: HandlerResult(1)))
    world = World(first_records=[rec])
    run(world, ctx, Vec())
    assert not any(e[0] == "log" and e[1] == 1 for e in world.events)
    assert any(e[0] == "log" and e[1] == 2 for e in world.events)


def test_threshold_from_last_pending_and_latest_log():
    # Predicate code 0 forces the second replay, which refills pending.
    ctx2 = Ctx(chain_head=matching_chain(lambda g: HandlerResult(0)),
               f148="ctx148")
    world2 = World(second_records=[Elem(10), Elem(42)])
    pending = Vec([Elem(10), Elem(42)], capacity=2)
    run(world2, ctx2, pending)
    logs = [e for e in world2.events if e[0] == "log" and e[1] == 1]
    assert logs and logs[0][3] == 42


def test_threshold_via_custom_hook18():
    last = Elem(5, hook18=lambda el: 99)
    ctx = Ctx(chain_head=matching_chain(lambda g: HandlerResult(0)))
    world = World(second_records=[last])
    run(world, ctx, Vec())
    logs = [e for e in world.events if e[0] == "log" and e[1] == 1]
    assert logs and logs[0][3] == 99


def test_partition_boundary_equal_processes():
    rec = Elem(42)
    ctx = Ctx(chain_head=matching_chain(lambda g: HandlerResult(0)))
    world = World(first_records=[rec], second_records=[Elem(42)])
    run(world, ctx, Vec())
    assert any(e[0] == "parse_zero" for e in world.events)
    assert any(e[0] == "log" and e[1] == 2 for e in world.events)


def test_partition_parse_variant_selection():
    hi = Elem(50, field10=3)
    lo = Elem(50, field10=0)
    ctx = Ctx(chain_head=matching_chain(lambda g: HandlerResult(0)))
    world = World(first_records=[hi, lo], second_records=[Elem(1)])
    run(world, ctx, Vec())
    assert ("parse_nonzero", 50) in world.events
    assert ("parse_zero", 50) in world.events


def test_partition_custom_hook10_called():
    seen = []
    rec = Elem(50, hook10=lambda el, cell: seen.append(el) or cell.__setitem__(0, "custom"))
    ctx = Ctx(chain_head=matching_chain(lambda g: HandlerResult(0)))
    world = World(first_records=[rec], second_records=[Elem(1)])
    run(world, ctx, Vec())
    assert seen == [rec]
    assert any(e[0] == "log" and e[3] == "custom"
               for e in world.events if e[0] == "log" and e[1] == 2)


def test_partition_move_inline_and_epilogue_skips_moved():
    rec = Elem(1)
    ctx = Ctx(chain_head=matching_chain(lambda g: HandlerResult(0)))
    world = World(first_records=[rec], second_records=[Elem(100)])
    pending = Vec()
    run(world, ctx, pending)
    assert pending.items[-1] == rec and len(pending.items) == 2
    assert not any(e[0] == "grow" for e in world.events)
    # Moved slot is null, so the epilogue must not destroy it again.
    assert world.events.count(("destroy", rec)) == 0


class NoReserveWorld(World):
    """Reserve that records but does not grow capacity, so the grow
    arm (unreachable when reserve covers the count) can be exercised."""

    def reserve(self, vec, count):
        self.events.append(("reserve", count))


def test_partition_move_grow_when_full():
    rec = Elem(1)
    ctx = Ctx(chain_head=matching_chain(lambda g: HandlerResult(0)))
    world = NoReserveWorld(first_records=[rec], second_records=[Elem(100)])
    pending = Vec([Elem(100)], capacity=1)
    run(world, ctx, pending)
    assert any(e[0] == "grow" for e in world.events)
    assert rec in pending.items and len(pending.items) == 2


def test_epilogue_destroys_processed_in_order():
    a, b = Elem(50), Elem(60)
    ctx = Ctx(chain_head=matching_chain(lambda g: HandlerResult(0)))
    world = World(first_records=[a, b], second_records=[Elem(1)])
    run(world, ctx, Vec())
    destroys = [e[1] for e in world.events if e[0] == "destroy"]
    assert destroys == [a, b]


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
        (0x520E1B0, bytes.fromhex("f30f1efa")),
        (0x520E22C, bytes.fromhex("e86ff1ffff")),
        (0x520E5A7, bytes.fromhex("e884040200")),
    ]
    for addr, expected in samples:
        assert raw[addr - 0x1000:addr - 0x1000 + len(expected)] == expected


def test_corruption_control_manifest():
    # Control 1: flipping one byte in an excerpt breaks its manifest hash.
    manifest = {}
    for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
        digest, name = line.split("  ", 1)
        manifest[name] = digest
    window = (PACKET / "window.txt").read_bytes()
    tampered = window[:100] + bytes([window[100] ^ 0xFF]) + window[101:]
    assert hashlib.sha256(tampered).hexdigest() != manifest["window.txt"]


def test_corruption_control_records():
    # Control 2: changing the bound window start breaks the record check.
    records = json.loads((PACKET / "records.json").read_text())
    assert records["window"]["start"] == "0x520e1b0"
    mutated = json.loads(json.dumps(records))
    mutated["window"]["start"] = "0x520e1b4"
    assert mutated["window"]["start"] != "0x520e1b0"
    assert mutated != records


def test_known_18_body_is_trivial_field_load():
    text = (PACKET / "known-18.txt").read_text()
    assert "mov    0x8(%rdi),%rax" in text
    assert "ret" in text


if __name__ == "__main__":
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = []
    for name, fn in tests:
        try:
            fn()
            print(f"PASS: {name}")
        except Exception as exc:  # noqa: BLE001 - report and continue
            failed.append(name)
            print(f"FAIL: {name}: {exc!r}")
    print(f"{len(tests) - len(failed)}/{len(tests)} passed")
    sys.exit(1 if failed else 0)
