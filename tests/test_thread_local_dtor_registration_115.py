"""Tests for tools/thread_local_dtor_registration_115.py.

Every expectation is grounded in the evidence packet
research/work-items/RE-001-thread-local-dtor-registration-115/: the
excerpts (register_dtor 0x5ca0d20, key_enable 0x5ca0e20, dtor_runner
0x5ca53f0, guard_alloc/use/free, grow helper 0x5c8b980, the 28
destructors), callers.tsv (1153 sites), and records.json. Run:
    python3 tests/test_thread_local_dtor_registration_115.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "tools")))

from thread_local_dtor_registration_115 import (
    CENSUS_CALLER_FDES,
    CENSUS_DTORS,
    CENSUS_SITES,
    DANGLING_PTR,
    DSO_HANDLE_SLOT,
    DTOR_TABLE,
    GuardObject,
    KeyState,
    RegistrationPanic,
    RunnerPanic,
    DtorRegistry,
    TlsObject,
    census_summary,
    grow_capacity,
)


def check(name, cond):
    assert cond, name
    return 1


def main():
    n = 0
    rec = DtorRegistry()

    # --- fast path: libc impl present -> dispatch (dtor, t, dso_handle slot).
    n += check("fast path dispatches to the impl",
               rec.register_dtor(0x1000, 0x5CDF410, impl_present=True)
               == ("fast-path", 0x5CDF410, 0x1000, DSO_HANDLE_SLOT))
    n += check("fast path leaves the registry untouched",
               rec.count == 0 and rec.guard == 0 and rec.capacity == 0)

    # --- slow path: first registration grows the vector 0 -> 4.
    n += check("slow path appends",
               rec.register_dtor(0x1000, 0x5CDF410) == ("slow-path", 0x5CDF410, 0x1000, DSO_HANDLE_SLOT))
    n += check("first grow: capacity 4", rec.capacity == 4)
    n += check("count 1 after first registration", rec.count == 1)
    n += check("guard back to 0 after registration", rec.guard == 0)
    n += check("key created by the first registration", rec.key.key != 0)
    n += check("setspecific called once", rec.key.setspecific_calls == 1)

    # --- growth: max(4, 2 * old) at the 5th and 9th registrations.
    for i in range(2, 5):
        rec.register_dtor(0x1000 + i, 0x5CDF410)
    n += check("capacity stays 4 through 4 entries", rec.capacity == 4)
    rec.register_dtor(0x1005, 0x5CDF410)
    n += check("capacity 8 at the 5th entry", rec.capacity == 8)
    for i in range(6, 9):
        rec.register_dtor(0x1000 + i, 0x5CDF410)
    rec.register_dtor(0x1009, 0x5CDF410)
    n += check("capacity 16 at the 9th entry", rec.capacity == 16)
    n += check("grow helper policy", grow_capacity(0) == 4 and grow_capacity(4) == 8
               and grow_capacity(8) == 16 and grow_capacity(100) == 200)

    # --- key::enable is idempotent for creation, setspecific every time.
    k = KeyState()
    n += check("first enable creates the key", k.enable() is True)
    n += check("second enable does not recreate", k.enable() is False)
    n += check("setspecific called on every enable", k.setspecific_calls == 2)
    k.race_loser()
    n += check("race loser deletes its spare key", k.spare_keys_deleted == 1)

    # --- runner drains LIFO, then resets (cap, ptr, count) to (0, 8, 0).
    seen = []
    reg = DtorRegistry()
    reg.register_dtor("A", lambda t: seen.append(("A", t)))
    reg.register_dtor("B", lambda t: seen.append(("B", t)))
    reg.register_dtor("C", lambda t: seen.append(("C", t)))
    calls = reg.run_dtors()
    n += check("LIFO drain order", [t for _, t in calls] == ["C", "B", "A"])
    n += check("dtors ran with their t", seen == [("C", "C"), ("B", "B"), ("A", "A")])
    n += check("capacity reset to 0", reg.capacity == 0)
    n += check("vec_ptr reset to the dangling pointer 8", reg.vec_ptr == DANGLING_PTR)
    n += check("count reset to 0", reg.count == 0)
    n += check("guard incremented to 1 after drain", reg.guard == 1)
    n += check("array freed", reg.freed is True)

    # --- guard panics: registration after drain, and re-entrant registration.
    try:
        reg.register_dtor("D", lambda t: None)
        n += check("registration after drain panics", False)
    except RegistrationPanic:
        n += check("registration after drain panics", True)
    reg2 = DtorRegistry()
    reg2.guard = -1  # registration in progress
    try:
        reg2.register_dtor("X", lambda t: None)
        n += check("re-entrant registration panics", False)
    except RegistrationPanic:
        n += check("re-entrant registration panics", True)
    reg2.guard = 1  # runner already ran
    try:
        reg2.run_dtors()
        n += check("runner with guard != 0 panics", False)
    except RunnerPanic:
        n += check("runner with guard != 0 panics", True)

    # --- guard object: alloc / use / free.
    epoch = [0]
    g = GuardObject.alloc(epoch)
    n += check("guard alloc refcount 1", g.refcount == 1)
    n += check("guard alloc second field 1", g.second == 1)
    n += check("guard alloc epoch from the global counter", g.epoch == 1)
    n += check("guard alloc string empty", g.string_first_byte == 0)
    g.use()
    n += check("guard use bumps the refcount", g.refcount == 2)
    fired = []
    g.callback = lambda: fired.append(True)
    g.string_first_byte = ord("x")
    g.free()
    n += check("guard free clears the string first byte", g.string_first_byte == 0)
    n += check("guard free invokes the callback", fired == [True])
    n += check("guard free decrements the second field", g.second == 0)

    # --- arc-dec destructor shape (0x5cdf410 family, state byte +0x48).
    o = TlsObject(0x48, discriminant=0, refcount=2)
    n += check("arc-dec refcount 2 does not drop",
               o.arc_dec_drop("drop0", "drop1") is None and o.dropped is False)
    n += check("arc-dec marks state 2", o.state == 2)
    o2 = TlsObject(0x48, discriminant=0, refcount=1)
    n += check("arc-dec discriminant 0 drops via drop0",
               o2.arc_dec_drop("drop0", "drop1") == "drop0" and o2.dropped is True)
    o3 = TlsObject(0x48, discriminant=1, refcount=1)
    n += check("arc-dec discriminant 1 drops via drop1",
               o3.arc_dec_drop("drop0", "drop1") == "drop1" and o3.dropped is True)
    o4 = TlsObject(0x48, discriminant=2, refcount=1)
    n += check("arc-dec discriminant 2 returns without dropping",
               o4.arc_dec_drop("drop0", "drop1") is None and o4.dropped is False)

    # --- slice-drop destructor shape (+0x20, element size 0x38).
    s = TlsObject(0x20)
    n += check("slice-drop marks state 2 and drops count*0x38",
               s.slice_drop(3) == ("slice", 3, 0x38) and s.state == 2 and s.dropped is True)

    # --- inner-counter-callback shape (+0x08, old state must be 1).
    ic = TlsObject(0x08)
    ic.state = 1
    counter = [2]
    fired2 = []
    n += check("inner-counter decrements without callback at 1",
               ic.inner_counter_callback(counter, lambda: fired2.append(True)) is False
               and counter == [1] and fired2 == [])
    icb = TlsObject(0x08)
    icb.state = 1
    n += check("inner-counter fires the callback at 0",
               icb.inner_counter_callback(counter, lambda: fired2.append(True)) is True
               and fired2 == [True])
    ic2 = TlsObject(0x08)  # state 0, not 1
    try:
        ic2.inner_counter_callback([1], lambda: None)
        n += check("inner-counter with old state != 1 panics", False)
    except RegistrationPanic:
        n += check("inner-counter with old state != 1 panics", True)

    # --- census constants match the evidence packet.
    here = os.path.dirname(__file__)
    packet = os.path.join(here, "..", "research", "work-items",
                          "RE-001-thread-local-dtor-registration-115")
    records = json.load(open(os.path.join(packet, "records.json")))
    rows = open(os.path.join(packet, "callers.tsv")).read().splitlines()[1:]
    n += check("census sites 1153", CENSUS_SITES == 1153 == len(rows))
    n += check("census caller FDEs 604",
               CENSUS_CALLER_FDES == 604 == len({r.split("\t")[1] for r in rows}))
    n += check("census dtors 28",
               CENSUS_DTORS == 28 == len({r.split("\t")[3] for r in rows}))
    n += check("dtor table site counts sum to 1153",
               sum(v[2] for v in DTOR_TABLE.values()) == 1153)
    n += check("dtor table matches records.json",
               all(records["destructors"][i]["address"] == hex(a)
                   for i, a in enumerate(sorted(DTOR_TABLE))))
    n += check("tls objects sum to 1153",
               sum(v[0] for v in census_summary()["tls_objects"].values() if isinstance(v, tuple)) == 1153)
    n += check("dominant object -0x1130 has 845 sites",
               census_summary()["tls_objects"][-0x1130] == (845, "arc-dec"))
    n += check("second object -0x1180 has 287 sites",
               census_summary()["tls_objects"][-0x1180] == (287, "slice-drop"))

    print(f"{n} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
