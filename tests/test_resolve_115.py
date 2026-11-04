"""Tests for tools/resolve_115.py: node #115's resolve-and-cache
wrapper 0x5d8cf30 with its default leaf 0x5d8ce80 (RE-001).

Run from the repository root:
    python3 tests/test_resolve_115.py
Prints "checks pass" on success, else raises.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from resolve_115 import default_leaf, resolve

CHECKS = []


def check(name, actual, expected):
    if actual != expected:
        raise AssertionError("%s: got %r, want %r" % (name, actual, expected))
    CHECKS.append(name)


def check_raises(name, fn):
    try:
        fn()
    except ValueError:
        CHECKS.append(name)
        return
    raise AssertionError("%s: expected ValueError" % name)


def main():
    # Leaf alone.
    check("leaf-present", default_leaf({"default": 700}), 700)
    check("leaf-zero", default_leaf({"default": 0}), 0)
    check_raises("leaf-missing", lambda: default_leaf({}))
    check_raises("leaf-not-dict", lambda: default_leaf(None))

    # Wrapper, zero-id arm: default value cached in both slots.
    obj = {"sub": {"default": 1234}}
    check("zero-hit-bool", resolve(obj, 0, lambda s, i: 9999), 1)
    check("zero-hit-slot10", obj["slot_0x10"], 1234)
    check("zero-hit-slot38", obj["slot_0x38"], 1234)
    # The stub value lookup must not have been used on this arm:
    # the slots hold the default (1234), not the stub's 9999.

    # Wrapper, zero-id arm with a zero default: miss-like outcome.
    obj = {"sub": {"default": 0}}
    check("zero-default-bool", resolve(obj, 0, lambda s, i: 9999), 0)
    check("zero-default-slot10", obj["slot_0x10"], 0)
    check("zero-default-slot38", obj["slot_0x38"], 0)

    # Wrapper, nonzero-id arm: stub hit and stub miss.
    obj = {"sub": {"default": 1234}}
    check("nonzero-hit-bool", resolve(obj, 7, lambda s, i: 555), 1)
    check("nonzero-hit-slot10", obj["slot_0x10"], 555)
    check("nonzero-hit-slot38", obj["slot_0x38"], 555)
    check("nonzero-miss-bool", resolve(obj, 8, lambda s, i: 0), 0)
    check("nonzero-miss-slot10", obj["slot_0x10"], 0)
    check("nonzero-miss-slot38", obj["slot_0x38"], 0)

    # A hit whose value is itself 0 is indistinguishable from a miss.
    obj = {"sub": {"default": 1234}}
    check("zero-value-hit-bool", resolve(obj, 9, lambda s, i: 0), 0)

    # The value lookup receives the subobject and the id dword.
    seen = {}

    def recording(subobject, ident):
        seen["sub"] = subobject
        seen["id"] = ident
        return 42

    sub = {"default": 1234}
    obj = {"sub": sub}
    check("recording-bool", resolve(obj, 77, recording), 1)
    check("recording-sub", seen["sub"] is sub, True)
    check("recording-id", seen["id"], 77)

    # Id dword semantics: only the low 32 bits reach the branch.
    obj = {"sub": {"default": 314}}
    check("wide-id-zero-low", resolve(obj, 0x100000000, lambda s, i: 9999), 1)
    check("wide-id-zero-low-slot", obj["slot_0x10"], 314)
    obj = {"sub": {"default": 314}}
    check("wide-id-nonzero-low", resolve(obj, 0x100000005, recording), 1)
    check("wide-id-nonzero-low-id", seen["id"], 5)

    # Previous cached values are unconditionally overwritten.
    obj = {"sub": {"default": 0}, "slot_0x10": 111, "slot_0x38": 222}
    check("overwrite-bool", resolve(obj, 0, lambda s, i: 9999), 0)
    check("overwrite-slot10", obj["slot_0x10"], 0)
    check("overwrite-slot38", obj["slot_0x38"], 0)

    # The wrapper does not modify the subobject.
    sub = {"default": 808}
    obj = {"sub": sub}
    resolve(obj, 3, lambda s, i: 909)
    check("sub-untouched", sub, {"default": 808})

    # Guards.
    check_raises("missing-sub", lambda: resolve({}, 0, lambda s, i: 1))
    check_raises("missing-default", lambda: resolve({"sub": {}}, 0, lambda s, i: 1))

    print("checks pass (%d checks)" % len(CHECKS))


if __name__ == "__main__":
    main()
