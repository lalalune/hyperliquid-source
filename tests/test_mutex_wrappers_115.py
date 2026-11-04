"""Model tests for the node #115 mutex lock/unlock wrappers.

Run with plain python3 (no pytest needed):
    python3 tests/test_mutex_wrappers_115.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from mutex_wrappers_115 import (  # noqa: E402
    ACCEPTED_RESULTS, ERROR_FORMAT, lock, lock_via_stub, unlock,
)

CHECKS = []


def check(name, condition):
    CHECKS.append((name, bool(condition)))
    if not condition:
        raise AssertionError("failed: %s" % name)


def main():
    for code in (0, 16, 110):
        check("lock accepts %d" % code, lock("m", code) == ("ok", []))
        check("unlock accepts %d" % code, unlock("m", code) == ("ok", []))
        check("stub accepts %d" % code,
              lock_via_stub("m", code) == ("ok", []))
    for code in (1, 2, 22, 35, 111, 255, -1):
        status, events = lock("m", code, "oops")
        check("lock rejects %d" % code, status == "fatal")
        check("lock fatal order %d" % code, events == [
            "build_error_string:%d" % code,
            "fprintf:" + ERROR_FORMAT % ("lock", "oops"),
            "dispose",
            "abort",
        ])
        status, events = unlock("m", code, "oops")
        check("unlock rejects %d" % code, status == "fatal")
        check("unlock fatal op word %d" % code,
              events[1] == "fprintf:" + ERROR_FORMAT % ("unlock", "oops"))
        check("stub matches lock %d" % code,
              lock_via_stub("m", code, "oops") == lock("m", code, "oops"))
    check("accepted set is exactly 0, 16, 110",
          ACCEPTED_RESULTS == frozenset((0, 16, 110)))
    check("format string", ERROR_FORMAT == "pthread %s: %s\n")
    for fn in (lock, unlock, lock_via_stub):
        try:
            fn(None, 0)
            check("null mutex raises", False)
        except ValueError:
            check("null mutex raises", True)
    print("ALL MODEL TESTS PASSED (%d checks)" % len(CHECKS))


if __name__ == "__main__":
    main()
