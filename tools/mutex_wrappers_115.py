"""Python model of the node #115 mutex lock/unlock wrappers
(0x60d5230 / 0x60d52f0) and the lock stub (0x606ca00).

The wrappers take one argument, the mutex pointer, pass it
unchanged to pthread_mutex_lock / pthread_mutex_unlock, and
accept result codes 0, 16, or 110 (the rule in the binary is
``(result & ~0x10) == 0`` or ``result == 110``). Any other
result takes the fatal path, in order: build an error string
from the result code, report ``pthread <op>: <error>`` to the
report stream, dispose the temp string, and abort (never
returns). The model raises on a null mutex pointer; the
binary itself checks nothing before the pthread call, so that
guard is model-side and stated openly.
"""

ACCEPTED_RESULTS = frozenset((0, 16, 110))
ERROR_FORMAT = "pthread %s: %s\n"
OPS = {
    "lock": "0x60d5230",
    "unlock": "0x60d52f0",
}
LOCK_STUB = "0x606ca00"


def run_wrapper(op, mutex, result, error_text):
    """Return (status, events) for one wrapper invocation.

    status is "ok" for an accepted result and "fatal" otherwise.
    events lists the observable steps in order; on the fatal
    path the final event is "abort", after which nothing runs.
    """
    if op not in OPS:
        raise ValueError("unknown op: %r" % (op,))
    if mutex is None:
        raise ValueError("null mutex pointer")
    if result in ACCEPTED_RESULTS:
        return "ok", []
    return "fatal", [
        "build_error_string:%d" % result,
        "fprintf:" + ERROR_FORMAT % (op, error_text),
        "dispose",
        "abort",
    ]


def lock(mutex, result, error_text=""):
    """The lock wrapper at 0x60d5230."""
    return run_wrapper("lock", mutex, result, error_text)


def unlock(mutex, result, error_text=""):
    """The unlock wrapper at 0x60d52f0."""
    return run_wrapper("unlock", mutex, result, error_text)


def lock_via_stub(mutex, result, error_text=""):
    """The lock stub at 0x606ca00: a tail jump to the lock
    wrapper, so its outcome is exactly the lock outcome."""
    return lock(mutex, result, error_text)
