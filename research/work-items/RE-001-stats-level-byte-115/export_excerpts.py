"""Export verbatim objdump excerpts for RE-001-stats-level-byte-115.

Run from the repository root:
    python3 research/work-items/RE-001-stats-level-byte-115/export_excerpts.py

Writes one file per window next to this script, using the relative binary
path work/hl-node-115.bin so the objdump header line matches verify.py.
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = "work/hl-node-115.bin"

# (filename, start, stop). Whole-function windows (FDE ranges).
WINDOWS = [
    # The StatisticsImpl ctor (352 B), re-shipped byte-identical from
    # #3572: installs vtable 0x64d2d88 and writes the level byte
    # `movb $0x3,0x20(%rdi)` at 0x6071a32 (kExceptDetailedTimers, the
    # header default -- NOT the maximum; kAll is 5).
    ("ctor-6071a00.objdump.txt", "0x6071a00", "0x6071b60"),
    # recordTick, slot 0xb0 (185 B), re-shipped byte-identical from
    # #3396: gate `movzbl 0x20(%rdi)` then records iff level != 0 and
    # id <= 0xb1; per-CPU shard pick with the LCG fallback.
    ("record-tick-606fba0.objdump.txt", "0x606fba0", "0x606fc59"),
    # recordHistogram, slot 0xd8 (222 B), re-shipped byte-identical
    # from #3396: gate `movzbl 0x20(%rdi)` then records iff level > 1.
    ("record-hist-606fef0.objdump.txt", "0x606fef0", "0x606ffce"),
    # recordHistogram devirtualized twin, slot 0xd0 (244 B),
    # re-shipped byte-identical from #3396: same level > 1 gate.
    ("record-hist-devirt-606ffd0.objdump.txt", "0x606ffd0", "0x60700c4"),
    # recordInHistogram forwarder, slot 0xc8 (25 B): gate level > 2,
    # then tail-jump to slot 0xd8.
    ("forwarder-5d48960.objdump.txt", "0x5d48960", "0x5d48979"),
    # InstrumentedMutex::Lock (554 B): timed mutex lock. Gate:
    # stats_ and clock_ non-null and stats_level_ > 4 (kAll); only
    # stats_code_ == 52 (DB_MUTEX_WAIT_MICROS) takes the timed path
    # (two clock slot-0xa0 reads bracketing the lock, elapsed via
    # recordTick slot 0xb0, plus the TLS perf-counter add).
    ("mutex-lock-606ca40.objdump.txt", "0x606ca40", "0x606cc6a"),
    # InstrumentedCondVar::Wait (554 B): same gate shape; stats_ at
    # +0x38 (cond_ is 56 B: 48-B pthread_cond_t + the mutex pointer).
    ("condvar-wait-606ccb0.objdump.txt", "0x606ccb0", "0x606ceda"),
    # InstrumentedCondVar::TimedWait (555 B): same gate shape plus
    # the abs_time_us argument (rsi) converted by 0x606cee0.
    ("condvar-timedwait-606cf20.objdump.txt", "0x606cf20", "0x606d14b"),
    # The TLS once-init (107 B) called first by all three timed
    # helpers and by ~300 other FDEs: guards the thread-local state
    # the helpers read (perf_level, perf_context).
    ("tls-init-606dd10.objdump.txt", "0x606dd10", "0x606dd7b"),
    # pthread_mutex_lock wrapper (149 B) behind the 0x606ca00 thunk.
    ("lock-wrapper-60d5230.objdump.txt", "0x60d5230", "0x60d52c5"),
    # pthread_cond_wait wrapper (153 B) behind the 0x606cc70 thunk.
    ("condwait-wrapper-60d5530.objdump.txt", "0x60d5530", "0x60d55c9"),
    # Microsecond-split math (221 B) behind the 0x606cee0 thunk:
    # magic-number division/modulo by 1,000,000 for the timed wait.
    ("time-math-60d55f0.objdump.txt", "0x60d55f0", "0x60d56cd"),
    # Default-SystemClock accessor (214 B): function-local-static
    # shared_ptr<PosixClock>, lazily built; the timed helpers time
    # with the clock it returns (deref the returned shared_ptr*).
    ("clock-accessor-5fe2680.objdump.txt", "0x5fe2680", "0x5fe2756"),
    # The builtin "Statistics" factory lambda (299 B), catalogue
    # row 4516: operator new(0x70) + the ctor, wrapped in a
    # shared_ptr (control vtable 0x64d2eb8+0x10).
    ("factory-lambda-6071ba0.objdump.txt", "0x6071ba0", "0x6071ccb"),
    # The second ctor caller (2176 B): a factory that allocates
    # 0x70 bytes, calls the ctor with a zeroed delegate-args struct
    # and wraps the result in a shared_ptr (control vtable
    # 0x64d2eb8+0x10); TLS prologue + a "stati" name check precede.
    ("factory-create-6077820.objdump.txt", "0x6077820", "0x60780a0"),
    # CompactionJob::Run (5373 B), catalogue row 1381: the packet's
    # claims on this window are bounded to the two gated
    # recordHistogram forwards (histogram ids 2 and 3, devirt check
    # on slot 0xc8 == 0x5d48960, level > 2) on the Statistics* at
    # struct+0x220; the rest of Run's behavior is open.
    ("compaction-run-5e080f0.objdump.txt", "0x5e080f0", "0x5e095ed"),
    # The three 9-B lock/wait/time thunks (endbr64 + jmp + int3).
    ("thunk-606ca00.objdump.txt", "0x606ca00", "0x606ca09"),
    ("thunk-606cc70.objdump.txt", "0x606cc70", "0x606cc79"),
    ("thunk-606cee0.objdump.txt", "0x606cee0", "0x606cee9"),
]


def main():
    for name, start, stop in WINDOWS:
        out = subprocess.run(
            ["objdump", "-d", "--start-address=" + start,
             "--stop-address=" + stop, BIN],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        with open(os.path.join(HERE, name), "w") as fh:
            fh.write(out)
        print("wrote", name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
