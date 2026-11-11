"""Generate records.json for RE-001-stats-level-byte-115.

Reads the census outputs (stats-marked-fdes.tsv, level-writes.tsv,
level-reads.tsv, timer-callers.tsv, frames.txt, relocations.txt) plus
the window list, and writes the packet's semantic records. No
per-instruction mnemonic list: instruction-level detail lives only in
the verbatim excerpts.

Run from the repository root:
    python3 research/work-items/RE-001-stats-level-byte-115/gen_records.py
"""

import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

WINDOWS = [
    ("ctor", 0x6071A00, 0x6071B60, "ctor-6071a00.objdump.txt", "#3572"),
    ("record_tick", 0x606FBA0, 0x606FC59,
     "record-tick-606fba0.objdump.txt", "#3396"),
    ("record_hist", 0x606FEF0, 0x606FFCE,
     "record-hist-606fef0.objdump.txt", "#3396"),
    ("record_hist_devirt", 0x606FFD0, 0x60700C4,
     "record-hist-devirt-606ffd0.objdump.txt", "#3396"),
    ("forwarder", 0x5D48960, 0x5D48979,
     "forwarder-5d48960.objdump.txt", "new"),
    ("mutex_lock", 0x606CA40, 0x606CC6A,
     "mutex-lock-606ca40.objdump.txt", "new"),
    ("condvar_wait", 0x606CCB0, 0x606CEDA,
     "condvar-wait-606ccb0.objdump.txt", "new"),
    ("condvar_timedwait", 0x606CF20, 0x606D14B,
     "condvar-timedwait-606cf20.objdump.txt", "new"),
    ("tls_init", 0x606DD10, 0x606DD7B, "tls-init-606dd10.objdump.txt", "new"),
    ("lock_wrapper", 0x60D5230, 0x60D52C5,
     "lock-wrapper-60d5230.objdump.txt", "new"),
    ("condwait_wrapper", 0x60D5530, 0x60D55C9,
     "condwait-wrapper-60d5530.objdump.txt", "new"),
    ("time_math", 0x60D55F0, 0x60D56CD, "time-math-60d55f0.objdump.txt", "new"),
    ("clock_accessor", 0x5FE2680, 0x5FE2756,
     "clock-accessor-5fe2680.objdump.txt", "new"),
    ("factory_lambda", 0x6071BA0, 0x6071CCB,
     "factory-lambda-6071ba0.objdump.txt", "new"),
    ("factory_create", 0x6077820, 0x60780A0,
     "factory-create-6077820.objdump.txt", "new"),
    ("compaction_run", 0x5E080F0, 0x5E095ED,
     "compaction-run-5e080f0.objdump.txt", "new"),
    ("thunk_lock", 0x606CA00, 0x606CA09, "thunk-606ca00.objdump.txt", "new"),
    ("thunk_condwait", 0x606CC70, 0x606CC79,
     "thunk-606cc70.objdump.txt", "new"),
    ("thunk_time_math", 0x606CEE0, 0x606CEE9,
     "thunk-606cee0.objdump.txt", "new"),
]

STATS_LEVEL = [
    {"value": 0, "name": "kDisableAll",
     "note": "Disable all metrics; also kExceptTickers"},
    {"value": 1, "name": "kExceptHistogramOrTimers",
     "note": "Ticks only: recordTick runs, recordHistogram does not"},
    {"value": 2, "name": "kExceptTimers",
     "note": "Ticks and histograms; no timer stats"},
    {"value": 3, "name": "kExceptDetailedTimers",
     "note": "HEADER DEFAULT (stats_level_{kExceptDetailedTimers}); "
             "the ctor writes 3. NOT the maximum."},
    {"value": 4, "name": "kExceptTimeForMutex",
     "note": "All stats except time inside mutex lock and time spent "
             "on compression"},
    {"value": 5, "name": "kAll",
     "note": "Collect all stats, including measuring duration of "
             "mutex operations; the only level that enables the timed "
             "mutex-wait report"},
]

READERS = [
    {"site": "0x606fba4", "fde": "0x606fba0", "routine": "recordTick (slot 0xb0)",
     "base": "rdi (this)", "gate": "level != 0 and ticker id <= 0xb1",
     "effect": "per-CPU shard pick (CPUID 0x60d5cd0, LCG fallback "
               "0x61c4080), lock add of count, forward to the delegate's "
               "slot 0xb0"},
    {"site": "0x606fef4", "fde": "0x606fef0", "routine": "recordHistogram (slot 0xd8)",
     "base": "rdi (this)", "gate": "level > 1",
     "effect": "per-CPU shard pick, HistogramImpl::Add via the record's "
               "slot 0x20, forward to the delegate's slot 0xd8 only when "
               "hist id <= 0x33"},
    {"site": "0x606fffb", "fde": "0x606ffd0",
     "routine": "recordHistogram devirtualized twin (slot 0xd0)",
     "base": "rdi (this)", "gate": "level > 1",
     "effect": "same as slot 0xd8 but inlines the body when this's slot "
               "0xd8 is the local 0x606fef0"},
    {"site": "0x5d48964", "fde": "0x5d48960",
     "routine": "recordInHistogram forwarder (slot 0xc8)",
     "base": "rdi (this)", "gate": "level > 2",
     "effect": "tail-jump to slot 0xd8 (recordHistogram); level <= 2 "
               "returns without recording"},
    {"site": "0x606ca85", "fde": "0x606ca40",
     "routine": "InstrumentedMutex::Lock",
     "base": "r12 (the mutex's stats_)", "gate": "stats_ and clock_ "
     "non-null and level > 4 (kAll); then stats_code_ == 52 "
     "(DB_MUTEX_WAIT_MICROS) selects the timed path",
     "effect": "two default-clock slot-0xa0 reads bracket the lock; "
               "elapsed is added to the TLS perf counter when the "
               "perf_level flag is set and reported via recordTick "
               "slot 0xb0 (code, elapsed) when stats_ is present; "
               "code != 52 locks and returns without timing"},
    {"site": "0x606ccf5", "fde": "0x606ccb0",
     "routine": "InstrumentedCondVar::Wait",
     "base": "r12 (the condvar's stats_)", "gate": "same shape as "
     "Lock (stats_/clock_ non-null, level > 4, code == 52)",
     "effect": "times the pthread_cond_wait (thunk 0x606cc70 -> "
               "0x60d5530) the same way Lock times the mutex lock"},
    {"site": "0x606cf67", "fde": "0x606cf20",
     "routine": "InstrumentedCondVar::TimedWait",
     "base": "r12 (the condvar's stats_)", "gate": "same shape as "
     "Wait, plus the abs_time_us argument",
     "effect": "the timeout is split into seconds/remainder by the "
               "0x606cee0 thunk (magic-number modulo by 1,000,000) "
               "before the timed wait; elapsed is reported the same way"},
    {"site": "0x5e084ac", "fde": "0x5e080f0",
     "routine": "CompactionJob::Run (catalogue row 1381)",
     "base": "rdi (Statistics* at struct+0x220)", "gate": "level > 2, "
     "after a devirtualization check that slot 0xc8 == 0x5d48960",
     "effect": "recordHistogram via slot 0xd8 with histogram id 2"},
    {"site": "0x5e084e3", "fde": "0x5e080f0",
     "routine": "CompactionJob::Run (catalogue row 1381)",
     "base": "rdi (Statistics* at struct+0x220)", "gate": "level > 2, "
     "after a devirtualization check that slot 0xc8 == 0x5d48960",
     "effect": "recordHistogram via slot 0xd8 with histogram id 3"},
]


def read_tsv(name):
    with open(os.path.join(HERE, name)) as fh:
        lines = fh.read().splitlines()
    header = lines[0].split("\t")
    rows = [dict(zip(header, l.split("\t"))) for l in lines[1:] if l]
    return rows


def main():
    marked = read_tsv("stats-marked-fdes.tsv")
    writes = read_tsv("level-writes.tsv")
    reads = read_tsv("level-reads.tsv")
    callers = read_tsv("timer-callers.tsv")
    relocs = read_tsv("relocations.txt")
    from collections import Counter
    by_kind = Counter(r["kind"] for r in callers)

    records = {
        "target": {
            "binary": "work/hl-node-115.bin",
            "node": 115,
            "sha256": DIGEST,
            "provenance": "provenance/artifacts.json "
                          "artifacts/node/115/hl-node",
        },
        "work_item": "RE-001-stats-level-byte-115",
        "task": "RE-001",
        "question": "Which routine writes the StatisticsImpl level byte "
                    "at +0x20 besides the ctor (#3396's open unknown), "
                    "and which routines read it as a gate?",
        "answer": "No routine writes it besides the ctor: the only "
                  "+0x20 byte store in any StatisticsImpl-referencing "
                  "FDE, and in the whole StatisticsImpl code region, "
                  "is the ctor's `movb $0x3,0x20(%rdi)`. The setter is "
                  "a non-virtual inline (v8.1.1 statistics.h), so it "
                  "has no vtable slot and is never instantiated in "
                  "this binary. Nine sites in eight FDEs read the byte "
                  "as a gate: the three record slots, the slot-0xc8 "
                  "forwarder, the three instrumented timed-lock "
                  "helpers, and two forwards in CompactionJob::Run.",
        "stats_level_byte": {
            "offset": 0x20,
            "field": "std::atomic<StatsLevel> stats_level_",
            "size": 1,
            "header": "v8.1.1 include/rocksdb/statistics.h, "
                      "enum StatsLevel : uint8_t (L1079-1117), "
                      "set_stats_level/get_stats_level non-virtual "
                      "inlines (L1258-1268), default "
                      "stats_level_{kExceptDetailedTimers} (L1273)",
            "levels": STATS_LEVEL,
            "setter": "set_stats_level(StatsLevel) is a NON-virtual "
                      "inline: stats_level_.store(sl, relaxed) -- a "
                      "plain `movb $imm,0x20(%reg)` at each instantiation "
                      "site. It has no vtable slot.",
            "getter": "get_stats_level() is a NON-virtual inline: "
                      "stats_level_.load(relaxed) -- a plain "
                      "`movzbl 0x20(%reg),%eax` at each use site.",
            "ctor_write": {"site": "0x6071a32", "bytes": "c6 47 20 03",
                           "value": 3, "level": "kExceptDetailedTimers",
                           "note": "The header default, NOT the maximum: "
                                   "kAll is 5."},
        },
        "writer_census": {
            "movb_0x20_stores_binary_wide": 16889,
            "stats_marked_fdes": len(marked),
            "writes_in_marked_fdes_or_stats_region": len(writes),
            "writer": writes,
            "note": "16,889 `movb $imm,0x20(%reg)` stores exist "
                    "binary-wide (hash tables and other structs use "
                    "+0x20 freely), but inside the 62 FDEs that "
                    "reference a StatisticsImpl -- and inside the whole "
                    "StatisticsImpl code region 0x606b000..0x6072000 -- "
                    "the ctor's write is the ONLY one. The census "
                    "definition (FDE references a slot target, the "
                    "ctor, the vtable 0x64d2d88 or the 'BasicStatistics' "
                    "string) is the packet's bound: an inlined setter "
                    "instantiated in a host that never references a "
                    "StatisticsImpl symbol would escape it; see open "
                    "unknowns.",
        },
        "reader_census": {
            "movzbl_0x20_loads_binary_wide": 11335,
            "reads_in_marked_fdes_or_stats_region": len(reads),
            "readers": READERS,
            "note": "11,335 `movzbl 0x20(%reg)` loads exist binary-wide; "
                    "only these 9 sites read a Statistics object's "
                    "level byte. Every read site's gate compare is "
                    "pinned in the excerpts.",
        },
        "gates": {
            "record_tick": "level != 0 and ticker id <= 0xb1",
            "record_hist": "level > 1",
            "record_hist_devirt": "level > 1",
            "forwarder_slot_0xc8": "level > 2, then tail-jump slot 0xd8",
            "timed_lock_helpers": "stats_ and clock_ non-null, "
                                  "level > 4 (kAll), stats_code_ == 52 "
                                  "(DB_MUTEX_WAIT_MICROS)",
            "compaction_run": "level > 2, with a devirtualization "
                              "check that slot 0xc8 == 0x5d48960",
        },
        "instrumented_mutex": {
            "header": "v8.1.1 monitoring/instrumented_mutex.h L34-109",
            "layout": [
                {"offset": 0, "size": 40, "field": "port::Mutex mutex_",
                 "note": "pthread_mutex_t; Lock passes `this` to the "
                         "0x60d5230 pthread_mutex_lock wrapper via the "
                         "0x606ca00 thunk"},
                {"offset": 40, "size": 8, "field": "Statistics* stats_",
                 "note": "raw pointer (not shared_ptr); read at "
                         "0x606ca55 into r12; the level byte is read "
                         "from stats_+0x20"},
                {"offset": 48, "size": 8, "field": "SystemClock* clock_",
                 "note": "null-checked at 0x606ca6d (bpl); the timing "
                         "itself uses the default PosixClock from the "
                         "0x5fe2680 accessor, not this member"},
                {"offset": 56, "size": 4, "field": "int stats_code_",
                 "note": "compared to 0x34 (52) at 0x606cafd; only 52 "
                         "takes the timed path"},
            ],
            "routine": "0x606ca40 InstrumentedMutex::Lock (554 B)",
            "timed_path": "NowMicros via the default clock's slot 0xa0, "
                          "lock, NowMicros again, elapsed = end - start; "
                          "elapsed is added to the TLS perf counter at "
                          "+0x1b8 when the perf_level flag is set and "
                          "reported via stats_->recordTick(code, elapsed) "
                          "(slot 0xb0) when stats_ is present",
            "plain_path": "code != 52: lock and return without timing",
            "callers": by_kind.get("mutex-lock", 0),
        },
        "instrumented_condvar": {
            "header": "v8.1.1 monitoring/instrumented_mutex.h L181-222",
            "layout": [
                {"offset": 0, "size": 56,
                 "field": "port::CondVar cond_",
                 "note": "48-byte pthread_cond_t PLUS the 8-byte mutex "
                         "pointer (CondVar stores mu_); that is why "
                         "stats_ sits at +0x38 here, 8 higher than the "
                         "header's field order alone would suggest"},
                {"offset": 56, "size": 8, "field": "Statistics* stats_",
                 "note": "read at 0x606ccc5 / 0x606cf35 into r12"},
                {"offset": 64, "size": 8, "field": "SystemClock* clock_",
                 "note": "null-checked at 0x606ccdd / 0x606cf4f"},
                {"offset": 72, "size": 4, "field": "int stats_code_",
                 "note": "compared to 0x34 (52) at 0x606cd6d / 0x606d02f"},
            ],
            "routines": ["0x606ccb0 InstrumentedCondVar::Wait (554 B)",
                         "0x606cf20 InstrumentedCondVar::TimedWait (555 B, "
                         "extra abs_time_us argument in rsi)"],
            "callers": {"wait": by_kind.get("condvar-wait", 0),
                        "timedwait": by_kind.get("condvar-timedwait", 0)},
        },
        "db_mutex_wait_micros": {
            "value": 52,
            "name": "DB_MUTEX_WAIT_MICROS",
            "derivation": "counted from the v8.1.1 Tickers enum order "
                          "(statistics.h L55-602): BLOCK_CACHE_MISS=0 "
                          "through NO_FILE_ERRORS=50, STALL_MICROS=51, "
                          "DB_MUTEX_WAIT_MICROS=52",
            "header_note": "statistics.h L286: 'Disabled by default. "
                           "To enable it set stats level to kAll' -- "
                           "exactly the gate the three helpers implement",
        },
        "wrappers": [
            {"address": "0x60d5230", "fde": "0x60d5230..0x60d52c5",
             "call": "pthread_mutex_lock@plt 0x63f0b60",
             "note": "lock wrapper with system-error reporting; called "
                     "via the 0x606ca00 thunk"},
            {"address": "0x60d5530", "fde": "0x60d5530..0x60d55c9",
             "call": "pthread_cond_wait@plt 0x63f17e0",
             "note": "cond-wait wrapper: loads the mutex from +0x30 of "
                     "its argument; called via the 0x606cc70 thunk"},
            {"address": "0x60d55f0", "fde": "0x60d55f0..0x60d56cd",
             "call": "none (pure arithmetic)",
             "note": "splits a microsecond value by 1,000,000 "
                     "(magic 0x431bde82d7b634db, 0xf4240): seconds in "
                     "rdx, remainder in rsi; called via the 0x606cee0 "
                     "thunk for the timed wait"},
        ],
        "clock_accessor": {
            "address": "0x5fe2680",
            "fde": "0x5fe2680..0x5fe2756",
            "returns": "pointer to the function-local-static "
                       "shared_ptr<SystemClock> holding the default "
                       "PosixClock (callers deref it: mov (%rax),%reg)",
            "construction": "guard 0x6504c98 (__cxa_guard_acquire); "
                            "operator new(0x10) for the shared_ptr pair "
                            "and new(0x30) for the control block + "
                            "in-place PosixClock; control vtable "
                            "0x64ced00, object vtable 0x64ce930 "
                            "(PosixClock, #3902); counts from 0x459b20",
        },
        "tls_init": {
            "address": "0x606dd10",
            "fde": "0x606dd10..0x606dd7b",
            "behavior": "reads the TLS-initialized byte at %fs:-0x358; "
                        "if unset, sets it and registers the TLS "
                        "destructor 0x606dcf0 via __cxa_thread_atexit "
                        "with __dso_handle 0x64efa20",
            "call_sites": by_kind.get("tls-init", 0),
            "note": "Called first by all three timed helpers and by "
                    "~500 sites binary-wide; it is the shared TLS "
                    "once-init for the thread-local perf state.",
        },
        "factories": [
            {"address": "0x6071ba0", "fde": "0x6071ba0..0x6071ccb",
             "identity": "RegisterBuiltinStatistics factory lambda "
                         "(catalogue row 4516): operator new(0x70), the "
                         "ctor at 0x6071bda, wrapped in a shared_ptr "
                         "(control vtable 0x64d2eb8+0x10); the "
                         "ObjectLibrary 'Statistics' builtin entry",
             "delegate_args": "zeroed like the other factory: "
                             "`movaps %xmm0,(%rsp)` at 0x6071bd6 with "
                             "rsi=rsp -- this factory also always builds "
                             "a StatisticsImpl with a null delegate"},
            {"address": "0x6077820", "fde": "0x6077820..0x60780a0",
             "identity": "second ctor caller: a 2176-byte factory; "
                         "TLS prologue, a 'stati' name check, operator "
                         "new(0x70) at 0x6077b58, the ctor at 0x6077b74 "
                         "with a ZEROED delegate-args struct (movaps "
                         "%xmm0), shared_ptr wrap (control vtable "
                         "0x64d2eb8+0x10, counts from 0x459b20)",
             "delegate_args": "zeroed: this factory always builds a "
                             "StatisticsImpl with a null delegate",
             "name_open": "the exact C++ name of this factory is open; "
                          "it is most plausibly CreateDBStatistics, but "
                          "the packet does not claim it"},
        ],
        "vtable_accounting": {
            "vtable": "0x64d2d88 (installed by the ctor; typeinfo "
                      "N7rocksdb14StatisticsImplE)",
            "slots": 32,
            "note": "All 32 slots are named in #3396 (vtables.tsv) and "
                    "the slot targets are the census markers: the "
                    "write side (0xb0/0xb8/0xc0/0xc8/0xd0/0xd8/0xe0), "
                    "the locked read accessors (#3392), the histogram "
                    "getters (0x98/0xa0/0xa8), produce (0xe8, #3362), "
                    "slot 0xf0 (#3378), the delegate getter (0x88) and "
                    "the shared Configurable/Customizable base methods. "
                    "None of the 32 slot bodies writes +0x20: the only "
                    "+0x20 store in the whole StatisticsImpl code "
                    "region is the ctor's. set_stats_level is not a "
                    "slot at all (non-virtual inline).",
        },
        "windows": [
            {"name": n, "fde": "%#x..%#x" % (s, e), "excerpt": x,
             "source": src}
            for n, s, e, x, src in WINDOWS
        ],
        "caller_census": {
            "timer_calls_total": len(callers),
            "by_kind": dict(by_kind),
            "note": "244 mutex-lock, 27 condvar-wait and 3 "
                    "condvar-timedwait call sites, plus 500 TLS-init "
                    "sites and the 5 thunk calls. The mutex-lock "
                    "callers span the whole DB (compaction, flush, "
                    "table, memtable, block cache); the packet records "
                    "their FDEs in timer-callers.tsv without claiming "
                    "each host's role.",
        },
        "relocations": {
            "rows": len(relocs),
            "note": "RELATIVE rows for the StatisticsImpl vtable "
                    "region 0x64d2d78..0x64d2e90 plus the clock "
                    "vtables, the shared_ptr control vtable and the "
                    "perf-level GOT slot.",
        },
        "corrections_to_3572_and_3396": [
            "The ctor's `byte this+0x20 = 3` is NOT 'the maximum': 3 is "
            "kExceptDetailedTimers, the header default "
            "(stats_level_{kExceptDetailedTimers}); kAll is 5.",
            "The 'enable byte' IS stats_level_: the record gates "
            "(tick: level != 0; hist: level > 1; forwarder: level > 2; "
            "timed lock: level > 4) match the v8.1.1 StatsLevel enum "
            "names exactly, and the timed-lock gate matches the "
            "header comment that DB_MUTEX_WAIT_MICROS needs kAll.",
            "The level byte is an std::atomic<StatsLevel> (1 byte), "
            "not a plain bool/enable flag.",
        ],
        "open_unknowns": [
            "An inlined set_stats_level instantiated in a host that "
            "never references a StatisticsImpl symbol would escape "
            "the marker census: the packet bounds the claim to the 62 "
            "marked FDEs plus the StatisticsImpl code region, and "
            "names the re-check (grep the binary for "
            "`movb $0x[0-5],0x20(%reg)` and trace the base register to "
            "a Statistics*).",
            "The TLS perf gate: the helpers compare a TLS byte to 4 "
            "(strictly above) while the v8.1.1 PerfLevel enum tops out "
            "at 4 (kEnableTimeAndCPUTime); whether any perf level "
            "exceeds 4 in this build, and the exact TLS variable "
            "identity, is open -- the perf-counter add may be "
            "unreachable here.",
            "The exact C++ name of factory 0x6077820 (most plausibly "
            "CreateDBStatistics, unclaimed).",
            "The rest of CompactionJob::Run 0x5e080f0 beyond the two "
            "gated forwards (histogram ids 2 and 3; their Histograms "
            "enum names are not pinned here).",
            "Why only stats_code_ == 52 takes the timed path in the "
            "three helpers (recorded as observed; the header only "
            "says DB_MUTEX_WAIT_MICROS needs kAll).",
            "The member clock_ is only null-checked; the timing uses "
            "the default PosixClock via the 0x5fe2680 accessor. "
            "Whether the member clock_ is always that same default in "
            "practice is open.",
            "The C++ names of StatisticsImpl vtable slots 4, 8, 17 "
            "and 18 (carried from #3902's open unknowns for the "
            "shared base methods).",
        ],
    }
    with open(os.path.join(HERE, "records.json"), "w") as fh:
        json.dump(records, fh, indent=1)
        fh.write("\n")
    print("wrote records.json (%d marked FDEs, %d writes, %d reads, "
          "%d timer calls)" % (len(marked), len(writes), len(reads),
                               len(callers)))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
