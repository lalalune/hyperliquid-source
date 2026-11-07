# RE-001: pin node #115 the StatisticsImpl stats_level_ byte (+0x20): the single writer, the inline setter/getter, and the gate readers

Task: RE-001 (#115 function map). Bounded question: which routine
writes the StatisticsImpl level byte at +0x20 besides the ctor
(#3396's open unknown), and which routines read it as a gate?

- Component: node #115 StatisticsImpl stats_level_, extracted from
  the digest-verified work binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  windows `0x6071a00..0x6071b60` (ctor),
  `0x606fba0..0x606fc59` (recordTick, slot 0xb0),
  `0x606fef0..0x606ffce` (recordHistogram, slot 0xd8),
  `0x606ffd0..0x60700c4` (recordHistogram devirtualized, slot 0xd0),
  `0x5d48960..0x5d48979` (recordInHistogram forwarder, slot 0xc8),
  `0x606ca40..0x606cc6a` (InstrumentedMutex::Lock),
  `0x606ccb0..0x606ceda` (InstrumentedCondVar::Wait),
  `0x606cf20..0x606d14b` (InstrumentedCondVar::TimedWait),
  `0x606dd10..0x606dd7b` (TLS once-init),
  `0x60d5230..0x60d52c5` (pthread_mutex_lock wrapper),
  `0x60d5530..0x60d55c9` (pthread_cond_wait wrapper),
  `0x60d55f0..0x60d56cd` (microsecond-split math),
  `0x5fe2680..0x5fe2756` (default-SystemClock accessor),
  `0x6071ba0..0x6071ccb` (builtin "Statistics" factory lambda),
  `0x6077820..0x60780a0` (second ctor caller / factory),
  `0x5e080f0..0x5e095ed` (CompactionJob::Run),
  `0x606ca00..0x606ca09`, `0x606cc70..0x606cc79`,
  `0x606cee0..0x606cee9` (the three 9-byte thunks).
- Claim status: observation for the window bounds, the census counts,
  the gate compares and the layouts; inference for the C++ names
  "InstrumentedMutex::Lock", "InstrumentedCondVar::Wait/TimedWait"
  (they match the v8.1.1 `monitoring/instrumented_mutex.h` member
  layouts exactly, including the 56-byte cond_); unresolved for the
  items listed in records.json.
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in them (including
  `endbr64` at the window entries and at each landing pad) are
  genuine instructions present in the target binary, not
  placeholders; the packet checker re-verifies sampled instructions
  byte-for-byte against a fresh objdump run and the raw binary.
- Relationship to earlier work: the ctor excerpt is re-shipped
  byte-identical from #3572 and the three record-slot excerpts
  byte-identical from #3396 (verified by diff against the fork
  branches `fix/statistics-impl-ctor-115` and
  `fix/stats-write-side-115`). This packet answers #3396's open
  unknown ("Which routine writes the enable byte at +0x20 besides
  the ctor") and corrects #3572/#3396 (see below). The forwarder
  0x5d48960's level gate was the centerpiece of open PR #2715 (cited,
  not re-shipped: its 25-byte body is excerpted here for the first
  time). The big registry method 0x5ff88c0 and the ObjectRegistry
  work (#4015/#4138) are unrelated. No open PR covers the level byte,
  the timed-lock helpers or the two factories (checked this cycle:
  open-PR snapshot, no title hit; the state file's do-not-pick list
  was honoured).

## The answer in one paragraph

The byte at StatisticsImpl+0x20 is `std::atomic<StatsLevel>
stats_level_` (v8.1.1 `include/rocksdb/statistics.h`, default
`kExceptDetailedTimers` = 3). `set_stats_level` and
`get_stats_level` are NON-virtual inlines, so the setter has no
vtable slot and compiles to a plain `movb` store wherever it is
instantiated. In this binary it is instantiated exactly once: the
ctor's `movb $0x3,0x20(%rdi)` at 0x6071a32. The census proves it:
16,889 `movb $imm,0x20(%reg)` stores exist binary-wide, but inside
the 62 FDEs that reference a StatisticsImpl -- and inside the whole
StatisticsImpl code region 0x606b000..0x6072000 -- the ctor's write
is the only one. Nine sites in eight FDEs read the byte as a gate
(see below). Both factories (0x6071ba0, 0x6077820) build with a
zeroed delegate-args struct, so every StatisticsImpl in this binary
starts at level 3 with a null delegate.

## The level values (v8.1.1 StatsLevel enum)

| value | name | what it enables |
|---|---|---|
| 0 | kDisableAll (= kExceptTickers) | nothing |
| 1 | kExceptHistogramOrTimers | ticks only |
| 2 | kExceptTimers | ticks + histograms |
| 3 | kExceptDetailedTimers | **header default; the ctor writes 3** |
| 4 | kExceptTimeForMutex | all except mutex-time and compression-time |
| 5 | kAll | everything, including mutex-wait timing |

## The readers and their gates

- `recordTick` slot 0xb0 (0x606fba0): `movzbl 0x20(%rdi)` at
  0x606fba4, records iff level != 0 and ticker id <= 0xb1.
- `recordHistogram` slot 0xd8 (0x606fef0): `movzbl 0x20(%rdi)` at
  0x606fef4, records iff level > 1.
- `recordHistogram` devirtualized slot 0xd0 (0x606ffd0): same
  level > 1 gate at 0x606fffb.
- `recordInHistogram` forwarder slot 0xc8 (0x5d48960): `movzbl
  0x20(%rdi)` at 0x5d48964, `cmp $0x2`, tail-jumps to slot 0xd8
  iff level > 2, else returns.
- `InstrumentedMutex::Lock` (0x606ca40): `movzbl 0x20(%r12)` at
  0x606ca85, where r12 is the mutex's `stats_`. Gate: stats_ and
  clock_ non-null, level > 4 (kAll), then `cmpl $0x34,0x38(%rbx)`
  -- only stats_code_ == 52 (DB_MUTEX_WAIT_MICROS) takes the timed
  path. The timed path reads NowMicros twice from the default clock
  (slot 0xa0, via the 0x5fe2680 accessor), locks in between, adds
  the elapsed time to the TLS perf counter at +0x1b8 when the
  perf_level flag is set, and reports it via `recordTick` slot 0xb0
  (code, elapsed) when stats_ is present. Code != 52 locks and
  returns without timing. 244 call sites.
- `InstrumentedCondVar::Wait` (0x606ccb0): the same gate shape
  (level > 4 at 0x606ccf5, code == 52 at 0x606cd6d); times the
  `pthread_cond_wait` (thunk 0x606cc70 -> 0x60d5530). 27 call sites.
  The cond_ is 56 bytes (48-byte pthread_cond_t + the mutex
  pointer `mu_`), which is why stats_ sits at +0x38 here.
- `InstrumentedCondVar::TimedWait` (0x606cf20): the same gate shape
  plus the `abs_time_us` argument in rsi, split into seconds and
  remainder by the 0x606cee0 thunk (magic-number modulo by
  1,000,000, 0x60d55f0) before the timed wait. 3 call sites.
- `CompactionJob::Run` (0x5e080f0, catalogue row 1381): two reads
  (0x5e084ac, 0x5e084e3) on the Statistics* at struct+0x220, each
  gated on level > 2 after a devirtualization check that slot 0xc8
  == 0x5d48960, forwarding to slot 0xd8 with histogram ids 2 and 3.
  The packet's claims on this 5373-byte window are bounded to those
  two forwards; the rest of Run is open.

## The layouts (header-corroborated)

`InstrumentedMutex` (v8.1.1 `monitoring/instrumented_mutex.h`
L34-109): mutex_ 40 B at +0x00, stats_ (raw Statistics*) at +0x28,
clock_ at +0x30, stats_code_ (int) at +0x38. `InstrumentedCondVar`
(L181-222): cond_ 56 B at +0x00, stats_ at +0x38, clock_ at +0x40,
stats_code_ at +0x48. `DB_MUTEX_WAIT_MICROS` = 52, counted from the
v8.1.1 Tickers enum order (BLOCK_CACHE_MISS=0 ... STALL_MICROS=51,
DB_MUTEX_WAIT_MICROS=52); the header comment at statistics.h L286
("Disabled by default. To enable it set stats level to kAll") is
exactly the gate the three helpers implement.

## The factories and the clock accessor

- 0x6071ba0 (catalogue row 4516, the RegisterBuiltinStatistics
  factory lambda): operator new(0x70), the ctor at 0x6071bda with a
  zeroed delegate-args struct (`movaps %xmm0,(%rsp)`), wrapped in a
  shared_ptr (control vtable 0x64d2eb8+0x10).
- 0x6077820 (2176 B): a second factory with a TLS prologue and a
  "stati" name check; operator new(0x70) at 0x6077b58, the ctor at
  0x6077b74 with a zeroed delegate-args struct, the same shared_ptr
  wrap. Its exact C++ name is open (most plausibly
  CreateDBStatistics, unclaimed).
- 0x5fe2680: the default-SystemClock accessor -- a
  function-local-static shared_ptr<PosixClock>, lazily built
  (guard 0x6504c98, make_shared-style 48-byte control block +
  in-place object; control vtable 0x64ced00, object vtable
  0x64ce930 = PosixClock). It returns a pointer to the static
  shared_ptr; callers deref it (`mov (%rax),%reg`) to get the clock.
  The timed helpers time with this default clock, not with the
  member clock_ (which is only null-checked).
- 0x606dd10 (107 B): the TLS once-init called first by all three
  timed helpers and by 500 sites binary-wide; it guards the
  thread-local perf state (sets the byte at %fs:-0x358 and
  registers the destructor 0x606dcf0 via __cxa_thread_atexit).

## Corrections to #3572 and #3396

- The ctor's `byte this+0x20 = 3` is NOT "the maximum": 3 is
  kExceptDetailedTimers, the header default; kAll is 5.
- The "enable byte" IS stats_level_: the record gates (tick:
  level != 0; hist: level > 1; forwarder: level > 2; timed lock:
  level > 4) match the v8.1.1 StatsLevel enum names exactly, and
  the timed-lock gate matches the header comment that
  DB_MUTEX_WAIT_MICROS needs kAll.
- The level byte is an std::atomic<StatsLevel> (1 byte), not a
  plain bool/enable flag.

## Verification

`verify.py` passes ALL CHECKS PASSED: the provenance digest, the
manifest (19 excerpt files + 6 census/script files + records.json),
excerpt regeneration byte-for-byte, 13 fixed instruction samples +
3 seeded random gate spots byte-for-byte against a fresh objdump run
and the raw binary, all 19 FDE ranges, census reproduction (135,313
FDEs, 62 marked, 16,889 movb stores, 11,335 movzbl loads, the single
writer, the 9 reader sites, 779 timer/forwarder calls with the
pinned per-kind split), model constants, 916 relocation rows against
a fresh readelf -rW run, the "BasicStatistics" string at 0x432248,
the excerpt content pins, and the 21 model tests in
tests/test_stats_level_byte_115.py (run directly; pytest is not
installed on this VM).

## Open unknowns

- An inlined set_stats_level instantiated in a host that never
  references a StatisticsImpl symbol would escape the marker census:
  the packet bounds the claim to the 62 marked FDEs plus the
  StatisticsImpl code region, and names the re-check (grep the
  binary for `movb $0x[0-5],0x20(%reg)` and trace the base register
  to a Statistics*).
- The TLS perf gate: the helpers compare a TLS byte to 4 (strictly
  above) while the v8.1.1 PerfLevel enum tops out at 4
  (kEnableTimeAndCPUTime); whether any perf level exceeds 4 in this
  build, and the exact TLS variable identity, is open -- the
  perf-counter add may be unreachable here.
- The exact C++ name of factory 0x6077820 (most plausibly
  CreateDBStatistics, unclaimed).
- The rest of CompactionJob::Run 0x5e080f0 beyond the two gated
  forwards (histogram ids 2 and 3; their Histograms enum names are
  not pinned here).
- Why only stats_code_ == 52 takes the timed path in the three
  helpers (recorded as observed; the header only says
  DB_MUTEX_WAIT_MICROS needs kAll).
- The member clock_ is only null-checked; the timing uses the
  default PosixClock via the 0x5fe2680 accessor. Whether the member
  clock_ is always that same default in practice is open.
- The C++ names of StatisticsImpl vtable slots 4, 8, 17 and 18
  (carried from #3902's open unknowns for the shared base methods).

## Artifact

Node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(`provenance/artifacts.json`, `artifacts/node/115/hl-node`).

Environment limits: this VM has no cargo/rustc, no git-lfs and no
Ghidra/Java, so `make verify`, `make test` and `make catalogue-check`
could not be run here; the packet's own `verify.py` (digest,
manifest, excerpt regeneration, gate spots, frames, census, model
tests, relocations) passes instead.
