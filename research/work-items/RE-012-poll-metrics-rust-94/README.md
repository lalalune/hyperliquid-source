# RE-012 / node-runtime: independent Pending-poll metric Rust projection

## Question and provenance

The baseline has target-bound instrumentation evidence for the twin accept
loops, but no Rust implementation at `src/node94-poll-metrics/`. Recover the
established counter increments and last-end value for one normal Pending poll
over the explicitly bounded u64-nanosecond scalar domain.

- Base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Node94 SHA-256:
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Existing project-authored evidence/model: `tools/connections_accept_metrics_static.py`
  and `research/work-items/connections-accept-metrics-94/`.
- All addresses are ELF virtual addresses. The new Rust was independently
  authored from observations; no unlicensed inferred Rust is copied.
  Existing static discoveries are not claimed again as new discoveries.

## Evidence and implemented behavior

`evidence.json` binds the capture, maintained producer hash, fresh observations,
unique non-overlapping FDEs and complete owner-body hashes. Complete LLVM
listings cover `0x203f3e0..0x204010a` and `0x2041c60..0x204298a`, each 3,370
bytes / 663 instructions. Capstone agrees on all 6,740 bytes and 1,326
instruction boundaries after joining LLVM's contiguous standalone LOCK display
prefixes to their following instruction. No operand or byte is masked. The
listings are complete; semantic recovery is limited to the projection below.

The maintained checker binds the qword counter updates, threshold comparisons,
first-poll and wake gates, clock/difference call operands, twin correspondence,
waker table and normal Pending state/last-end writes. The new API returns
increments in this explicit observed offset order, not a claimed original
memory layout:

| Category | Count offset | Duration offset |
| --- | --- | --- |
| First poll | `0x18` | `0x58` |
| Idle | `0x20` | `0x60` |
| Scheduled | `0x28` | `0x68` |
| Fast poll | `0x30` | `0x70` |
| Slow poll | `0x38` | `0x78` |
| Long delay | `0x40` | `0x88` |
| Short delay | `0x48` | `0x80` |

First delay uses entry time since creation. Idle is counted only when the wake
value exceeds the previous poll end; a zero wake never counts as scheduled.
Delay and poll differences saturate at zero. Threshold equality chooses
long/slow. The supplied Pending-exit time becomes last-end. `apply` performs
offline modulo-2^64 addition, corresponding only to the locked qword arithmetic;
it makes no atomic-ordering or concurrent-execution claim.

The caller must establish normal clock/helper returns and that the scalar
durations and thresholds are representable u64 nanoseconds. The new API does
not silently claim wide-Duration conversion or Instant-overflow equivalence.

## Frozen comparison and controls

Before the Rust source existed, `verify.py --prepare` fixed `corpus.json` and
the evidence. Preparation refuses an existing source. A separate tuple oracle
cross-checks the maintained dict/offset model. The 22,432 cases exhaust the first
flag, five time inputs over 0/1/2/3 and both thresholds over 0/1/3 (18,432 rows),
then add 4,000 seeded full-width/edge combinations. Baseline
counters near u64 overflow make saturating/wrapping confusion observable.
Some tuples are counterfactual; original caller reachability is not asserted.

The linked harness gets inputs only, receives a projection, applies it to
nonuniform baseline counters, and reports all 14 increments, last-end and all
14 totals. rustc 1.94.1, edition 2021, warnings denied, overflow checks enabled:
debug/optimized/repeated optimized builds match every row; own optimized rlib
hashes repeat. Two own unit tests pass. Nine separately compiled controls
complete normally and are detected:

| Mutation | Mismatches |
| --- | ---: |
| Count idle on equality | 4,770 |
| Schedule without wake | 4,913 |
| Treat delay equality as short | 4,379 |
| Treat poll equality as fast | 5,523 |
| First delay uses start instead of entry | 8,857 |
| Delay subtraction wraps | 8,844 |
| Poll subtraction wraps | 8,806 |
| Counter addition saturates | 11,412 |
| Last-end uses start | 17,673 |

`results.json` records compiler, source/harness/verifier and corpus fingerprints,
decoder coverage, outputs, rebuilt library hashes and mutation results. Raw
inputs, expectations, runner outputs and command/compiler logs remain in the
ignored output directory and reproduce deterministically.

## Reproduction and validation scope

```sh
python3 -B research/work-items/RE-012-poll-metrics-rust-94/verify.py \
  --rustc /path/to/rustc-1.94.1 --output work/poll-new --controls
python3 -B -m unittest discover -s tests -p test_connections_accept_metrics_static.py -v
make doctor verify catalogue-check reproduce
make test
```

Use a new output directory. Python/Capstone 5.0.7, LLVM 23.1.4 and rustc
1.94.1 were used. All 26 existing target-evidence methods pass without skips.
Repository-wide validation is recorded in `VALIDATION.md`.

No captured code runs. This does not implement a socket, runtime, poll future,
waker, clock, original object layout/ABI, wide-time truncation or overflow-panic
path. Helper effects, concurrency, unwind, code/data/call identity and integrated
node acceptance remain open. No dependencies, stubs, shared tools/tests, pins,
progress gates or selected-byte comparison registry are changed.
