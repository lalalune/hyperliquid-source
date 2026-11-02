# RE-001: timed snapshot refresh 0x514f270 (node #94)

## Bounded question

What does node #94 function 0x514f270 do with its outer object and flag
byte: under which two mutexes, with which thresholds, when does it
rebuild the snapshot at inner+0x188 via 0x514ed50 versus only
incrementing its +0x124 field, how are its clock (+0x98) and consumer
(+0xb8) dispatch chains walked, and what does it publish under the
second lock?

## Answer in brief

The window is a mutex-guarded, throttle-gated snapshot refresh. It takes
an outer object and a flag byte; the inner object is `[outer+0x128]`
and a null inner returns immediately with no lock taken. Under mutex A
(inner+0x160) it picks a threshold pair from the flag byte — flag 0
gives (count limit 500, time limit 180000000), any nonzero flag gives
(10, 10000000) — inflates the time limit when the two timestamp fields
are stale (`inner+0x2c0 < inner+0x2c8`), then reads a clock value
through the +0x98 dispatch chain (head `[inner+0x2d8]`, sentinel cell
0x5777bc8, +0x20 links, at most 4 nodes, fourth unconditional). When
the elapsed value (clock minus inner+0x2c8) exceeds the time limit it
rebuilds the snapshot at inner+0x188 with the 0x514ed50 builder, builds
a consumer-call struct, and runs the +0xb8 consumer chain (head inner
`[[inner+0x2d0]]`, sentinel cell 0x5777a50, +0x38 links, at most 11
nodes, eleventh unconditional), then commits a fresh clock value to
inner+0x2c8 and snapshot+0x130. When the elapsed value is within the
limit it instead increments snapshot+0x124 and skips the rebuild and
the commit. Under mutex B (the inner object itself) it publishes the
0x138-byte snapshot to inner+0x28, with the string slot copied by
`_M_assign` instead of a raw copy, then unlocks B and A in that order.

## Evidence

The packet holds semantic records only (`records.json`); instruction
detail lives in the raw disassembly excerpts, kept verbatim and
whole-function. The mnemonics in those excerpts (including `endbr64`
at every function entry) are genuine instructions present in the
target binary, not placeholders: `verify.py` regenerates every excerpt
byte-for-byte from a fresh objdump run and re-checks the SHAs, the
call targets, the sentinel resolutions, the PLT GOT slots, the caller
census and the landing-stub jumps.

- `window.objdump.txt` — whole function 0x514f270..0x514f719 plus its
  one int3 padding byte.
- `cleanup.objdump.txt` — the exception cleanup routine
  0x514f224..0x514f26d plus its three int3 padding bytes, with its
  three entries (callback + A unlock, A unlock only, both unlocks).
- `ctor.objdump.txt`, `timestamp_set.objdump.txt`,
  `counter_inc.objdump.txt` — the three small callees 0x514def0,
  0x514df30, 0x514df40 with their int3 padding.
- `snapshot_callee.objdump.txt` — the snapshot builder 0x514ed50, bound
  by the RE-001-snapshot-identity-format-94 packet, cited here as a
  callee only.
- `caller.objdump.txt` — sample around the 0x514fda5 call site: the
  flag setup, the window call, and the caller's post-call read.
- `frames.txt` — the FDE records for all six functions above.
- `relocations.txt` — the PLT stubs and GOT slots used by the window
  and its cleanup routine.
- `verify.py` + `export_excerpts.py` — the verification code and the
  excerpt generator, committed in the packet.

## Target binding

All results bind to one artifact SHA-256 from
`provenance/artifacts.json`: node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
work copy `work/hl-node-94.bin`. Environment limits, stated honestly:
this VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so the
model is a Python reconstruction of established semantics, not an
execution of the target binary; the clock and consumer values are
taken as parameters because their runtime contents are not retained
locally.

## What is NOT claimed

The identities of the outer/inner objects, the wrappers, the clock
object and the consumers; the meaning of the flag byte to its callers;
the reason the stale path inflates the threshold; the meaning of the
consumer struct's +0x10 callback and of the qword 0x100 passed beside
it; why the commit clock call skips the chain walk; which call site
each landing stub serves. See `unknowns` in `records.json`.
