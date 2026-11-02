# RE-004: all-count six-word doubling closure

Independent MIT Rust reconstruction of four complete node94 entries:
`0x5656c40..0x5656d04` (counted), `0x5656d20..0x5656d80` (prepared step),
`0x5656de0..0x5656e57` (three steps), and `0x5656f00..0x5656fb7` (paired
three steps). The coherent closure is **594 bytes / 165 instructions**.
The prepared step is a required dependency, not a separate contribution.

Component/task: bounded arithmetic, RE-004; no progress gate update.
Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Target: node94 `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All coordinates are ELF virtual addresses. New source is MIT; no unlicensed
inferred implementation was read or copied. Existing evidence, pins, gates,
workspace/dependency structure and imports remain unchanged.

## Bounded finding

For K=2^384, one raw step is `(2X - M*[2X>=M]) mod K`, for every X,M in [0,K).
Counted uses the incoming low32 count, with zero meaning **2^32 iterations**.
Every raw state reaches either X=M or X<M within 384 steps; M=0 reaches zero.
The former is a fixed point, while the latter admits modular exponentiation.
The source accelerates large counts and separately reconstructs the exact last
uncorrected doubled limbs. It does not assume initially reduced input, equate
X=M to zero, or invent a cryptographic interpretation.

The [full proof](PROOF.md) closes the carry/borrow/CMOV relation, finite raw-state
convergence, modular arithmetic, count width, full fifteen-register observation
(except RSP), and byte aliases. PairThree stores low 48 bytes before reading high A
and M, so those reads see the modified image. PreparedStep requires only M and
supplied incoming R8..R13; A/output spans are not required. `None` is a new
atomic image-domain refusal. Stable within-block M, mapped nonwrapping spans
and valid control/stack storage disjoint from data are explicit premises.
Flags, RSP, faults, concurrency/MMIO, original ABI and caller meanings are open.

Tripling wrappers `0x5656d80` and `0x5656e60` additionally call separately
covered addition interior `0x565699b` and remain context only. Repeated-halving,
fixed thirty-step coefficient and single conditional-correction packets answer
different questions. This PR groups both fixed-three variants with the loop;
no semantic twin is split into another contribution.

## Target closure and independent expectations

`static-lock.json` authenticates four full bodies, their FDE/CIE records and
alignment bytes, plus five complete external caller bodies (1,957 bytes).
The full .text E8/E9/EB scan finds seventeen actual E8 instruction boundaries:
nine within the fixed wrappers, eight in caller context. No E9/EB candidate
or naming relocation appears. All 80,300 RELA records are checked for naming
addends and overlapping body/padding writers. Scoped entries have no RIP data
dependency; all scoped callees are the included prepared step. Other caller
callees and indirect references are not claimed closed.

Nine readable GNU listings preserve all 2,551 body bytes; only display trailing
whitespace is trimmed. Exact original stdout remains in the archive. Full
Capstone decodes and GNU byte coverage agree; selected complete GNU FDE/CIE
records are retained with their explicit excerpt selection in `commands.json`.
`exact-body-census.json` records that each scoped full body occurs once in .text.
Selection checked 216 open PRs, zero issues, 100 recent merges; final refresh
checked 222/0/100. No scoped address/semantic claim or prior src implementation
was found. Compressed public snapshots and query details remain in `overlap.json`.

The independent oracle was frozen at `2026-11-01T23:41:11.762935+00:00`, before
the Rust directory existed. Unchanged oracle SHA-256:
`ed0e700f6cd2227548714ef068ac686296a0c128fbb829d7c41cb71d1d05a9d3`.
It computes threshold residues directly from the initial whole-integer excess,
finds the first reduced state, uses Python modular power, and evaluates immutable
byte overlays. Rust instead performs a bounded limb-step prefix, wordwise
modular multiplication/exponentiation, and ordered live image stores/reads.
No fixture depends on Rust/native output. No captured instruction interpreter,
emulator or captured execution is used.

| Decompressed fixture | SHA-256 |
| --- | --- |
| 536-byte input records | `11c64c6143fa7713c68e7659ba6950fb0ac997247297c7fe25ccb223c102cc6e` |
| 512-byte observations | `4b2ed52906d582541a6ce2612807dc59c53241dbc90e0404b925f3ed144a1e6b` |

The input-only client reads 19 little-endian u64 fields followed by 384 image
bytes: member,base,A,M,destination,length,raw_count,saved[6],prepared[6]. Member
codes 0..3 select PreparedStep,Three,Counted,PairThree. It receives no expected
output or helper result. Output is sixteen u64 fields followed by 384 image
bytes: admission,RAX,RDX,RSI,RCX,RDI,R8..R11,RBX,RBP,R12..R15. Refusal register
zeros are protocol fields, not recovered original register values. The original
image suffix outside `length` stays unchanged.

## Native qualification

Pinned installed Rust 1.94.1 (commit `e408947bfd200af42db322daf0fadfe7e26d3bd1`)
builds new `no_std` source and the input-only native client at opt0/opt3, twice
each, with warnings denied, overflow checks and panic=abort. Every repeated
library/client/output hash matches at its optimization. All **19,877 cases per
build** match: **79,508 observations**, including 74,124 admitted projections
and 5,384 new-API refusals.

| Member | Cases / build | Admitted / build |
| --- | ---: | ---: |
| PreparedStep | 5,017 | 4,802 |
| Three | 5,017 | 4,646 |
| Counted | 5,018 | 4,647 |
| PairThree | 4,825 | 4,436 |
| Total | 19,877 | 18,531 |

Coverage includes all 384 ranks with +/-1 neighbors, M=0/1, X=M, arbitrary raw
states, zero/large/high32 counters, saved/prepared register bits, every output
byte offset over four alias layouts, unavailable spans and address limits.
There are 1,619 admitted aliases, 380 actual changed high-A snapshots, 285 changed
high-M snapshots, 70 counted low32-zero cases and 93 counted high32 cases.
All three possible step masks occur. Small count cases and the 383/384/385
boundary complement the accelerated huge counts.

All 32 compiled wrong variants differ. Twenty-nine change successful admitted
values. Two wrongly require Prepared A/destination memory (98/136 rejections
of admitted cases); one changes 144 API refusals only. These three are API
controls, not successful target-value observations. Representative actual counts:

| Wrong variant | Changed records |
| --- | ---: |
| Drop preceding doubling carry | 14,513 |
| Omit outer384-bit carry from selection | 6,389 |
| Only383 raw-state steps | 23 |
| Assume initially reduced | 2,917 |
| Collapse X=M sentinel to zero | 2,699 |
| Low32-zero count means one | 46 |
| Use high32 counter bits | 17 |
| Omit bit63 in modular multiply | 45 |
| Compute last auxiliaries from final state | 15,575 |
| Pair entry snapshot of high A | 380 |
| Pair entry snapshot of M | 268 |
| Preserve last mask in Counted RDX | 3,541 |

M changes in 285 input snapshots but only 268 change this mutant's output. The
full results retain all 32 transformations, source hashes and actual witnesses.
All 212 independent static corruptions are rejected. Malformed client input
exits 2 without stdout. A corrupted expected byte produces exactly one mismatch.
The first native qualification passed without a failed native compilation,
ineffective control or correct-build mismatch.

An earlier shell ENOSPC prevented harness/log creation before native execution;
`observed/initial-enospc.json` preserves a factual transcription of the tool
failure (not a claimed byte-exact unavailable stderr file). Exact frozen-equal
regenerated input copies were removed with parent authorization and hash journals;
completed archives were atomically replaced with byte-identical APFS clones.
Original frozen inputs, archives, source and failures remain retained. Neither
oracle nor Rust changed to resolve that disk failure.

`observed/raw-streams.json.gz` losslessly retains 242 exact command streams
in 8,226,660 bytes via
base64 and XOR-to-first output compression. `verify_recorded.py` reconstructs
every stream and checks exact hashes, source/fixture identities, complete GNU
bytes, actual comparisons, mutant transformations and witnesses. Selected frame
excerpts are the explicitly documented exception to whole-command retention.
The exact archive count/size and successful replay are in the recorded audit.

Focused 24 tests and `make doctor verify catalogue-check reproduce` passed;
compressed exact logs and commands are retained. Rustfmt and the complete staged
whitespace check pass. No duplicate full sweep ran.
The shared baseline reported 971 files/15,462 tests/69 skips; its original exit 2
was solely three disk-full errors and all 20 affected retry tests passed. That
is not a clean original sweep or a full sweep on this head. Linux native,
hosted CI, whole-node/ABI equivalence, compiled target-byte equality and progress
gate completion are not claimed. Callers' intended arithmetic meanings remain
open; the contributed result is the proven arbitrary-input relation.

Reproduce from the repository root:

```sh
python3 -O research/work-items/RE-004-node94-repeated-doubling-rust/validate.py --output work/node94-repeated-doubling/recheck
python3 -O research/work-items/RE-004-node94-repeated-doubling-rust/verify_recorded.py
```

Authorship: OpenAI via Codex. Exact runtime model ID is not exposed and is not
invented. Parent review/publication are separate. No captured node/visor,
networked chain, keys, secrets, copied reference implementation or emulator was
used.
