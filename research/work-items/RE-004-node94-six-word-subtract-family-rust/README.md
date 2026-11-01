# RE-004: one six-word subtraction/correction family

Independent Rust reconstruction of the saved wrapper at `0x56570a0..0x56570dc`,
raw helper at `0x56570e0..0x5657169`, and high-first pair wrapper at
`0x5657180..0x56571e3`: **296 canonical bytes/82 instructions**. Exact raw
aliases at `0x56580a0..0x5658129` and `0x565ae00..0x565ae89` authenticate
another 274 bytes/78 instructions and share the same implementation. Actual
prepared-register calls enter those aliases at `0x56580bb` and `0x565ae1b`.
The 110-byte tails are inside the authenticated bodies, not extra FDEs or bytes.
All coordinates are ELF virtual addresses. This is one coherent family PR.

Component: bounded arithmetic helpers, RE-004; no gate update requested.
Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Target: node94 `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
New source is MIT; no unlicensed reference implementation was read or copied.
No dependency, Cargo workspace, pin, existing packet or gate is changed.

## Bounded result

The value relation is `(A-B+[A<B]*M) mod 2^384`, with arbitrary word values.
It is one conditional correction, with no reduced-input or canonical-modulus
claim. Raw/Prepared return corrected words in R8..R13 and masked M words in
R14/R15/RAX/RBX/RBP/RSI; full RDX is the unsigned borrow mask. Saved restores
six entry registers. Pair executes its high block first, then samples low A/B/M
from the modified image and returns the low call's values with six restores.

The [proof](PROOF.md) covers all thirteen returned registers, arbitrary partial
data aliases, unconditional correction reads, prepared entries with no A read,
high-store effects on low inputs, and arithmetic/index totality. API admission
requires nonwrapping image spans and original stack/control memory disjoint from
the data image. `None` is a new atomic refusal, not a recovered target result
or fault model. Original ABI, flags, stack bytes, concurrent/MMIO observations,
and the callers' quantity meanings remain outside this safe value projection.

The initial addition candidate `0x5658000` was rejected before any oracle
freeze or Rust: its 147 bytes exactly duplicate separately covered `0x5656980`.
`aliases-and-exclusion.json` records the actual byte equalities. No addition
code or duplicate implementation is contributed here. The earlier twelve-word
family is distinct and remains untouched.

## Static closure and provenance

`static-lock.json` binds all five complete scoped bodies, exact FDE/CIE records,
padding, and thirty complete external caller bodies (23,428 bytes). The complete
`.text` E8/E9/EB scan finds 167 actual E8 instruction boundaries: three internal
wrapper calls and 164 calls in the external caller context, including two used
prepared interiors. No E9/EB candidate appears. All 80,300 RELA records are
checked for naming addends and overlapping writers. No scoped entry has a
static table/global dependency; the only callees are included Raw calls.
External callers' other multiplication helpers are context, not reconstructed
dependencies of this scoped family. Indirect references remain open.

Thirty-five `body-*-disassembly.gnu.txt` files retain complete readable GNU
listings. Only trailing whitespace is removed; exact original stdout is in
the raw archive. Full Capstone decodes and GNU byte coverage agree on every
retained body. `observed/target.frames.txt` retains complete selected GNU
CIE/FDE records with explicit excerpt selection in `commands.json`; the
unrelated remainder of the full unwind dump is not claimed retained.

The whole-integer/snapshot-overlay oracle was frozen at
`2026-11-01T23:17:26.129535+00:00`, before the new Rust directory existed.
Its unchanged source SHA-256 is
`c8bd6e726ab8045c59a40f3cfd0a26572d6f8f03d0102816980998c55229f040`.
It computes unsigned borrow by comparing whole 384-bit integers and applies
one immutable high-output patch before deriving low input intervals. Rust
uses word-level borrow/carry loops and live mutable image accesses. No fixture
is derived from Rust or native output, and no captured instruction is executed
or emulated. `frozen/ORACLE-FREEZE.json` binds all static facts and coverage.

| Decompressed fixture | SHA-256 |
|---|---|
| Input-only records | `f0ec7150eeeac108ba3aa99a3569b66d2d79cfbfbef98cfe2621ff31943e46d0` |
| Expected observations | `6c692e9855d53df04eb976245451f7052576e2ab4366cef0f35a0ee7aee76751` |

Selection overlap checks covered 204 open PRs, zero issues and 100 recent
merges; final refresh covered 206/0/100. The only selected-address textual
match, PR#1395, names `0x56570a0` solely as its excluded callee's padding
endpoint; its claimed rule is `0x5650a60..0x5650ab8`. Full body review found no
scope overlap, and `src` has no prior implementation claim. Compressed public
snapshots and `overlap.json` preserve this decision.

## Reproduce

From repository root with pinned artifacts materialized:

```sh
python3 -O research/work-items/RE-004-node94-six-word-subtract-family-rust/validate.py --output work/node94-six-word-subtract-family/recheck
python3 -O research/work-items/RE-004-node94-six-word-subtract-family-rust/verify_recorded.py
python3 -m unittest tests.test_fde_extents tests.test_elf_index tests.test_readelf_crosscheck -v
PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH make doctor verify catalogue-check reproduce
```

Observed environment: macOS 27.0.1 arm64, Python 3.14.3, Capstone 5.0.7,
GNU objdump 2.47.20260726. Installed rustc 1.94.1 is pinned by commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1` and executable SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
The library builds directly without Cargo dependencies using edition2021,
`-Dwarnings`, opt0/opt3, overflow checks enabled, panic abort, one codegen
unit, and remapped source paths. Exact commands/tool outputs/hashes are in
`observed/commands.json` and `results.json`.

The input-only driver consumes 536-byte records (19 u64 fields plus a 384-byte
synthetic image) and emits 496-byte records (status, thirteen register values,
and all 384 image bytes). It never reads expectations. No normalization masks
are applied. Its finite record capacity is separate from the library domain.
Refusal register zeros are protocol fields, not original register observations.

## Observed qualification

All **20,577 cases per build** match at opt0/opt3, each built twice:
**82,308 exact observations**, comprising 78,748 admitted target projections
and 3,560 new-API refusals. Library, driver and output hashes are identical
between repeated builds at each optimization.

| Mode | Cases per build | Admitted |
|---|---:|---:|
| Raw | 5,012 | 4,789 |
| Saved | 5,396 | 5,173 |
| HighFirstPair | 5,157 | 4,916 |
| Prepared | 5,012 | 4,809 |
| Total | 20,577 | 19,687 |

The corpus includes all 384-bit rank boundaries with +/-1 neighbors, arbitrary
correction values, saved/prepared register values, all destination byte offsets
over five alias layouts, and image/address limits. There are 3,591 admitted
aliases, all four Pair borrow combinations, 222 changed low-A snapshots,
247 changed low-B snapshots, 284 changed low-M snapshots and twenty Prepared
admissions with absent A memory.

All 26 actually compiled wrong variants are detected. Twenty-four alter
successful admitted values; requiring Prepared A memory incorrectly refuses
twenty otherwise admitted records; the separate refusal mutation changes only
128 new-API refusal records. These last two are not successful target-value
comparisons. Representative measured differences:

| Wrong variant | Changed records |
|---|---:|
| Drop preceding limb borrow | 17,205 |
| Signed limb comparison | 17,575 |
| Keep discarded final correction carry | 9,059 |
| Store before reading B | 2,330 |
| Store before reading M | 791 |
| Pair low block first | 844 |
| Pair entry snapshot of low A | 222 |
| Pair entry snapshot of low B | 247 |
| Pair entry snapshot of M | 147 |
| Restore callee registers in raw modes | 9,598 |
| Omit wrapper register restores | 10,089 |

The M snapshot input changes in 284 Pair cases; only 147 alter outputs because
the low borrow mask can suppress correction values. All 419 static corruptions
are rejected, including scoped instructions, caller boundaries, FDE extents,
body ends, CIE, padding, naming RELAs and overlapping writers. Malformed input
exits2 without stdout. One corrupted expected byte produces exactly one
mismatch. The first complete native/static run passed without a native mismatch,
failed compile or ineffective control; no failed attempt is discarded.

`observed/raw-streams.json.gz` preserves **258 exact command streams** in
10,270,379 bytes, using base64 and lossless XOR-to-first compression for native
outputs. `verify_recorded.py` reconstructs every stream and rechecks command
hashes, full GNU bytes, fixture/source identities, actual native witnesses and
counts, mutant source transformations and repeated builds. The successful
archive audit is in `observed/recorded-audit.json`.

Focused 24 tests and `make doctor verify catalogue-check reproduce` passed;
exact compressed logs and commands are retained. Rustfmt passed. The full
staged whitespace check reports only the frozen oracle's two trailing blank
lines at EOF (exit2). Its pre-Rust bytes remain unchanged; the check excluding
only that file passes. Exact lint output and the exception rationale are in
`observed/whitespace-check.json`. The shared baseline reported
971 files/15,462 tests/69 skips, with original exit2 solely from three disk-full
errors; isolated retries of all twenty affected tests passed. This is not a
clean original sweep or a full sweep on this head. No duplicate full sweep,
Linux native qualification, hosted CI, container, captured execution, compiled
target-byte identity or whole-node equivalence is claimed. Gates remain false
where previously false. The unresolved question is the callers' intended
arithmetic domain; the source deliberately implements only the proven raw relation.

Authorship: OpenAI via Codex. Exact runtime model ID is not exposed by the
client and is not invented; parent review and publication are separate.
