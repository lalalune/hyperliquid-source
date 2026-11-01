# RE-004: twelve-word arithmetic with live correction reads

This independently authored Rust contribution closes one three-entry family:
`0x5657ce0..0x5657dec`, `0x5657e00..0x5657f02`, and
`0x5657f20..0x5657ff1`. All addresses are node94 ELF virtual addresses.
The complete FDE bodies total **735 bytes and 200 instructions**. The bounded
question is their full twelve-word result, ordered overlapping memory effects,
and thirteen final GP register observations, including saved-versus-raw returns.

Component: arithmetic helpers, RE-004 evidence without a component/milestone
gate update. Source base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Target: `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
New source is MIT. No unlicensed reference implementation was read or copied.
No dependency, root Cargo workspace, pin, existing evidence or gate is changed.

The [proof](PROOF.md) distinguishes observations, arithmetic derivation and
unknown meanings. Addition stores low words in order 0,1,2,4,3,5; each later
B word observes the preceding stores. Subtraction also reads each correction
word before the next low store. Arbitrary partial data aliases are modeled.
The API admits all raw word values with valid nonwrapping image spans and
disjoint original stack/control storage. It does not assume reduced operands
or claim canonical modular reduction. Missing spans produce a new atomic
`None`, not an inferred original result. Original fault order, flags, stack
bytes, native ABI, timing and whole-node behavior remain excluded.

## Evidence and provenance

`static-lock.json` binds every complete body, FDE/CIE byte sequence, padding
and caller site. `oracle.py` rechecks full target identity, executable mappings,
complete Capstone decodes, no callee/branch/static-data edges, all 80,300 RELA
records for entry naming and overlapping writers, and full `.text` E8/E9/EB
pattern scans. There are 108 actual E8 instruction boundaries in eight complete
caller FDEs (5,615 bytes/1,354 instructions). Caller context is authenticated,
not reconstructed; indirect references and whole-node ownership remain open.

`body-*-disassembly.gnu.txt` exports all eleven complete GNU byte listings.
Exact original stdout is retained in `observed/raw-streams.json.gz`; readable
exports remove only trailing line whitespace. `observed/target.frames.txt`
retains complete selected GNU CIE/FDE records, with explicit excerpt selection
in `commands.json`; the entire unrelated unwind dump is not claimed retained.
No target code is executed. The adjacent six-word helper at `0x5658000` and
published SIMD family ending `0x5657bbd` are excluded.

The independent whole-integer/immutable-overlay oracle was frozen at
`2026-11-01T23:03:52.111572+00:00`, before any new Rust source existed.
Its source SHA-256 is
`2d0e66a86d5b895cee955414476c580b7170a6a0eb5afb8279e3dfde902e83bd`.
It uses whole 384/768-bit arithmetic and immutable interval overlays; the
Rust uses per-word carry/borrow chains and live mutable image operations.
`frozen/ORACLE-FREEZE.json` binds the oracle, static facts and coverage.
Decompressed fixture hashes:

| Fixture | SHA-256 |
|---|---|
| Input-only records | `f56d9f55b6eedc2a352d0599fb3f67b3761776798827001c43f0d99ff1bb1a1d` |
| Expected observations | `5e5e7d920ffa92d226087eac4d564c00b94445dcb1c4d960db3ab8b447d8d84e` |

Selection overlap snapshots had 194 open PRs, zero open issues and 100 recent
merges. Final refresh had 201/0/100; no selected address/name match, and no
existing `src` claim outside the new component. `overlap.json` and compressed
public snapshots preserve the evidence. Initially restricted final GitHub
reads failed to connect; read-only retries with network access succeeded.

## Reproduction

From repository root, with pinned artifacts already materialized:

```sh
python3 -O research/work-items/RE-004-node94-twelve-word-correction-rust/validate.py --output work/node94-twelve-word-correction/recheck
python3 -O research/work-items/RE-004-node94-twelve-word-correction-rust/verify_recorded.py
python3 -m unittest tests.test_fde_extents tests.test_elf_index tests.test_readelf_crosscheck -v
PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH make doctor verify catalogue-check reproduce
```

The validator uses installed rustc 1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, compiler SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`.
Observed host: macOS 27.0.1 arm64, Python 3.14.3, Capstone 5.0.7 and GNU
objdump 2.47.20260726. Exact commands/flags/versions and executable hashes are
in `observed/commands.json` and `results.json`. The library builds directly
with edition2021, `-Dwarnings`, opt0/opt3, overflow checks enabled, panic abort,
one codegen unit and remapped source paths. There are no Cargo dependencies.

The driver reads only synthetic 488-byte input records: thirteen u64 fields
and a 384-byte image. It emits fourteen u64 status/register fields and the
384-byte image (496 bytes), never reading expected output. Valid-image length
is independently specified in the record. No normalization masks are used;
all status, thirteen register values and all image bytes compare exactly.

## Observed results

All **19,410 cases per build** matched at opt0/opt3, each built twice:
**77,640 total observations**, comprising 75,132 admitted target projections
and 2,508 new-API refusals. Each profile has 6,470 cases per entry, 18,783
admitted cases and 627 refusals. Coverage includes all 768/384 bit boundaries,
carry and borrow combinations, 3,141 admitted aliases, 865 changed live-B and
975 changed live-M observations, saved-register bit bases and address limits.
Repeated library, driver and output hashes agree within each optimization.

All 24 actually compiled wrong variants are detected. Of these, 23 change
successful admitted values; the refusal mutation only changes 72 API refusals
and is not counted as target behavior evidence. Examples:

| Wrong variant | Changed records |
|---|---:|
| Sort addition low stores | 115 |
| Snapshot high B before stores | 865 |
| Snapshot correction before stores | 563 |
| Read subtraction correction after all low stores | 148 |
| Reload A high words after stores | 865 |
| Discard low carry/borrow | 8,338 |
| Ignore global carry in addition correction | 780 |
| Restore callee registers in raw entry | 6,261 |
| Clobber callee registers in saved entries | 12,522 |

All 340 structural corruptions are rejected, including every scoped instruction,
every caller edge, each FDE extent/body end, CIE, padding, entry-naming RELA and
partial code writer. Altering one expected byte yields exactly one mismatch.
Malformed driver input exits2 with no stdout. The first complete qualification
passed; there was no native mismatch, failed compile or ineffective control.

`observed/raw-streams.json.gz` retains **198 exact command streams** in 6,076,116
bytes. The first native output is base64; later equal-width outputs use lossless
XOR-to-first plus base64. `verify_recorded.py` reconstructs every stream,
authenticates raw hashes, full GNU bytes, fixture/source identities, actual
mutant witnesses/counts and repeat identities. `observed/recorded-audit.json`
records that successful independent archive audit.

The 24 focused repository tests and `make doctor verify catalogue-check reproduce`
passed; compressed exact logs and commands are retained. The shared baseline
sweep reported 971 files/15,462 tests/69 skips, with original exit2 solely from
three disk-full errors; all 20 affected tests passed isolated retries. That is
not a clean original sweep or a full sweep on this head. No duplicate full
suite, captured execution, hosted CI, Linux native or container success is
claimed. Target machine-code byte equality is not measured. Gates remain
unchanged. The unresolved question is the callers' intended arithmetic domain
and quantity meaning; the proved relation does not assign either.

Authorship: OpenAI through Codex; exact runtime model ID is not exposed by this
client and is not invented. Parent review/publication is separate from these
local observed results.
