# RE-004: node94 packed-date addition in Rust

This contribution resolves the complete converter body at
`[0x151f870,0x151fa9c)` that `foundation-days-to-date-94` explicitly excluded.
Its bounded result is independently authored `no_std` Rust for valid packed
date representations and every signed i32 day offset. It proves that the
normal result is the new packed date or zero when the result is outside
`-262143..=262142`, while preserving the effect of the original i32 overflow
checks. It does not interpret the outer checked wrapper as the same function.

Target: node #94, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
All addresses are ELF VAs. Base commit:
`56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. Reference pin
`999556f6e0a474b8312db96ec3149e1c44e97c23` stays unchanged; its unlicensed
implementation was not read or copied. Provider/client: OpenAI / Codex. The
exact model identifier is not exposed in this session.

## What is established

The helper reads the low 32 bits of EDI as a signed 19-bit year, a 9-bit
one-based ordinal and a 4-bit year flag. It reads ESI as signed day offset;
it does not consume the outer wrapper's computed RCX. The valid input domain
requires the exact year bounds, Gregorian ordinal bound and table-derived
flag nibble documented in [PROOF.md](PROOF.md). `InvalidPackedDate` is a new
safe-API refusal outside that domain, not an inferred original outcome.

The complete 556-byte body has 145 decoded instructions. The actual FDE is
at `.eh_frame+0x15094`, with 4 separate int3 bytes after its endpoint. Both
Capstone and GNU decode the complete selected body. The record PC/range and
CIE linkage are rechecked, not inferred from next-start spacing.

The two table edges are closed: all 401 leap-prefix bytes at `0x250354` and
all 400 flag bytes at `0x2504e5` match independently generated arithmetic
identities. Their relocation absence is checked. The five panic arms and
source-location records are retained, with precise slots and RELATIVE addends:

| Call sites | Slot | Relocated target |
| --- | --- | --- |
| 0x151fa55, 0x151fa62 | 0x576e150 | 0x157b520 |
| 0x151fa74, 0x151fa89 | 0x576dfc8 | 0x157b64f |
| 0x151fa96 | 0x576e118 | 0x157b480 |

The proof excludes every panic call on admitted inputs. These target
implementations are not executed or transitively reconstructed. Five location
records at `0x5672140..0x56721b8` and their two referenced artifact path
strings are locked. Those paths are binary provenance, not operator files.

A full `.text` E8/FF15/FF25 pattern scan retains 150 incoming candidates and
all RELA records are scanned for pointers naming the callee. There is one
naming slot, `0x576e8b0`. Three representative caller sites are independently
qualified by decoding from their complete FDE starts:

| Complete caller body | Site |
| --- | --- |
| [0x13c8f60,0x13c907a) | 0x13c8ff7 |
| [0x1450810,0x145085b) | 0x1450836 |
| [0x151d080,0x151d1a4) | 0x151d143 |

The other pattern candidates remain unqualified; this is not a complete xref
census or a reconstruction of the callers. The direct and indirect bytes,
full caller hashes, actual FDE/CIE records and independent GNU exports are
retained. Register-indirect uses and other pointer paths remain unknown.

## Proof and independent expectations

Before Rust existed, the oracle and expectations were frozen at
`2026-11-01T21:04:45.912819+00:00`; oracle SHA-256 is
`1ac6cb0ed5a8b440ee78338b732e572247c2b2f145593c4ff39ccec41be65c6e`.
The oracle uses a generated 400-year prefix partition and Euclidean cycle
arithmetic. Rust instead computes a closed global serial-day formula and
binary-searches the entire admitted year range. The input-only native client
has no expected results or target instruction bytes.

The proof covers fast-path field preservation, signed reciprocal division,
positive i32 overflow rejection, negative-year normalization, all cycle
corrections, output-year range and final ordinal/flag validity. Arithmetic
certificates exhaust all 146,097 possible normalized cycle days, including
19,600 decrement corrections, and verify full-domain reciprocal inequalities.
These are integer identities, not captured instruction execution/emulation.

Frozen fixtures include every normalized cycle destination day; leap/century
boundaries and negative years; first/last admitted years and days; extreme i32
offsets and overflow; all 16 flag nibbles on selected ordinals/years; malformed
ordinals; and deterministic random cases. The 348,734 cases comprise 300,328
nonzero accepted results, 38,465 accepted-domain zero results and 9,941 new
API refusals. Proof extends beyond these samples; the full input space is not
claimed to have been exhaustively executed.

## Observed validation

All **348,734 cases** match in each of four native opt0/opt3 repeat builds.
Same-optimization library, executable and stdout hashes repeat exactly. All
14 separately compiled and executed wrong variants produce mismatches:

| Wrong variant | All differing rows | Differing admitted rows |
| --- | ---: | ---: |
| Drop century correction | 328042 | 327756 |
| Drop 400-year correction | 290910 | 290659 |
| Truncate negative year division | 233485 | 233337 |
| Wrong year-zero origin | 204681 | 204571 |
| Treat delta as unsigned | 74271 | 74271 |
| Truncate delta to i16 | 242968 | 242968 |
| Ignore delta | 333081 | 333081 |
| Reject first admitted day | 5712 | 5712 |
| Allow first excluded day | 5712 | 5712 |
| Exclusive year partition | 24235 | 24235 |
| Zero-based output ordinal | 300328 | 300328 |
| Preserve input flags in result | 234353 | 234353 |
| Ignore flag admission | 5041 | 0 |
| Allow ordinal zero | 46 | 0 |

The last two test the **new API's refusal policy only**; they do not establish
original behavior on invalid packed representations. Counterexamples and
both counts are separately audited in `observed/selected-controls.json`.
A changed expected row produces exactly one comparator mismatch. All 55
structural corruption controls reject after bypassing only the identity gate,
exercising body, flags, tables, actual frames, callers, slots, locations and
relocation checks. None is counted as a native wrong-variant execution.

Focused legacy days-to-date tests: **10/10 pass**. `rustfmt --check`,
`make doctor verify catalogue-check reproduce`, optimized-Python static and
recorded-stream verification pass. No duplicate full-suite run or hosted CI
result is claimed. Target machine-code equality is not measured and the
original ABI is not reproduced. This is one function's validated numeric
projection, not a foundation completion gate or full node reconstruction.

## Reproduce and retention

From the repository root with pinned submodules/LFS artifact materialized:

```sh
python3 -O research/work-items/RE-004-node94-packed-date-add-rust/validate.py
python3 -O research/work-items/RE-004-node94-packed-date-add-rust/verify_recorded.py
python3 -m unittest tests.test_foundation_days_to_date -v
PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH make doctor verify catalogue-check reproduce
shasum -a 256 -c research/work-items/RE-004-node94-packed-date-add-rust/MANIFEST.sha256
```

The standalone compiler is rustc 1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, LLVM 21.1.8; host is macOS
27.0.1 arm64, Python 3.14.3, Capstone 5.0.7 and GNU binutils
2.47.20260726. `validate.py --rustc ... --objdump ... --output ...` allows
installed executable paths while retaining the exact compiler lock.

`observed/commands.json` records exact command arguments (repository prefix
normalized to `/repo`), outcomes and raw stream hashes. The deterministic
`raw-streams.json.gz` retains **120 exact stdout/stderr streams** as base64
with their individual SHA-256 hashes. The verifier reconstructs and checks
every stream and every native mismatch count. No original streams are silently
normalized. Readable GNU text strips trailing whitespace only, a transformation
checked against the exact archive. The huge GNU frame output is explicitly
retained only as the selected actual CIE/FDE records in `target.frames.txt`.

`observed/repository-checks.json.gz` retains successful focused/global command
output with only local path prefixes sanitized, recording both original and
retained hashes. `MANIFEST.sha256` binds every new source/evidence file except
itself and Python cache files. Ignored work output is reproducible and is not
a substitute for the retained raw evidence.

Live PRs/issues/recent merges and local source were checked before selection
and again before submission, with no overlap; `overlap.json` records counts,
terms and snapshot hashes. Only the new source and evidence directories are
added. Pins, prior evidence, generated catalogues and progress gates remain
unchanged. New code/docs are MIT; imported static bytes/disassembly retain the
artifact's rights. No unlicensed implementation was read or copied. No captured
binary, emulator, live node, chain, keys, secrets or networked runtime was used.
The remaining boundary is invalid representations and the surrounding caller
and panic behavior; this packet makes no claim for those paths.
