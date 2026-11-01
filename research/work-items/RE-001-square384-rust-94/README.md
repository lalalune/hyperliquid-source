# RE-001: complete node94 scalar 384-to-768-bit square

This packet recovers the full 528-byte scalar square in independent safe
`no_std` Rust. It computes the exact 768-bit square of every six-u64 input,
preserves all fourteen written GP observations, and applies the twelve stores
under arbitrary admitted input/output aliases. It closes a concrete numeric
implementation gap without changing a component completion gate.

## Target, bounds and closure

- Node94 `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base/source revision `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`;
  unchanged reference gitlink `999556f6e0a474b8312db96ec3149e1c44e97c23`.
- RE-001 bounded arithmetic reconstruction. Coordinates are linked ELF virtual
  addresses; the complete selected body is `[0x565b800,0x565ba10)`.
- Source: [node94-square384](../../../src/node94-square384/README.md).
  Final `lib.rs` SHA-256:
  `7eda896048279f6bb0b512ea9c8f8e5319d19b97b373ce7bbd68b6fd53a71e59`.

The full 528-byte / 160-instruction body and four complete caller FDE contexts
are decoded independently by GNU and LLVM. All five windows total 1,116 bytes /
304 instructions; the external contexts contribute 588 bytes / 144 instructions.
[Static records](static/records.json) retain every byte, exact raw FDE/CIE records,
full decoder partitions, 16 following padding bytes and the adjacent FDE.
The complete 121,299-FDE / 3-CIE inventory proves unique exact bounds with shared
CIE `0xce1518`.

| Incoming E8 | Complete caller context | Bytes |
| --- | --- | ---: |
| `0x565b7c2` | `[0x565b7a0,0x565b7ec)` | 76 |
| `0x565ba54` | `[0x565ba20,0x565ba9a)` | 122 |
| `0x565c966` | `[0x565c920,0x565c9ce)` | 174 |
| `0x565ca26` | `[0x565c9e0,0x565cab8)` | 216 |

Complete .text E8/E9 scans into every byte of the selected interval find only
those four instruction-qualified entry calls. All 80,300 RELA records have no
selected-interval naming addend or writer overlapping bound code. The scalar
body has no call, branch, RIP-relative literal/table, import or unknown helper.
All data reads are the supplied six words. Caller contexts establish incoming
boundaries only; their other helpers and algorithms remain outside this packet.
There is no complete computed/indirect reachability claim.

[Scope-selection records](scope-selection.json) distinguish a related ADX body
at `[0x5658a00,0x5658c02)`, which reloads input between stores and uses a custom
stack output address. Its alias/register/stack relation is not reconstructed or
counted here. The scalar body has one exact occurrence in .text; that is not an
exhaustive semantic census or all-square-variants claim. A proposed 48-step loop
was rejected as the same transition as an existing 30-step contribution.

## Universal arithmetic and memory relation

[PROOF.md](PROOF.md) derives the identity `A^2 = 2K+D`, with K the off-diagonal
cross polynomial and D the diagonal-square polynomial. Every product and carry
chain is accounted for, including all high halves. Pair carries are at most 2.
A square's low word is 0 or 1 modulo 4, so adding such a carry cannot overflow;
this proves why several target additions may safely have their flags replaced
before the next carry use. No small-limb or reduced-input assumption is needed.

The final result contains all twelve square words and all fourteen written GP
values. R9/R11/R12 retain low-diagonal-plus-carry intermediates, R13 the carry
entering word 10, R8 a specific partial cross-row carry, and RBP the wrapped
final doubled cross digit. RSI is the last input word, not the original pointer.
The proof supplies each exact formula. Unchanged RDI, flags, native ABI and
return/control state are outside this projection; no register mask is applied.

All six loads finish before the first output store at `0x565b870`, and no input
is read afterward. Thus one complete 48-byte snapshot preserves all exact,
partial, cross-limb and unaligned data aliases with the 96-byte destination.
Only destination bytes change. The safe image API requires ordinary stable
little-endian nonwrapping spans, with image end at most 2^64, and valid separate
return/control storage. It admits exact-end accesses. Invalid spans refuse
before any store and leave the image unchanged; this is an added API policy,
not native fault-order emulation. MMIO, races, volatile effects, faults, control
aliases and arbitrary wrapped pointer layouts are excluded. The pure value API
retains all 2^384 inputs independently of any mapping.

## Independent frozen expectations

The [oracle](oracle.py) computes one unbounded integer square, whole cross
polynomials, quotient/remainder carries and base-B output digits. Its image
expectation writes one whole square into a copied image. It does not execute
instructions, import Rust or mirror source limb carry loops. Rust instead uses
a cross-product word array and paired u128 column sums.

The [freeze](fixtures/freeze.json) was made at
`2026-11-01T23:33:36.438344+00:00`, with the Rust source directory absent. Its
9,592 unchanged cases comprise 8,447 pure values and 1,145 images. Each correct
build admits 9,474 cases and refuses 118. Coverage includes all 4,096 six-limb
0..3 tuples, 64 zero/max patterns, 1,152 single-limb bit boundaries, 735 cross
product boundaries, 2,400 full-width random inputs, 603 overlapping and 410
disjoint image cases, exact-end/range cases and wrapping-image refusals.
There is no post-source supplement.

- Raw input SHA-256:
  `2e7d1cf3c42f9c1410139b7c2d3e16a99e226004b9023982a2a79cbd428d1395`.
- Raw expectation SHA-256:
  `45daea73f95920b04cb766709eaa927aa09e54c7a7d701295a240fcae8dbea78`.
- Oracle SHA-256:
  `ba6b2cdc7919ae6b4395ef085e13ab96a2c036f04e9e904136b1a4ca204724c9`.

Rust 1.94.1 on macOS arm64 produced four input-only correct builds: opt0 and
opt3, each repeated. All 9,592 × 4 = 38,368 outputs match exactly (37,896 admitted
observations and 472 safe refusals). The comparator checks all fourteen full GP
values, all twelve output words, every final image byte, refusal status, IDs and
order without normalization. Same-option library/client artifact hashes repeat
identically. All 35 compiled mutant programs exit normally and differ, covering
cross-product halves/propagation, diagonal terms, doubling, carries, each raw
register mapping, endianness, pre-snapshot stores and atomic refusal. All 178
static corruptions reject, including every selected instruction, four caller
edges, all five FDEs, CIE, padding, extra E8/E9/RELA records, overlapping unrelated
FDE, adjacent FDE and full target SHA. Five comparator controls and two archive
controls also reject. All 39 exact native stdout streams are retained.

[Final result](native/result.json), [commands](native/commands.json) and
[qualification log](native/qualification.log) retain exact outcomes. The
input-only native client never receives expected outputs. Original stdout
streams are retained in [native/raw-streams.json.gz](native/raw-streams.json.gz)
as a deterministic lossless shared-line archive. Each stream retains its exact
label, order, newline bytes, byte count and SHA-256; every reconstructed raw
stream is hashed. Storage deduplication is not comparison normalization.

[The initial static-control failure](initial-static-control-failure/) is kept.
The FDE immediately after the square is also one of the bound callers. Its
corrupted range was correctly rejected earlier as `caller_1 FDE overlap`, while
the harness expected the later `next FDE bytes` check. Qualification stopped
before any native compilation/output. Only that expected error label changed,
then the full qualification was rerun. Source, oracle, fixtures and the static
verifier stayed fixed. [Mutation preflight](mutant-preflight.json) separately
retains all 35 metadata builds; effective-control evidence comes from actual
native execution of the deliberately wrong Rust, not compilation alone.

[The interrupted parent replay](parent-disk-failure/) is also retained. At
committed head `5b7d841bf330408372669bc378efe566da618796`, it completed all four
correct builds and 28 effective mutant runs before macOS `ld` failed with
`write() failed, errno=28` while linking the `big-endian-store` mutant client.
The failed link is not an effective control or a completed replay. All 32
completed stdout streams, the exact 66-command partial log, compiler failure
and failing source snapshot are preserved. Disk recovery did not change source,
oracle, fixtures or validator.

At the parent's request, the worker then completed a fresh-directory optimized
retry with those committed executable files unchanged. [Retry evidence](parent-retry/)
records exit 0, all 9,592 × 4 correct outputs, all 35 effective mutants and all
178 static / 5 comparator / 2 archive controls. Its result JSON and complete
39-stream raw archive are byte-identical to the original complete qualification;
the shared raw archive is retained once with both run records. This does not
convert the earlier interrupted parent process into a completed independent run.

## Reproduce and check scope

From the repository root with pinned inputs materialized:

```sh
python3 -O research/work-items/RE-001-square384-rust-94/verify.py --out work/square384-replay
python3 -O research/work-items/RE-001-square384-rust-94/verify.py --check-archive
cargo +1.94.1 check --locked --offline --manifest-path src/node94-square384/Cargo.toml --all-targets
cargo +1.94.1 fmt --manifest-path src/node94-square384/Cargo.toml -- --check
```

[Check commands](checks/commands.json) and raw logs record 22 focused ELF/FDE
tests, Cargo/rustfmt, doctor, verify, catalogue-check and reproduce, all passing.
GNU binutils and rustup were placed on PATH for the global checks; actual tool
versions and submodule state are retained in [tool versions](checks/tool-versions.json).
The component has no third-party dependency or node integration.

The separate shared base sweep covered 971 files / 15,462 reported tests / 69
skips. Its aggregate exit 2 came only from three disk-full errors; all 20 affected
tests passed isolated retry. That is not a clean aggregate rerun or full-suite
qualification on this head. No captured execution, instruction emulator, Linux
differential, container, hosted CI, byte identity, whole-node equivalence or
completion gate is claimed. Only new source/evidence paths change.

[Live-overlap records](overlap/summary.json) retain initial 212 and final 218 open
PRs, zero issues and 100 recent merges at each check, plus the empty current-main
source-address search. No selected-range claim was found; other active
reservations were excluded. Imported evidence, pins and progress remain unchanged.

New implementation and documentation are independently authored under MIT by
신준. Captured artifacts retain their existing rights/provenance. No unlicensed
inferred implementation was read or copied. Provider OpenAI; client Codex;
exact model identifier unavailable and not invented. This bounded packet and
the retained replay evidence do not advance broader node gates.
