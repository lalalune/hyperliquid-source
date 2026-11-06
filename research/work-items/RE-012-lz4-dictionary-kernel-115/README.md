# RE-012: node #115 conditional LZ4 dictionary probe in Rust

Target Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `05bc2de303c05525b71e7e257426e741bc66a390`, transport / RE-012.
All addresses are ELF virtual addresses, no rebasing and no normalization.
New Rust and research use MIT. The original static evidence and verifier are
reused under the repository MIT license from author 0xQueenQ's
[PR #2771](https://github.com/lalalune/hyperliquid-source/pull/2771), head
`8ede1e78eb0b18d0faeb5dea619a566b73d4221c`; no unlicensed inferred source or
public codec implementation was consulted or copied.

## Gap and deliverable

The base has no buildable implementation of the compressor dictionary probe;
#2771 established static semantics only. This change adds a real dependency-free
Rust crate at `src/node115-lz4-dictionary-kernel`, with a caller-owned typed
4096-cell table and the two conditional probe entry points. It preserves hash
widths, store truncation, store-before-rejection, guard distinctions, and the
large arm's four-byte comparison. It is useful as the candidate lookup unit of
a future compressor; it is not a replacement for the whole compressor.

The existing static packet's two full FDEs are retained here so this PR can be
reproduced independently of an unmerged PR: `0x477e950..0x477f036` and
`0x477f040..0x477f746`, 3,564 bytes / 809 instructions. Those bytes are repeated
context, not new coverage. `verify.py` freshly authenticates them against the
retained target, checks their actual unwind records, GNU/LLVM/Capstone complete
partitions, calls, branches, relocation writers, and eight instruction anchors.
It rejects two identity corruptions and eight actual anchor-byte corruptions
without executing mutated instructions.

## Established semantics and implementation boundary

| Observation | Evidence | Rust behavior |
| --- | --- | --- |
| Small index is low32(LE32 * 0x9e3779b1) >> 20 | 0x477eab4..0x477eac1 | `small_bucket`, 4096 u16 cells |
| Large index is low64(LE64 * 0xcf1bbcdcbb000000) >> 52 | 0x477f1a4..0x477f1bd | `large_bucket`, 4096 u32 cells |
| Old cell load precedes current-position truncated store | 0x477eac1..0x477eacb; 0x477f1bd..0x477f1c5 | Table mutated before `judge`, even on rejected candidates |
| Current absolute minus old candidate borrow | 0x477eacb..0x477ead4; 0x477f1c5..0x477f1ce | Logical `CandidateAhead` boundary after mutation |
| Candidate minus saved origin borrow | 0x477ead4..0x477eae1; 0x477f1ce..0x477f1db | `BeforeOrigin` miss after mutation |
| Distance >= 65536 rejects | 0x477eae1..0x477eaea; 0x477f1db..0x477f1e8 | `TooFar`; 65535 and zero are not rejected by this condition |
| Four-byte equality even in large arm | 0x477eaf7; 0x477f1f5 | Four-byte compare, not eight |

The outer loop first checks position <= source-end-minus-12, then checks the
addition of saved origin and position before the hash load/store
(`0x477ea90..0x477eab4`, `0x477f180..0x477f1a4`). The safe API enforces this
source-position domain before touching the table and returns `AbsoluteOverflow`
for the checked addition failure. `InvalidPosition` is expressly an adapter
rejection, not a recovered native error.

A useful closure result follows from these guards. After old <= current and
old >= origin, old-origin <= position. In the accepted source-position domain,
`candidate_relative + 4 <= position + 4 <= source_end - 8`. Thus the candidate
bounds failure helpers at the later +4 checks are unreachable for inputs this
API accepts. We neither add a synthetic reachable native error nor claim a
negative fixture exercises those failure helpers. The proof is conditional on
the established loop-entry domain, not on a guessed allocator contract.

The multiplier's 24 trailing zero bits mean the large hash's high three loaded
bytes have no effect. The source still performs the established eight-byte
load. Original table initialization, source types, startup arm and skip loop
are outside this implementation. No zero-filled table is silently supplied.
Native failure-helper objects, register ABI, pointer provenance, match
extension, literal emission and complete compression are not reconstructed.

## Independent expectations and actual qualification

`oracle.py` is independently written branch mathematics from the pinned
instruction fields. It is not an instruction evaluator. Its 32,608 case rows
were frozen in `cases.tsv` **before the new Rust directory existed**;
`freeze.json` records that fact and the exact file/oracle hashes. It does not
consult production Rust or run a captured function. The input generator uses
eight-byte synthetic repeated patterns, not user data. Cases cover both table
widths, current/candidate/origin boundaries, small/large stored truncation,
hash changes, zero distance, 65535/65536 distance, differing four/eight-byte
prefixes and safe adapter rejection. The fixture hash is
`61dfa96e3290e7a7b5828d168482bfb1f47e24e2ff3d5aa70b4c2e8966b83568`.

`qualify.py` reconstructs the independent frozen relation and compiles/runs the
actual crate at debug and release optimization. Its host probe checks actual
caller table storage and that all 4095 other buckets remain unchanged; adapter
rejections preserve the entire table. Seven compiled production mutations
attack both hash constants, the distance threshold, four-versus-eight compare,
zero-distance handling, large stored width, and store-only-on-success. Original
stdout/stderr and each actual mutant build are retained in ignored
`work/environment/ten-tasks/dictionary-kernel/qualification/`. A store-order
mutation can be caught by a failing table-state assertion rather than normal
output mismatch; the exact exit is recorded, not relabeled as success.

Reproduce from repository root after selecting the documented pinned environment:

```
python3 -B research/work-items/RE-012-lz4-dictionary-kernel-115/verify.py
python3 -B research/work-items/RE-012-lz4-dictionary-kernel-115/qualify.py
cargo +1.95.0 fmt --check --manifest-path src/node115-lz4-dictionary-kernel/Cargo.toml
cargo +1.95.0 clippy --all-targets --offline --locked --manifest-path src/node115-lz4-dictionary-kernel/Cargo.toml -- -D warnings
cargo +1.95.0 build --lib --offline --locked --release --target x86_64-unknown-linux-gnu --manifest-path src/node115-lz4-dictionary-kernel/Cargo.toml
```

Only newly compiled independent Rust executes on the host. The Linux rlib is
built but not executed; no captured execution/emulation, networking, chain
traffic or ABI/binary identity claim occurs. This is a conditional semantic
implementation, not target execution equivalence. All full-scope gates and
compiled-byte coverage remain unchanged. Next establish initialization and
carry these typed table effects into the complete match-extension/emission path.
