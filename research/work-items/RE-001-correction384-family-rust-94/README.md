# RE-001: complete 384-bit single-correction addition family

This packet recovers three complete node94 bodies and their actual interior
entry as independently authored safe `no_std` Rust. The core forms a 385-bit sum,
conditionally subtracts an arbitrary 384-bit correction once, and preserves its
full auxiliary register results. The ordered pair wrapper writes its high block
before reading its low block, including any operands changed by overlapping
stores. This closes an implementation gap; no component completion gate changes.

## Identity and selected closure

- Target: node94 `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source/base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference gitlink
  `999556f6e0a474b8312db96ec3149e1c44e97c23`, unchanged.
- Task: RE-001, bounded numeric helper and actual wrappers. Coordinates are
  linked ELF virtual addresses, with file offsets resolved from ELF sections.
- Source: [node94-correction384-family](../../../src/node94-correction384-family/README.md).
  Final `lib.rs` SHA-256:
  `14329b8ad758f1d1da0fbbff0700f95e19e4403896b5b1941a15c26cb7119a0a`.

| Selected body | Complete interval | Bytes | Instructions |
| --- | --- | ---: | ---: |
| Core | `[0x5656980,0x5656a13)` | 147 | 40 |
| Single wrapper | `[0x5656940,0x565697c)` | 60 | 17 |
| Ordered pair wrapper | `[0x5656a20,0x5656a83)` | 99 | 26 |
| Total | Three complete FDEs | 306 | 83 |

The three real calls to `0x565699b` enter the core after its initial input loads.
This is an actual instruction-boundary interior entry within the complete core,
not another complete FDE. The API supplies its six arbitrary R8..R13 words
independently. Its first ADD overwrites incoming carry; the unused incoming RSI
requires no mapping. Other overwritten entry-register values are unrestricted.
The proof does not impose consistency with any known caller or reduced operands.

GNU and LLVM decode the selected closure and all 41 external caller FDEs.
The 44 bound windows contain 32,780 bytes / 8,087 instructions: selected bodies
306 / 83, external caller contexts 32,474 / 8,004. The complete executable text
census finds 146 E8 sites (3 core, 3 interior, 51 single, 89 pair) and one E9
site (`0x564680a` to pair), each checked at an instruction boundary. Forty-three
caller-containing windows include the two selected wrappers. These contexts
establish incoming boundaries, not their unrelated algorithms. The early scout's
hand-summed 144-call description was corrected to the actual 146 before Rust;
the exact site inventory is retained in [static records](static/records.json).

The full 121,299-FDE / 3-CIE inventory establishes exact unique selected bounds,
shared CIE `0xce1518`, complete raw records and adjacent alignment gaps. All
80,300 RELA records are scanned: no selected-entry naming relocation or bound
code writer exists. The selected closure calls only the bound core; it has no
static RIP-relative data, import, table or other helper dependency. Supplied
operand memory is explicit. The adjacent `0x5656aa0` halving FDE is boundary
context only. Absence of E8/E9/RELA references does not exclude computed indirect
references. Both full disassemblies, commands and tool versions are retained.
Parent review separately identified the byte-identical 147-byte core copy at
`[0x5658000,0x5658093)`. It is outside this selected implementation/qualification
closure and is not counted as an additional recovered body here. This packet
does not claim an exhaustive census of equivalent bodies.

## Established relation and safe domain

[PROOF.md](PROOF.md) derives the relation for every unsigned 384-bit A, B and C.
Writing Q=2^384 and S=A+B, the six output words represent
`(S-C*[S>=C]) mod Q`. The subtraction occurs at most once; C=0 and unreduced
inputs remain valid. This is not an assumption of general modular reduction.
The core also returns all seven other written GP values. RAX/RSI/RBX/RBP/R14/R15
retain sum words 2/5/3/4/0/1. RDX equals the negative of the sum of addition carry and subtraction
borrow, namely `-(carry+borrow) mod 2^64`; the borrow compares low384(S)
with C. Its possible values include `2^64-2`.

Each core call reads all operands before storing. The single wrapper returns
nine selected full register values while restoring six entry-dependent saved
registers, explicitly outside its tuple. The pair performs high48 first, then
loads low48 and the shared correction from the changed image. Its second call
supplies the returned observations. There is no carry connecting the blocks.

The safe image API admits every data overlap under explicit valid nonwrapping
48/96-byte spans, stable ordinary little-endian memory, and separation from
native saved-register/return/control storage. Byte alignment is unrestricted;
the exclusive image end may equal 2^64. All spans are checked before stores, so
refusal leaves the whole image unchanged, including when a pair's later span is
invalid. This refusal is an added safe-API behavior. Native pointer ABI, faults,
MMIO, volatile effects, concurrency, stack aliases, flags and timing are outside
the projection. Unknown source, library or cryptographic identity is unclaimed.

## Independent expectations and native qualification

The unbounded-integer [oracle](oracle.py) computes the whole sum and a single
conditional whole-integer subtraction. Division/remainder extracts words;
mathematical comparisons compute the raw carry/borrow observation. Its copied
image relation applies whole-integer high-then-low updates. It neither imports
Rust nor interprets instructions or mirrors the source limb borrow chain.

[Freeze record](fixtures/freeze.json) was written at
`2026-11-01T23:07:39.617974+00:00`, while the Rust source directory was absent.
The original 6,703 cases remain unchanged: 3,289 pure core, 743 interior-entry
image, 731 full-core image, 738 single wrapper and 1,202 ordered pair cases.
Coverage includes all four carry/borrow combinations, 1,573 alias cases, 1,389
disjoint cases, 112 wrapping-image cases and 340 range refusals. Category counts
may overlap. No post-source supplement was added.

- Raw input SHA-256:
  `fe762cdfbd9c27e0cb948d2b6799ea3dcb810140d3595a3ca8128c3b635c7349`.
- Raw expectation SHA-256:
  `8f27f51c5ca7138bb59730c94110f0e5092b6dafd5439e82e7d5c0ce947ba4c0`.
- Oracle SHA-256:
  `0583dcfb04d35d81ab01bf442a2cfb3112b3bae11c4dd0423511bd5d7ae9151b`.

The input-only client receives inputs, never expected results. Rust 1.94.1 on
macOS arm64 builds opt0 and opt3 twice each: 6,703 × 4 = 26,812 complete outputs
match exactly. Both repeated library and client artifact hashes match at each
optimization level. The comparator checks full 13-value core or 9-value wrapper
tuples, every image byte, refusal status, order and IDs without normalization.
All 37 compiled mutants terminate normally and produce observable differences,
including carry/borrow, raw auxiliary registers, interior register input,
endianness, early stores, pair order, stale correction/input snapshots, wrong
last-call registers and refusal mutation. The 181 static corruption controls
exercise every selected instruction, incoming caller representatives, all bound
FDEs, CIE, gaps, extra E8/E9/RELA records, unrelated-overlapping FDE and full SHA.
Five comparator and two archive controls also reject their corruption.

[Final result](native/result.json), [commands](native/commands.json) and
[qualification log](native/qualification.log) retain the exact outcomes.
[native/raw-streams.json.gz](native/raw-streams.json.gz) is a deterministic
lossless shared-line archive of all 41 original stdout streams. Each stream
retains its own byte count, SHA-256, order and newline bytes; the line dictionary
is storage compression, not comparison normalization. The verifier reconstructs
and hashes every raw stream and tests archive corruption.

Two control-construction failures are retained rather than counted as effective
mutants. [Initial compile failure](initial-mutant-compile-failure/) preserves
four matching correct runs and 19 effective mutants as 23 exact archived streams,
then a deliberate wrapper-pointer mutant rejected by `-D warnings` because it
made a parameter unused. Only the mutation expression was repaired. A later
metadata preflight rejected the strict-less-than image-end mutant because `<`
after a cast parsed as generic arguments; the equivalent bad bound was rewritten
as `<= 2^64-1`. [Preflight failure](initial-mutant-preflight-failure/) retains
that exact source/error and a subsequently interrupted replay: the shell had
continued after preflight failure, and the replay was stopped during static
checks before any native compilation or output. [The repaired preflight](mutant-preflight.json)
compiled all 37 mutations. The final full replay above then executed all of them.
Base Rust, oracle and fixtures never changed during these control fixes.

## Reproduction and checks

From the repository root, with the pinned target and submodules materialized:

```sh
python3 -O research/work-items/RE-001-correction384-family-rust-94/verify.py --out work/correction384-family-replay
python3 -O research/work-items/RE-001-correction384-family-rust-94/verify.py --check-archive
cargo +1.94.1 check --locked --offline --manifest-path src/node94-correction384-family/Cargo.toml --all-targets
cargo +1.94.1 fmt --manifest-path src/node94-correction384-family/Cargo.toml -- --check
```

The verifier uses GNU objdump and Apple LLVM objdump plus the repository's ELF
and complete FDE parsers. [Check commands](checks/commands.json) and logs record
22 focused parser tests, Cargo, rustfmt, `make doctor`, `make verify`,
`make catalogue-check` and `make reproduce`, all passing. GNU binutils and rustup
were placed on PATH for global checks. No dependencies were added.

The shared campaign baseline at the unchanged base covered 971 test files /
15,462 reported tests / 69 skips. Its original aggregate `make test` exited 2
solely for three disk-full errors; all 20 affected tests passed isolated retries.
This is not a clean aggregate rerun or a full-suite run on this contribution.
No captured executable, instruction emulator, Linux-target differential, hosted
CI, container run, whole-node equivalence or completion gate is claimed.

[Overlap inventory](overlap/summary.json) retains initial 201 and final 204 open
PRs, zero open issues and 50 recent merges at each check, plus the empty current
main source-address search. None matched this scope; other workers' reservations
were excluded. The packet and new component are the only changed paths.

New implementation and analysis are independently authored under MIT by 신준.
Captured artifacts retain their existing provenance/rights; no unlicensed
inferred implementation was read or copied. Provider: OpenAI; client: Codex;
the exact model identifier was unavailable and is not invented. The remaining
review step is independent replay of this bounded contribution; it does not
advance any broader node gate.
