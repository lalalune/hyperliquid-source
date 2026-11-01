# RE-001: complete 384-bit parity-add/halve family

Independent safe `no_std` Rust now reconstructs the six-word arithmetic core
and both actual wrappers, including every raw repeated count and arbitrary data
aliases. The target adds C only when A is odd, retains the 385th carry, halves,
and either returns once or repeats according to low32 count. This is one coherent
366-byte family with its actual call closure; it does not split related wrappers
into separate contributions or assume cryptographic/modulus identities.

Node94 target: `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Reference pin: `999556f6e0a474b8312db96ec3149e1c44e97c23`.
Author: 신준. Provider/client: OpenAI/Codex. Exact model ID is not exposed in
this session and is not invented. New implementation and evidence are MIT.
No unlicensed inferred implementation, target execution or instruction emulator
was used. Prior independently authored MIT PR #1522 is acknowledged below.

## Reconstructed scope

| Complete linked ELF VA range | Bytes / instructions | Result |
| --- | ---: | --- |
| `5656b20..5656bb9` | 153 / 46 | Exact `floor((A+(A mod2)C)/2)`; six full words plus six auxiliary GP values |
| `5656bc0..5656c2a` | 106 / 30 | Single invocation, all 48 output bytes, nine selected wrapper GP observations |
| `5656aa0..5656b0b` | 107 / 31 | Repeated invocation; low32 zero means 2^32 iterations; final RDX=0 |

All 384-bit inputs and corrections are allowed, including unreduced values,
even C and zero C. The safe image API validates all three full 48-byte spans
before mutation, even on zero/even arithmetic paths. Data spans can overlap in
any way under stable ordinary-memory and control-stack-disjointness premises.
No pointer ABI, faults, MMIO, concurrency, flags or timing equivalence is claimed.
Refusal is a new unchanged-image safe API response. See [PROOF.md](PROOF.md) for
load/store order, full register tuples, every-count proof and exact limitations.

The source is [`src/node94-halving384-family`](../../../src/node94-halving384-family/README.md).
Final `lib.rs` SHA-256:
`ac4b467a58d95433c6b6d0ae20621ec28aa409dff7f73d42f17a7b4a5a74fedd`.
After at most 384 direct arithmetic steps, it uses a proved odd-divisor reduction
and modular exponentiation to compute the remaining count. This is a total
all-count reconstruction, without a budget refusal or a 32-bit wrap shortcut.
The core's RAX and RSI are low63 parts of output words 2 and 5, unlike the
separate four-word target. The wrappers restore six saved registers after storing
the full output; those entry-dependent values are excluded from returned tuples.

## Static and mathematical evidence

`static_evidence.py` verifies full target size/SHA, all 121,299 FDEs and three
CIEs, each exact overlap and raw unwind record, alignment gaps of 21/7/22 bytes,
and the next FDE as a boundary only. GNU and LLVM partition the complete 2,126
bound bytes into the same 559 instructions: 366/107 for the family and 1,760/452
for two complete external caller contexts. Every selected entry is a complete FDE.

Whole `.text` E8/E9 scans find two core calls from the selected wrappers and four
single-wrapper calls in the two external caller FDEs. All six are confirmed at
instruction boundaries. Repeated has no E8/E9 candidate. All 80,300 RELA records
have no selected-entry name or writer overlapping bound code. The selected
closure has no RIP-relative constant/table/import or unknown callee: C is a
caller-provided readable 48-byte value. Other behavior and constants in context
callers are not claimed. Computed indirect references beyond this census remain
unknown. Exact raw bytes, full GNU/LLVM exports and FDE records are under `static/`.

The universal proof derives the 385-bit sum and all 12 core/9 wrapper observations.
For C>0, set odd D=C or C−1 according to C's parity. Then
`2^n*A_n=A_0+D*T` with `0<=T<2^n`; after 384 steps every positive result lies in
1..D. Inverse-two exponentiation gives the remaining steps with zero residue
represented by D. Zero C, zero A and D=1 are handled separately. The Rust tail
uses high-to-low Horner modular multiplication, with full carry-aware addition.

The distinct four-word repeated-halving reconstruction at `565dbc0..565dc5f`,
PR #1522 / commit `c4efb12070859ebe2674208aea16cfa4d66fa8a5`, supplied mathematical
context. `prior-context.json` records exactly which MIT proof/source was read and
its hashes. Its target bytes, register layout and implementation are not reused
as evidence for this family. The new proof and oracle independently establish
six-word bounds and these three actual bodies; no existing source is changed.

## Frozen oracle and native qualification

The independent whole-integer oracle and exact input/expected bytes were frozen
before the source directory existed, at `2026-11-01T22:56:26.019468+00:00`.
For small counts it solves the congruence for T using inverse(D) modulo 2^n;
for large counts it directly computes the positive inverse-two residue. It does
not mirror the Rust limb recurrence, its transient or Horner multiplication.
`fixtures/freeze.json` hashes the oracle plus raw and deterministic-gzip TSVs.

The original immutable corpus has 6,574 cases: 2,809 core, 667 single and 3,098
repeated. It includes all 384 bit positions, long carries, even/zero corrections,
383/384/385 transitions, 481 admitted low32-zero counts, 1,256 other accelerated
tails, 1,276 output aliases and 172 range/image-wrap refusals. There is no
post-source supplement. The native client receives only these inputs, never
expected values. Qualification compares all returned bits and every image byte
without comparison masks.

Final `native/result.json` and `native/qualification.log` record 6,574 cases × four
independent builds = 26,296 exact rows; optimization 0 and 3 each repeated twice.
Both rlib/client artifacts reproduce byte-for-byte at each optimization. All 41
actually compiled mutants exit normally and differ observably, with at least six
mismatches per mutant. All 129 static corruption controls, five comparator controls
and two archive controls reject as intended. This is native execution of new Rust,
not captured-target differential qualification or machine-code equivalence.

All 45 exact stdout streams are losslessly retained in `native/raw-streams.json.gz`
with original byte counts/SHA-256 and a shared-line dictionary. Every stream is
reconstructed and verified by `--check-archive`. Compiler commands/output, source
hashes, build hashes and mismatch witnesses are retained alongside the archive.

The first full run also passed. A later source-comment precision fix changed
"entry-preserved registers" to "restored saved-register values" because the
selected RDI/RCX/RDX pointer observations can be preserved. No executable code,
oracle or fixture changed. That complete first run remains in `native-initial/`;
the final source hash received a fresh full qualification. Neither qualification
had a compile failure, surviving mutant or output mismatch. Completed duplicate
stdout was pruned only after exact archive verification, with path/hash journals
in ignored `work/halving384-family/`; all raw bytes remain in committed archives.

## Reproduction and limits

From the repository root, using a fresh output directory:

```sh
python3 -O research/work-items/RE-001-halving384-family-rust-94/verify.py --out work/halving384-family-replay
python3 -O research/work-items/RE-001-halving384-family-rust-94/verify.py --check-archive
cargo +1.94.1 check --locked --offline --manifest-path src/node94-halving384-family/Cargo.toml --all-targets
```

`checks/` records 22 focused ELF/FDE tests, locked/offline Cargo, rustfmt and
`make doctor`, `make verify`, `make catalogue-check`, `make reproduce`: all pass.
GNU binutils and rustup paths are prepended to PATH; exact versions and commands
are retained. `MANIFEST.sha256` covers the packet, component and reused parsers/
focused tests; run `shasum -a 256 -c MANIFEST.sha256` from this packet directory.

No whole-suite sweep was duplicated. Shared base context is 971 files, 15,462
reported tests, 69 skips, original aggregate exit 2 due solely to three disk-full
errors; all 20 affected tests passed isolated retry. This is not a clean full sweep
at this head. Hosted CI, Linux/container and captured-native execution are unclaimed.

Initial/final inventories in `overlap/` contain 191/197 open PRs, zero open issues
and 50 recent merges each. No selected address matches; main's source search is
empty. The earlier four-word arithmetic relation is explicit context, not an
overlap. Pins, generated progress/catalogue files and all project completion gates
remain unchanged. Other callers and neighboring arithmetic bodies require their
own independent reconstruction; this packet makes no completion claim for them.
