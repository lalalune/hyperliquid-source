# RE-006: Rust source for the qualified raw-key monotone path

- Component: existing standalone `src/node94-orderbook`; new isolated
  `monotone_keys` module, with its existing manifest/lock preserved.
- Target: node #94 SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source baseline: qualified draft #1455 head
  `1fd3b0212ddc73b5e83a62905a99ca2348654535`, based on upstream main
  `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Exact native FDE: `[0x4dbd490,0x4dbdb5e)`. The predecessor's complete
  operand/CFG proof and frozen vectors remain unchanged and are credited.
- Status: independently authored Rust in the existing component, compiled
  and locally compared with frozen static expectations using official Rust
  1.94.1. No captured target execution, target identity or gate is claimed.

## Implemented source relation

For raw unsigned qwords, lengths 21..4096, the module first classifies the
whole input. A nondecreasing array, including equality, takes the source path
without mutation. A strictly decreasing array is reversed by opposite qword
swaps; the odd center is untouched. This scalar Rust permutation equals the
previously proved native four-pair SIMD plus scalar-tail permutation.

`QualifiedOrdering` and `Unsupported` are newly chosen Rust API metadata.
Unsupported length/order returns before any write; this is safe-API policy,
not a target error or target refusal. Arbitrary arrays enter native fallback
or merge paths that remain unproved. No source symbol, original ABI, captured
layout, allocator, scratch image, private nominal type, generic sort or whole
book integration is invented. Existing book callers are not migrated.

The existing component can host this behavior cleanly: it is dependency-free
and already contains bounded RE-006 behavior with explicitly chosen safe APIs.
No root workspace, new crate, dependency or replacement lockfile is created.
The production module has no fixture/expected-answer reader and allocates no
memory. The separate input-only driver links the actual component library and
receives only input words. It emits status plus **every** resulting qword;
expected answers remain in the external Python comparator.

## Frozen expectations and observed builds

The 76 complete monotone cases come from the pre-Rust #1455 fixture file,
SHA-256 `086d75c7e15d84bd83c9575640b02286fd53b291d390badab30f0054af34b542`.
Each reconstructed stimulus must reproduce its frozen input hash, and each
complete expected output must reproduce its frozen native-derived output
hash. No second newly invented sorting model supplies the acceptance oracle.
Five additional refusal cases are labeled safe-API policy and kept outside
the native-case denominator.

Fixture preparation and its separate Python controls:

```sh
python3 -B research/work-items/RE-006-monotone-keys-rust-94/verify_rust.py \
  --out work/re006-monotone-rust/prepared
python3 -m unittest discover -s tests -p test_monotone_keys_rust_fixture94.py -v
```

Use a fresh `--out` directory for each invocation. The harness snapshots every
tracked component file, the new module and the driver before compilation;
all compiler commands and mutant derivations read that fixed snapshot. Exact
per-file lengths/hashes are recorded, snapshot integrity is checked, and the
live candidate must still match it before success. Each mutant has its own
source manifest and uses the same fixed driver. A concurrent live edit cannot
silently acquire credit for outputs built from another source.
After that guarded build completed, the component README alone was updated
to describe the observed results. All nine compiler-read Rust source files
and both package pins still match the compiled snapshot. The full historical
snapshot's README hash is therefore a pre-build documentation hash, while
`compiled-results.json` separately pins the actual compiler-read sources.
Both binary fixture artifacts are checked against their frozen hashes before
each client run and again before the final report; the client receives the
same input bytes that passed that hash check.

Fixture preparation writes ignored binary input/expectation files and checks exact full-buffer
comparison, including a corrupt qualified output. It does not compile, run or
validate Rust. The prior native proof can be replayed independently:

```sh
python3 -B research/work-items/RE-006-large-sort-monotone-path-94/verify.py \
  --llvm /workspace/.tools/llvm19/usr/lib/llvm-19/bin/llvm-objdump
```

The observed compiled comparison command was:

```sh
python3 -B research/work-items/RE-006-monotone-keys-rust-94/verify_rust.py \
  --rustc /workspace/.tools/rust-1.94.1-x86_64-unknown-linux-gnu/bin/rustc \
  --out work/re006-monotone-rust/compiled-official-1.94.1
```

The compiler reports `rustc 1.94.1 (e408947bf 2026-03-25)`, host
`x86_64-unknown-linux-gnu`, LLVM 21.1.8. Its executable SHA-256 is
`ef6d716e5d1c6c93def277c0afa037c21e7a74f7de3aed4ee0700646c3301b1d`.
`toolchain-provenance.json` preserves the parent's verified official download
receipt; that verification was not independently repeated by this lane. A
post-build inventory hashes 93 installed compiler/sysroot files; its identity
and limits are recorded in `compiled-results.json`.

The real dependency-free component built directly with edition 2024 and
overflow checks enabled at optimization levels 0 and 3, twice each. All four
input-only clients matched all 76 qualified and five policy cases: 304 native
domain records and 20 policy records, with zero mismatches. All output files
have SHA-256 `31b596f9f5a3f39a26136465184f24df3a9a76fca23f43b7819ecdba1e04f9e6`.
The component's 30 unit tests passed at both optimization levels. All 34
recorded commands exited zero and produced empty stderr, including production
builds with warnings denied. Client bytes repeat within each optimization;
raw rlib archive hashes differ and are reported without normalization.

The six compiled controls have these exact mismatch counts:

| Wrong variant | Qualified cases with changed arrays | Qualified cases with only wrong API status | Policy cases |
| --- | ---: | ---: | ---: |
| signed comparisons | 19 | 38 | 0 |
| reject ascending ties | 0 | 38 | 0 |
| skip final swap | 19 | 0 | 0 |
| reverse ascending inputs | 57 | 0 | 0 |
| upper limit 4095 | 1 | 3 | 0 |
| allow descending ties | 0 | 0 | 1 |

The first five have counterexamples within the qualified native domain.
Some detect refusal to support that domain through our chosen API metadata;
those failures are distinct from changed target-derived array values. Status
bytes are not native return values. The sixth is solely an unsupported-order
policy control, with zero qualified-case mismatches, and is never counted as
a native-derived kill. The receipt retains first counterexamples and exact
source/driver/package hashes. Historical `preparation.json` remains labeled
as preparation; `compiled-results.json` records the observed compiled result.

## Source and physical-write limits

The source no-write ascending branch is explicit: only
`StrictlyDecreasing` reaches the mutation loop, after whole-input validation.
Value-output comparison alone cannot detect redundant same-value writes.
`compiled-no-write.json` and the two compact native exports therefore bind
the actual opt3 client's `normalize` function: `[0x16de0,0x16ed4)`, 244 bytes,
77 instructions, with GNU/LLVM partition and byte agreement. These are local
compiled-client VAs, separate from node94 addresses.

For a qualified nondecreasing input, unsigned JAE at function offset `+0x26`
enters the scan at `+0x50`. It exits to `+0x68`, and JAE at `+0x72` reaches
the `+0xc9` pop/return. This graph excludes both input stores at `+0xb4` and
`+0xb7` and both panic calls. Stack push/pop remain. This closes no-input-store
behavior for this opt3 artifact; opt0's transitive helper/store closure remains
unclaimed. Generated store widths, original ABI and target code equality are
not inferred from the source or these value comparisons.

The target proof is static and conditional on valid, stable, disjoint memory.
No captured node, emulator, network service or signing path is executed.
Newly compiled independent Rust ran only as the documented local fixture
client and component tests. No progress gate,
byte-window registry, whole-sort or node-equivalence claim is made.

## Checks and remaining scope

`checks.json` records fixture controls, native-proof replay and repository
checks. Build logs, binary inputs/outputs and compiler artifacts stay in
ignored work; no binaries are committed. The complete repository test suite
remains coordinated separately. This minimal approved toolchain contains
rustc/std/Cargo; clippy and rustfmt were not installed or run by this lane.

The compiler blocker is resolved. Review of this bounded implementation and
the broader native fallback/merge gap remain separate from full-component
acceptance. The source is local until coordinating review authorizes delivery.

First unknown native boundary remains the short-run branch at `0x4dbd6f1`
into the fallback below `0x4dbd593`, relocated helper
`0x57768a0 ->0x4497a90` and its selected small-sort delegate `0x4918d30`.
The module assigns no target behavior to that branch.
