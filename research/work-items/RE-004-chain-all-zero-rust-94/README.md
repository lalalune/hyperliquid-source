# Node #94 flag-gated chain predicate in safe Rust

This RE-004 packet adds the Rust implementation left open by
[`foundation-chain-all-zero-predicate-94`](../foundation-chain-all-zero-predicate-94/README.md):
the complete 72-byte node #94 leaf `[0x51a5d60,0x51a5da8)`. The
[safe `no_std` library](../../../src/node94-chain-all-zero/lib.rs) preserves the
flag-first gate, full-qword zero test, field-before-link short circuit and exact
normal-return RAX 0/1 projection. No existing evidence, tools, imports, pins,
registry or progress gate changes.

The [proof](PROOF.md) covers every admitted ordinary immutable image, including
unaligned/overlapping storage and modular effective-address arithmetic. The new
API adds bounds refusals and a separate Cycle outcome for an all-zero cycle,
which would not return in the original. Cycle detection uses the actual image's
bound on distinct readable qword-start addresses, with no arbitrary node cap or
allocation. Worst-case cycle work is linear in image size. Runtime mappings,
original ABI/flags/faults, caller purpose, compiler provenance, target compiled
bytes and whole-node equivalence remain outside the claim.

## Target and static closure

Node #94 is 91,774,280 bytes, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Fresh GNU, LLVM and Capstone agree on all 25 leaf instructions and 949 instructions
in its complete 4,573-byte caller `[0x51fd4c0,0x51fe69d)`. The aligned call at
`0x51fd9e5` and following AL test, exact FDE/CIE records, neighbors, padding and
all five branch/three return targets are retained. No decoder normalization was
needed. The leaf has no helpers, stores or external constant loads.

The whole-text E8 scan has that one candidate; the E9 scan and entry-naming
relocation scan are empty. All 80,300 RELA records are checked for protected code
writes. This does not establish an exhaustive indirect-reference census or the
caller's wider behavior. All 18 structural corruption controls fail below the
whole-target digest check. `disassembly.json` records actual export commands,
versions and executable/output hashes.

## Pre-Rust graph expectations and actual native qualification

`oracle.py` froze 3,724 complete input images and expectations before the Rust
directory existed. Its visited-address-set reachability algorithm is independent
of the implementation's image-derived count bound. `frozen.json` binds the
oracle, target, static record and streams. Local chronology is recorded, not
externally timestamp-attested. The oracle is neither captured execution nor an
instruction interpreter.

Coverage includes all 64 successor maps on three named nodes, all eight binary
zero/nonzero field assignments and all four head choices including null, plus
longer chains, tails into cycles, all 256 flag values, all 64 single-bit nonzero
qwords, partial images, short-circuit invalid links/heads, wrapped addresses,
unaligned and aliased layouts, and digest-derived graphs. Of 3,724 cases, 3,156
return normally (2,218 false and 938 true), 470 are proved cycles, and 98 exercise
all six bounds-error categories. The 512-byte backing image is a client fixture
choice, not a library size limit.

The actual installed rustc 1.94.1 executable, SHA-256
`b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6`, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, built and ran the new library and
input-only client on `aarch64-apple-darwin` at opt0/3 with overflow checks enabled.
Both profiles matched every frozen record and passed three unit tests. Each
profile's independently repeated rlib/client were raw-byte identical, four
comparisons total, with no artifact normalization.

Sixteen wrong implementations were actually compiled and run in each profile:

| Mutation | Mismatches per profile | Admitted value mismatches |
| --- | ---: | ---: |
| Invert flag gate | 1,739 | 952 |
| Test only flag bit zero | 132 | 4 |
| Read head before flag gate | 258 | 0 |
| Null termination returns false | 938 | 938 |
| Test only low32 node-field bits | 342 | 122 |
| Invert node-field gate | 1,591 | 696 |
| Read link before node field | 39 | 0 |
| Wrong node-field displacement | 931 | 425 |
| Wrong head displacement | 3,335 | 8 |
| Wrong flag displacement | 1,705 | 932 |
| Skip first node | 560 | 395 |
| Return true after first zero field | 1,368 | 875 |
| Arbitrary two-node cap | 526 | 0 |
| Report cycle as true | 470 | 0 |
| Saturate node-field address | 5 | 0 |
| Reject exact endpoint | 10 | 0 |

Some controls differ through new safe-admission/cycle classifications rather
than admitted boolean values, as shown separately. Head/link ordering controls
expose unwanted reads of unavailable memory on paths that should return.
Raw first witnesses and all return/admission/memory counts are retained.
Framing, oversized client storage, missing output and altered output are checked.

`native/calls.json` binds every command, status, stdin and stdout/stderr hash.
`native/results.json` records source/compiler/linker identities, comparisons and
repeat builds. `native/raw-streams.json.gz` retains every raw stream losslessly
with duplicate payloads stored once. `checks.json` and `checks/` retain completed
focused/global validation. `SHA256SUMS` covers all new files and unchanged legacy
tool/test inputs; gzip objects require Git LFS materialization.

## Replay and limits

From the repository root with materialized pinned inputs and the exact compiler:

```sh
python3 -B research/work-items/RE-004-chain-all-zero-rust-94/verify_static.py
python3 -O -B research/work-items/RE-004-chain-all-zero-rust-94/verify_rust.py \
  --rustc "$(/opt/homebrew/opt/rustup/bin/rustup which --toolchain 1.94.1 rustc)" \
  --out work/chain-all-zero-rust/replay
```

The recorded native run used normal Python with `-B`. Static replay passed under
normal/`-O` Python with changed hash seeds and time zones. Native replay requires
a fresh output directory; freeze commands refuse to overwrite evidence or run
after source exists.

Local doctor, verify, catalogue-check, reproduce, all eight focused legacy tests,
legacy evidence replay and rustfmt passed. No full-suite or hosted-CI claim is
made here. No captured binary or instruction emulator ran; no unlicensed inferred
implementation was read or copied. This is independently authored OpenAI/Codex
work; the exact model identifier was unavailable. Full-scope gates remain open.
