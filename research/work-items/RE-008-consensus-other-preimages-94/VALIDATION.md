# Recorded validation

All captured-artifact work was static parsing and native disassembly. The only
executed research implementation was the independently authored Rust value API,
its tests and input-only driver, plus pure value-level Python expectations.
No captured instructions, emulator, signing key, network service or full
repository test suite was used.

## Static evidence

`verify.py` passed with ordinary Python and `python3 -O`; their retained
`validation.json` bytes are identical. Each invocation regenerated two trees
and matched every retained native export, compact record and frozen fixture:

| Check | Result |
| --- | --- |
| Whole input | Exact SHA-256 and 91,774,280-byte size admitted |
| Full FDEs | 38, totaling 19,172 bytes and 4,655 instructions |
| Native agreement | Complete GNU/LLVM byte spans and instruction boundaries |
| Structural obligations | 619 instruction pins, eight exact data spans |
| Negative controls | All 55 rejected; rejection reason and changed bytes retained |
| Pre-Rust corpus | All 534 cases unchanged; two deterministic regenerations |
| Original proof freeze | Reconstructed exactly through the explicit memcpy correction |

Of the controls, 34 change real instruction bytes and obtain fresh disassembly
of the entire containing FDE below both the whole-target and body-identity gates.
They change field offsets, stride, branch/guard conditions, call target, selectors,
option markers, scalar thresholds and hash/concat operations. Other controls
cover missing/shortened scope, native partition disagreement, literal/tables,
raw FDE extent, RELATIVE type/symbol/addend and the imported memcpy symbol.
Rejection is structural; these controls do not replace the manual semantic proof
or claim exhaustive mutant coverage. Top-level SHA/size rejection is recorded
separately from the below-identity checks.

`native-providers.json` records GNU objdump2.47.20260726 and Apple LLVM21.0.0
versions and executable hashes. The private input snapshot is checked unchanged
after native tools return. Provider path overrides are supported, while exact
text regeneration remains version-sensitive.

## Own Rust

[`rust-validation/results.json`](rust-validation/results.json) binds all32 files
in the actual three-package build graph, the driver, original expectation freeze,
input-only byte stream, four tool executable hashes and `rustc -vV`.
The pinned compiler was Rust1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, host `aarch64-apple-darwin`.
`commands.json.gz` retains normalized arguments, exit statuses and logs.
Public toolchain paths use `<TOOLCHAIN>/name` and repository paths use `<ROOT>`.
`PUBLIC-METADATA-NORMALIZATION.json` binds the private actual-run and public-copy
hashes for the two metadata files; only those path strings changed. Executable
hashes, source identities and all behavior/output bytes are identical. Fresh
local build results record the explicitly selected local toolchain path.

- Debug and release: **534/534** frozen input cases each, zero mismatches for
  independently derived lengths, preimages and digests.
- Actual crate tests in each profile: **53 passed**, zero failures (37 unit,
  nine existing evidence tests and seven new integration tests); doc tests empty.
- Each driver rejected six malformed/short/trailing input frames.
- Rustfmt checked the new module, integration test and driver. Clippy checked
  all actual-crate targets with `-D warnings`. Cargo used `--offline --locked`.
- The real manifests and lock contain only the two existing local MIT dependencies;
  no registry, Git, build script, proc macro or ancestor Cargo configuration was
  admitted. An empty task-local Cargo home and explicit pinned compiler/doc tools
  excluded ambient wrappers/flags. Existing evidence tests only read retained
  data and run `shasum` over the captured file; they do not execute it.

Ten actual compiled release-profile behavioral mutants changed only the new
module in copies of those same real packages/manifests/lock:

| Mutant | Frozen cases rejecting it (of534) |
| --- | ---: |
| Serialize raw65 signature bytes | 203 |
| Omit nested QC votes | 203 |
| Reverse nested vote order | 25 |
| Replace claimed signers with zero | 533 |
| Ack round before random | 143 |
| Collapse present-empty maps to absent | 8 |
| Summary hash before its words | 92 |
| Hash only the first136 bytes | 143 |
| Drop a byte at exact rate multiples | 3 |
| Interpret signature limbs big endian | 116 |

All outputs are retained, including surviving cases for each mutant. The
expectations never entered the driver: its runtime input contains only the
fixed-width protocol in [PROTOCOL.md](PROTOCOL.md). Expected digests are standard
Keccak values over independently derived bytes; correspondence with native P
retains the credited structural-identity premise.

The first build attempt stopped at its package-copy hash audit after concurrent
README/lib documentation edits. The recorded successful run was repeated after
those files stabilized; its final graph hash audit passed. There was no fixture
rewrite to make the source pass. The sole proof amendment is the explicitly
recorded memcpy premise, made after the first source draft and before compilation.

## Reproduction and remaining limits

The exact commands and path override flags are in [README.md](README.md).
`validation-runs.json` identifies the static invocations and shared output digest.
`FINAL-FREEZE.json` binds the reviewable own source files and validation receipts;
`MANIFEST.sha256` covers the packet. `git diff --check` passed for the changed
component and packet; newly added text files were also checked for whitespace.

There is no full-suite, native runtime, complete ECDSA, native-tree constructor,
ownership, allocator or unconditional Keccak permutation equivalence claim.
Finite tree/order/count, disjoint stable memory, imported-copy and opaque-call
preservation premises are material to the stated contract.
