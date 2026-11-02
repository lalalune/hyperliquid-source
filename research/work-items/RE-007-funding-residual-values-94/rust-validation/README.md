# Residual source qualification phase

This additive phase contains the independently authored, dependency-free
`src/node94-funding-residual-values` package and a separate input-only client.
The original89-file pre-code packet stays immutable. The supplied-summary
post-worker contract and conditional native premises are in the original
CONTRACT/PROOF/TREE-PROOF/CALL-FRAMES files. SOURCE-PROOF and BRIDGE explain the
actual source relation, safe-policy boundary and transport envelope.

At SOURCE-FREEZE creation no Rust build, test, client or mutant has executed.
Preparation consists only of pinned tool versions, Cargo's actual offline
lock generation/locked metadata and rustfmt. SOURCE-AUDIT records those runs,
including the initial pre-execution /tmp alias rejection and corrected admission.
Source authoring was gated independently; a separate root/peer review of this
exact freeze is required before the campaign's first compilation.

After that gate, invoke the frozen harness from a clean checkout with the
captured node94 data hydrated, the pinned97-file Rust1.94.1 aarch64-apple-darwin
payload, Apple Command Line Tools and the pre-code packet's recorded GNU/LLVM
providers available. The native verifier defaults are recorded-host-specific;
this qualification command is not a cross-platform toolchain promise. The
standalone production package itself has only std dependencies.

```sh
python3 -B research/work-items/RE-007-funding-residual-values-94/rust-validation/build.py \
  --toolchain <PINNED_TOOLCHAIN_ROOT> \
  --out /tmp/residual-author-fresh \
  --private-map <NEW_PRIVATE_PATH_MAP_JSON> \
  --source-freeze-sha <SHA256_OF_SOURCE_FREEZE_JSON>
```

Use a fresh output and private-map path for every attempt. The harness admits
all original89 pre-code files and actual five-file package, then runs the
unchanged static verifier. Its historical pre-freeze receipt is compared with
only the explicit additive `freeze_sha256` field populated. No historical
receipt is rewritten. Rust sources are copied exactly into real component build
roots and linked directly; no captured binary is linked or executed.

Planned qualification:13 integration tests in debug/release, all912 original
full-state frames in both profiles, one clean same-path repeat, one separate
build directory,22 independently compiled behavioral mutants in both profiles,
11 comparator controls and26 malformed transports plus extra argv/empty stdin.
The22 mutations comprise19 native-domain distinctions and3 safe-policy-only
controls; every result records differences separately across853 conditional
native and59 policy cases. A policy-only mutation must leave all native frames
unchanged. These are plans until an actual results.json receipt exists.

Every first failure stops the run and retains its actual commands, raw streams
and available compiled artifacts. No mutant compile failure counts as semantic
detection. All compiled bytes are retained privately before any build-directory
removal; public results may reference their hashes and private availability, but
must not blindly publish binaries that can embed personal paths. Raw command
stdout/stderr remain unchanged. Logical path mapping applies only to metadata.
Full bin/lib payload and selected linker/SDK identities are audited; OS/dyld/full
SDK and native compiler equivalence are not claimed. Source and all pre-code
inputs are re-admitted after a passing run.

The parent qualifies the same freeze in independent output roots. Exact outputs
and same-path artifacts are compared; cross-directory artifact inequality is
reported without masking or guessing a cause. No full repository suite, captured
program execution, live funding computation or completed component gate is
implied. All target evidence has one project/native source lineage.
