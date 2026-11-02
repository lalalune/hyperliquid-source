# RE-004: reconstruct the node #115 scalar quantity preparation cut

> Current #115 migration (2026-11-02): this implementation was rebuilt and
> compared at opt-level 0 and 3 after retiring the older node and trimming
> its shared tooling. `migration-validation.json` records the fresh run and
> compiled mutation controls. Historical blocker reports below describe the
> original environment; they do not require the retired binary. Original
> negative results and target-bound records remain unchanged.


- Component: assets/foundation; established scalar preparation before formatting.
- Target: release #115, 105,896,032 bytes, full SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source base: main `3324e50333042b391312515e542279ca21f63dc8` plus the shared
  CI prerequisite `516b1e3aadc21cae29ee7042ba464a9dace6b049` (PR #1295).
  That prerequisite is not additional reconstruction credit.
- Established evidence: merged PR #966,
  `research/work-items/RE-001-node115-wire-qty-normal-form/`; preserved unchanged.
- Outcome: independently authored Rust for the proven coefficient/scale and
  prepared-word values, with a real direct-compiler build. No original ABI claim.

## The gap and the native boundary

Before this change, the accepted packet had a static whole-domain arithmetic
theorem and Python proof machinery, but no Rust implementation of this cut.
The existing #94 fixed-point library covers different quantity policies and
floating price conversion. No #94 correspondence or shared implementation is
inferred. The contribution advances RE-004 by implementing established semantics,
as allowed by the reconstruction scope; it does not invent a new feature or
claim that an existing numeric policy was defective.

The complete native denominator remains one real unwind body:
`0x41c57f0..0x41c5b83`, 915 bytes / 237 decoded instructions, body SHA-256
`697cfe8a1ab3360ab1777aff851cd9f4f65ba39e47eb842845d075831ac84483`.
These are ELF virtual addresses. The previous packet retains the complete
disassembly, FDE/CIE bytes, source Location, four relocation bindings and thirteen
complete-domain reciprocal certificates. The new oracle authenticates the
whole capture, regenerates those records and requires exact equality before
using its extracted operands. No inferred reference implementation is read.

This change recovers the sign-clear scalar result at the preparation cut,
including all eight trailing-zero stages and the four observed stack-word
values. It does **not** recover the rest of the 915-byte function. In particular,
the formatter call at `0x41c5aeb` through `0x64e95c8 -> 0x5c449c0` remains opaque.
Formatting/vtables, error/cleanup helpers, ABI and caller input representation
retain the previous packet's gaps. The raw stack values do not identify a Rust
Decimal type, a wire schema or quantity units.

## Rust relation and whole-domain argument

The production function is `prepare_quantity(u64)`. Its own API refuses inputs
with bit 63 set; that refusal deliberately makes no claim about the original
Result/niche representation or negative-quantity policy. Within the established
normal domain:

1. Zero takes the separate `(0,0)` path.
2. A nonzero input starts at coefficient `N`, scale eight. Each loop iteration
   is allowed only when the current coefficient is divisible by ten and the
   scale is positive; division is exact and scale decreases by one.
3. The invariant `N = coefficient * 10^(8-scale)` is preserved. At most eight
   iterations occur; coefficient division cannot overflow. Exit leaves either
   scale zero or a coefficient not divisible by ten.
4. These exit conditions uniquely identify the same pair as the accepted
   full-domain split-limb theorem. The Rust does not copy its reciprocal machine
   implementation. `prepared_words()` then applies exactly its established
   shift/low-word/high-word value projections.

This is a semantic argument over unsigned low-63-bit inputs, with finite
compiled comparisons as additional controls. No whole-input-space compiled
enumeration, target execution, native fault trace or byte equality is claimed.

## Expectations and independent comparator

Commit `5334c263` freezes the fixture and precursor oracle before `lib.rs`
exists; `PRE-RUST-FREEZE.json` records that fact and the hashes. Later reporting
metadata additions to the runner do not replace this historical freeze.
The 2,540 sign-clear inputs cover zero, all nine output scales, the eight-stage
cap, decimal and binary boundaries, low/high-word carries, maximal admitted
multiples, the low-63-bit maximum and 1,024 deterministic generated words.
The entire input domain is not claimed to be sampled.

Expectations use actual captured multipliers, shifts, inverse and divisibility
threshold in the accepted split-limb recurrence. Every result is independently
checked by counting terminal zeros in a decimal string. Neither calculation
reads Rust outputs. The separately linked production driver receives only an
input file; expected answers are held by the Python comparator. Ordinary Rust
tests also consume the frozen fixture, only under `cfg(test)`.

Two actual operand mutations are made only in private byte arrays:
inverse-five `0x41c5861: cd -> ce` changes input 5 from `(5,8)` to `(0,0)`;
low-reciprocal `0x41c5858: 19 -> 00` changes input 10 from `(1,7)` to `(0,0)`.
The accepted certificate checker rejects both. These are algebraic
counterfactuals, never executed or emulated altered node programs.
Three compiled Rust mutants separately change zero's scale, the eight-place
cap and low-word width. Both actual production outputs and ordinary compiled
assertions detect them. Results retain mismatch counts over all 2,540 inputs.

## Build and reproduction

Only the newly authored Rust and its research driver execute. No captured node,
visor or emulator is invoked by this component runner. Other repository tests
have their existing offline Python evaluator scope and authorization.

```sh
python3 -m unittest tests.test_wire_qty_rust tests.test_wire_qty_normal_form -v
python3 tools/wire_qty_rust.py --rustc /path/to/rust-1.94.1/bin/rustc \
  --output /new/output/directory --controls
make doctor verify catalogue-check reproduce
make test
git diff --check
```

The research compiler is the repository-pinned Rust 1.94.1, commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, host aarch64-apple-darwin, LLVM
21.1.8. The component has no dependency or Cargo manifest because the original
crate/dependency graph is not established. `rustc` builds a genuine `no_std`
rlib and a separate standard-library research driver, edition 2021,
`-D warnings -C codegen-units=1 -C overflow-checks=on`, at opt levels zero
and three. The host Apple clang driver and SDK are recorded in `build-result.json`.
It also retains the complete compiler recipes with `$REPO`, `$OUTPUT`, `$RUSTC`
and `$LINKER` path placeholders; these are path spelling substitutions, not
code/operand normalization. Actual raw stdout/stderr stay in the output folder.

Official compiler and standard-library archives were verified against the
SHA-256 values in the official Rust 1.94.1 channel manifest before copying only
manifest-listed regular files into a private tool directory. No archive installer
or remote shell script was executed; global Rust installations remain unchanged.
Archive URLs and hashes are retained in `compiler-inputs.json`.

## Results and remaining limits

`build-result.json` records actual local compilation: both profiles agree on all
2,540 normal inputs and three separately labelled own-API refusal inputs, with
two ordinary Rust tests passing per profile. Two identical optimized builds
produce raw-equal own `.rlib` bytes, with no normalization. Three Rust mutants
are rejected by actual value comparisons and compiled assertions. The separate
eleven-test focused run passed in 42.396 seconds; safe repository checks and
the full-suite state are retained in `validation.json`.

The own-library reproducibility result is **not** a match against the x86-64
Linux target: the host build is arm64 macOS. Raw/normalized target byte-match
counts are unmeasured. No whole-function equivalence, original compiler recovery,
formatter output or full assets/foundation gate is claimed. All four component
gates remain false. The next question is the opaque formatter's own complete
function and vtable/data closure, before proposing a string or wire codec.

Pinned-toolchain follow-up: Rust 1.94.1 rustfmt and Clippy (library and test configuration, warnings denied) pass. The manual divisibility expression now uses the standard integer method with the same relation. Both build profiles and all three compiled mutants were rerun against the unchanged 2,540-row fixture; five runner tests pass in 4.847 seconds. `build-result-before-style.json` preserves the initial submitted build record; `build-result.json` records the current source. The zero-scale mutant selects the same field after formatting; the pre-Rust freeze remains unchanged.
