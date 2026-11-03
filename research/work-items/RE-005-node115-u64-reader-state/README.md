# RE-005: Node115 reader cursor, errors and precharged aggregate

Component: serialization. Bounded question: recover the connected little-endian
u64-shaped scalar reader and two four-read callers' observable state relation.
This adds independent Rust where the active base had no implementation for
these six addresses; it is not a product vulnerability or a complete codec.

Target: Linux x86-64 node115,
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
Frozen expectations commit: `e19631325a3518f950ae3e011e1323e3e0bf590b`,
created before any Rust in this component. CONTRACT.md, spec.json, cases.tsv,
and native bindings from that commit remain byte-identical.

## Evidence and limits

Six complete unwind extents,1807 bytes,512 GNU/Capstone address/raw-byte pairs:
2cd7d90..2cd7fac and5821540..582171f (four-read callers),
2cd7ac0..2cd7ba5 and5821250..5821335 (scalar copies),
58225c0..58226fc (slow helper),5822700..582270e (raw error constructor).
All addresses are unrebased ELF virtual addresses. Full FDE coverage does not
prove original source function extents. No instruction operands are masked.
The original GNU output is retained in the six `.objdump.txt` files; misleading
nearest-export symbol suffixes are GNU presentation, not recovered names.

Both scalar copies resolve GOT64e6c38 to slow helper58225c0. Actual error
slots64e6c40/64e7f78 resolve to5822700 via unique RELATIVE relocations. Three
bound LEA/signed-relative dispatch tables select FB/FC/FD/FE paths. The two
aggregate bodies each contain four actual direct calls to its measured scalar.
CONTRACT.md separates raw tags/layout observations from inferred logical names.
In particular, fast invalid-marker errors retain cursor and rawexpected2;
slow errors consume marker and rawexpected3. Limit charges remain after errors.

Source-location byte leads reference z_forks/bincode-fork/src/de/decoder.rs93:13
and impls.rs499:20, but do not identify crate revision, license or original types.
The leads file includes unvalidated raw discovery leads outside this scope;
only selected instruction starts/FDEs enter the denominator. No inferred source
was copied. New Rust and analysis code are independently authored under root MIT;
captured bytes/disassembly retain upstream rights and are evidence, not linked code.

## Reproduce

With the authenticated capture materialized from pinned Git LFS and Capstone
installed, from repository root (all output paths are operator-selected):

```sh
python3 -B research/work-items/RE-005-node115-u64-reader-state/verify.py --objdump objdump --output work/reader-static
python3 -B research/work-items/RE-005-node115-u64-reader-state/verify-rust.py --rustc /absolute/path/rustc.exe --linker /absolute/path/rust-lld.exe --output work/reader-compiled
```

The compiled comparator uses the documented Windows gnullvm host; the no_std
library separately builds for Linux x86-64. It compiles only independently
authored source; it never runs/emulates the capture. `generate-cases.py` is the
frozen static mathematical projection, not a dynamic target oracle. Its manual
anchors cross-check endian value, shortfall, charge overflow/limit equality,
aggregate precharge and the 8/9-byte invalid-marker boundary. To regenerate it,
use a disposable copy and compare to committed cases.tsv; do not overwrite evidence.

## Results

static-result.json: six FDEs/512 pairs and eight malformed-metadata controls.
compiled-result.json:9610 frozen cases match independently compiled opt0 and
opt3 baseline programs; all nine semantic mutant programs differ as intended.
These are static-contract checks, not9610 target execution comparisons or a
whole-input-space behavior proof. build-checks.json preserves actual Cargo
fmt/test(opt0/3)/Clippy/native/Linux build exit0 results. linux-build.json binds
the produced ELF64 machine62 archive objects; Linux code was not executed.

Two native release probe builds differ at file offset128 only (PE timestamp).
own-build-repeat.json retains both raw hashes and rawEqual=false; zeroing only
the four-byte IMAGE_FILE_HEADER.TimeDateStamp makes the own builds equal.
This is not original-target code comparison. Compiled source/target body
identity remains unmeasured: raw-equal0, normalized-only0, unmatched0 over0
registered compiled-target windows. Native static byte denominator is separate.

Execution-status.json preserves an important non-green result: the combined
proof root exited0 and wrote its results, but the supervisor detected a remaining
own child and marked failed-leftover-child, then cleaned only its Job and
confirmed own0/lock release. Descendant identity is unresolved; no clean-lifecycle
pass is claimed. An earlier run's final raw-repeat assertion also failed; no
unchanged full build was retried to hide it. Initial make doctor passed;
initial make verify failed at GPG public-key import after six artifact SHA checks.
Final exact-head repository command results are disclosed in the PR; ordinary
PR submission does not imply all checks passed.

## Remaining unknowns

Original Rust enum/ABI/layout padding, source/version/license identity, compiler
flags, surrounding node call sites and whole-codec ownership remain unknown.
Domain excludes arbitrary raw modes, aliasing, invalid pointers and nonzero
endianness. Diagnostic tag19/unclaim-underflow helpers are not recovered; their
paths are unreachable only within the explicitly closed canonical-mode relation.
No gate changes, network compatibility, target execution/emulation, whole-node
build or binary equivalence. Next question: identify an actual service caller
and establish its type/format contract before integrating this logical fragment.
