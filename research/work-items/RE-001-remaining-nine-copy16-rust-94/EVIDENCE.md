# RE-001-remaining-nine-copy16-rust-94: snapshot-preserving sixteen-byte copy

- Research allocation: RE-001 / foundation; bounded independent Rust.
- Base: `e5c9b6436876b2a4a39daef813171f9879317699`. Reference pin: `999556f6e0a474b8312db96ec3149e1c44e97c23`; its unlicensed inferred implementation was not read or copied.
- Target: Linux x86-64 node #94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Coordinates: ELF virtual addresses, not loader-rebased addresses.
- New source: `src/node94-remaining-nine-copy16/lib.rs`.
- Claim: finite static-observation/compiled-Rust projection agreement. No native ABI, fault or compiled-byte equivalence claim.
- Progress/gates: unchanged. No first-party ownership or compared-byte denominator is supplied.

## Gap and established sequence

The base has static target evidence for these windows, but no independent
Rust implementation at this source path. Reconstruct the established behavior
without inventing source types, dependencies, consumers or helper semantics.

The complete FDE is `[0x5454710,0x545472e)`, 30 bytes, with no
outgoing call. Incoming RDX and RSI are pointer-container arguments, not the
destination and source data addresses themselves. The retained order is:

1. Load destination from `[incoming RDX+8]`.
2. Load middle from `[incoming RSI+0x10]`.
3. Load q from `[middle+8]`, leaving q in RDX.
4. Snapshot **all sixteen bytes** at `q-0x10` before any destination write.
5. Store that snapshot at destination and return full RAX=1. RSI is unchanged.

Independent Rust returns the RAX/RDX/RSI projection and performs those
explicit memory operations in order. The fixed-array value prevents a
forward byte-stream copy from consuming bytes it has already overwritten.
This handles identical, forward-overlapping and backward-overlapping data
spans without assuming disjoint pointers or aligned addresses.

The Python oracle uses a dictionary image; the Rust client separately builds
a BTreeMap image. Initialization writes destination guard bytes, source guard
bytes, then the three little-endian pointer slots in that order. Aliases are
resolved from the resulting bytes, not from the requested pointer labels.
Selected mask bits then remove spans or individual source/destination bytes.
Missing reached data is a safe refusal; an unsuccessful store preflights its
entire sixteen-byte span and preserves the image. This refusal atomicity is
the new safe API's contract, not a claim about partially faulting native SIMD
stores. Every result, reached operation/address/width and final image byte
is compared. Unchanged guard bytes make stores wider than sixteen visible.

Cases cover every data displacement from -20 through +20 with four patterns,
destination overlap with already-read pointer slots, pointer-slot aliases,
all selected missing spans, each of sixteen source/destination holes,
wrapping/high addresses and 256 fixed-seed layouts. This is finite ordinary
memory evidence, not native faults, MMIO, races or arbitrary state proof.

## Static admission and fixture freeze

`ORACLE-FREEZE.json` records the absent Rust source and freezes the Python
oracle, compressed corpus and retained target-inspector reports **before** the
Rust library is created. Qualification rechecks those hashes, regenerates every
fixture and locks each unchanged base inspector's source hash. The inspectors
bind the complete body, padding, current/neighbor unwind records and the
cross-reference/relocation evidence they explicitly describe.

The qualifier additionally decodes raw FDE length, backward CIE reference,
signed PC-relative initial address and unsigned extent. Exact window ranges
and raw-record hashes are retained in `qualification/result.json`; no guessed
global VA/file-offset relationship is used. CIE encoding is locked by the
base inspectors. Fresh bounded GNU disassembly is retained compressed beside
this packet. E8 byte-pattern candidates and naming RELATIVE slots are limited
observations, not a complete call graph or source-ownership proof.

No captured binary, instruction emulator, inferred reference implementation,
networked provider or chain service participates in qualification. Original
machine code is neither transplanted nor linked into the Rust library.

## Actual builds and comparisons

- Linux x86-64, rustc1.94.1 / LLVM21.1.8, edition2021. Full compiler identity and commands are in the result.
- No Cargo dependency graph is invented. This dependency-free standalone library and input-only stdin client build directly with rustc.
- Opt-level0 and opt-level3, two independent output directories each: all 554 frozen observations match on all four executions.
- At each optimization, complete rlib/client artifacts repeat byte-for-byte. Their hashes and compressed raw comparison outputs are retained.
- Safe-success fixtures: 356/554. Refused-view cases are reported separately from successful target projections.
- Four separately compiled semantic corruptions must exit normally and differ on successful observations; a crash, missing row or changed safe refusals alone cannot qualify a control.

- `shifted-destination`: 411/554 observations differ; 356 differences also occur with successful outcomes. Exit0; raw mutant outputs and a first witness are retained.
- `reversed-snapshot`: 356/554 observations differ; 356 differences also occur with successful outcomes. Exit0; raw mutant outputs and a first witness are retained.
- `wrong-return`: 356/554 observations differ; 356 differences also occur with successful outcomes. Exit0; raw mutant outputs and a first witness are retained.
- `wrong-rdx`: 356/554 observations differ; 356 differences also occur with successful outcomes. Exit0; raw mutant outputs and a first witness are retained.

The client receives only fixture inputs. Expected output remains in the
independent Python corpus, never in the Rust client's input. Every command's
exit/stdout/stderr is retained under `qualification/commands/`; build-path
text is sanitized to `<REPO>`/`<HOME>`, while numeric comparison streams are
unchanged. Check the stream hashes, source hashes, qualifier hash and witnesses
in the machine-readable result.

## Reproduce

With the authenticated pinned inputs prepared by `bash scripts/setup.sh`:

```sh
python3 -O research/work-items/RE-001-remaining-nine-copy16-rust-94/verify.py --rustc /path/to/rustc-1.94.1
rustfmt --edition 2021 --check src/node94-remaining-nine-copy16/lib.rs src/node94-remaining-nine-copy16/client.rs
```

Both scoped commands passed on the source hashes in the result. The worker
also ran the four relevant predecessor files under Python `-O`: 7 tiny-gate,
8 fallback-gate, 9 copy16 and 12 error-band tests passed (36 total). Sanitized
raw outputs are retained under `predecessor-checks/`. These are focused checks,
not a full repository test pass or a per-head full sweep. Required
`make doctor verify test catalogue-check` and `make reproduce` results must
be stated separately by the submitter. No hosted CI result is claimed here.

## Limits and next step

The finite fixture relation is not a proof across every native state. Safe
view refusals, algebraic wrapping/noncanonical addresses and callback behavior
must not be relabeled as native faults, actual runtime pointer validity or
physical instruction traces. Native ABI, flags, SIMD/stack/unwind state,
concurrency/MMIO, unknown call/data closure, first-party ownership, complete
xrefs, original compiled bytes, the whole component and the network node
remain unresolved. No acceptance gate or catalogue is changed.

Next: review this explicit projection and its remaining layout/callee/consumer
gaps before integrating it into a native calling path. No standalone fragment
is presented as a working or synchronized network node.
