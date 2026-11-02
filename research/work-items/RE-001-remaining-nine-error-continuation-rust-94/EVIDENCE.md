# RE-001-remaining-nine-error-continuation-rust-94: post-call error-band and signed-range continuation

- Research allocation: RE-001 / foundation; bounded independent Rust.
- Base: `e5c9b6436876b2a4a39daef813171f9879317699`. Reference pin: `999556f6e0a474b8312db96ec3149e1c44e97c23`; its unlicensed inferred implementation was not read or copied.
- Target: Linux x86-64 node #94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Coordinates: ELF virtual addresses, not loader-rebased addresses.
- New source: `src/node94-remaining-nine-error-continuation/lib.rs`.
- Claim: finite static-observation/compiled-Rust projection agreement. No native ABI, fault or compiled-byte equivalence claim.
- Progress/gates: unchanged. No first-party ownership or compared-byte denominator is supplied.

## Gap and established sequence

The base has static target evidence for these windows, but no independent
Rust implementation at this source path. Reconstruct the established behavior
without inventing source types, dependencies, consumers or helper semantics.

The complete caller FDE is `[0x555e870,0x555e898)`. Its call at
0x555e874 targets 0x555e670. This packet reconstructs **only the continuation
`[0x555e879,0x555e898)`**, after that opaque call has returned. No stub,
callee implementation, native ABI, incoming-argument preservation or
call/stack/unwind behavior is supplied.

Inputs are observed post-call RAX, RDX and RSI. In particular, ESI is the
low32 of **post-call RSI**, not an assumed surviving incoming argument.
The explicit register projection is:

1. RCX becomes the complete post-call RAX; output RAX starts at zero.
2. Unsigned post-call RAX above `2^64-120` returns that zero. The threshold
   itself (-120 as an i64 bit pattern) is admitted; only [-119,-1] is rejected.
3. Compare signed low32(post-RSI) against signed low32(post-RDX). A smaller
   value returns zero, leaving the complete post-RDX unchanged.
4. Otherwise arithmetic-shift RDX by32 and retain that sign-extended value
   even when the upper-bound check fails. Set clean RAX=1 iff signed ESI is
   no larger than signed low32 of the shifted RDX.
5. The complete post-RSI remains unchanged on every modeled path.

The independent oracle uses signed struct unpacking and the cardinality of
the 119-value top-u64 error band, rather than copying the Rust shift/cast
implementation. Cases cover both threshold neighbors, signed-i32 extreme,
equal and reversed bounds, lower/upper neighbors, nonzero RSI upper halves
and 512 fixed-seed triples. Output comparison includes all four scoped GP
values, so a zero boolean alone cannot hide the wrong RDX branch state.
RSI/RDX production by the unresolved callee, other registers, flags and native
call/return behavior remain unestablished.

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
- Opt-level0 and opt-level3, two independent output directories each: all 1,216 frozen observations match on all four executions.
- At each optimization, complete rlib/client artifacts repeat byte-for-byte. Their hashes and compressed raw comparison outputs are retained.
- Safe-success fixtures: 1,216/1,216. Refused-view cases are reported separately from successful target projections.
- Four separately compiled semantic corruptions must exit normally and differ on successful observations; a crash, missing row or changed safe refusals alone cannot qualify a control.

- `inclusive-error-band`: 60/1,216 observations differ; 60 differences also occur with successful outcomes. Exit0; raw mutant outputs and a first witness are retained.
- `high-as-low`: 363/1,216 observations differ; 363 differences also occur with successful outcomes. Exit0; raw mutant outputs and a first witness are retained.
- `logical-rdx-shift`: 226/1,216 observations differ; 226 differences also occur with successful outcomes. Exit0; raw mutant outputs and a first witness are retained.
- `wrong-rsi-half`: 470/1,216 observations differ; 470 differences also occur with successful outcomes. Exit0; raw mutant outputs and a first witness are retained.

The client receives only fixture inputs. Expected output remains in the
independent Python corpus, never in the Rust client's input. Every command's
exit/stdout/stderr is retained under `qualification/commands/`; build-path
text is sanitized to `<REPO>`/`<HOME>`, while numeric comparison streams are
unchanged. Check the stream hashes, source hashes, qualifier hash and witnesses
in the machine-readable result.

## Reproduce

With the authenticated pinned inputs prepared by `bash scripts/setup.sh`:

```sh
python3 -O research/work-items/RE-001-remaining-nine-error-continuation-rust-94/verify.py --rustc /path/to/rustc-1.94.1
rustfmt --edition 2021 --check src/node94-remaining-nine-error-continuation/lib.rs src/node94-remaining-nine-error-continuation/client.rs
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
