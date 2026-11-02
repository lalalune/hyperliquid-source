# RE-001-remaining-nine-byte-family-rust-94: short-circuit byte-gate family

- Research allocation: RE-001 / foundation; bounded independent Rust.
- Base: `e5c9b6436876b2a4a39daef813171f9879317699`. Reference pin: `999556f6e0a474b8312db96ec3149e1c44e97c23`; its unlicensed inferred implementation was not read or copied.
- Target: Linux x86-64 node #94, 91,774,280 bytes, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Coordinates: ELF virtual addresses, not loader-rebased addresses.
- New source: `src/node94-remaining-nine-byte-family/lib.rs`.
- Claim: finite static-observation/compiled-Rust projection agreement. No native ABI, fault or compiled-byte equivalence claim.
- Progress/gates: unchanged. No first-party ownership or compared-byte denominator is supplied.

## Gap and established sequence

The base has static target evidence for these windows, but no independent
Rust implementation at this source path. Reconstruct the established behavior
without inventing source types, dependencies, consumers or helper semantics.

Two complete FDE windows form one coherent byte-selection family:

| Window (ELF VA) | First byte | Conditional second byte | Full RAX |
| --- | --- | --- | --- |
| `[0x51647b0,0x51647c4)` | `[RDI+0x58]` | `[RDI+0x68]` only if first is nonzero | 0 for first=0; otherwise 1 iff second=0 |
| `[0x51c09f0,0x51c0a07)` | `[RDI+0xd0]` | `[RDI+0xf8]` only if first is zero | first when nonzero, otherwise the raw second byte |

MOVZX clears the upper RAX bits before either return. The fallback is not a
boolean: e.g. first=255 returns 255 and does not access the second byte. The
Rust family preserves those different polarities, exact offsets, clean full
return and reached-read sequence. Object meanings, consumers, native calling
convention and complete indirect cross-references remain unknown.

The corpus exhausts all 65,536 byte pairs once per FDE at one chosen base.
It adds 120 representative zero/wrapping-base and missing-read controls,
including an unmapped second byte on paths that must not read it. This is
131,192 distinct fixtures, not a redundant cross-product across addresses.
Python dictionary reads and the Rust BTreeMap client resolve actual byte
views. The read-only library has no write primitive. Its safe missing-view
error is a new API outcome, not native hardware-fault reconstruction.

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
- Opt-level0 and opt-level3, two independent output directories each: all 131,192 frozen observations match on all four executions.
- At each optimization, complete rlib/client artifacts repeat byte-for-byte. Their hashes and compressed raw comparison outputs are retained.
- Safe-success fixtures: 131,117/131,192. Refused-view cases are reported separately from successful target projections.
- Four separately compiled semantic corruptions must exit normally and differ on successful observations; a crash, missing row or changed safe refusals alone cannot qualify a control.

- `tiny-inverted-second`: 65,289/131,192 observations differ; 65,289 differences also occur with successful outcomes. Exit0; raw mutant outputs and a first witness are retained.
- `tiny-one-as-zero`: 262/131,192 observations differ; 259 differences also occur with successful outcomes. Exit0; raw mutant outputs and a first witness are retained.
- `fallback-normalized`: 65,036/131,192 observations differ; 65,036 differences also occur with successful outcomes. Exit0; raw mutant outputs and a first witness are retained.
- `fallback-wrong-polarity`: 65,566/131,192 observations differ; 65,551 differences also occur with successful outcomes. Exit0; raw mutant outputs and a first witness are retained.

The client receives only fixture inputs. Expected output remains in the
independent Python corpus, never in the Rust client's input. Every command's
exit/stdout/stderr is retained under `qualification/commands/`; build-path
text is sanitized to `<REPO>`/`<HOME>`, while numeric comparison streams are
unchanged. Check the stream hashes, source hashes, qualifier hash and witnesses
in the machine-readable result.

## Reproduce

With the authenticated pinned inputs prepared by `bash scripts/setup.sh`:

```sh
python3 -O research/work-items/RE-001-remaining-nine-byte-family-rust-94/verify.py --rustc /path/to/rustc-1.94.1
rustfmt --edition 2021 --check src/node94-remaining-nine-byte-family/lib.rs src/node94-remaining-nine-byte-family/client.rs
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
