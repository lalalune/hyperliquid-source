# RE-001: unsigned clamp with complete RAX/RCX and field admission

This contribution reconstructs node94's complete 69-byte function
`[0x15e4f70,0x15e4fb5)` in independent safe `no_std` Rust. It closes the
Rust gap in [foundation-unsigned-clamp-94](../foundation-unsigned-clamp-94/README.md),
preserves the asymmetric full64/low32 tag tests, and returns both full
RAX and RCX. The cap remains required on the other-tag path even though
that path's RAX is always zero. A copied-field API makes those selected-path
requirements explicit without asserting a native pointer ABI or tag enum.

## Identity and boundary

- Component/task: foundation, bounded RE-001 reconstruction. Source-level
  function, type and field meanings remain unknown.
- Target: node94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference gitlink
  `999556f6e0a474b8312db96ec3149e1c44e97c23` is unchanged. No inferred
  reference implementation was read or copied.
- Coordinates: linked ELF VAs; file offsets resolved from section headers.
- New component: [src/node94-unsigned-clamp](../../../src/node94-unsigned-clamp/README.md),
  standalone Rust 1.94.1, dependency-free, `no_std`, `forbid(unsafe_code)`.
- Author: 신준, with AI assistance; no exact model identifier is asserted.
  New implementation/prose use MIT; retained target bytes keep their
  original rights. Pins, imports, catalogues and progress gates are unchanged.

[PROOF.md](PROOF.md) covers every path and the supplied-value boundary.
The complete body has 23 instructions and a unique exact FDE overlap in
all 121,299 decoded FDEs. Eleven trailing `int3` bytes are separately bound
padding. GNU and LLVM agree on all bytes/instruction boundaries. The shared
and caller CIEs and complete FDE records are fixed independently of code.
The one incoming E8 site at `0x15e482d` is boundary-confirmed in the complete
caller `[0x15e4610,0x15e4913)`, **771 bytes / 188 instructions**. The prior
README's 803-byte description is inconsistent with these endpoints; this
packet records the fresh byte/FDE result without editing historical evidence.
The caller's wider behavior is not reconstructed.

Full `.text` E8/E9 pattern scans find that single call and zero E9 candidates.
All 80,300 RELA records contain no entry-naming addend and no write overlapping
the bound code. Indirect references and other pointer paths are not a complete
xref census. The leaf has no calls or branches outside its bound body, and no
RIP-relative data/global dependency. `static/` contains both complete decoder exports, raw code and
FDE/CIE hex, mapping/hashes and census results.

## Exact API relation

Let T be the original qword at object+0, X at +16, Y at +24 and C at +40.
All values and comparisons are unsigned:

| Tag | Required values after T | RAX | RCX |
| --- | --- | --- | --- |
| full64 T is zero | Y, C | `min(Y,C)` | C |
| low32 T is one | X, Y, C | `min(saturating_sub(X,Y),C)` | C |
| other | C | 0 | C |

Tag `0x100000001` uses the difference path; `0x100000000` uses the zero-result
path. The latter still loads the entire cap into RCX. No data is written.

`clamp(tag, first, second, cap)` accepts copied u64 values; the final three
are optional. Only selected-path values are checked, in original load order.
An absent required value returns `Err(Unavailable)`. The already supplied
tag must correspond to the original tag load. Successful correspondence
requires stable ordinary complete little-endian target reads, unchanged code
and valid return control. `None` describes a value not supplied to this API,
not an OS mapping or native fault. The API excludes original pointers/ABI,
fault timing, MMIO, concurrency, flags, access traces and RET/RSP effects.
The proof states why a dense image would unnecessarily couple availability
of the intermediate fields to the mandatory cap.

## Frozen oracle, preserved initial gap and final qualification

The original oracle and **30,896** input/expected rows were frozen at
`2026-11-01T21:54:56.006021+00:00`, before Rust existed. Its own hash and
raw/compressed fixture hashes are in `fixtures/freeze.json`. It computes
nonnegative difference and minimum through unbounded absolute-value formulas,
independently of Rust's typed saturation/minimum. The oracle evaluates the
required value set, not a native access trace. Neither captured code nor an
instruction emulator supplies expectations.

Original coverage: 5,880 full-zero cases, 11,815 low32-one cases, 12,093
other-tag cases, 643 missing-cap refusals, 390 missing-difference-field refusals
and 75 missing-zero-path-field refusals. It includes extreme values, every
bit boundary, high-half tag differences, all eight availability masks for
ten tags, and deterministic randomized values.

The first four correct opt0/opt3 runs matched all original rows. However,
the fourth compiled mutation, using low8 instead of low32 for tag one,
**survived**. Its sole original distinguishing random tag had X<Y, so the
mistaken difference path also produced zero. `initial/` retains the exact
verifier at that time, all compiler commands, traceback, artifact hashes,
three detected mutants, the actual surviving mutant result, and all eight
stdout streams. This first attempt was not successful qualification.

The original oracle, corpus and Rust source remain unchanged. A separate,
explicitly **post-Rust 72-case supplement** tests each tag bit 8..31 with
three high-word prefixes and nonzero distinguishing arithmetic values.
Its expectations follow directly from the other-tag theorem: RAX=0 and
RCX=C. `supplement.py` and `fixtures/supplement.json` bind its provenance,
source and exact files plus the unchanged original source/oracle/freeze.
The expanded corpus is not called pre-Rust frozen evidence.

Final qualification passed **30,896 original + 72 post-Rust = 30,968 cases
× four runs = 123,872 complete observations**. Opt0 and opt3 were each built
and run twice, with identical rlib/client hashes within each level. All 27
compiled Rust mutations exited normally and produced observable differences.
The input-only client receives only input rows via stdin and emits full
availability status plus all 64 bits of RAX and RCX. It never opens or receives
expected values; there are no comparison masks.

Thirty-five static corruption controls cover each leaf instruction, incoming
call, both FDEs/CIEs, padding, injected E8/E9 edges, entry naming/code
relocations and an unrelated FDE shifted to overlap the leaf. Internal
structural controls bypass only the full-target digest gate. Four comparator
controls and two archive corruptions also reject. Final exact compiler
commands, source/artifact hashes, first mismatch witnesses and counts are
in `native/`. Its 31 exact stdout streams and the initial eight streams are
losslessly stored in deterministic gzip shared-line archives with original
byte lengths and SHA-256 hashes. `audit_archive.py` verifies both archives
and rejects the deliberate final-archive corruptions.

These are native executions of newly authored Rust on macOS arm64. They
support the static all-input proof on the stated supplied-value domain;
they are not target differential execution, x86 code generation qualification,
compiled-byte equality, native ABI or whole-node equivalence.

## Reproduction and observed checks

From repository root with the pinned LFS artifacts materialized:

```sh
export PATH="/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH"
python3 -O research/work-items/RE-001-unsigned-clamp-rust-94/oracle.py
python3 -O research/work-items/RE-001-unsigned-clamp-rust-94/supplement.py
python3 -O research/work-items/RE-001-unsigned-clamp-rust-94/verify.py --out work/unsigned-clamp/replay
python3 -O research/work-items/RE-001-unsigned-clamp-rust-94/audit_archive.py
python3 tools/foundation_unsigned_clamp.py --check research/work-items/foundation-unsigned-clamp-94/evidence.json
python3 -m unittest tests.test_foundation_unsigned_clamp -v
cargo +1.94.1 check --offline --locked --manifest-path src/node94-unsigned-clamp/Cargo.toml --target-dir work/unsigned-clamp/cargo
rustfmt +1.94.1 --check --edition 2024 src/node94-unsigned-clamp/lib.rs src/node94-unsigned-clamp/client.rs
make doctor
make verify
make catalogue-check
make reproduce
```

Use a fresh output directory. `initial/verify-initial.py` is a historical
source record, not the current reproduction entry point. Exact compile
commands/flags/results are retained in `native/commands.json`. GNU Binutils
2.47.20260726 and Apple LLVM 17.0.0 independently decoded the code; Python
3.14.3 and Rust 1.94.1 ran on macOS 27.0.1 arm64. The packet's Python code
uses the standard library and existing repository ELF/FDE parsers.

Prior checker, all **12 focused tests**, Cargo locked/offline, rustfmt,
doctor, verify, catalogue-check and reproduce passed. Logs include actual
exit records. The separate shared baseline reported 971 files / 15,462
tests / 69 skips; its original `make test` exited 2 solely from three disk-full
errors, and all 20 affected tests passed isolated retries. It was not rerun
on this head; skipped Linux tests and hosted CI success are not claimed.

Live PR/issue/recent-merge snapshots and the source overlap census are retained
in `logs/overlap.json` and `logs/live-inventories.json.gz`. The only generic
phrase match is PR #1465, the distinct scaled-advance function at `0x4ea41e0`;
it does not overlap this range or implement this tag/field relation.

From this packet directory, run `shasum -a 256 -c MANIFEST.sha256` to check
packet, component, parser and predecessor-check/test files. The manifest
excludes itself and Python caches. Maintainer review and broader component
acceptance remain separate; no progress gate is advanced. No live node,
chain action, credential, paid input or unlicensed inferred source was used.
