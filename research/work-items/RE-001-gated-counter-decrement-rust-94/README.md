# RE-001: gated counter decrement in independent safe Rust

This contribution reconstructs node94's complete 109-byte function at
`[0x50a90a0,0x50a910d)`, including its actual five-byte called helper at
`[0x5334d60,0x5334d65)`. It closes the Rust gap left by
[foundation-all-empty-gate-94](../foundation-all-empty-gate-94/README.md)
and additionally preserves the full path-dependent raw RAX value, proves
the helper's lack of argument-memory requirements, and admits arbitrary
data aliases in a safe memory-image API. It is one bounded arithmetic/state
reconstruction, not a separate contribution for the no-op helper.

## Identity and scope

- Component: foundation, RE-001. The source-level owner/name remains unknown.
- Target: node94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; reference gitlink remains
  `999556f6e0a474b8312db96ec3149e1c44e97c23`. Reference implementation content
  was not read or copied. No imported evidence, pin, catalogue or progress
  gate is changed.
- Coordinates: linked ELF VAs, with file offsets resolved from section
  headers. The `.text` offset relation is not assumed for other sections.
- New implementation: [src/node94-gated-counter-decrement](../../../src/node94-gated-counter-decrement/README.md),
  dependency-free `no_std`, `forbid(unsafe_code)`, Rust 1.94.1, MIT.
- Author: 신준, with AI assistance. No exact model identifier is asserted.
- Live overlap checks: 135 initial and 139 final open PRs, zero open issues,
  30 recent merged PRs at both checks, and a source census at the untouched
  base contain no address/semantic overlap. Exact public inventory snapshots
  and their hashes are preserved in `logs/live-inventories.json.gz`; scope
  and search records are in `logs/overlap.json`.

## Target evidence and behavior

[PROOF.md](PROOF.md) derives the memory and raw-register relation from every
instruction, including the exact five-byte dependency and alias restrictions.
`static/` retains complete GNU and Apple LLVM outputs, shared CIE and both
FDE records, body hex/hashes, overlap inventory identity, call edge and
relocation census. Each decoder covers all 28 primary and two helper
instructions without a gap. All 121,299 FDEs are decoded to establish a
single exact overlapping FDE for each body. The primary's three trailing
`int3` bytes are separately bound padding.

The primary reads an inner pointer and, in order, tests five pairs of
64-bit words at offsets `(8,16)`, `(56,64)`, `(104,112)`, `(128,136)` and
`(176,184)`. On the first mismatch it returns the inner pointer in full RAX
and writes no data. When all match, it reads an owner pointer from outer+8,
calls the actual `endbr64; ret` body with an unused numeric owner+1792
argument, reloads the owner, and decrements the little-endian dword at
owner+5276 modulo `2^32`. Full RAX is that owner snapshot before the store.
Only those four data bytes change; the store may overwrite earlier-read
fields, including the owner pointer itself.

There are zero `.text` E8 candidates targeting the primary. The sole call
inside it is verified at its decoded instruction boundary. A complete byte
scan records 116 E8 candidates to the helper, including this one; the other
115 candidates and their caller semantics are outside this API. This is
not a complete indirect-reference census. All 80,300 RELA records have no
addend naming either entry and no destination overlapping either body.
The closure has no other calls, external branches, RIP-relative data loads
or inferred global/table requirements.

The safe API projects one nonwrapping image of abstract u64 addresses;
effective field addresses still wrap modulo `2^64`. Every required access
must fit, while unused pairs, owner fields and the unused helper argument
need no mapping. An unmapped owner value can still have a mapped used
counter field. Arbitrary data aliases/unaligned reads are allowed. Missing
ranges return `Err(Unavailable)` without mutation. Correspondence requires
valid ordinary stable native accesses and disjoint valid control stack/code;
it excludes native faults, MMIO, concurrency, control-stack/data aliases,
code modification, nonordinary return behavior and pointer-ABI equivalence.
No container emptiness, reference counting, destructor or business identity
is inferred from the observed equality gates.

## Frozen expectations and observed qualification

The independently authored oracle was frozen at
`2026-11-01T21:43:00.992638+00:00`, before the Rust directory existed.
It compares byte strings and computes positional base-256 integers and
modular output bytes; it does not execute or emulate target instructions.
The later Rust uses typed qword equality and wrapping dword subtraction.
`fixtures/freeze.json` pins the oracle and raw/compressed input/expected
hashes. Neither oracle nor corpus changed after that freeze.

| Frozen category | Cases |
| --- | ---: |
| First mismatch at gates 1 / 2 / 3 / 4 / 5 | 2,124 / 945 / 611 / 469 / 331 |
| Decrement, including aliases and wrapping effective addresses | 2,047 |
| Required access unavailable | 1,837 |
| Whole image wraps | 108 |
| Total | 8,472 |

The corpus includes all 32 equality patterns, high-word-only differences,
counter edges, every counter displacement through earlier-read fields,
exact/truncated read-prefix lengths, pointer and partial aliases, wrapped
positive field offsets, high bases and deterministic randomized images.
The standard-library client receives only input rows on stdin; it never
reads expected values. It emits full RAX/refusal and lossless differences
for every image byte. There are no comparison masks.

The first native qualification passed all **8,472 × 4 = 33,888** comparisons:
opt0 and opt3, each independently built and run twice. Rlib and client hashes
repeat exactly within each optimization level. All 33 deliberately changed
Rust variants compiled, exited normally and differed observably. Their
first witnesses and mismatch counts are in `native/result.json`; examples
include 53 cases rejecting a late owner reload, 226 detecting checked
instead of wrapping counter-address addition, and 2,047 detecting an
invented mapping requirement for the unused helper argument. No failed or
surviving trial was discarded; this task's first full qualification passed.

Forty-one static corruption controls include every primary/helper instruction,
FDE extents, the shared CIE, padding, injected primary call, naming and code
relocations for both entries, and an unrelated FDE shifted over the primary.
Internal controls bypass only the outer digest check to prove the relevant
structural rejection. Four comparator corruptions and two archive corruptions
are also rejected. `native/raw-streams.json.gz` contains all 37 exact stdout
streams using a lossless shared line dictionary, original byte counts and
SHA-256 values, with deterministic gzip timestamp zero. `audit_archive.py`
reconstructs and verifies every stream before its two deliberate corruptions.

These are native executions of newly authored Rust on macOS arm64, not
captured x86-64 target execution or instruction emulation. They support the
static proof on the admitted domain; they do not establish whole-node,
native-target differential, ABI or machine-code equivalence.

## Reproduce

From repository root with the pinned LFS inputs materialized:

```sh
export PATH="/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH"
python3 -O research/work-items/RE-001-gated-counter-decrement-rust-94/oracle.py
python3 -O research/work-items/RE-001-gated-counter-decrement-rust-94/verify.py --out work/gated-counter-decrement/replay
python3 -O research/work-items/RE-001-gated-counter-decrement-rust-94/audit_archive.py
python3 tools/foundation_all_empty_gate.py --check research/work-items/foundation-all-empty-gate-94/evidence.json
python3 -m unittest tests.test_foundation_all_empty_gate -v
cargo +1.94.1 check --offline --locked --manifest-path src/node94-gated-counter-decrement/Cargo.toml --target-dir work/gated-counter-decrement/cargo
rustfmt +1.94.1 --check --edition 2024 src/node94-gated-counter-decrement/lib.rs src/node94-gated-counter-decrement/client.rs
make doctor
make verify
make catalogue-check
make reproduce
```

The native output directory must be fresh. Its exact compiler commands,
flags, tool versions and outputs are retained in `native/commands.json` and
`native/result.json`; raw disassembly options are in `static_evidence.py`.
GNU Binutils 2.47.20260726 and Apple LLVM 17.0.0 independently decoded the
bodies. Python 3.14.3 and Rust 1.94.1 ran on macOS 27.0.1 arm64. No third-party
Python package is needed by this packet. The ELF/FDE parsers are existing
repository code whose hashes are included in the manifest.

Observed checks: prior packet checker PASS; 18 focused tests PASS; Cargo
locked/offline and rustfmt PASS; doctor, verify, catalogue-check and reproduce
PASS. Exact outputs and exit records are retained in `logs/`. Expected
negative-control messages in the focused test log are passing assertions.
The shared campaign baseline completed 971 files / 15,462 reported tests /
69 skips; its original `make test` exited 2 solely from three disk-full
errors, with all 20 affected tests passing isolated retries. That baseline
was run separately, not repeated on this head. No hosted CI, Linux/container
qualification or skipped test success is claimed.

To verify packet/source/parser/prior-test hashes, change into this packet
and run `shasum -a 256 -c MANIFEST.sha256`. The manifest excludes itself and
Python caches. The remaining acceptance boundary is maintainer review of
this bounded proof/domain and its replay; all broader component gates stay
false. No captured binary, live service, chain action, credential, paid
input or unlicensed inferred implementation was used.
