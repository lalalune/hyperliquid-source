# RE-001: reconstruct the fixed-record cursor walk

- Component: foundation; bounded RE-001 function/data-flow reconstruction.
- Target: node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Baseline main: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
- Reference gitlink: `999556f6e0a474b8312db96ec3149e1c44e97c23`; no inferred
  unlicensed source implementation was opened or copied.
- Scope: complete walk, exact body/FDE/caller setup/data operands, and a safe
  finite-record projection with independently frozen expectations.
- Excluded: arbitrary raw pointers, aliased cursor/node memory, nonterminating
  off-lattice walks, caller dispatch semantics, source identity and progress gates.

The earlier `foundation-cursor-walk-94` static packet and broader historical
`bridge-signed-action-admission-94` packet both left Rust unimplemented. This
contribution adds independent Rust for this leaf only. Historical captured
execution/emulation results are neither rerun nor used as the oracle. Existing
packets, their claims and their limits remain unchanged.

## Reconstructed behavior

`src/node94-cursor-walk` is a real dependency-free, safe `no_std` crate. The
[proof](PROOF.md) follows both the first iteration and loop backedge: entry
equality returns false without mutation; otherwise each visited record advances
the cursor first, then requires tag byte +9==2 and first byte==0. A failure
returns false with the cursor already one record beyond the failed node. A
nonempty passing range returns true exactly at the limit; the limit itself is
never read. The redundant first-iteration tag-3 test does not change this rule.
Full native RAX is 0 or 1, not an unspecified register with only AL meaningful.

The independently chosen API uses `[u8;56]` records and cursor/limit indices.
It accepts equality before bounds checks, including equal out-of-slice indices.
Unequal inputs require `cursor < limit <= records.len()`; refusal preserves the
cursor. This explicit safe policy is additional to native behavior. On admitted
ranges, a pointer/index induction proves node order, first-failure state, success
state and termination. All record byte patterns are allowed.

The admitted native domain requires contiguous aligned-stride records with
mapped nonwrapping addresses, stable node memory and separate cursor/limit
storage. The API strengthens availability to complete records. Native aliases,
wrapped paths, backward/off-lattice limits, faults, MMIO/concurrency and original
ABI are excluded. This is a complete value/state relation on the stated domain,
not a claim that every raw native input is represented or that every caller
satisfies these premises.

## Static evidence and concrete caller

Full-target authentication precedes structural analysis. ELF virtual addresses
are mapped through actual sections, without a guessed loader rebase. GNU and
Apple LLVM independently agree on every instruction boundary and byte:

| Body | Extent | Bytes | Instructions | .eh_frame FDE offset |
|---|---|---:|---:|---|
| Walk | `0x3c1d690..0x3c1d6e1` | 81 | 28 | `0x1beec4` |
| Caller | `0x3362f30..0x3362fc2` | 146 | 41 | `0x11818c` |

Walk SHA-256:
`ae2cf37c1a3a17292c3c809245e4836f4a7efeebeff46b2fdd689567dd75e9f3`.
Caller SHA-256:
`d88cce48e8fc7d8f16658000055516e356a1c459291914439d9a861f7d2c4e3b`.
All 3 CIEs / 121,299 FDEs are decoded; each selected range overlaps exactly its
own complete FDE. Raw records, the shared CIE and inventory hash are retained,
and GNU frame output independently agrees. Fifteen following `int3` bytes are
padding outside the walk FDE. The internal alignment NOP belongs to its body.

The complete 70,370,352-byte `.text` E8-pattern scan finds one direct call at
0x3362fb8, confirmed at a caller instruction boundary. The setup block at
0x3362f9d multiplies object+0x40's qword by 56, adds the pointer at object+0x38,
stores base/result at RSP+8/RSP+0x10, and passes that stack pair to the leaf.
This grounds the finite base/count projection when addresses and count are
valid; it does not establish arbitrary caller bounds. The rest of the complete
caller is retained as context, including dispatch/tail paths whose semantics
and external data targets are outside this reconstruction.

The leaf has no calls or static data constants. Its complete dynamic data edges
are cursor/limit fields at RDI/+8, node byte +9 and node byte +0, with a write
only to the cursor slot. No naming relocation appears in all 80,300 RELA entries.
Neither that absence nor the direct-call scan is a complete indirect-reference
census. `static/records.json` retains body/call bytes, offsets, exact FDE overlap
lists and all hashes; decoder/frame text is retained without normalization.

## Frozen expectations and measured comparison

The oracle was frozen before any Rust existed. It selects all failing indices
in an immutable range and takes the minimum, yielding `first_failure+1` and
false; a nonempty range with no failure yields the limit and true. Equality
and invalid ranges are handled separately. This closed-form oracle does not
replay target instructions or duplicate the native cursor loop. It does not
import the earlier rule helper or read Rust outputs. `fixtures/freeze.json`
binds its source and both raw/deterministically compressed fixture streams.

There are 7,009 cases: 1,540 complete nonempty passes, 272 entry equalities,
742 first-record failures, 2,519 later failures and 1,936 safe refusals. They
cover every possible tag/first-byte value, first/later failure positions,
nonzero starts, records outside the interval, exact slice ends, unequal invalid
ranges and huge/equal indices. Irrelevant record bytes vary independently of
the two checked fields. This is finite coverage of the static relation, not
exhaustive enumeration of all record arrays.

The input-only client receives indices and complete raw records, never expected
answers. All public result and final cursor bits are compared without masks;
records are immutable through the API. All 7,009 cases match at opt0 and opt3,
each built/run twice (28,036 comparisons). Repeated rlib/client hashes match
at each optimization.

All 21 compiled mutants exit normally and produce observable mismatches. These
include empty=true (272), skipping every second record (3,154), checking only
the first record (2,519), failure before advance (3,261), consuming the remaining
range on failure (3,060), and treating invalid input as false (1,936). Other
mutants cover field offsets, predicate combination, tag 3, exact-end refusal,
empty cursor mutation and successful return/cursor updates. No crashing or
noncompiling mutant is counted. The complete verifier passes under Python `-O`.

There are 42 static corruption and 4 comparator controls. Structural controls
bypass only full-target authentication to reach body/caller-setup/FDE/CIE,
padding, direct-call-census and relocation checks. `native/result.json` retains
counts and first witnesses; `native/commands.json` retains every compile command
and exit result. One deterministic `native/raw-streams.json.gz` archive preserves
all 25 exact stdout streams with their original labels, byte counts and hashes.

## Reproduce and limits

From the repository root, with pinned artifacts materialized:

```sh
export PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH
python3 -B research/work-items/RE-001-cursor-walk-rust-94/oracle.py
python3 -O -B research/work-items/RE-001-cursor-walk-rust-94/verify.py \
  --out work/cursor-walk-review
python3 -B research/work-items/RE-001-cursor-walk-rust-94/verify.py --check-archive
CARGO_TARGET_DIR=work/cursor-walk-cargo cargo build --offline --locked --release \
  --manifest-path src/node94-cursor-walk/Cargo.toml
python3 -B tools/foundation_cursor_walk.py \
  --check research/work-items/foundation-cursor-walk-94/evidence.json
python3 -B -m unittest tests.test_foundation_cursor_walk -v
make doctor verify catalogue-check reproduce
(cd research/work-items/RE-001-cursor-walk-rust-94 && shasum -a 256 -c MANIFEST.sha256)
```

Native validation uses macOS ARM64/rustc 1.94.1 with edition2024,
codegen-units=1, overflow-checks=yes, panic=abort, debuginfo=0, warnings denied
and remapped source paths. Python is 3.14.3; exact GNU/LLVM/compiler versions
are in `logs/tool-versions.log`. `--out` must be fresh. `GNU_OBJDUMP`,
`LLVM_OBJDUMP` and `--rustc` select installed tools; raw export equality requires
the retained decoder versions. This is not Linux target execution or hosted CI.

The native matrix, predecessor static checker, all 12 focused predecessor tests,
offline Cargo, rustfmt and repository doctor/verify/catalogue/reproduce pass.
No implementation repairs or failed native/control runs occurred. The full
repository sweep was not duplicated and is not claimed here. Public scope
checks retained in `overlap.json` found no match among 81 initial/84 final open
PRs, zero issues and 30 recent merges; source search found no Rust implementation.
No captured code, emulator, networked node, chain/key operation or unlicensed
implementation was used. Imported evidence, pins and progress gates are unchanged.
The leaf's admitted relation is reconstructed; source identity, record meaning,
and behavior outside the explicitly selected memory domain remain unclaimed.
