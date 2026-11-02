# RE-004: node94 eight-byte search, including unsorted tables

This contribution independently reconstructs the complete 115-byte leaf
`[0x52ca970,0x52ca9e3)` as dependency-free `no_std` Rust. It resolves the
Rust gap left by the [foundation packet](../foundation-eight-byte-binary-search-94/README.md).
Target node #94 is 91,774,280 bytes with SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`;
base commit is `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.

`raw_index(&[u64], key, limit) -> u64` preserves the unsigned limit shortcut,
its empty-table wrap, and the exact midpoint decisions. It accepts unsorted
tables without adding validation or sorting. Only sorted tables on the
search path justify a lower-bound interpretation. The existing caller's
sorting invariant and the limit's meaning remain unknown.

The [proof](PROOF.md) covers every u64 entry/key/limit and every admitted
slice length, including termination, safe indices and the conditions for
the sorted lower-bound interpretation. The original memory projection is
a stable readable contiguous qword span, nonwrapping and below 2^63 bytes,
as valid slices are on the supported 32/64-bit hosts. Malformed, negative,
nonaligned or wrapping original pointer differences and volatile/concurrent
memory are excluded explicitly. This does not replace original faults or
out-of-domain behavior with invented results.

## Static closure and independent expectations

The exact full target, leaf body, CIE/FDE, 13 padding bytes and complete
131-byte caller `[0x52cab00,0x52cab83)` are checked. Capstone 5.0.7
linearly decodes all 36 leaf and 39 caller instructions; GNU objdump
retains both complete bodies and selected frame records. The actual body
has five conditional branches, one unconditional jump and three returns.
The prior packet's prose counted six conditional branches; this packet
states the corrected count without changing prior evidence.

The full 70,370,352-byte .text direct-e8 scan finds the one site at
0x52cab17, which is qualified by the complete caller decode. All 80,300
RELA records are scanned and no addend names the leaf. These are specific
scans, not a complete indirect-reference census. The caller supplies
descriptor address 0x578e240 in NOBITS `.bss`; the initialized pointers
and limit are not established by file bytes. They remain explicit runtime
inputs. The leaf itself has no calls, external constants, tables or
relocations to close beyond its input memory. Its wider caller behavior,
descriptor initialization, source name and ownership remain unclaimed.

The independent oracle enumerates every terminal decision-tree leaf as
an interval of queries, rather than executing a query-driven search.
Right-edge predicates give an exclusive lower bound and left-edge
predicates give an inclusive upper bound. It checks that all nonempty
leaf intervals partition the complete u64 domain, then linearly locates
the query. Sorted cases are additionally checked by a separate linear
count of entries smaller than the key. No instruction, register, flags
or captured-code evaluator is used.

`frozen/ORACLE-FREEZE.json` was created at
`2026-11-01T20:06:02.497738+00:00` before new Rust source existed. It
binds the unchanged oracle source, original static facts and exact input
and expected-output hashes. Its creation code refuses an existing Rust
implementation or existing freeze. The Rust is independently authored
from the static relation; no unlicensed inferred implementation was read
or copied. New code/prose use the root MIT license; captured bytes and
disassembly retain the artifact's rights.

Only `src/node94-eight-byte-search/` and this packet change. Pins, prior
evidence, generated catalogues and progress gates are intact. The final
live overlap check found no match in 64 open PRs (including draft/review
status), zero open issues, or 20 recent merges; `overlap.json` retains the
inventory. Existing `src` had no implementation of this address or family.
The separate 16-byte pointer-entry search leaf is not claimed here.

## Actual native checks

The input-only client reads query, limit and numeric entries, and emits
only the returned index. Expected values and comparisons remain in the
external validator. The target is never executed. There are 58,476
frozen cases across 1,745 distinct tables:

- 7,253 sorted search cases, 20,240 unsorted search cases and 30,983
  limit-shortcut cases, including 15 empty-table shortcut wraps.
- Every ordered array of length 0..5 over `{0,1,2^63,2^64−1}`, including
  duplicates, plus ascending, descending, constant and deterministic
  additional arrays up to length 1,025.
- Query/limit equality, zero limits, empty and singleton spans, insertion
  past the end, high unsigned values, duplicate keys, and lengths around
  powers of two. The proof handles larger admitted slices; fixtures are
  not claimed as exhaustive enumeration of every possible table.

Installed rustc 1.94.1 (`e408947bfd200af42db322daf0fadfe7e26d3bd1`,
LLVM 21.1.8) built the library/client twice at opt-level 0 and twice at
opt-level 3. All four builds match every case: 233,904 row comparisons,
zero mismatches. Repeated rlib, executable and stdout hashes match within
each optimization level. The native host is aarch64-apple-darwin on
macOS 27.0.1; 32-bit builds, cross-host binary reproducibility and original
x86 ABI equivalence are unmeasured. Python 3.14.3 ran the validator under
`-O`; validation guards do not depend on Python assertions.

Eleven wrong Rust variants actually compile and execute against the same
driver and frozen inputs:

| Variant | Mismatched rows |
| --- | ---: |
| Shortcut only for key>limit | 14,590 |
| Empty check before shortcut | 15 |
| Saturating shortcut subtraction | 15 |
| Shortcut returns count | 30,983 |
| Signed limit comparison | 16,115 |
| Signed entry comparison | 20,911 |
| Upper-bound equality rule | 5,668 |
| Lower-middle pivot | 4,479 |
| Narrow entries to u32 | 13,279 |
| Return byte offset | 19,306 |
| Linear first-match search | 9,162 |

For `[0,0,0,1,0]`, key=1, limit=2, the target-grounded expected index
is 5; both the lower-middle and linear-first-match mutants return 3.
For an empty table with key=limit=0, the correct raw result is
18446744073709551615; checking emptiness first or saturating gives zero.
These controls demonstrate observed distinctions, not just changed
source text. One deliberately corrupted expectation gives exactly one
mismatch against actual unmodified native output.

Thirteen structural corruptions bypass whole-file SHA admission and are
rejected by the complete body/caller, CIE/FDE, padding or relocation
checks. They include unsigned branch/stride changes and a newly naming
relocation. The original artifact is never altered. No control executes
captured instructions or an emulator.

## Reproduce and audit

From the repository root with the pinned artifacts and installed tools:

```sh
python3 -B -O research/work-items/RE-004-node94-eight-byte-search-rust/validate.py
python3 -B -O research/work-items/RE-004-node94-eight-byte-search-rust/verify_recorded.py
python3 -B tools/foundation_eight_byte_binary_search.py --check research/work-items/foundation-eight-byte-binary-search-94/evidence.json
python3 -B -m unittest tests.test_foundation_eight_byte_binary_search -v
/opt/homebrew/opt/rustup/bin/rustfmt +1.94.1 --check --edition 2021 src/node94-eight-byte-search/lib.rs src/node94-eight-byte-search/input_only_driver.rs
env PATH=/opt/homebrew/opt/binutils/bin:/opt/homebrew/opt/rustup/bin:$PATH make doctor verify catalogue-check reproduce
shasum -a 256 -c research/work-items/RE-004-node94-eight-byte-search-rust/MANIFEST.sha256
```

`validate.py` accepts `--rustc`, `--objdump` and `--output` overrides,
while checking the compiler version/commit. Builds and input expansion
remain in ignored `work/node94-eight-byte-search/` (about 46 MiB here).
There is no new Cargo workspace or invented dependency lock. Frozen and
observed `.gz` files use the repository's existing Git LFS attributes and
require materialization.

`observed/results.json` binds sources, native artifacts, outputs and
concrete mutant counterexamples. `observed/commands.json` retains exact
command arguments, statuses and stream hashes with the worktree as
`/repo`. The single `raw-streams.json.gz` archive retains 98 exact raw
stdout/stderr streams as base64 plus SHA-256. `verify_recorded.py`
independently rechecks every stream hash and all 15 native-run mismatch
counts. Large GNU frame stdout is explicitly excerpted separately in
`observed/target.frames.txt`; the command record states that limit.

The legacy evidence checker, eight focused tests, rustfmt check and
`make doctor verify catalogue-check reproduce` passed.
`observed/repository-checks.json.gz` retains those logs; repository log
paths use `/repo` and `<home>`, and original/retained hashes are labeled.
No duplicate full repository test sweep was run, and the coordinator's
separate sweep is not claimed as this packet's result. Hosted CI,
captured execution, target-byte matching, full caller reconstruction and
component gate completion remain unmeasured or outside scope.

Authorship tooling: OpenAI / Codex. This runtime exposes no exact model
identifier; none is invented.
