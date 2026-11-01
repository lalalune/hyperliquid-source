# RE-009: node94 non-full parent append after a leaf split

The nonzero-parent, last-child route absorbs one promoted opaque key/value
pair, installs the new child edge, repairs that child's parent and 16-bit
index, and reaches the ordinary return. This closes a selected continuation
left open by the split-plan and null-parent packets. It is a conditional
static native relation, not complete insertion or an implementation gate.

Target: Linux x86-64 node #94, `artifacts/node/94/hl-node`, 91,774,280 bytes,
SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base main: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`. The credited caller
at `0x2854859` calls owner FDE `0x1ab3d20..0x1ab4a43` (exclusive end),
body SHA-256 `93d07eae728e5ddaadc820741e5508fffe77bf2a74f50ec73d3bd448b3124d15`.
FDE `0x1016d98`, CIE `0xfbdc2c`, LSDA `0x967024` and the caller's complete
body/FDE/CIE/index membership are authenticated as well.

## Ownership and scope

[PR #1426](https://github.com/lalalune/hyperliquid-source/pull/1426) supplies
the caller/key-order context;
[PR #1438](https://github.com/lalalune/hyperliquid-source/pull/1438) supplies
the split plan and credited owner bytes;
[PR #1457](https://github.com/lalalune/hyperliquid-source/pull/1457) supplies
the separate null-parent/root-growth path. This sibling packet follows on
the same draft and leaves its original packet and tests unchanged. No
credited owner, caller or prologue bytes count as new reconstructed coverage.

The ownership refresh inspected 187 full open PR bodies and current main.
Only #1457 matched the selected addresses: its shared entry and exclusive
endpoint `0x1ab4705`, rather than this nonzero-parent append route.
`ownership.json` pins relevant heads and body hashes. This point-in-time
check cannot exclude unpublished work; refresh before push.

## Entry and memory premises

At `0x1ab40d6`, R15=L is the old leaf, R14=N is the new sibling, R13=h=0,
and B is the current stack pointer. Let P=u64[L+0x2c0] be nonzero,
n=u16[P+0x2ca]<11, and d=u16[L+0x2c8] be a valid child index d<=n with d=n.
The promoted key occupies B+0x50/+0x60 and its paired value B+0x70/+0x80,
each 32 opaque bytes. These names express recovered local roles, not original
source types, an entry ABI, or a general tree representation.

P is a valid writable 816-byte object; L and N are valid 720-byte objects.
Mutable node and result objects are mutually disjoint and disjoint from ALL
live frame/saved-register/return-address storage, including the prepared and
saved source regions. Prepared buffers and saved source words occupy their
declared regions inside that live frame. B+0x18 and B+0x38 are the two explicit
frame writes and must be separate from those protected sources. No address
wrap, concurrent mutation or intermediate observer is allowed. B is 16-byte
aligned for MOVAPS. R=u64[B+0x28] denotes a valid disjoint 24-byte output.
Prepared and saved source bytes remain stable until consumed. These alias,
capacity and ownership properties, allocator effects and preceding imported
copy/leaf-transfer effects remain premises. This continuation has no call;
it supplies no new guarantee about those earlier operations.

## Complete selected normal path

| Native edge | Selected decision |
| --- | --- |
| `0x1ab40e0` fallthrough; `0x1ab40e8 -> 0x1ab413f` | P!=0; ECX becomes zero |
| `0x1ab4142` fallthrough | h=0 matches RCX |
| `0x1ab4169 -> 0x1ab4705` | zero-extended n<11 |
| `0x1ab471f -> 0x1ab47df` | unsigned d>=n plus premise d<=n gives equality |
| `0x1ab4837` fallthrough | d+1=n+1<n+2 |
| `0x1ab484a` fallthrough | remainder `(n-d+1)&3` is one |
| `0x1ab487d` fallthrough after one iteration | repair-loop index advances zero to one |
| `0x1ab4889 -> 0x1ab46d8` | remaining n-d is zero, below three |
| `0x1ab4704` RET | complete ordinary epilogue |

The append predicate skips all imported memmove calls. The four-child repair
loop is skipped as well. The native JAE does not validate d<=n: d=n+1 also
enters append but skips repair and is explicitly outside this relation.
Count 11 takes the parent-split route; d<n takes a memmove corridor; h!=0
fails the saved-level guard. None is characterized here.

## Stores, byte extents and return

| Native sites | Destination and width | Value |
| --- | --- | --- |
| `0x1ab415f`, `0x1ab4164` | B+0x38, B+0x18; 8 bytes each | N, n |
| `0x1ab47e9`, `0x1ab47ee` | P+32*n+16, P+32*n; 16 bytes each | promoted key high, low |
| `0x1ab4803`, `0x1ab480b` | P+0x170+32*n, P+0x160+32*n; 16 bytes each | promoted value high, low |
| `0x1ab4825` | P+0x2d8+8*n; 8 bytes | N, child slot n+1 |
| `0x1ab482d` | P+0x2ca; 2 bytes | n+1 |
| `0x1ab4864` | N+0x2c0; 8 bytes | P |
| `0x1ab486f` | N+0x2c8; 2 bytes | n+1 |
| `0x1ab46e5`, `0x1ab46e8`, `0x1ab46ec` | R, R+8, R+16; 8 bytes each | saved D, A, C |

The scalar repair reads exactly the just-written child slot, writes its
parent using R11=P, and its index using R13=n+1. It executes once. The
16-bit index ends immediately before N's 16-bit count, which is preserved.
At n=10 the last key ends at P+0x160, the value ends at P+0x2c0, and edge
slot 11 spans `[P+0x328,P+0x330)`, within the stated parent extent.

At `0x1ab4813/18`, RDI receives R and R10 receives C=u64[B+0x10]. The
repair temporarily uses RDI for N, saving it in R9 and restoring it at
`0x1ab4882`. The epilogue loads A=u64[B+0x98], D=u64[B+0x30], writes
`[D,A,C]`, and sets RAX=R at `0x1ab46f0`. ADD RSP,0x178 and six POPs reverse
the credited 17-byte prologue; RET consumes the protected saved return
address. D/A/C are raw words. The fixtures choose local saved words without
claiming they form reachable original handles.

## Frozen witnesses and operative byte controls

`PLAN.json` first froze target-derived predicates, store widths, four native
control sites and n=0/1/9/10. It then froze independent input/expected
whole-buffer hashes before the store relation was written. Historical
`new_model_written:false` fields describe that intake checkpoint. Four inputs
each contain a parent, new child, old child, valid inactive dummy child and
result: 3,000 bytes. The independent test oracle directly maps nominal
destinations; it does not use decoded fields or the relation's output.
All 12,000 final bytes are compared, including untouched bytes.

| n=d | Final count/index | New edge offset | Repair iterations |
| ---: | ---: | --- | ---: |
| 0 | 1 | `0x2d8` | 1 |
| 1 | 2 | `0x2e0` | 1 |
| 9 | 10 | `0x320` | 1 |
| 10 | 11 | `0x328` | 1 |

`verify.py` authenticates the whole image, both complete bodies/unwind
records, all six retained windows and nine branch encodings. GNU 2.44 and
LLVM 19.1.7 row boundaries agree over 99 rows/428 bytes: 406 continuation
bytes, five credited caller bytes and 17 credited prologue bytes. The entry
window includes the bypassed loop-back corridor for context; the selected
edge list explicitly skips it. Both exported listings are checked for exact
bytes, completeness, unique coverage and row boundaries.

Below whole-image authentication, the control decoder varies only the four
selected fields; the other 424 bytes must match a fixed grammar hash. Four
one-byte replacements are made in inert copies with unchanged image length.
Each fails nominal field validation and feeds the conditional static store
relation, producing four actual final-buffer counterexamples. No original
or mutated captured program is run or evaluated as instructions.

| Site, byte change | Decoded change | Actual static witness at n=10 |
| --- | --- | --- |
| `0x1ab4709`, `01 -> 02` | count increment 1 -> 2 | parent count `0b00 -> 0c00` |
| `0x1ab4829`, `d8 -> d0` | write edge n instead of n+1 | old edge overwritten; valid inactive dummy repaired; new child parent remains zero |
| `0x1ab4864`, `4c -> 44` | 64 -> 32-bit parent store | nonzero high parent bits missing |
| `0x1ab486f`, `66 -> 90` | WORD store -> NOP plus DWORD store | adjacent new-child count `0500 -> 0000` |

The last replacement preserves the total eight-byte site span, but changes
instruction partition into NOP plus MOV. The test does not claim unchanged
instruction boundaries for it. Wrong-edge repair uses a valid dummy object,
so its mismatch does not depend on a mutant fault. `controls.json` retains
all 16 case outputs: raw metadata/result hex, output hashes, differing-byte
counts and first differing object/offset. These are **static layout relation
outputs**, not target observations. Source/frame alias, helper behavior and
intermediate-store equivalence are not tested by the synthetic relation.

## Reproduce and results

```sh
python3 -I -B research/work-items/RE-009-evm-parent-append-94/verify.py
python3 -I -B -m unittest discover -s tests -p test_evm_parent_append94.py -v
python3 -I -O -B -m unittest discover -s tests -p test_evm_parent_append94.py -v
python3 -I -B research/work-items/RE-009-evm-parent-append-94/verify.py --out /tmp/re009-append-export
(cd research/work-items/RE-009-evm-parent-append-94 && sha256sum -c MANIFEST.sha256)
make doctor verify catalogue-check reproduce
```

The verifier uses Python and the existing ELF/unwind parsers; it invokes no
subprocess, instruction evaluator or emulator. The flat root test is found
by the repository's existing isolated unittest discovery. Standard LFS
filters may be supplied only to the `make verify` invocation for the known
materialized-input status issue; no persistent settings or gates change.

Observed checks: all 10 new focused tests and all 10 original root-growth
tests pass normally and under `-O` (exit 0 for each run). The new verifier
passes normally and under `-O`; all eight scoped manifest entries pass
(exit 0). Exports with effective Python hash seeds 94/115 and time zones
UTC/Pacific-Honolulu match each other and the retained evidence/control JSON
(exit 0). `make doctor`, `make verify`, `make catalogue-check` and
`make reproduce` each exit 0. Verification covers three target signatures,
38 imported files and all seven pinned source repositories. Logs are in
`/tmp/re009-parent-append-checks/`. The original #1457 packet and test have an
empty diff against `48f2f6a88db86d3ab1dacb0b8a44969469c8a5e0` (exit 0).

No full-suite, hosted-CI or container success is claimed. No Rust source,
workspace, lockfile or component build is added.
Allocator ownership/capacity, imported copy effects, prepared-pair/saved-frame
provenance, alias closure, other parent indices, full-parent propagation,
fault/unwind behavior, complete insertion and global ordering remain open.
The complete RE-009 acceptance gates are unfinished.
