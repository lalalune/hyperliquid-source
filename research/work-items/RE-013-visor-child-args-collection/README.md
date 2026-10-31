# RE-013: conditional visor child-argument collection

- Component: visor; source base `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Target: captured visor, 8,305,392 bytes, SHA-256
  `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
- Question: how do actual callback results become the child-argument output;
  which prefix/order/count is retained, how does an empty payload differ
  from stop, and is generic growth needed for this fixed descriptor interval?
- Claim: complete **conditional normal-path** block/cursor/resource argument,
  with explicit opaque allocator/copy/callee-frame contracts. No gate requested.

[#988](https://github.com/lalalune/hyperliquid-source/pull/988) leaves this
collection external. [#1029](https://github.com/lalalune/hyperliquid-source/pull/1029)
closes the actual UTF-8 adapter's conditional successful span return while
leaving collection count/order/allocation unknown. This packet supplies the
next used prerequisite. It preserves #45 lifecycle, #407 unwind, #988 parser
and #1029 validation boundaries; it does not extend their unknown semantics.

## Observations and result

The actual FDE `[0x61da10,0x61dd6c)` is 860 bytes: 220 native instruction
rows, 61 blocks, 33 branches and 16 call sites. All raw blocks/edges are
bound, including cold context. These are **not** function coverage counts.
The normal call/return projection has 176 reachable instruction nodes; the
explicit conditional proof projection has 144. Exception/LSDA edges, cleanup
ownership and external error-helper returns remain unqualified.

[PROOF.md](PROOF.md) establishes every empty/stop/append case, actual capacity
arithmetic, row placement and finite prefix progress. For an immutable readable
nonwrapping N-by-24-byte descriptor interval of extent at most isize_max,
with finite normal callback returns and the stated fresh-storage/copy contracts:

- N=0 or a zero pointer from the first callback produces raw `(0,8,0)`,
  before record allocation. No capacity formula is assigned to these routes.
- Otherwise the allocation branch reserves C=max(4,N) slots and requests
  exactly 24*C bytes. Callback visits preserve descriptor order and stop
  before appending a pointerzero result. Completed rows are the preceding prefix.
- A **nonzero** pointer with length zero appends `(0,1,0)` and does not
  stop. Positive payloads request/copy exactly their length and append raw
  `(length,fresh_copy_pointer,length)`. No extra terminator is requested or
  copied by this controller; later OS/C-string rules are unknown.
- Before each append, completed_count j<N<=C, so j<C and the generic
  growth call is unreachable on this domain. The final count may equal C.
  Output words are `(C,record_buffer,completed_count)` on allocation paths.

These word relationships do not establish original private Vec/String types,
public accepted CLI syntax or later process-launch behavior. The allocator
at `0x70bf30` remains opaque; freshness/writable storage is an **assumed
external contract**, not inferred from its name. The `memcpy` import is
actually bound, but its C copy behavior and frame preservation are external
assumptions. Every used callback/allocator/memcpy must also preserve SysV
callee-saved registers (RBX/RBP/R12–R15 and caller RSP), live caller locals
and immutable input/image. Freshness or hardware return alone does not imply
those obligations. Error/unwind/failure paths remain open; no noreturn inference is
used. Actual hardware return requires ordinary valid call-state contents.

The active collector stack/return and argument/descriptor/payload/image/result
separation are explicit in PROOF.md. #1029's additional callback-frame domain
is required when composing the actual UTF-8 stage. A valid empty UTF-8 span
with pointerzero would still select this collector's sentinel; no original
Rust nonnull premise is silently imported.

## Reproduce

Recorded platform: Linux x86-64, Python 3.12.14, GNU objdump 2.44.
From the repository root with the authenticated pinned artifacts:

```sh
mkdir -p work/visor-collection
PYTHONDONTWRITEBYTECODE=1 python3 -B tools/visor_child_args_collection.py \
  --output work/visor-collection/record.json
cmp research/work-items/RE-013-visor-child-args-collection/record.json \
    work/visor-collection/record.json
PYTHONDONTWRITEBYTECODE=1 python3 -B \
  research/work-items/RE-013-visor-child-args-collection/check_packet.py
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s tests \
  -p test_visor_child_args_collection.py -v
```

The independent stdlib producer uses one admitted full-target byte snapshot.
Native decoding receives only a private 860-byte raw slice with explicit
x86-64/linked-VA options. Every native row is checked against those same
bytes; the original ELF pathname is never reopened by a native provider.
The retained native output is unnormalized. Call/relocation/FDE/dynamic-symbol
coordinates and file offsets are in `record.json`. The 51-byte caller and
67-byte callback are revisited prerequisite witnesses, counted separately
from the owned 860-byte body; they are not new recovered-function coverage.

The actual inverse-three operand and fixed-multiple arithmetic close the
capacity proof for all N in the domain. Boundary examples and the separate
symbolic prefix/resource model support that result; neither is target
execution, an x86 interpreter/emulator or an automatic equivalence proof.
Source/packet regeneration, real-byte corruption and real CLI preservation
controls are retained. `PREPARATION-FAILURE.json` preserves an author prototype
metadata-key mistake corrected before the initial record; it is not a target
failure. `DOMAIN-REFINEMENT.json` retains the independent pre-freeze correction
that allocator/copy register preservation must be explicit for every callee,
not inferred merely from freshness/return. Final required checks and independent review are recorded separately
on the actual frozen publication commit.

## Reconstruction and remaining gaps

This is independently authored MIT static research/tooling. No inferred
unlicensed reference source was read/copied. The generic native byte-binding
pattern adapts project-authored code from our #1029; this standalone producer
has no dependency on that unmerged tool. Original artifacts/imports/pins and
generated component gates are unchanged.

Rust reconstruction, dependencies/lock/compiler identity, two-build and
raw/normalized binary equality are not yet implemented/measured. No captured
code or emulator is run. Allocator/copy/error/unwind implementations, public
CLI grammar and private types remain unclosed. The next question is to
establish the actual allocation/copy/runtime contracts needed to replace
these explicit external assumptions before an implementation/behavior claim.
