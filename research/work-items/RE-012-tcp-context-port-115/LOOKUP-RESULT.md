# RE-012: conditional result writes at 0x1546570

- Component `transport`, task RE-012; this evidence directory is the owned scope.
- Sole target Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline `05bc2de303c05525b71e7e257426e741bc66a390`.
- Question: which output/context bytes can `0x1546570`, called through
  `0x64e0f80` at `0x2d4d5b0`, change on the selected handoff route?
- Status: observed normal-path byte writes and a scalar classifier relation;
  field names below are analytical coordinates, not recovered Rust types.

The two matching-result paths write only the eight-byte marker
**`0x8000000000000000` at output `+8`**. The mode-disabled path calls no
helper. The mode-enabled path calls a now-bounded scalar classifier whose
normal path has no nested call and writes only its own stack. Thus neither
matching-result path needs an opaque formatter side-effect premise.

The changed-result paths call an unclosed formatter. One of those paths
leaves output byte `+5` unwritten, although the parent later reads that byte
on its nonsentinel path. This prevents inventing an always-initialized
32-byte return type. The parent can also continue changing context after
receiving the sentinel, so this result does not make the entire parent inert.

## Binary identity and capture scope

Addresses are linked ELF VAs before load bias. Full FDE/LSDA metadata,
instruction rows, raw GNU/LLVM exports and commands are under
[lookup/records.json](lookup/records.json). The collector/spec are
[lookup.py](lookup.py) and [lookup-spec.json](lookup-spec.json).

| Complete FDE interval | Bytes / Capstone instructions | Role |
| --- | ---: | --- |
| `0x1546570..0x15466f3` | 387 / 85 | Selected conditional-result function |
| `0x1567ad0..0x1567b94` | 196 / 43 | Its scalar byte classifier |
| `0x2d4d540..0x2d4d749` | 521 / 121 | Revalidated parent context helper |

The capture denominator is **1,104 bytes / 249 instructions**. It is not
reconstruction coverage or binary equivalence. Both parent native exports
match the preceding handoff packet. Earlier mempool/role-cache records named
these helpers as call targets; their other subsystem behavior is not imported
into this transport claim. No imported packet or generated catalogue is edited.

## Input comparisons and the five selected result paths

At entry, let `O=RDI` be output, `C=RSI` context and `I=RDX` input.
The function retains O in RBX and C in R14, then reads DWORD `[I]` into EBP.
It tests BYTE `[C+0xa8]` against exactly 1. Other byte values use the plain
path; this is not an inferred Boolean-domain guarantee.

The following table is conditional on valid input/context storage and normal
returns of any called helper. `K` denotes DWORD `[I]`; `B` denotes the
classifier's returned low byte.

| Selected path | Comparisons | Calls before return | Output bytes explicitly written |
| --- | --- | --- | --- |
| Plain match | `C[a8] != 1`, `K == DWORD[C+98]` | None | `[8,16)` only; signed-minimum marker |
| Plain change | `C[a8] != 1`, key differs | Formatter at `0x15466aa` | `[0,5)` and `[6,32)`; byte 5 untouched |
| Tagged match | `C[a8] == 1`, `B == C[a9]`, key equal | Classifier at `0x154659a` | `[8,16)` only; same marker |
| Tagged byte change | `C[a8] == 1`, `B != C[a9]` | Classifier, then formatter at `0x154661a` | `[0,32)` |
| Tagged key change | Byte matches, key differs | Same two calls | `[0,32)` |

The plain/tagged match paths contain respectively 21/26 instructions before
RET; the changed paths contain 45/56/58. These path counts omit nested callee
instructions and do not establish dynamic reachability of every state.

The full lexical destination census is 19 lookup-stack stores, nine lookup
output stores and four classifier-stack stores, **32 sites** total. There
is no explicit store through a retained input/context base. This statement
requires distinct effective storage: aliasing O with C or I would defeat a
context-preservation conclusion. Formatter and diagnostic callees remain
separate side-effect boundaries on paths that invoke them.

On changed output, DWORD O+0 receives K; BYTE O+4 receives 0 or 1 according
to the selected mode. Tagged changes also set BYTE O+5 to B. The common
tail copies a 24-byte formatter result into O+8..O+32 through overlapping
stores. The MOVUPS at `0x15466d9` additionally writes O+6/O+7 from the low
two bytes of a local argument pointer previously placed at lookup stack +0x10.
Those two bytes are retained as incidental byte provenance, not named as
meaningful fields or a stable serialization format.

The marker path stores no other output byte. Unwritten bytes must remain
unknown, rather than being filled with zeros in a proposed reconstruction.
The plain-change gap at O+5 is similarly real: its later machine-level copy
does not establish a meaningful initialized value or a public Rust ABI.

## Classifier: a bounded division relation, not an assumed clock type

The call at `0x154659a` resolves uniquely through
`0x64e0f58 -> 0x1567ad0`, with RDI=I. This callee reads unsigned DWORD
`u=[I+4]`; it does not read `[I]` or the third DWORD on its normal path.

The encoded operations are:

- At `0x1567ad8`, compare u with `0xe1000` (921600); JAE enters diagnostics.
- Multiply the zero-extended u by `0x91a2b3c5`, shift right by 43 and retain AL.
- At `0x1567af3`, compare u with `0x15f90` (90000); JAE enters a second
  diagnostic path. Otherwise the function restores its stack and returns.

Consequently the selected normal return requires **`0 <= u < 90000`**.
Over every one of those 90,000 scalar values:

```text
((u * 0x91a2b3c5) >> 43) & 255 == floor(u / 3600)
```

The output buckets are 0..24, each containing exactly 3,600 values. This
exhaustive finite-domain arithmetic check corroborates the pinned operands;
it does not execute or emulate the captured instructions. The normal path
contains 14 instructions before RET, no call, and one BYTE store to its own
stack. The other three lexical stack stores belong to diagnostic paths.

For `90000 <= u < 921600`, the second diagnostic branch is taken after
the multiplication. At/above 921600, the first branch is taken before it.
Their formatting/unwind behavior remains unclosed. No hour, timezone, date,
wall-clock source or malformed-input recovery behavior is inferred merely
from the divisor 3600. The earlier
[role-cache freshness packet](../RE-001-node115-role-cache-freshness/README.md)
had left this helper's classification meaning unresolved; only the numeric
relation above is established here.

## Join to the outer tracked field and parent consumption

Let OS be the outer post-prologue stack used by the handoff packet. The
parent `0x2d4d540` has six register pushes and `sub rsp,0xb8` after the
call return address, so its post-prologue stack is **CS=OS-0xf0**. It passes
`O=CS+0x50`, `I=CS` and `C=H+0x18` at `0x2d4d5b0`.

Thus the whole observed output envelope is `[OS-0xa0,OS-0x80)`, disjoint
from the still-pending word `[OS+0x188,OS+0x18a)` on the admitted valid,
nonwrapping stack. The lookup's own post-prologue stack is CS-0x90; the
classifier's local stack is deeper again. None of their direct stack/output
writes reaches the outer word. The matching branches have no additional
opaque callee effects once the classifier's normal domain is admitted.

The parent initially reads **only QWORD O+8** at `0x2d4d5bc`. It also
compares zero with QWORD `[C+0x48]`; signed subtraction overflows exactly
when that context word is `0x8000000000000000`.

- If C+0x48 is that minimum and O+8 is the sentinel, the branch at
  `0x2d4d5c6` reaches the return epilogue. No additional call intervenes.
- Otherwise the sentinel branch at `0x2d4d5ee` skips the replacement block
  and proceeds to **`0x25f0250` at `0x2d4d6a5`**. This call remains opaque;
  normal continuation subsequently writes C+0xa4 and C+0x9c. Sentinel
  therefore does not imply the whole parent performs no context changes.

The two selected consumer paths read no other output field before those
endpoints. In contrast, the nonsentinel replacement block loads O+0, O+4
and **O+5** at `0x2d4d5f9..0x2d4d603`, later copying the last byte to
C+0xa9 at `0x2d4d671`. The unwritten plain-change byte must not be credited
as initialized just because the caller copies it.

## Verification and remaining boundaries

From the repository root, with Python 3.12, Capstone 5.0.7, GNU objdump and
llvm-objdump on PATH, use fresh output directories:

```sh
python3 -B research/work-items/RE-012-tcp-context-port-115/lookup.py --out work/context-lookup-recheck
python3 -B -O research/work-items/RE-012-tcp-context-port-115/lookup.py --out work/context-lookup-optimized
```

The complete target digest is checked first. The 12 instruction anchors,
11 unique relocations, complete FDEs and all 32 store sites are checked.
GNU/LLVM retain every byte and agree with Capstone instruction partitions;
no byte masks are used. This is not full CFG, source or behavior equivalence.

All **60 negative/scope controls** reject their selected invalid input:
12 changed anchor bytes, 22 changed/duplicate relocations, three truncated
FDEs, three store-census changes, five changed result paths, two forced
classifier diagnostic edges, six excluded classifier inputs, two invalid
output envelopes, three output-overlap cases and two wrong captures.
Body hashes may reject corrupt bytes before anchor pins; path and interval
controls operate on explicit annotations, not observed runtime states.

Normal and optimized outputs are identical. The preceding handoff collector
is replayed and compared with its retained output. Exact test results and
raw-log hashes are in [lookup-validation.json](lookup-validation.json).
The stale generated README catalogue failure remains, as do the earlier
incomplete full suite and recorded TLS metadata-path failure. No global
test-success claim is made.

All claims require valid storage, distinct frames/objects, compatible ABI,
selected normal returns and no interfering writes. Formatter callbacks,
allocations, diagnostic/unwind paths, parent `0x25f0250`, initialization of
other bytes, scheduler identity and resource lifetime remain open. All 92
full-scope gates remain false. No captured execution/emulation, socket, key,
chain action, commit, push, external message, hosted CI or container result
is claimed. There is no Rust implementation or independent-agent review.

The [formatter-output follow-up](FORMAT-OUTPUT.md) now binds
`0x64df6e8 -> 0x141e3a0` to both actual templates, its initial header and
24-byte output. Allocation helper `0x141e0e0`, nested callbacks and the
parent continuation `0x25f0250` remain separate unresolved boundaries.

New analysis and code are independently authored MIT work. Original bytes
and referenced evidence retain their own rights.
