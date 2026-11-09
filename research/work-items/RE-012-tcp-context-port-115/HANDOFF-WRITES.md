# RE-012: outer writes before the executor handoff

- Component `transport`, task RE-012; files owned: this evidence packet only.
- Sole target Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source baseline `05bc2de303c05525b71e7e257426e741bc66a390`.
- Question: which writes/calls between `0x2ad5e58` and the executor calls
  can affect the accepted-context word established by [CLEANUP-JOIN.md](CLEANUP-JOIN.md)?
- Status: selected static CFG paths, explicit destination census and conditional
  copy/alias joins. No Rust implementation or full mutation closure is claimed.

The eight selected handoff paths have **seven calls before the executor**:
six copies and one context helper. Their direct stack stores miss the tracked
word at each selected location. There are also writes through retained state
pointers, a relocated global and TLS, whose effective storage must be disjoint
from that word. The context helper has unclosed callees; one of them is now
shown to write **12 bytes at outer stack `+0x6388`**. Those writes also miss
the tracked word, but rule out treating the helper as transitively read-only
with respect to its first argument.

## Evidence scope

All coordinates are linked ELF VAs before load bias. `OS` is outer
post-prologue RSP, `R` its retained state pointer and `H=QWORD[R+0xa8]`.
`F=FS.base` and `T=QWORD[FS:0]` are kept distinct.

| Complete FDE interval | Bytes / Capstone instructions | Role |
| --- | ---: | --- |
| `0x2ad5980..0x2ad655e` | 3,038 / 568 | Revalidated outer caller |
| `0x2d4d540..0x2d4d749` | 521 / 121 | Context helper, already identified by RE-005 |
| `0x1629690..0x1629795` | 261 / 64 | First helper's nested 12-byte output writer |

The retained capture denominator is **3,820 bytes / 753 instructions**,
not source-equivalence coverage. [handoff-spec.json](handoff-spec.json) pins
13 spans, 18 relocation records and the lexical store census. Full native
exports, FDE/LSDA identity, exact commands, decoded transfers and path records
are under [handoff/records.json](handoff/records.json).

The outer exports match the prior factory exports byte for byte. The earlier
[spawn-payload packet](../RE-005-node115-spawn-payload-fields/README.md)
supplied the `0x2d4d540` lead. This collector freshly checks its retained
521-byte owner hash and five byte pins against #115; it does not replay or
adopt every assertion in that packet. Its files and manifest are unchanged.

## Selected branches and writes

The CFG walk starts at `0x2ad5e5e`, immediately after the accepted-context
copy, and stops before `0x2ad6325` or `0x2ad633a`. It chooses:

- No reference-increment guard's `JLE` trap edge. These are encoded flag
  conditions, not proof of valid reference-count ownership or a positive
  signed post-increment value.
- The returned address WORD at `OS+0x10` is not 1; the equal branch calls
  cleanup and loops back to accepting instead of handing off this context.
- Both first CAS operations succeed: BYTE `[H+0x10]`, expected 0 to 1 for
  entry at `0x2ad609d`, then expected 1 to 0 at `0x2ad60f2`. The slow lock
  and unlock helpers at `0x2ad6255` / `0x2ad6265` are excluded.
- The first `lock xadd` at `0x2ad6155` returns a nonzero old global value.
  The zero-result retry is excluded; uniqueness or lifetime of IDs is not proved.
- TLS flag BYTE `[F-0x10e8]` is 1. **Flag 2 does not take the successful
  outer handoff route**: it falls into `0x2ad61e7` and the cleanup/diagnostic
  branch. Other flags invoke registration via `0x64e0510`, then write 1.
  They are outside this selected join, even though earlier supplements
  analyzed that registration helper in a different caller context.
- QWORD `[F-0x1130]` is unsigned-less-than `0x7fffffffffffffff`; it is
  incremented once. QWORD `[F-0x1128]` is not 2, so the unavailable-executor
  branch is excluded. Low DWORD equal to 1 selects executor A; otherwise B.
  The full domain of legal executor values is not established.

Two optional clone groups are each kept or skipped, giving four combinations
and two executor endpoints: **eight syntactic paths**. Skipping the first
means BYTE `[R+0x178]==4`; skipping the second means BYTE `[R+0xe8]!=0`.
These combinations do not establish that all copied fields are initialized
or all eight states are dynamically reachable.

| Optional groups skipped | Instructions per endpoint | Explicit writes per endpoint |
| --- | ---: | ---: |
| Neither | 179 | 58 |
| Second only | 145 | 47 |
| First only | 168 | 53 |
| Both | 134 | 42 |

Across the selected paths there are 58 distinct explicit write sites:
**38 stack, 18 through state-derived pointers, one global and one TLS**.
The full lexical scope additionally includes excluded branches and the two
helper bodies: 99 explicit stores in total. These categories exclude implicit
stack pushes and writes made by callees; those are stated separately.

The 18 state-derived sites cover QWORD increments through pointers loaded
from R offsets `+0x180,+0x188,+0x160,+0x168,+0x170,+0x190,+0x100,+0x108,
+0x110,+0x118,+0x138,+0x140,+0xa8,+0xa0`; the `+0x110` and `+0x138`
pointees also receive QWORD increments at pointee `+0x1c8`. Two BYTE CAS
sites target H+0x10. Some sites are skipped on the optional-group paths.
The global XADD target comes from RELATIVE slot
`0x64e16c0 -> 0x64fee40`, not a guessed symbol. The TLS store is at F-0x1130.
These exact regions still require nonaliasing with the primary stack word.

The adapter context pointer is formed from **T-0x1120**, while the counter
and executor discriminator use **F-relative** storage. This record does not
silently identify T with F or prove scheduler invocation identity.

## All six copies, including two secondary copies

The primary tracked word starts at `OS+[0x188,0x18a)`. The collector checks
each store against the primary location in effect at that instruction, and
checks that each copied word includes both bytes. All table offsets are
relative to OS; copy lengths come from pinned EDX loads and all six calls
resolve to the unique `memcpy` slot `0x64df508`.

| Copy call | Source / destination / length | Effect on the selected word |
| --- | --- | --- |
| `0x2ad6128` | `+0x48 -> +0x228`, `0xb0` | Auxiliary copy; misses primary `+0x188` |
| `0x2ad6140` | `+0xf8 -> +0x190`, `0x98` | Primary `+0x188 -> +0x220` |
| `0x2ad6196` | `+0x190 -> +0x3390`, `0x148` | Primary `+0x220 -> +0x3420` |
| `0x2ad629a` | `+0x3380 -> +0x6388`, `0x3008` | Secondary copy at `+0x6428`; source primary retained |
| `0x2ad62da` | `+0x3380 -> +0x370`, `0x3008` | Secondary copy at `+0x410`; source primary retained |
| `0x2ad6307` | `+0x3390 -> +0x9390`, `0x2ff8` | Primary `+0x3420 -> +0x9420` |

The secondary destinations do not overwrite the retained primary source.
For example, the `0x3008`-byte copy to `OS+0x370` ends at `OS+0x3378`,
before the primary word at `OS+0x3420`. The final argument is `OS+0x9390`,
so `OS+0x9420` is once again child input `+0x90` as in the factory packet.
This accounts for copies that a primary-only chain can omit without denying
that they happen. It does not establish initialization of whole copied records.

## The context helper is not transitively read-only

At `0x2ad60e9`, the arguments to `0x2d4d540` are:

- RDI = OS+0x6388, a scratch record pointer;
- RSI = H+0x18, the protected context pointer;
- RDX = OS+0x370, the temporary descriptor.

The helper retains these in RBX/R14/R15 respectively. Its own explicit stores
are local-stack stores and context stores. The latter cover context-relative
`[0x48,0xaa)`, with two alternative 0x50-byte store blocks including an
unwind block. Relative to H this is `[H+0x60,H+0xc2)`. The full list retains
15 context-store instructions rather than counting both blocks as one
observed execution. No explicit store through its retained RBX occurs.

However, before reading through RBX, `0x2d4d564` calls the RELATIVE slot
**`0x64e0990 -> 0x1629690` with the original RDI still present**. That callee
retains RDI in its own RBX at `0x162969a`. Its normal output block writes:

| Store | Destination / width |
| --- | --- |
| `0x1629746` | `[RBX+0]`, 4 bytes |
| `0x1629748` | `[RBX+4]`, 4 bytes |
| `0x162974c` | `[RBX+8]`, 4 bytes |

Thus a normal return along that block writes **`OS+[0x6388,0x6394)`**.
The pending primary word is still `OS+[0x188,0x18a)` at this call. The
regions are disjoint on the admitted valid stack, but a blanket claim that
the original scratch record is only read would be false across callees.
The older zero-store census is usable only as a direct-instruction statement.

This does not close every nested call. The output writer calls
`0x5c842e0`, `0x5c84210` and a slot targeting `0x1628f50` before its stores,
and has diagnostic branches. The context helper additionally calls the slot
`0x64e0f80 -> 0x1546570`, other bound helpers and several direct targets.
Their complete effects are not inferred from the stores shown here. Exact
transfer operands and relocation records are retained, with no guessed
timestamp type, clock semantics, map type or public Rust source attribution.

## Checks, limitations and next question

Reproduce with Python 3.12, Capstone 5.0.7, GNU objdump and llvm-objdump on
PATH, from the repository root into fresh output directories:

```sh
python3 -B research/work-items/RE-012-tcp-context-port-115/handoff.py --out work/context-handoff-recheck
python3 -B -O research/work-items/RE-012-tcp-context-port-115/handoff.py --out work/context-handoff-optimized
```

The complete target is authenticated first. Both native decoders account for
every byte and agree with the Capstone partitions, with recorded standalone
LOCK-prefix joins and **no byte masks**. Native syntax agreement, aliases,
execution and whole-function CFG completeness are not thereby proved.

All **85 corruption/scope controls** reject their selected input: 13 changed
anchor bytes, 36 changed/duplicate relocations, three truncated FDEs, two
store-census changes, eight forced excluded edges, six overlapping copy
intervals, three copies omitting the second tracked byte, twelve overlapping
write intervals and two wrong captures. Body hashes can reject byte mutations
before individual pins. Branch/interval controls operate on annotations and
encoded edges; they are not execution/emulation or proof of runtime reachability.

Normal and optimized outputs are byte-identical. The prior cleanup collector
was replayed and compared with all its retained outputs. Validation commands,
raw-log hashes and remaining repository failures are in
[handoff-validation.json](handoff-validation.json). Catalogue checking retains
the stale generated README failure; the earlier full suite remains incomplete
and the prior TLS metadata-path failure is not relabeled as passing.

Field preservation remains conditional on the selected branch outcomes,
normal calls, ordinary `memcpy`/SysV ABI behavior, valid nonwrapping storage,
nonaliasing state/pointee/global/TLS/stack regions and no interfering writes.
Slow lock/TLS paths, nested helper effects, initialization, resource lifetime
and later scheduler/poller behavior remain open. All 92 gates remain false.
No captured code, emulator, socket, key or chain operation ran; no commit,
push, PR or external message was made. No independent-agent review, Rust
equivalence, hosted CI or container success is claimed.

Next: inspect the context-helper call at `0x2d4d5b0`, slot
`0x64e0f80 -> 0x1546570`, to classify its output and context writes. This is
a concrete remaining side-effect boundary on the selected outer path.
The subsequent [conditional-result supplement](LOOKUP-RESULT.md) now resolves
its two matching-result paths and explicit output masks, retaining changed
result formatting, diagnostic and parent-continuation boundaries.

New analysis/code is independently authored MIT work. Original captured bytes
and referenced evidence retain their existing rights.
