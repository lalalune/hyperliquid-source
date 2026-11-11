# RE-012: allocator continuation, accounting and tail fill on node #115

Sole target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
105,896,032 bytes. Source baseline:
`05bc2de303c05525b71e7e257426e741bc66a390`.
Task RE-012, transport-context helper effects, with RE-001 address bindings.
Only this existing evidence directory is changed. Static analysis only.

This answers the bounded next question in [REALLOCATION-PATHS.md](REALLOCATION-PATHS.md):
what follows the return from `0x6365660` to `0x63503e8`? A null result skips
the caller's accounting and fill. A nonnull result updates two counters,
may invoke the same threshold helper twice, and may fill the increased
class-size tail with `0xA5` before returning the pointer. Four selected
threshold-helper paths have no nested calls; their TLS and local-stack
writes are recorded. Event-triggering branches remain open.

These are conditional encoded-path observations, not all-path equivalence,
observed runtime state, an ownership proof or a reconstructed Rust allocator.

## Captures and provenance

The full input digest, exact FDE extents, bytes, relocations, symbol names,
RIP operands and selected stores are checked by [accounting.py](accounting.py)
against [accounting-spec.json](accounting-spec.json). The full core-body hash
is the same owner hash already retained by [allocator-spec.json](allocator-spec.json)
and [reallocation-spec.json](reallocation-spec.json); the earlier collector
is replayed unchanged. Existing
[deallocator evidence](../RE-001-node115-lu-slow-dealloc/EVIDENCE.md) lists
`0x63eec80` as an unclosed helper; it is a lead, not borrowed validation.
The focused seed-candidate search supplies no boundary proof for these bodies.

| Export | Virtual interval, end exclusive | Scope | Bytes |
| --- | --- | --- | ---: |
| [core](accounting/core.capstone.txt) | `0x6350210..0x6352f5e` | Complete FDE; selected continuation only | 11,598 |
| [threshold helper](accounting/accounting_helper.capstone.txt) | `0x63eec80..0x63ef230` | Complete FDE; four selected leaves | 1,456 |
| [fill stub](accounting/fill_stub.capstone.txt) | `0x6349360..0x6349371` | Complete FDE | 17 |
| [memset PLT](accounting/memset_plt.capstone.txt) | `0x63f0a90..0x63f0aa0` | PLT window; not an inferred FDE | 16 |

Total: **13,087 captured bytes / 2,752 decoded instructions**, not a matched
implementation or coverage denominator. These text/PLT virtual addresses map
to file offsets `VA-0x1000`; the ELF parser checks membership and backing.
[records.json](accounting/records.json) retains owner/FDE identity, hashes,
transfers, paths and native comparisons. GNU/LLVM raw output, including empty
stderr, is preserved beside each Capstone export; no bytes are normalized.
The comparator permits a native standalone LOCK prefix to be joined to the
following instruction, without changing any bytes.

## Caller continuation

Use the established caller coordinates: `B = QWORD[FS:0]-0x10a8`, `S=R14`
is the new class-size word, `U=R15` is the old metadata size, and `Q=RAX` is
the returned pointer. `CS` denotes the core's post-prologue stack base;
`0x63503e8` restores it by adding `0x20`. `D=BYTE[CS+4]` is the earlier option.
The earlier selected reallocation paths require `D=0`; the additional
`D!=0` continuation below is recorded separately, not retroactively joined.
Stable class tables and normal ABI preservation remain premises.

`0x63503ec` saves `Q` in RBP. If `Q=0`, `0x63503f2 -> 0x63507e6` clears
RBP and jumps to the canary epilogue at `0x63504d1`. The selected 17-instruction
continuation before RET contains no store or call and returns zero. This
does **not** undo the metadata writes on the preceding null-result path.

For `Q!=0`, two updates occur in this order. Arithmetic is modulo `2^64`;
comparisons are unsigned, and each old counter is read before its store.

| Phase | Counter update before branch | Branch condition | Helper call |
| --- | --- | --- | --- |
| First | `[B+0x338] = oldA + S` at `0x6350448` | `S >= ([B+0x10]-oldA)` at `0x6350452` | `0x6350e9b -> 0x63eec80` |
| Second | `[B+0x348] = oldC + U` at `0x63504a8` | `U >= ([B+0x20]-oldC)` at `0x63504b2` | `0x6350eb3 -> 0x63eec80` |

Equality calls the helper. There is no carry/borrow rejection around these
updates. In particular, comparing the wrapped sum to the threshold is not
an equivalent substitute for the encoded subtraction-and-compare relation.
No allocation/free accounting meaning or monotonic counter invariant is
inferred solely from these offsets. Both same-pointer and replacement
nonnull results enter these updates.

The caller reuses a descriptor at `H=CS+0xc0`:

| Descriptor field | First call | Second call |
| --- | --- | --- |
| BYTE `H+0` | `1` | `0` |
| QWORD `H+8` | `&B[0x338]` | `&B[0x348]` |
| QWORD `H+0x10` | `&B[8]` | `&B[0x18]` |
| QWORD `H+0x18` | `&B[0x10]` | `&B[0x20]` |
| QWORD `H+0x20` | `&B[0x340]` | `&B[0x350]` |

The seven padding bytes `H+1..H+7` are not initialized by this construction.
Each nonnull selected continuation has 12 direct stores: ten descriptor
stores and two counter stores. Callee writes are additional. The helper's
selected leaves do not read the last descriptor pointer; they access both
auxiliary fields directly through `B` instead.

## Four call-free leaves of `0x63eec80`

The data operands are pinned at entry and at their later rechecks:

| Label here | Storage | File observation | Selected runtime premise |
| --- | --- | --- | --- |
| G1 | QWORD `0x64ffdd0`, `.data` | `0x10000` | Either zero, or nonzero with unexpired extra countdown |
| G2 | BYTE `0x6713606`, `.bss` | No file-backed byte | Zero for mode 1 |
| G3 | QWORD `0x64ffd00`, `.data` | All ones | Signed negative for mode 1 |

File initializers do not establish their values at these calls. G1-zero and
G1-nonzero leaves are both retained; neither is described as observed live.
All leaves require stable `BYTE[B+0x330]=0`. Joining that to the earlier
`FS:-0xd78` guard requires **FS base = QWORD[FS:0]**, plus preservation through
the selected preceding callees and absence of interference. This identity
is explicitly a premise, as in the prior TLS packet.

Let `A` be the already-incremented counter fetched through `H+8`, and `L` the
old base fetched through `H+0x10`. At `0x63eecac` the helper stores `A` into
that base. Define `delta=(A-L) mod 2^64`. The selected leaves additionally
require the following strict unsigned inequalities:

| Mode | Required countdown | Additional requirement when G1 != 0 |
| --- | --- | --- |
| 1 | `delta < old[B+0x58]` | `delta < old[B+0x28]` |
| 0 | `delta < old[B+0x60]` | `delta < old[B+0x30]` |

The relevant countdown is reduced by `delta` and stored at `0x63eedce`
(mode 1) or `0x63eee0a` (mode 0). When G1 is nonzero, the additional countdown
is also reduced and stored at `0x63eef90` / `0x63ef09c`. These strict bounds
exclude underflow for these subtractions; the earlier `delta` computation
and the final threshold addition still use machine-word arithmetic.

Let `R` be the reduced required countdown, and `E` the reduced extra
countdown when G1 is nonzero, otherwise `UINT64_MAX`. The unsigned CMOVA
sequence followed by `0x63eee31` writes:

```text
*QWORD[H+0x18] = (A + min(R, E, 0x400000)) mod 2^64
```

For stable `BYTE[B+0x330]=0`, both modes then copy the current thresholds
into auxiliary words. Define `aux(x)=0` for unsigned `x>=0xfffffffffffff001`,
otherwise `aux(x)=x`. The stores at `0x63eee5d` and `0x63eee64` are
`[B+0x340]=aux([B+0x10])` and `[B+0x350]=aux([B+0x20])`.
`0x63eee6b` performs **LOCK OR QWORD[helper RSP],0**, a local atomic
read-modify-write. Its value-preserving operand does not make it a non-write.
The second flag check at `0x63eee71` remains zero on these paths.

Mode 1 returns through cleared event flags; mode 0 returns through cleared
CL/BPL. The G1-zero leaves have 95 / 81 instructions and six explicit stores
each; G1-nonzero countdown leaves have 104 / 89 instructions and seven stores
each, all measured before RET. Each helper prologue also has six implicit
PUSH writes; normal call/return stack effects remain separate from the
explicit-store inventory. No selected helper leaf invokes another function.

## Conditional tail fill and final return

`0x63504b8` is **CMP R15,R14**, followed by SETB BL and AND BL with
`BYTE[0x651174a]`. Thus the fill condition uses `U<S` and **bit 0** of that
byte, not arbitrary nonzero-byte truth. The later `D==0` test is also required.
If any condition fails, the continuation proceeds to the canary epilogue.

When all three hold, `0x6351350..0x6351361` passes `RDI=Q+U`, `RSI=S-U` to
the indirect call through `0x64ffb38`. The unique RELATIVE relocation has
`r_info=8`, addend `0x6349360`. This slot is writable `.data`, whose file
bytes are zero before relocation; the claim requires that the relocated
function pointer still has that value when called.

The complete 17-byte stub at `0x6349360` moves the length from RSI to RDX,
sets ESI to `0xA5`, and tail-jumps to `0x63f0a90`. That PLT entry jumps through
`0x64ee198`, whose unique JUMP_SLOT relocation has symbol index 10,
`r_info=42949672967`, symbol **memset**. With normal import resolution,
valid storage and the ordinary memset contract, this expresses:

```text
memset(Q + U, 0xa5, S - U)
```

It covers `[Q+U,Q+S)`, conditional on valid address arithmetic. `S` is the
class-size word, not requested logical length `N`. This is a caller-side
write after the previous packet's `memcpy(Q,P,min(U,S))`; that copy alone
did not account for the tail. The import contract and pointer-slot lifetime
remain unclosed. No libc implementation or captured execution is used.

On normal returns and an unchanged canary, the epilogue moves RBP into RAX
and returns `Q`. The prior `0x635a7a0` wrapper delegated by tail jump, so no
post-core wrapper work is inserted by this join. The already-established
allocation-result wrapper can then package null/non-null and the growth
consumer can install its header under the earlier packet's premises.

## Verification, limits and next question

The collector retains eight core continuations, four helper leaves and the
fill stub prefix before its pinned tail jump: **13 selected paths**. The
union has **21 explicit store sites**: 12 in the core and nine in the helper.
This is not a lexical all-path census. Imported memset effects, implicit
stack writes, excluded callees and aliases are separate.

From the repository root, with Python/Capstone and both native decoders:

```sh
python3 -B research/work-items/RE-012-tcp-context-port-115/accounting.py --out work/context-accounting-recheck
python3 -B -O research/work-items/RE-012-tcp-context-port-115/accounting.py --out work/context-accounting-optimized
```

All **82 negative/scope controls** reject: 22 changed code anchors, four
wrong extents, five relocation/import changes, three store changes,
12 changed entry edges, 11 excluded edges, nine invented runtime values,
six changed initial-data bindings, eight invalid scalar inputs and two
wrong captures. Full-body hashes can reject code mutations before narrower
anchors. Sixteen scalar cases cover threshold equality/wrap and fill-guard
boundaries; these are arithmetic corroboration, not execution fixtures.

Normal and optimized exports are byte-identical; all 38 prior reallocation
exports replay unchanged. The 34 focused existing tests pass. Commands,
source hashes and local raw-log hashes are retained in
[accounting-validation.json](accounting-validation.json). The known stale
generated README catalogue failure and historical full-suite/TLS failures
remain recorded; the full suite is not claimed green.

Initialization, runtime mutable globals, valid non-aliasing frames/metadata,
ABI, stable tables, disabled events or unexpired countdowns, and import
contracts remain premises. Exhausted countdowns, enabled events, flag changes,
canary failure and general allocation ownership remain open. No conclusion
that every allocator write misses the outer transport word follows here.
All 92 full-scope gates remain false; no Rust reconstruction, captured
execution, independent-agent review, network action, commit or push occurred.

Next bounded question: inspect the fresh-allocation fallback **`0x6353a70`**
already reached by `0x6355830`, beginning with its guards and small-size
return paths. This closes a different reachable allocation boundary in the
formatter chain; the remaining callbacks and event-triggering allocator
branches still need their own evidence.

Follow-up: [FRESH-FALLBACK.md](FRESH-FALLBACK.md) now records that fallback's
selected small cache returns, error writes and first refill-call boundaries.
It preserves the distinction between actual incoming fallback conditions;
the refill callees themselves remain open.

New analysis and code are independently authored MIT work. Original bytes
and referenced evidence retain their own rights.
