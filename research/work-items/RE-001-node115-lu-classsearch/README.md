# RE-001: the node #115 lu class-search helper — snap, index, first set class, dispatch

## Question

Packet #229's next question: decode the FDE starting at `0x63d9340`
end to end — what it does with the size helper's return, why it
derives a class index from it, and why it clears that class's bit
in a bitmap at record `+0x400`.

## Answer

`0x63d9340(record, x)` = (rdi, rsi) snaps `x` through the size
representative helper, derives a size-class index from the snapped
value, finds the first set bit in the bitmap at record `+0x400` at
or above that class, and tail-calls the consumer `0x63b9690` with
the slot entry `record + found * 16`. When no class is found it
returns the pointer stored at `record + 0x1080` instead.

## Correction of the premise

This function does **not** clear any bitmap bit. There is no store
to the bitmap anywhere in the FDE: the `and` at `0x63d93b4` is a
register test (`and mem, %rsi` in AT&T order writes `%rsi`, not
memory), and the only memory writes in the FDE are `push`/`pop`.
The search reads the bitmap; it never modifies it. Packet #229's
next-question wording ("bitmap-bit clear") and packet #227's
fourth-caller note ("clears that class's bit") are therefore
refuted by these bytes. What this function does with the class is
dispatch on it, not clear it.

## Entry and the snapped value

- Entry: `endbr64`, `push %rbx`, `rbx = record`, `rdi = x`.
- `call 0x63e8c80(x)` at `0x63d934b` — packet #227's size
  representative helper. Its return `v` is the only value the
  rest of the function operates on.
- Huge check: `movabs $0x7000000000000000, %rax`;
  `cmp %rdx, %rax`; `jb 0x63d9420` — the huge path runs exactly
  when `v > 0x7000000000000000` (`v` equal to the threshold takes
  the normal path).

## Normal path: class index

The `bsr` index idiom, identical to packet #226's finder index
(no `-1` adjustment, unlike packet #227 round 1):

- `rsi = v - 1`; `bsr v` gives `floor_log2(v)`;
  `rdx = (v - 1) & v`; `cmp $1, %rdx`;
  `sbb $-1, %edi` yields `ceil_log2(v)`.
- `edi = max(ceil_log2(v), 14)`;
  `shift = (edi == 14) ? 12 : edi - 3`;
  `index = (edi - 14) * 4 + (((v - 1) >> shift) & 3)`.
  Index range is 0..199, the same scale as #226.

## Normal path: bitmap search

With `w = index >> 6`, `bit = index & 63`, bitmap base
`record + 0x400` (`lea 0x400(%rbx), %r9`):

- Mask `= -(1 << bit)` (bits at or above `bit` set).
- Test `rsi = mask & bitmap[w]` — register only, no store.
- If nonzero: `c = w * 64 + tzcnt(rsi)`, the first set class at
  or above `index`.
  - If `c == 64`: return `[record + 0x1080]` (`mov 0x1080(%rbx),
    %rax` at `0x63d9410`, single `ret` at `0x63d9418`).
  - Else: `rax = c << 4`, `rdi = record + rax`,
    `pop %rbx`, `jmp 0x63b9690` (tail call, `0x63d940a`).
- If zero in word `w`: if `w == 0`, return
  `[record + 0x1080]` directly — words above word 0 are not
  scanned in this case. Otherwise scan words `w + 1, w + 2, ...`
  for the first nonzero word; `c = word * 64 + tzcnt(word)`;
  tail-call as above. The scan loop as written has no upper
  bound observed in this FDE.

## Huge path

At `0x63d9420`, for `v > 0x7000000000000000`:

- `r10 = [record + 0x418]` — bitmap word 3, bits 192..255.
- `r10 &= ~0x7f` — keeps bits 199..255 only.
- If nonzero: `c = 192 + tzcnt(r10)`, the first set class at or
  above 199; tail-call `0x63b9690(record + c * 16)`.
- If zero: scan words 4, 5, ... with the same loop (entered with
  word index 4); first nonzero word gives `c` and the tail call.
  The huge path never returns the `[record + 0x1080]` fallback.

## Arguments and return

- Arguments: `rdi = record`, `rsi = x` (the size-helper input).
- Return: either the pointer `[record + 0x1080]` (two fallback
  paths: word-0 miss, and found class exactly 64), or whatever
  the consumer `0x63b9690` returns via the tail call. The
  consumer's internals are cited by address only, not decoded
  here.

## The dispatch stride, and an open layout tension

The consumer receives `record + c * 16`: a 16-byte stride from
the record base. That stride collides with the bitmap exactly at
class 64 (`record + 64 * 16 = record + 0x400`, the bitmap base) —
the one class the function refuses to dispatch, returning the
fallback pointer instead. That coincidence is consistent with
16-byte entries occupying `record + 0x00..record + 0x3ff`
(classes 0..63), but how classes 65 and above map to entries is
not settled by these bytes: the dispatch arithmetic is exact,
the entry layout beyond class 63 is not.

## Census

Whole-`.text` byte scan + per-site disassembly; `.rela.dyn` for GOT
(60,723 entries). Helper `0x63d9340`: 2 direct E8, 0 E9, 0 LEA,
0 GOT. E8: `0x63b827f` (FDE `0x63b8160..0x63b81ab`, passes
(r12, r13), tests the return for `NULL`), `0x63b8918` (FDE
`0x63b8820..0x63b8d85`, passes (rbx + 0x140, r13), tests the
return for `NULL`, then passes it onward as an argument). Both
callers' purposes are cited by address only, not decoded here.

## Corrections to earlier packets

- **#229 corrected.** Its next question's premise is refuted:
  this FDE contains no bitmap store; it searches the bitmap and
  dispatches, it does not clear a bit.
- **#227 corrected and confirmed.** The fourth caller is this
  FDE (call site `0x63d934b` confirmed); its description is
  corrected from "clears that class's bit" to "finds the first
  set class at or above the class of the size helper's return
  and tail-calls the consumer with the class's slot entry".
- **#226 confirmed.** The class index idiom here is exactly the
  finder's idiom (same `bsr` shape, same 0..199 range, no `-1`),
  applied to the size helper's return rather than a raw
  threshold.
- No bytes claimed by packets #183–#229 are re-claimed. All
  exhibits lie strictly inside the class-search FDE; the size
  helper, the consumer, and all caller FDEs are cited by
  address only.

## Unresolved, stated not inferred

The identity of the pointer at `record + 0x1080` (the fallback
return); why found class exactly 64 returns the fallback rather
than dispatching (consistent with, but not proven by, a 64-entry
prefix before the bitmap); how classes 65 and above map to
16-byte entries given the bitmap at `+0x400`; the purpose of the
two callers beyond their argument setup and `NULL` tests; what
the consumer `0x63b9690` does with the slot entry and returns;
why the upward scan loop has no upper bound in this FDE.

## Next question

Decode the consumer `0x63b9690` end to end: what it does with the
slot entry `record + found * 16` it receives by tail call, how it
merges and relinks the chain it reads there, and what it returns
— this decides what the class search in this packet actually
dispatches to.

## Verification

- Static verifier `tools/node115_lu_classsearch.py`: exit 0
  (5 excerpts, 188 bytes, 49 strict mnemonics, 1 internal call,
  census 2 E8 sites, MANIFEST 15/15).
- Unit tests `tests/test_node115_lu_classsearch.py`: 10/10.
- `make verify`: exit 0 (29 manifests, 471 entries).
- `make catalogue-check`: exit 0.
- `make test`: 77 files attempted, 1 failed — the single
  failure is the pre-existing test_node115_catalogue Errno 18
  cross-device-link error, identical on pristine checkouts,
  not a packet regression; this packet's file [36/77]
  passes 10/10.
- Target: node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  (105,896,032 bytes), upstream main `8fd8db6`
  (fetch-confirmed unmoved before analysis).
- No bytes claimed by packets #183–#229 are
  re-claimed; earlier bytes are cited by address
  only. No execution of the node binary at any
  point.

## Files (16)

- `research/work-items/RE-001-node115-lu-classsearch/README.md`
- `research/work-items/RE-001-node115-lu-classsearch/EVIDENCE.md`
- `research/work-items/RE-001-node115-lu-classsearch/records.json`
- `research/work-items/RE-001-node115-lu-classsearch/MANIFEST.sha256`
- `research/work-items/RE-001-node115-lu-classsearch/cs_entry.hex`
- `research/work-items/RE-001-node115-lu-classsearch/cs_entry.objdump.txt`
- `research/work-items/RE-001-node115-lu-classsearch/cs_index.hex`
- `research/work-items/RE-001-node115-lu-classsearch/cs_index.objdump.txt`
- `research/work-items/RE-001-node115-lu-classsearch/cs_test.hex`
- `research/work-items/RE-001-node115-lu-classsearch/cs_test.objdump.txt`
- `research/work-items/RE-001-node115-lu-classsearch/cs_scan.hex`
- `research/work-items/RE-001-node115-lu-classsearch/cs_scan.objdump.txt`
- `research/work-items/RE-001-node115-lu-classsearch/cs_huge.hex`
- `research/work-items/RE-001-node115-lu-classsearch/cs_huge.objdump.txt`
- `tools/node115_lu_classsearch.py`
- `tests/test_node115_lu_classsearch.py`
