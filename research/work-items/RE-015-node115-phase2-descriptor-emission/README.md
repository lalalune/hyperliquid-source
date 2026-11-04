# RE-015 — node 115 phase-2 descriptor emission

Question (from the map-owner packet, #2479): the large consumer's
phase-2 probe walk loads only the found entry's capacity word and
compares it against the sentinel `0x8000000000000000` (`0x15a45e0`);
the probe's two branches build descriptor records from `.rodata`
strings and the consumer's argument block and hand them to
`0x474d890` and to a call through slot `0x64e1458`. What does
`0x474d890` do with the records, what does the slot call do, and
does the branch change *what* is emitted or only *which* records
are built?

Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Static trace only; no captured code executed.

## Owners

| Role | FDE | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| large consumer | `0x15a3b90..0x15a6509` | 10617 | `7995f7af57e2be27ca6ed1e307d9bcce9d6140f72b0ff0cf0804d7f09e5505fb` |
| descriptor stream collect | `0x474d890..0x474dadd` | 589 | `4514bf01206da3b66445a38797f30810be0986c60d0b603943f25bb5bd551102` |
| descriptor record bind | `0x47473c0..0x47475b9` | 505 | `b520689de276f092431c1551c2de71915a728cc43666c51b1ff5b9a92766db26` |

The consumer is retained as four windows (entry, phase-2 branch A,
tail A, branch B); the two callees are retained in full.

## Trace

### Stage 1 — the compare and the identical build

`rbp` holds the sentinel at the compare: the only write to `rbp`
between the consumer entry and `0x15a45e0` is the entry `movabs`
at `0x15a3bd5`. The fall-through (capacity == sentinel) and the
`0x15a4840` branch (capacity != sentinel) then execute the same
build in two segments — a descriptor build plus collect call
(66 bytes) and a string boxing plus second-record build
(130 bytes). The segments are byte-identical outside their
displacement fields, and the fields decode to the same targets
on both branches: the descriptor record at `[rsp+0x20]` is

```
+0x00  0x468adf   +0x08  0x30        (48-byte format string)
+0x10  0x468adf   +0x18  0x468b0f    (its begin/end)
+0x20  0          +0x30  dword 0x110001
```

(+0x28 is written by neither build.) The string at `0x468adf` is
`{d(%Y-%m-%d %H:%M:%S.%f)} {l} {f}:{L} >>> {m}{n}`. The collect
call passes `(r12, record)`; on every path into phase 2 the last
write to `r12` is `lea r12,[rsp+0x90]`, so the collect result
header lands in the scratch block at `[rsp+0x90]`. The second
record is then built from that header's three words plus a boxed
copy of the same 48-byte string: `(cap, buffer, count, 0x30,
copy, 0x30)`.

### Stage 2 — what the collect function does (0x474d890)

It is a stream collector. `visit` (slot `0x64eafb0` →
`0x4744b60`) expands a cursor into a 0x58-byte state; a dword tag
of 5 ends the walk. `next` (slot `0x64eaf10` → `0x4735b30`)
yields the element record; a qword tag of 5 ends it. Either
terminal case stores the empty header `{0, 8, 0}` to the output
and returns it. Otherwise it allocates `0x160`, stores the first
element verbatim, seeds a stack cursor with the input record's
first `0x38` bytes, and loops — visit, next, append verbatim at
stride `0x58`, growing through `0x474e640` when count ==
capacity — then stores `{capacity, buffer, count}` to its first
argument and returns it. The input descriptor record is consumed
as the cursor seed only; it is stored nowhere and no field of it
reaches an element or the header. Direct-call census: exactly
three call sites in the binary — the two phase-2 sites and
`0x473a03b`, inside the bind function's default-record producer.

### Stage 3 — what the slot call does (slot 0x64e1458 → 0x47473c0)

The bind function (no direct call sites anywhere; slot-only)
overwrites its first argument — the descriptor record — in place
and returns it: words +0x00/+0x08 are configuration outputs,
word +0x10 is `0x6500060` (slot object) when the second record's
+0x10 byte is 1 and `0x64fe408` (global table) otherwise, word
+0x18 is the second record's first word (or a fresh heap copy of
a default record from slot `0x64e12f8` when that word is 0),
word +0x20 is the second record's second word (or the static
`0x6495038`), and byte +0x28 is the configuration flag — on the
default arm the second record's +0x11 byte XOR 1. The lookup
consults once-initialised globals (`0x64fdbe0`, initialiser
`0x4752c90`; byte `0x64fdbe8`; table `0x64fe408`/`0x64fe440`,
initialiser `0x5c6c15a`) and `isatty(1)`/`isatty(2)` through
GLOB_DAT slot `0x64eaf90` on the arms where the consulted byte
is 0. The second record is only read, never stored or freed.
For the consumer's call (second record +0x10 byte is 0, globals
at their file-initial values 0/3/3) the output is
`{1, 0, 0x64fe408, boxed record, 0x63ffbd0, flag 1}` and neither
isatty arm is reached.

### Stage 4 — where the branches actually diverge

First differing sites: `0x15a46ad` (sentinel) vs `0x15a4904`
(non-sentinel).

- **Sentinel branch:** the second record's header is rewritten
  in place to `{boxed record, 0x63ffbd0, word 0}` and handed,
  with the descriptor record, to the bind function. A 0x30-byte
  heap copy of the *transformed* descriptor is then stored into
  the consumer's second structure under tag `0x63ffbf8`. Nothing
  of the found entry beyond the capacity word is read.
- **Non-sentinel branch:** the boxed second record is stored
  into the scratch block at `[rsp+0x90]` (`{boxed, 0x63ffbd0,
  byte 1 at +0x10}`); the found entry's pointer/length words —
  the only read of the entry beyond the capacity word — are
  copied out as the format argument; the format consumer (slot
  `0x64df6e8`, the #2408 owner) runs over the piece at
  `0x445923` (legible part `_overflow{}`); the descriptor is
  passed to the emit function behind slot `0x64e1460`
  (`0x473c130`) and inserted into a map by `0x156f680` (its only
  direct caller in the binary); finally a 0x70-byte heap
  snapshot of `[rsp+0x20..0x90]` is stored into the second
  structure under tag `0x63ffc70`.

So the branch changes the destination and the downstream
emissions — an in-place bind plus a 0x30-byte tagged copy versus
a format/emit/insert sequence plus a 0x70-byte tagged snapshot —
but not the descriptor record's contents, the collect call, or
its result.

## Boundaries (hash-pinned, not traced)

Stream visit `0x4744b60` (5,696 B), stream next `0x4735b30`
(3,781 B), collect grow `0x474e640`, collect cleanups
`0x474dc90`/`0x474e050`, bind initialisers
`0x4752c90`/`0x5c6c15a`, default-record producer `0x4739ff0`,
descriptor emit `0x473c130`, format consumer `0x141e3a0`
(traced as an owner by #2408), map insert `0x156f680`,
second-tree insert `0x1497040`, alloc `0x6355830`, dealloc
`0x635de30`, format-args drop thunk `0x15ebba0`.

## Validation

`tools/phase2_descriptor_static.py` regenerates this packet and
`tests/test_phase2_descriptor_static.py` checks the analysis,
the branch-identity comparison, the models, the censuses, and
counterfactuals (probe compare, collect tag, bind path byte,
slot binding, branch-build divergence, lea target, collect body,
bind globals), each rejected with its specific error.

## Limits and next question

Static trace only. How the visit/next functions expand the
cursor and which element records a descriptor produces are not
traced. The bind outputs are modelled under the file-initial
globals; runtime mutation of those globals by other callers and
the isatty-arm outputs are not traced. Next questions: what the
second structure's readers do with the two payload kinds (tag
`0x63ffbf8` vs tag `0x63ffc70`), and who consumes the vector the
collect call leaves at `[rsp+0x90]` after phase 2.
