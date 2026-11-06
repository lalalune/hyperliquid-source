# RE-015 — node 115 pair-destroy helpers: one element per call, clones with no module-local difference — and the caller family of the drain+free wrappers

Question: the sub-vector drain callees packet traced the four
drain callees of the record element drops and left its next
question in two parts. (1) "Are the two pair-destroy helpers
the normal drains' landing pads hand remaining elements to
(`0x1537b00` / `0x474e0b0`, 130 bytes each, hash-pinned in
this packet) also clones of one another" — and what does one
call do per element? (2) "do the 86-byte caller FDEs in the
drains' census (several per module) form a wrapper family of
the same drain-and-free shape over other vector headers?" —
the caller FDEs of the 86-byte unwind drains are exactly two
per module: the element drop and one further record
destructor. This packet opens both helpers in full, answers
the clone question by the #2714 unmasked-diff method, and
pins the shape of all four wrapper callers.

Overlap disclosure: the drain-callees packet (and, before it,
the merge-delegate packet #2615 for one drain) had already
hash-pinned both helpers as boundaries ("not traced"). No
merged or open work traces either helper body or the wrapper
callers' shapes; this packet opens them.

Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Static trace only; no captured code executed.

## Owners

| Role | FDE | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| vec-A pair-destroy helper | `0x1537b00..0x1537b82` | 130 | `30ce062b876d862e3961d70031ed434c3e520457bc3c16900e1b6fafa6a4511a` |
| reader pair-destroy helper | `0x474e0b0..0x474e132` | 130 | `ae6e68cf8978e52df9dda3f1d2849d62d09fa99f0f880c04137413d82a93a12d` |

Both bodies are retained in full. Retained as traced-shape
context (full dumps included): the four caller FDEs of the
86-byte wrappers — the two element drops (#2714 owners,
`0x1538ec0..0x1538fc2` / `0x474dcd0..0x474ddd2`, 258 bytes
each) and the two record destructors (`0x1538460..0x153871b`,
699 bytes; `0x474dba0..0x474dc86`, 230 bytes). The two normal
drains and the two 86-byte wrappers are hash-pinned boundary
context (traced by the drain-callees packet).

## Trace

### Stage 1 — what one pair-destroy call does

The arguments are the element's two words: `rdi` = the data
word, `rsi` = the descriptor word — a pointer to the
0x18-byte descriptor record. The helper saves both words,
then:

1. Descriptor word 0 (`[rsi+0x0]`) is called on the data when
   non-null (`call rax` at `0x1537b16` / `0x474e0c6`).
2. The size word (`[rsi+0x8]`) is tested. When zero, the
   helper restores the registers and returns — no free.
   When non-zero, the dealloc class is computed from the
   align word (`[rsi+0x10]`) by the same tzcnt/cmov idiom
   the drains and drops use (`tzcnt` at `0x1537b25` /
   `0x474e0d5`): class 0 when align ≤ size, tzcnt(align)
   when align > size, and tzcnt(align) whenever
   align ≥ 0x11. The registers are restored and the data is
   freed through the dealloc slot `0x64df4a0` (RELATIVE
   target `0x635de30`) as a **tail jump** (`0x1537b41` /
   `0x474e0f1`) with (data, size, class).

Order is descriptor call first, free second — the normal
drains' per-element order, one element at a time. There is
**no loop in the helper**: the iteration over the remaining
elements lives in the drain landing pads (counter `dec` at
`0x153df70` / `0x474e960`, cursor advancing 0x10 per element,
the element's data and descriptor words loaded at
`0x153df7a`/`0x153df7f` and mirror sites, one helper call per
element at `0x153df83` / `0x474e973`).

Unwind behaviour: the helper's own landing pad (body
+0x4d) saves the exception, re-runs the same size/class
computation, and — when the size word is non-zero — frees
the data through the slot in **call** form (`0x1537b74` /
`0x474e124`), then calls `_Unwind_Resume` (PLT `0x63f0a50`)
with the saved exception. So a throwing descriptor function
does not leak the element's data.

### Stage 2 — the clone verdict

Judged by the #2714 method (unmasked instruction diff +
consumption order): both helpers decode to **44
instructions at identical offsets** and, after masking the
address-dependent tails of branch and slot instructions,
byte-identical streams. The unmasked difference is exactly
**three sites**, each a 4-byte displacement field, and every
one resolves to the **same shared target** in both instances
(full rows in `records.json`):

| Offset | Kind | Target (both) |
| --- | --- | --- |
| 0x41 | ripdisp32 (tail jump) | dealloc slot `0x64df4a0` |
| 0x74 | ripdisp32 (pad call) | dealloc slot `0x64df4a0` |
| 0x7d | rel32 (resume call) | `_Unwind_Resume` PLT `0x63f0a50` |

Unlike the drain pairs — whose five (235-byte) and four
(86-byte) differences each include a module-local call
target (the pair-destroy helper itself, the module-local
normal drain) — **no difference here resolves to a
module-local target**: the helpers call nothing of their own
module. The descriptor function is indirect through the
descriptor, the free goes through the shared dealloc slot,
and the resume through the shared PLT. The bodies' own
hashes differ, as the owner table shows; identity is claimed
at the masked instruction shape only.

### Stage 3 — the caller family of the 86-byte wrappers

The transfer census (whole `.text`, E8 calls and E9 tail
jumps, sites attributed by containing FDE) confirms the
drain packet's caller sets and adds the helpers': each
pair-destroy helper has exactly **one** direct caller — its
own module's normal-drain landing-pad loop — and each
86-byte wrapper exactly two, one per record destructor in
its module. No tail-jump caller exists for any of the four.

The four wrapper callers are **not wrappers themselves**
and are not mutual clones (258 / 699 / 258 / 230 bytes; the
two element drops are clones of each other per #2714; the
two record destructors are clones of nothing). Each is a
record destructor that embeds the same **two-half
drain-and-free pattern** over its record's sub-vector
header, at the sites pinned in `records.json`
(`caller_shapes`):

- **Normal half.** Call the module's normal drain on the
  header; then free the buffer inline: capacity word
  (header +0x0) loaded and gated non-zero, buffer pointer
  (header +0x8), size = capacity << 4, align 0, through the
  dealloc slot `0x64df4a0`.
- **Unwind half.** A landing pad that protects the fields
  destroyed *before* the drain call routes the same header
  through the 86-byte drain+free wrapper — exactly one
  wrapper call per caller FDE, always inside a pad block —
  because on the unwind path the inline drain+free never
  ran. A landing pad that protects the drain call *itself*
  re-runs only the inline buffer free: the drain has
  already consumed the elements, so the wrapper's drain
  half must not run again.

So the whole drop path in each module is generated from one
pattern, and the 86-byte body is its shared out-of-line
unwind half: the callers do not repeat the wrapper's work,
they *contain* its normal half inline and delegate the
unwind half to it.

Two measured deviations, both pinned:

- **Free form.** The vec-A record destructor `0x1538460`
  performs the normal-path free as a slot **call**
  (`0x1538570`) — further fields follow it — where the
  other three callers restore the registers and use the
  epilogue **tail-jump** form.
- **Header offset.** The reader record destructor
  `0x474dba0` has its sub-vector header at record **+0x0**:
  the record pointer itself is passed to both the drain
  (`0x474dbf0`) and the wrapper (`0x474dc56`), and its first
  field is an inline pair-destroy of the tagged pair at
  record +0x18/+0x20 (descriptor call `0x474dbbf`, tzcnt
  `0x474dbd0`, dealloc call `0x474dbe7`, re-run on the pad
  at `0x474dc4d`). The other three callers pass record
  +0x18 as the header.

## Limits

Static trace only. Hash-pinned, not traced: the two normal
drains and the two 86-byte wrappers (traced by the
drain-callees packet, retained here as boundary context),
the dealloc target `0x635de30`, and `_Unwind_Resume`.
Caller shapes are pinned at the drain/free/wrapper sites
listed in `records.json`; the remaining fields of the two
record destructors (strings, tagged pairs, the tag-3
dispatch in `0x1538460`) are not traced, and which landing
pad protects which call range is identified by pad content
and position, not by re-decoding the LSDA. What the
elements' descriptor drop functions do beyond the call, and
any semantic name for the element or record types, are not
claimed. No captured code executed, no runtime value or
reconstruction gate is claimed.

## Next question

Do the further 86-byte drain callers in the drain packet's
census (vec-A FDEs `0x1569cd0` / `0x158b8e0` / `0x15ac910` /
`0x15bb960`, reader FDEs `0x4747f50` / `0x4753450`) — whose
size already matches the wrappers — form further instances
of the same drain+free wrapper over other headers: are they
clones of the 86-byte pair or a wider wrapper family, which
headers do they wrap, and do their own callers again embed
the same two-half pattern?

## Reproduce

```sh
python3 tools/pair_destroy_helpers_static.py \
  --output research/work-items/RE-015-node115-pair-destroy-helpers
python3 -m unittest tests.test_pair_destroy_helpers_static
(cd research/work-items/RE-015-node115-pair-destroy-helpers \
  && sha256sum -c MANIFEST.sha256)
```
