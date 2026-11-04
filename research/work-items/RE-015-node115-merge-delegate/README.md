# RE-015 — node 115 merge-delegate later phases: the third-vector merge, the transform gate, and the consumer exit

Question (the recorded next question of the assembled-record-readers
packet, #2559): what does the merge delegate `0x4748500` do in its
later phases — how does the 0x20-byte entry vector built from both
record vectors merge with the third argument's vector (the consumer
passes an empty `{0, 8, 0}` vector) — and what does the transform
gate `0x474ba60` decide per element? Where does the merged output go
after the delegate returns, on the consumer-exit path?

Target: Linux x86-64 node #115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Static trace only; no captured code executed.

## Owners

| Role | FDE | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| merge delegate | `0x4748500..0x4749aa9` | 5545 | `7b1d3b86c285b089e030cba72aa9fc2b71cba2009d2849c91ec06977ea9b2691` |
| transform gate | `0x474ba60..0x474bcd3` | 627 | `4527e1e0d1ad267cdd6951f2eb2898a962a2124d6096038fd63087ea43637d44` |
| exit reader | `0x4749ab0..0x4749d71` | 705 | `6f4caa139b97d81e99776e8cf0f570c906c02c5133d755baec41104d77e9b0bb` |
| hash function | `0x4744490..0x47445fb` | 363 | `a63e8df74f90feb19a2edfb54c63f81974bac2b7c325c363bc7fe23f9c757f62` |
| set initializer | `0x4743990..0x4743ff0` | 1632 | `eeac52dec8e29f0c1c3084ba80545a9b551b44c69b974a60f2220d564f961eef` |

The delegate body is retained as four later-phase windows (third-vector
loop, vecB loop + scan, sub-vector loop, temp assembly + epilogue) plus
its entry loops from #2559; the gate is retained in full (627 bytes);
the consumer exit block is retained as a window. Larger bodies are
hash-pinned with FDE records only.

## Boundaries

| Role | FDE | SHA-256 |
| --- | --- | --- |
| destroy-remaining-vecA | `0x47536c0..0x475376c` | `e3c793207685fccbf4993b8cbda1ac1b5d2c86bf2736c52186e02099d68ebc5c` |
| destroy-remaining-vecB | `0x4753770..0x4753864` | `95719dc118a1c123f82dd721aeba0f0488383549aa9e0cedeb045c851c246e98` |
| 0x10-sub-vector drop | `0x474e8a0..0x474e98b` | `21ec3b9046cb0e2e6cd091e7d20552f94cbe40a9da2ab582c98111a771b7417e` |
| entry-vector grow | `0x474e490..0x474e4f4` | `fe1531d90ea4cec8186fadce65b5b41958fc149a15603278e5d6afe7179123f3` |
| 0x40-vector grow | `0x474e420..0x474e484` | `447b3ab590a04170647c65d904bb5f18f8239c675c6f2d8f51fa1617f0f604d8` |
| 0x18-vector grow | `0x5c8b150..0x5c8b1b7` | `6555ee2a1d59fa37dbfe2f43e79c149a4322d1ab07a887b5e507ad4773fd23ae` |
| assertion entry | `0x1680c30..0x1680c82` | `2d00fd36dc6102ab0738e08907482bb818bca6e76e32a5b941eabf431f20767a` |
| descriptor-adjacent stub | `0x4747850..0x4747861` | `b377569e096d02820d07e894b96aca22d53b82d28b4af6a319a0cf1785eb76e9` |

## Trace

### Layouts

Each vector header is 24 bytes `{cap, buffer, count}` in that word
order. An empty vector is `{0, 8, 0}` (buffer 8 = dangling). A pair is
two such headers (0x30 bytes). The third-argument struct P is
`{leading word, vec at +0x8}` (0x20 bytes). The delegate's entry
vector holds 0x20-byte entries `{tag, a, b, c}`; the tags are 0 (vecA
duplicate), 1 (third/sub-vector non-member), 2 (vecB duplicate) and 3
(vecB scan outcome).

The delegate uses two call-local hash sets. Set A lives at frame
`[rsp+0x120]` (loaded from the template at entry); set B lives at
frame `[rsp+0x60]` (reloaded from the same template at vecB setup,
`0x4748c1d`/`0x4748c29`). Both start from the same `.data.rel.ro`
template at `0x64950f8`/`0x6495108`: `{base -> .rodata 0x450150,
mask = 0, init flag = 0, name pointer -> .rodata 0x4354fc}` (the
`.rodata` string begins `/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/core/src`).
The file values of the mask, flag and spare words are all zero; the
base and name words arrive only through RELATIVE relocations
(`0x64950f8 -> 0x450150`, `0x6495118 -> 0x4354fc`; an adjacent slot
`0x64950f0 -> 0x4747850` points at a 17-byte stub and is not loaded by
the delegate). Because the template's mask and flag are zero, the set
initializer runs on the first gate use of each set (see below), and
both tables are freed in the epilogue — the sets are call-local heap
state, not persistent across calls.

### Phase A — vecA (entry loop, restated from #2559)

Each 0x40-byte element whose word0 is not the sentinel
`0x8000000000000000` is staged, its string copied via alloc (slot
`0x64df480` -> `0x6355830`) + memcpy (slot `0x64df508`, memcpy) for
the gate call only, and gated against set A. Gate-true appends
`{0, word0, original string pointer, length}` to the entry vector;
gate-false copies the staged element verbatim into the rejected vector
at frame `[rsp+0xb8]`. After the loop, helper `0x47536c0` destroys the
remaining vecA elements `[cursor, end)`.

### Phase B — third-vector loop #1

Each 0x18-byte element `{size, string pointer, string length}` of P's
vector is partitioned by read-only membership in set A: the probe hashes
via `0x4744490` with the saved thread-local seed, scans hashbrown-style
control groups, and confirms by length then bcmp (slot `0x64df9f8`,
bcmp). A member is appended verbatim (0x18 bytes) to the found vector
at frame `[rsp+0xd0]` (grow `0x5c8b150` via slot `0x64e0c10`); a
non-member is appended as tag-1 entry `{1, word0, word1, word2}` to the
entry vector. Sentinel word0 == `0x8000000000000000` terminates;
post-sentinel elements' allocations are freed. Then P's vector is
REPLACED by the found vector: the old buffer is freed at cap*0x18 when
cap != 0, the found header is written to P+8 and its count to P+0x18
(`0x4748b9d..0x4748be7`). The third vector is therefore not
concatenated or interleaved with the entry vector — it is filtered
against set A, and the filtered subset replaces it in place.

### Phase C — vecB

Each 0x40-byte element whose word0 is not 6 is staged (string at
+0x10/+0x18) and gated against set B. Gate-true appends a tag-2 entry
`{2, element+0x8, element+0x10, element+0x18}`. Gate-false runs the
UTF-8 ':' scan (below). Normal loop end (6-terminator or cursor ==
end) calls helper `0x4753770` to destroy the remaining vecB elements,
then temp assembly.

### The ':' scan

The scan walks the element's string codepoint by codepoint with a full
UTF-8 decode, tracking a colon-run count: on ':' with count >= 2 ->
exit (a); on non-':' with count == 1 -> exit (b); string ends
immediately after ':' (count 1 or 2) -> exit (c); string ends after a
non-':' codepoint with count in {0, 2} -> exit (d). Exits (a), (b) and
(c) each alloc+memcpy a fresh copy of the whole string and append a
tag-3 entry `{3, word0, fresh copy, length}`, then destroy the
element's sub-vector (helper `0x474e8a0` drops the 0x10-stride
sub-vector at element+0x18/+0x20) and continue the vecB loop. Exit (d)
appends NO tag-3 entry: control enters loop #2 and the vecB loop is
abandoned. Zero-length strings take a tag-3 entry with pointer 1 via
`0x4748efc`. In run-length terms: (a) = a run of >= 3 colons, (b) = a
run of exactly 1 colon followed by a non-colon, (c) = the string ends
with a colon, (d) = every colon run has length exactly 2 and the string
does not end with a colon. Reading (d) as a well-formedness check for
"::"-separated strings is interpretation; the state machine is the
pinned fact.

### Phase D — sub-vector loop #2

Reached only from scan path (d). The current vecB element's sub-vector
(0x18-byte elements at staged+0x28/+0x30) is partitioned by the same
read-only set-A rule: member -> verbatim 0x18 entry into the found
vector at frame `[rsp+0x100]`; non-member -> tag-1 entry into the entry
vector; sentinel terminates; post-sentinel allocations freed. The
element's sub-vector fields are then REPLACED by the found vector, and
the whole staged 0x40-byte element (with the replaced sub-vector
header) is appended to the 0xe8 vector (grow `0x474e420` via slot
`0x64e1478`); the function proceeds to temp assembly and does NOT
return to the vecB loop.

### Temp assembly and epilogue

Temp+0x00..0x10 = P's first 16 bytes (leading word + post-write-back
vec cap); temp+0x10..0x20 = P vec buffer + count; temp+0x20..0x30 =
rejected-vecA cap + buffer; temp+0x30..0x40 = rejected-vecA count +
0xe8 cap; temp+0x40 = 0xe8 buffer; temp+0x48 = 0xe8 count;
temp+0x50..0x60 = entry-vector cap + buffer; temp+0x60 =
entry-vector count (`0x47494d6`/`0x47494df`). The epilogue
(`0x474952c..0x47496ea`) frees set B's table (bucket strings at record
word1 with size record word0, then the table allocation sized from the
mask), then set A's table the same way, then returns.

### The gate's decision rule

Gate `0x474ba60`, args rdi = set descriptor, rsi = &{len, copy
pointer, len}. If the init flag (descriptor+0x10) is 0, the set
initializer `0x4743990` is called through slot `0x64eaf88` with
(descriptor, 1, descriptor+0x20 = saved thread-local seed, 1) and the
probe retries. The string is hashed by `0x4744490` (seed =
descriptor+0x20's 16 bytes); the probe is hashbrown style: h2 = hash
>> 57, bucket index = hash & mask, 16-byte control-group compare,
candidate confirmed by length then bcmp. FOUND -> the caller's copy is
freed through the dealloc slot with (copy pointer, len, 0) and the gate
returns 1 (TRUE). NOT FOUND -> the copy is INSERTED into the set (h2
byte written to the control byte and its wrapped mirror, counter
adjusted, 24-byte bucket record {len, copy pointer, len} stored at base
- 24*index) and the gate returns 0 (FALSE). The gate is a test-and-insert:
TRUE means the string was already present (a duplicate), FALSE means it
is a first occurrence now owned by the set. The delegate's entry
vectors reference the ORIGINAL record strings, never the gate's copies.
The gate is called only from the delegate, at `0x4748742` (vecA) and
`0x4748dae` (vecB).

### Caller census — the non-empty third vector has no live caller

The exit reader `0x4749ab0` is the delegate's SOLE caller in node 115:
zero direct E8 calls to `0x4748500` anywhere in .text, and exactly one
slot call through `0x64eafd8`, at `0x4749ac9` inside the reader
(verified additionally by a full-binary objdump grep for rip-relative
references to `0x64eafd8`, which returns only `0x4749ac9`). The reader
itself is called only through slot `0x64e1480`, at `0x15a592a` in the
consumer exit block, with the consumer's empty `{0, 8, 0}` third
vector. Therefore loop #1 iterates an empty vector on the only call
path, its write-back writes an empty found vector over an already-empty
P vector, and the write-back is unobservable there. The third-vector
merge rule above is traced statically from the delegate body, not
observed from a live caller.

### Consumer exit — where the output goes

The consumer builds the empty third vector at `[rsp+0xc0]` and calls
the exit reader through slot `0x64e1480` with rdi = &[rsp+0x20] (out),
rsi = &[rsp+0x240] (saved pair), rdx = &[rsp+0xc0]. The reader calls the
delegate to fill its 0x68-byte temp; if temp+0x60 (entry count) is
non-zero it writes out = {6, temp+0x50, temp+0x58, temp+0x60} and
destroys the temp's pair copy inline, else it copies temp[0..0x50]
verbatim to out and frees only the entry-vector buffer. Back in the
consumer, out word == 6 branches to the assertion arm at `0x15a5b8c`
(slot `0x64df6a0`, target `0x1680c30`); otherwise the consumer copies
the 0x50-byte out struct to the destination pointer loaded from
`[rsp+0x278]` and returns. Between the reader call and the assertion
arm, the consumer reads only the out discriminant word itself and the
destination pointer: no later phase re-reads the out struct before the
assertion arm, and the {6, ...} form never reaches the destination copy.

## Limits

Static trace only. The hash function, the set initializer, the
destroy-remaining helpers, the sub-vector drop, the grow functions and
the assertion entry are hash-pinned boundaries, not traced. Whether the
set initializer copies the `.rodata` template table image at `0x450150`
or starts empty is NOT established: the template's nominal base points
into read-only `.rodata`, so the initializer must replace it with heap
storage before any insert, but its exact allocation/copy behavior is
untraced. The meaning of the entry tags 0/1/2/3 downstream (what
consumes the 0x50-byte out struct versus the {6, ...} form, and what
the destination at `[rsp+0x278]` does with it) is not claimed. The
"::"-separated reading of scan path (d) is interpretation. No captured
code executed, no runtime value or reconstruction gate is claimed.

## Next question

What does the set initializer `0x4743990` do with the `.rodata`
template table image at `0x450150` — copy it to the heap as the set's
initial contents, or start empty — and what strings, if any, does the
initial table hold? What consumes the entry tags 0/1/2/3 downstream of
the reader (the 0x50-byte out struct versus the {6, ...} form, and the
destination object at `[rsp+0x278]`)?
