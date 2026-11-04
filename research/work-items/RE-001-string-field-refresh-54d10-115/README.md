# RE-001: map node #115 string-field refresh 0x5d54d10

Task: RE-001. Bounded question: what does the routine at 0x5d54d10 do
to its holder's +0x48 string, and which code calls it?

Target: node #115, `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
(bound via `provenance/artifacts.json`), upstream main `8fd8db68`
at the time of this work.

## Answer in one paragraph

The routine refreshes the holder's +0x48 string from a lazy-singleton
registry accessor: it calls the accessor 0x5d54c30 with a stack temp as
the output slot, then assigns the accessor's output into the holder's
+0x48 string with full libstdc++ move/copy assignment semantics. A
heap accessor output is moved in (the destination takes the produced
buffer, size and capacity); a short-form accessor output is copied
into the destination's existing buffer. On the move path only, a
previous heap destination buffer is freed with the sized delete
passing (old pointer, old capacity + 1); a previous short-form value
frees nothing. The routine returns no value, and its only consumer is
a single call site in the large caller 0x5d85480..0x5d878e2.

## Holder and string layout

The holder is rdi on entry. Its +0x48 slot is a libstdc++ string:

| Field | Offset from holder |
| ----- | ------------------ |
| destination pointer | +0x48 |
| destination size | +0x50 |
| destination capacity-or-inline-buffer | +0x58 |

String layout (relative to the string object): pointer +0x00, size
+0x08, capacity-or-inline-buffer +0x10. Short form holds when the
pointer equals the string's own +0x10 address (the 16-byte inline
buffer); a short-form value holds at most 15 bytes plus the NUL.

## The accessor 0x5d54c30 (214 bytes, called once at 0x5d54d36)

The accessor fills the output slot from a function-local static
object, pinned from its own body; the three sub-callees' bodies are
not pinned, only their call shapes:

1. Guard init: guard byte 0x6500248 and object 0x6500260 both live in
   BSS, so both are zero at load. If the guard byte is already set,
   init is skipped. Otherwise `__cxa_guard_acquire` runs on the guard
   address; a zero acquire result (another initializer owns the
   object) also skips init; otherwise the constructor 0x602ea50 runs
   on the object and `__cxa_guard_release` follows.
2. Lookup: 0x602ea80 is called with (object 0x6500260, address of the
   pair's second slot, address of the pair's first slot) and writes a
   pair to the stack temp. While the pair's first element is null,
   the lookup repeats — there is no separate retry cap in the
   accessor body.
3. Convert: 0x61af170 is called with (output slot, pair second, pair
   first) and fills the output string. The accessor returns the
   output slot.

What string the lookup/convert pair produces is the accessor's
output; it enters the refresh model as an input and is not claimed
here.

Observation: the refresh routine loads holder +0x318 into rsi before
the accessor call, but the accessor body never reads its second
argument — every use of rsi inside the accessor is a value the
accessor set itself. The load's source-level purpose is not pinned.

## Assignment semantics, in order

After the accessor call, the temp string sits at rsp (pointer +0x00,
size +0x08, buffer/capacity +0x10) and the destination is the
holder's +0x48 string:

1. Destination short-form, produced short-form: copy path. The
   produced bytes are copied into the destination's existing buffer
   (an inlined byte copy with 1-, 2-, 4- and 8-byte paths plus a
   qword loop), the destination size becomes the produced size, a
   NUL byte is stored at destination pointer + produced size, and
   the destination keeps its own pointer and capacity. The produced
   temp is then destroyed in place (size 0, NUL at its pointer + 0)
   and, being short-form, frees no buffer.
2. Destination short-form, produced heap: move path. The destination
   takes the produced pointer, size and capacity. The produced temp
   is reset to empty short form (pointer = its own +0x10 address,
   size 0, first buffer byte 0) and frees nothing. The old
   short-form value has no heap buffer, so nothing is freed for it.
3. Destination heap, produced short-form: copy path, exactly as in
   (1). The destination keeps its heap buffer and capacity — safe
   because a short-form produced value holds at most 15 bytes while
   a heap buffer holds at least 16. No buffer is freed.
4. Destination heap, produced heap: move path. The destination takes
   the produced pointer, size and capacity. The old heap buffer is
   freed with the sized delete passing (old pointer, old capacity
   + 1), unless the old pointer is null, in which case nothing is
   freed. The produced temp needs no reset: it is a dead stack slot
   at return.

The NUL stores at the old heap pointer and at the produced temp
pointer happen immediately before the corresponding free or return
and have no post-return effect; they are recorded as observed
stores, not as state effects.

Preconditions, all satisfied by the single caller shape: the
destination is a live string (pointer non-null, or short-form) and
the produced temp does not overlap the destination buffer.

## Consumer

Census (executable-LOAD-segment exhaustive E8/E9 scan with objdump
confirmation, reproduced by the packet's census.py and re-run inside
verify.py): the routine has exactly 1 direct call + 0 tail jumps, 0
stored qwords, 0 RELATIVE relocations — reached only by code, never
by data. The single site is 0x5d86d02 in FDE 0x5d85480..0x5d878e2,
which passes its holder in rdi. What that caller does with the
refreshed +0x48 string after the call is not pinned: the caller
continues with a holder +0x1790 list walk and later calls the RB
insert-position search 0x5d4e260 (covered by open PR #2619). The
accessor itself has exactly 1 direct call (the refresh routine's own
site 0x5d54d36) + 0 tail jumps, also with no stored qword or
RELATIVE relocation.

## Verification

`python3 research/work-items/RE-001-string-field-refresh-54d10-115/verify.py`
prints ALL CHECKS PASSED: binary digest vs provenance, manifest,
excerpt regeneration byte-for-byte from fresh objdump runs, every
excerpt line's bytes vs the raw binary, all three FDE ranges, both
censuses including the exact site lists, the empty relocation
record, the semantic-only records, and model spot checks. Three
extra spot checks, byte-for-byte vs a fresh objdump run and the raw
binary, were done beyond verify.py's own checks (see the PR body).
The model tests in tests/test_string_field_refresh_54d10_115.py were
run by invoking the test functions directly (pytest is not installed
on this VM); all pass.

## Commands (verbatim excerpts)

```
objdump -d --start-address=0x5d54d10 --stop-address=0x5d54ee3 work/hl-node-115.bin
objdump -d --start-address=0x5d54c30 --stop-address=0x5d54d06 work/hl-node-115.bin
readelf --debug-dump=frames-interp work/hl-node-115.bin
```

Excerpt files main.txt and accessor.txt are whole-function verbatim
objdump output with only the header normalized to the bare binary
name; the leading `endbr64` in each routine is a genuine
control-flow-integrity landing instruction present in the target
binary, not a placeholder.

## Environment limits (honest)

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java. All
evidence here is static objdump/readelf output against the retained
node #115 binary, whose hash matches provenance/artifacts.json. The
accessor sub-callees 0x602ea50, 0x602ea80 and 0x61af170 are pinned by
call shape only, not by body.
