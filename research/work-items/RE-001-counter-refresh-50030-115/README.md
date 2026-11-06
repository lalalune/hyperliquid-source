# RE-001: counter-refresh routine 0x5d50030 (node #115)

## Bounded question

What does the routine at `0x5d50030` do to the counter reached through
the state object, what decides whether it adds to or replaces that
counter, and what second dispatch does it run afterwards — and where is
that routine used?

## Answer (established semantics)

The routine `0x5d50030` is a whole 314-byte routine (FDE
`0x5d50030..0x5d5016a`), not a lone-window fragment: it takes a state
pointer in `rdi`, refreshes the counter slot reached through the state,
and then optionally runs a second dispatch on the state's waiter object.
It pushes only `r12`, `rbp` and `rbx`, uses no stack canary, makes no
direct calls and no PLT calls — all seven dispatches are indirect — and
writes nothing except the counter slot, at most twice. The disassembly
excerpt in this packet is verbatim objdump output: opcodes such as
`endbr64` are genuine instructions present in the target binary, not
placeholders.

The packet was produced with:

```
objdump -d --start-address=0x5d50030 --stop-address=0x5d5016a work/hl-node-115.bin
readelf --debug-dump=frames work/hl-node-115.bin
readelf -r work/hl-node-115.bin
```

## State layout (offsets pinned, kinds not pinned)

- `+0x00`: inner object pointer, whose vtable slot `0x98` is the producer.
- `+0x08`: waiter object pointer for phase B.
- `+0x10`: dword loaded in every phase-B path but never read afterwards
  (loaded-but-unused, recorded as an observation, not an input).
- `+0x18`: counter pointer; null skips phase A entirely.
- `+0x20`: flag byte, accumulate versus replace.
- `+0x21`: flag byte, run phase B or return.
- `+0x22`: flag byte, extra subtract or not.
- `+0x28`: extra subtrahend. `+0x38`: subtrahend.

## Phase A: refresh the counter (only when the counter pointer is non-null)

1. Read the slot-`0x98` value of the inner object's vtable. The two
   GOT slots the routine compares against resolve in the file, via
   `R_X86_64_RELATIVE` relocations, to `0x5d4d490` (slot `0x98`) and
   `0x5d48960` (slot `0xc8`); see `relocations.txt`.
2. If the slot-`0x98` value differs from the known producer
   `0x5d4d490`, call that slot value itself with the inner object.
   If it equals the known producer, call slot `0x98` of the delegate
   at inner object `+0x20` instead. Both callees are call-shape only:
   their implementations are not pinned here.
3. With the producer result `V`:
   - Flag `+0x20` zero (accumulate): store
     `old counter + V - field +0x38` into the counter slot.
   - Flag `+0x20` nonzero (replace): store
     `V - field +0x38` into the counter slot.
   - Flag `+0x22` nonzero: subtract field `+0x28` as well and store
     a second time to the same slot. All arithmetic is 64-bit wrapping.
4. If flag `+0x21` is zero, return. Otherwise run phase B.

## Null-counter path

When the counter pointer is null, phase A is skipped. If flag `+0x21`
is zero, the routine returns at once. Otherwise it still calls slot
`0x98` of the inner object directly — with no identity check and no
delegate — and computes `result - field +0x38`, which is then never
stored or returned: computed-but-unconsumed, recorded as such. Phase B
then runs as below.

## Phase B: waiter dispatch (only when flag `+0x21` is nonzero)

Let `W` be the waiter at state `+0x08` and `H` the slot-`0xc8` value of
`W`'s vtable:

- `H` differs from the known handler `0x5d48960`: call `H` with `W`,
  then return.
- `H` equals the known handler: if the byte at `W + 0x20` is at most 2,
  return; otherwise tail-dispatch slot `0xd8` of `W`'s vtable. This
  known-handler path duplicates, inline, the body of `0x5d48960`
  itself (a 25-byte routine: the same byte check followed by the same
  slot-`0xd8` tail dispatch) instead of calling it.

Exits are a plain return at `0x5d5010e`, a plain return at `0x5d50152`
after the direct handler call, and the slot-`0xd8` tail dispatch at
`0x5d500d2`.

## Consumers

Executable-LOAD-segment exhaustive E8/E9 scan with objdump
confirmation, reproduced by the packet's `census.py` and re-run
inside `verify.py`: exactly 91 direct calls and 0 tail jumps across
66 caller FDEs (see `callers.tsv`); 0 stored qwords, 0 RELATIVE
relocations for the routine itself — reached only by code, never by
data. The two GOT slots above are relocations the routine reads, not
references to the routine.

## Unknowns (kept separate from findings)

- The source-level names and kinds of the state object, the inner
  object, the delegate, the waiter, the producer and the handler, and
  what the flag bytes mean at source level.
- What the producer computes, what the handler does when it is not the
  known handler, and what the slot-`0xd8` target computes; all three
  are call-shape only here.
- Whether the counter is a reference count, a sequence number or some
  other tally; the observable behaviour is the store rule above, and
  any such reading is an inference, not a pinned claim.
