# RE-001: which code consumes the node #115 lu.rs function-pointer slots — two single-method vtables, their clone-and-hand-to-worker consumers, and the shared drop dispatcher

- Component: `base/src/lu.rs` conversion callers, reached indirectly.
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (upstream main, node-115-only migration).
- Question: packet #185 (PR #2137, open) left open which code consumes the
  two function-pointer slots `0x64014c0` (state machine) and `0x6401300`
  (caller-2) to reach those functions indirectly, and what the Q table's
  slot `+0x8` does. Answer, in one paragraph: the slots are not standalone
  function pointers — each is the method slot (`+0x18`) of a single-method
  Rust trait-object vtable, and exactly two functions consume each vtable by
  loading its base address and handing a cloned struct plus the vtable to
  the shared 1,733-byte worker. The state-machine consumer is additionally
  reachable through a once-closure shim. The Q table's slot `+0x8` is still
  open (see below). This packet cites #183 (PR #2106), #184 (PR #2125), and
  #185 (PR #2137, the inviting prior packet) as prior work; their bodies
  are cited, not re-claimed. The new bytes claimed here are the two
  consumers, the two vtables, the drop dispatcher, and the two drop
  functions only.

## Exact scope

| Role | FDE half-open VA range | Bytes | Native instructions |
| --- | --- | ---: | ---: |
| consumer, caller-2 vtable (characterized) | `0x15d6230..0x15d6310` | 224 | 58 |
| consumer, state-machine vtable (characterized) | `0x15d2fb0..0x15d31c7` | 535 | 126 |
| drop dispatcher (characterized) | `0x15dacd0..0x15dad33` | 99 | 35 |
| drop function, caller-2 type (characterized) | `0x15e04b0..0x15e0537` | 135 | 40 |
| drop function, state-machine type (characterized) | `0x15d9ca0..0x15d9d27` | 135 | 40 |

All bodies are hash-pinned without normalization. Coordinates are ELF
virtual addresses (PIE); `.text` file offset = VA − 0x1000,
`.data.rel.ro`/`.got` file offset = VA − 0x2000, `.rodata` file offset = VA.

## The correction to #185's framing: the slots are vtable methods

#185 reported each fn slot as "sitting immediately before" a `lu.rs`
Location record, with no `.text` instruction referencing the slot. That is
true of the slots — but the slot is the fourth qword of a vtable, and the
vtable base *is* referenced from `.text`. Layout, verified through
RELATIVE relocation addends (the file slots are zero):

| Vtable base | +0x0 drop | +0x8 size | +0x10 align | +0x18 method | Following Location |
| --- | --- | ---: | ---: | --- | --- |
| `0x64012e8` (caller-2) | `0x15e04b0` | 160 | 8 | `0x15d5b00` | `0x6401308`: `base/src/lu.rs`, len 14, 159:64 |
| `0x64014a8` (state machine) | `0x15d9ca0` | 168 | 8 | `0x15d6e00` | `0x64014c8`: `base/src/lu.rs`, len 14, 220:26 |

The file-pointer slots resolve through RELATIVE addends to the string
`base/src/lu.rs` at `0x4326c1`. The size fields match the consumers'
allocation sizes exactly (160 and 168), which is what confirms the
vtable reading: the consumers allocate precisely the vtable's size before
handing the clone to the worker.

## The consumers: clone, guard, hand to the worker

Each vtable base has exactly two `lea` sites in the whole binary (byte
scan over `.text`, every hit confirmed by objdump); the fn slots
themselves have zero `lea` sites:

| Vtable | `lea` sites | In function |
| --- | --- | --- |
| `0x64012e8` (caller-2) | `0x15d6272` (`lea r8`), `0x15d62e0` (`lea rsi`) | consumer `0x15d6230` |
| `0x64014a8` (state machine) | `0x15d3076` (`lea r8`), `0x15d3136` (`lea r8`) | consumer `0x15d2fb0` |

Caller-2 consumer (`0x15d6230`, args `(rdi, rsi, rdx)` saved to
`(r15, r14, r12)`):

- Allocates 160 bytes via GOT `0x64df480` (→ `0x6355830`); on null it
  takes the alloc-error path (`edi` = 8, `esi` = 160, GOT `0x64df490`,
  `ud2`). Otherwise it copies 160 bytes from `r12` into the new buffer
  via GOT `0x64df508` (dynamic symbol, runtime-resolved).
- Reads the guard DWORD `0x64f03d8` (the same global #183's guard
  function gates on). If it is 0, it calls the worker directly. If
  nonzero, it first calls the once helper via GOT `0x64df9f0`
  (→ `0x5c87d50`, the same slot #185 identified) with
  (`rdi` = &guard, `rsi` = 0, `rdx` = &stack cell, `rcx` = `0x6401200`,
  `r8` = `0x6401480`, the `lu.rs:215:36` Location), then loops back to
  the worker call.
- Worker call: `0x15d6730` with (`rdi` = `r15`, `rsi` = `r14`,
  `edx` = 1, `rcx` = clone, `r8` = vtable `0x64012e8`).
- Landing pads: one calls the drop dispatcher `0x15dacd0` on
  (clone, vtable) and resumes unwinding; the other runs a GOT
  `0x64df4c0` cleanup, calls the drop twin `0x15e04b0` on the original
  `r12`, and resumes unwinding.
- The consumer itself has exactly one direct `E8` caller: site
  `0x1534f75` in FDE `0x1534ed0..0x1534feb` (283 bytes, not decoded).

State-machine consumer (`0x15d2fb0`):

- Entry takes a pointer-to-pointer in `rdi`: it loads `rax = [rdi]`,
  reads the flag byte `[rax]`, clears it, and requires it to have been
  1 — otherwise it takes the landing pad (drop twin, then
  `_Unwind_Resume`).
- Twice it builds a stack template (`.rodata` words `0x45a024` then
  `0x45a174`, length 4, `0x6401498` → the string
  `tokio_scheduled_observer`, the 19-byte forwarding shim `0x15ebba0`,
  twice) and calls GOT `0x64df6e8` with (`rdi` = &output, `rsi` =
  `0x439955`, `rdx` = &template), producing a triple `(rbx, r14, r15)`.
  The first iteration stages f64 1.0 at `[rsp+0x30]`, the second f64
  30.0; `[rsp+0xd0]` is zeroed each time. The format/parse call's
  semantics are not decoded.
- Each iteration allocates 168 bytes via GOT `0x64df480`, copies 168
  bytes from the staged `[rsp+0x30]` template via GOT `0x64df508`,
  and calls the worker `0x15d6730` with (`rdi` = `r14`, `rsi` = `r15`,
  `edx` = 1, `rcx` = clone, `r8` = vtable `0x64014a8`). After each
  worker call, if `rbx` is nonzero it calls GOT `0x64df4a0` with
  (`rdi` = `r14`, `rsi` = `rbx`, `edx` = 0).
- Its landing pad loads `rdi` = `0x6401228`, calls GOT `0x64df830`,
  then drops the staged template through the drop twin `0x15d9ca0`
  before resuming unwinding.

## The once-closure shim: a second route to the state-machine consumer

The caller-2 consumer's once call passes `rcx` = `0x6401200`, a static
record whose fields are `[0, 8, 8, shim `0x15d8690` (REL), consumer
`0x15d2fb0` (REL), once.rs string `0x44e31f` (REL, 76 chars:
`/rustc/.../library/std/src/sync/once.rs`), length 76, (159, 50)]`.
The shim `0x15d8690..0x15d86a2` (18 bytes) adapts a cell pointer into
the consumer's pointer-to-pointer argument and calls the consumer
directly (`E8` at `0x15d869b` — the consumer's only direct caller).
The shim itself has 0 direct `E8` callers: it is reached through the
once record. So the state-machine consumer is reachable both from its
own two `lea` sites (via the worker path) and, indirectly, through the
caller-2 consumer's once path. The once record's full semantics are not
decoded.

## The worker handoff (context, not fully decoded)

The shared worker `0x15d6730..0x15d6df5` (1,733 bytes — the worker
#183's guard gates and #185 cites) is cited as context here, not
claimed as a characterized body. Observed handoff facts only:

- It takes (`rdi`, `rsi`, `edx`, `rcx` = cloned struct, `r8` = vtable)
  and stores the (data, vtable) pair into heap task structures.
- It ends with a call to `0x15d60b0` with (string `0x469bfb`,
  length 19: `tokio_spawn_forever`, arg1, arg2, struct).
- Its two `call [rax+0x20]` sites (`0x15d6a55`, `0x15d6bf2`) run on a
  `lock cmpxchg` 0xcc→0x84 guarded singleton's `+0x10` object, not on
  the lu vtables — the lu vtables' `+0x20` word is the Location file
  pointer, not code, so those calls cannot be lu method calls.
- Three of its landing pads call the drop dispatcher `0x15dacd0` with
  (data, vtable).
- Raw `E8` census for the worker: 24 sites (the three consumer sites
  and the guard site confirmed by objdump; the rest raw byte-scan).

## The drop dispatcher and the twin drops

Drop dispatcher `0x15dacd0` takes (`rdi` = data, `rsi` = vtable):

- `rax = [rsi]` (slot 0): if nonzero, call `rax(data)` — the vtable's
  drop function.
- Then `rsi = [vtable+0x8]` (size), `rax = [vtable+0x10]` (align), a
  `tzcnt`-based `edx` computation, and a tail jump to GOT `0x64df4a0`
  (→ `0x635de30`) with (data, size, edx) — the deallocation. Its
  landing pad calls `0x15e7680` (not decoded) and resumes unwinding.
- Raw `E8` census: 25 sites, including the caller-2 consumer, three
  worker landing pads, and the guard function (those five confirmed by
  objdump).

The two vtable drop functions are the same 40-instruction template
shifted by 8 bytes throughout — matching the 168 − 160 = 8 vtable size
difference:

| | Caller-2 drop `0x15e04b0` | State-machine drop `0x15d9ca0` |
| --- | --- | --- |
| Tag bytes that must all be 3 | `[rdi+0x98]`, `[rdi+0x90]`, `[rdi+0x88]` | `[rdi+0xa0]`, `[rdi+0x98]`, `[rdi+0x90]` |
| Refcounted field (pointer) | `[rdi+0x20]`, tag byte at `+0x18` | `[rdi+0x28]`, tag byte at `+0x20` |
| Zero-count drop, tag byte nonzero | GOT `0x64dfdc8` → `0x5ce8da0` | same |
| Zero-count drop, tag byte zero | GOT `0x64dfdb8` → `0x5ce86d0` | same |
| Tail | `jmp 0x15df190` on `[rdi+0x28]` | `jmp 0x15df190` on `[rdi+0x30]` |

The tag value 3 is the "set" state from #184; the drop helpers
`0x5ce8da0`/`0x5ce86d0` are the same two #183's conversion drop path
uses, selected by the same tag byte. Each twin has exactly one direct
`E8` caller — its consumer's landing pad (`0x15d62fd` and `0x15d31a1`
respectively); their other reachability is indirect, through the
vtable slot 0 via the dispatcher. The mnemonic sequences of the two
twins are identical (verified from the pinned objdump files); only
address-dependent bytes differ.

## What this does not claim

- The Rust type/trait names of the vtables, the consumers, the worker,
  and the drop functions are not asserted.
- The final `[vtable+0x18]` method invocation for these two trait
  objects is not singled out: 4,840 raw `[reg+0x18]` indirect
  call/jump sites exist binary-wide, and none is linked to these
  vtables by a static reference. The executor that polls the spawned
  task is generic over all task types, so the method call is not
  attributable to these vtables from static references alone.
- The Q table's slot `+0x8` (from #185) is still open: the table
  address is runtime data, and no static table instance is linked to
  the coop/proceed path.
- The once record `0x6401200`'s full semantics, the format/parse call
  via GOT `0x64df6e8`, the 19-byte forwarding shim `0x15ebba0` (tail
  jump via GOT `0x64df720`), the caller-2 consumer's direct caller
  (FDE `0x1534ed0..0x1534feb`), and the worker's full body are not
  decoded.
- No gate is requested by this packet; the next question is what the
  Q table's slot `+0x8` calls, which needs a static Q-table instance
  or a coop-site Q construction trace to answer.
