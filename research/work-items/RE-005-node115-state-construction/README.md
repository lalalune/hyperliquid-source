# RE-005 node115 reader state construction and twin registration

Status: static evidence packet for one bounded RE-005 question. The
companion verifier is `tools/state_construction_static.py`;
retained exports sit beside this file and are hash-bound by
`MANIFEST.sha256`.

## Question

The field1-5 caller-arguments packet (#2433) closed with an open
question: who constructs the reader state the four caller
functions forward — the first writer of its mode (+0x0) and limit
(+0x8) fields — and through which registration are the twin
decoders `0x26e5710` / `0x5aaa460` actually invoked, given that
they have no direct callers and are reached only through the
helper calls at `0x232cd90` / `0x58251a0`? This packet answers
both halves.

## Result

Every state the #2433 call sites consume is built on a
constructor's own stack, and the mode is the constant 1 at all
twelve construction sites.

- bulk copy a (`0x2cd9710`): the chain `0x2ce1dc0` ← `0x2ceaf00`
  ← constructor `0x26fe940` forwards the state pointer unchanged
  at every hop; the constructor stores the five fields at
  `rsp+0x20` at three identical sites: mode `1` (immediate),
  limit = its entry `rcx`, cursor = entry `rsi`, remaining =
  entry `rdx`, charged `0` (immediate). Its only caller, the
  dispatcher `0x2b67e50`, loads that `rcx` from `[rbx+0x220]`.
- twin a (`0x26e5710`): `0x2e466b0` ← constructor `0x26ff210`,
  same five stores at `rsp+0x70` (sites 1–2) and `rsp+0x98`
  (site 3); mode `1`, charged `0`, limit = entry `rcx`, loaded by
  its only caller `0x2b69d20` from `[rbx+0x180]`. Site 2 is
  entered only from a pre-call dispatch branch, so its registers
  are still the entry values; at site 3 the cursor/remaining are
  carried through the earlier stages and the limit register may
  first be reloaded from an earlier stage result's `+0x28`
  field (see Boundaries). The mode and charged stores are
  immediate on every path.
- bulk copy b (`0x5968840`): `0x4e05c10` ← `0x582b520` ←
  constructor `0x5821aa0`, which builds the state at `rsp+0x18`
  from its own arguments (mode = `rcx`, limit = `r8`, cursor =
  `rsi`, remaining = `rdx`, charged `0`). Its only caller
  `0x4e483d0` passes mode = `1` (immediate at all three sites)
  and limit = `[[view+0x10]]` of its entry view; the view is
  built by `0x5860cd0` as `{+0x0: entry rsi, +0x8: entry rdx,
  +0x10: &slot holding entry rcx}`, so this limit is ultimately
  `0x5860cd0`'s entry `rcx`, forwarded by pointer.
- twin b (`0x5aaa460`): `0x5aac7c0` ← constructor `0x4e465a0`,
  which stores mode `1` (immediate), limit = `[[view+0x10]]`,
  cursor = `[view+0x0]`, remaining = `[view+0x8]`, charged `0`
  at `rsp+0x58` at three sites. The view comes from `0x58606f0`
  with the same shape, and `0x58606f0`'s entry `rcx` is loaded
  by `0x5a6a640` from `[rbx+0xa60]`.

The limit is never a constant and never the buffer length: it is
one runtime qword per spine, taken from a dispatcher context
field or forwarded by pointer through the view structs. The
charged count starts at 0 everywhere.

Twin registration: the helpers `0x232cd90` / `0x58251a0` are
578-byte codegen twins (the bodies differ only in nine 4-byte
displacement fields). Each takes `(rdi = out, rsi = state,
rdx = element decoder)`. It reads a count with the u64 reader
(copy a `0x2cd7ac0` / copy b `0x5821250`) on the state; if the
state mode is nonzero it charges `count * 0x18` against the
state — the new charged count is stored before the limit
compare, and refusal is a result with rawtag 2. It allocates
`min(count, 0xaaaa) * 0x18` bytes through the slot at
`0x64df480`, then per element refunds `0x18` from the charged
count (panicking through the slot at `0x64df848`, followed by
`ud2`, if fewer than `0x18` remain) and calls the decoder
through the saved `rdx` register with the element result buffer
and the same state. The `0x18`-byte element is copied out of the
decoder result (`+0x8`) into the vector; growth goes through
the slot at `0x64e5008`; on a decoder error the error result is
copied out and the vector is freed through the slot at
`0x64df4a0`. Success writes rawtag `0x12` and the vector triple
at `out +0x8/+0x10/+0x18`.

So the twins are invoked only through these helpers: the
wrappers `0x2dd2980` / `0x4de6210` load the twin address in
`rdx` and forward their own entry state unchanged (the pinned
prologue sequence contains no `rsi` write before the helper
call), and every function above them forwards the constructed
states unchanged. The full caller census is exact: every traced
function has precisely the direct callers listed in
`records.json`, and none of them has any rip-relative `lea`
reference.

## Trace

Spines, bottom-up from the #2433 call sites (all hops are single
direct callers; forwarding is the entry `rsi` saved to a
callee-saved register and passed on unchanged):

- bulk a: `0x2cd9710` ← `0x2ce1dc0` (3 sites, `r14`) ←
  `0x2ceaf00` (1 site, `r12`) ← `0x26fe940` (3 sites, constructs
  at `rsp+0x20`) ← `0x2b67e50` (1 site; limit = `[rbx+0x220]`).
- twin a: `0x26e5710` ← (helper `0x232cd90` via `call r14`) ←
  `0x2dd2980` (`lea` + helper call, state untouched) ←
  `0x2e466b0` (1 site, `r14`; also performs its own mode-1
  inline charge on the state, storing only the charged count)
  ← `0x26ff210` (3 sites, constructs at `rsp+0x70`/`rsp+0x98`)
  ← `0x2b69d20` (1 site; limit = `[rbx+0x180]`).
- bulk b: `0x5968840` ← `0x4e05c10` (3 sites, `r15`) ←
  `0x582b520` (1 site, `r14`) ← `0x5821aa0` (constructs at
  `rsp+0x18`, calls down at `0x5821dd9`) ← `0x4e483d0`
  (3 sites, mode = 1, limit = `[[view+0x10]]`) ← `0x5860cd0`
  (view builder; limit pointee = its entry `rcx`) ←
  `0x5a64aa0` (1 site).
- twin b: `0x5aaa460` ← (helper `0x58251a0` via `call r14`) ←
  `0x4de6210` (`lea` + helper call, state untouched) ←
  `0x5aac7c0` (1 site, `r14`) ← `0x4e465a0` (3 sites,
  constructs at `rsp+0x58`) ← `0x58606f0` (view builder;
  limit pointee = its entry `rcx`) ← `0x5a6a640` (1 site;
  that `rcx` = `[rbx+0xa60]`).

The constructors and forwarders also read the same states with
the u32/u64 readers along the way (the exact in-window reader
call sites are recorded in `records.json`), which is consistent
with the states being live from construction to the decoders.

## Boundaries

- Who writes the limit fields in the top dispatchers' context
  objects (`[rbx+0x220]`, `[rbx+0x180]`, `[rbx+0xa60]`) and the
  bulk-b top caller `0x5a64aa0`'s `rcx` argument is above the
  traced window: the four top dispatchers each have many
  callers and are recorded here by span pins only.
- At the twin-a constructor's third site, the limit register
  may hold the `+0x28` field of an earlier stage result (via
  the reloads at `0x26ff330` / `0x26ff3fd`) instead of the
  entry `rcx`; who writes that result field is inside
  `0x2e466b0`'s result construction and is not traced. The
  mode is the immediate 1 on that path as well.
- The four #2433 caller functions and the reader families
  (u32 #2412, field1-5 #2422, u64 #2300) are cited boundaries,
  not re-derived.
- The five helper slots are `R_X86_64_RELATIVE` relocations to
  unnamed internal targets; they are identified by argument
  shape only (allocation, deallocation, growth, panic,
  allocation failure). No symbol names are claimed.
- Rawtag and result values are raw bytes; which Rust enum
  variants they name is not established from these bytes.

## Files

- `records.json` — authenticated owners and frame records, the
  four construction records with forwarding chains and top
  callers, the helper mechanics, the full call census, the
  in-window reader call sites, boundaries, relocations and
  limits.
- `ctor_bulk_a.objdump.txt`, `ctor_twin_a.objdump.txt`,
  `ctor_bulk_b.objdump.txt`, `ctor_bulk_b_mode.objdump.txt`,
  `ctor_twin_b.objdump.txt`, `helper_a.objdump.txt`,
  `helper_b.objdump.txt`, `fwd_bulk_a_high.objdump.txt`,
  `fwd_bulk_a_low.objdump.txt`, `fwd_twin_a.objdump.txt`,
  `fwd_bulk_b_high.objdump.txt`, `fwd_bulk_b_low.objdump.txt`,
  `fwd_twin_b.objdump.txt`, `wrap_twin_a.objdump.txt`,
  `wrap_twin_b.objdump.txt`, `view_bulk_b.objdump.txt`,
  `view_twin_b.objdump.txt` — retained disassembly of the
  seventeen traced functions (four constructors, the bulk-b
  mode supplier, two registration helpers, six forwarders, two
  twin wrappers, two view builders).
- `frames.txt` — native readelf FDE lines for the seventeen
  functions.
- `../../tools/state_construction_static.py` — regenerator and
  verifier; `../../tests/test_state_construction_static.py` —
  regeneration, construction, census and counterfactual tests.

## Next question

Who writes the limit qwords in the top dispatchers' context
objects (`[rbx+0x220]`, `[rbx+0x180]`, `[rbx+0xa60]`) — that is,
what ultimately decides how much a constructed reader may
charge — and what does the twin-a stage result's `+0x28` field,
which can replace the entry limit at the third construction
site, contain?
