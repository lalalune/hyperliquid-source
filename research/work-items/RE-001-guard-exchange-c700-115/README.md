# RE-001: map node #115 guard value-exchange chain 0x607c700/0x607c720 with its core 0x607c3b0, exchange 0x6078810 and gated getter 0x6078650

## Bounded question

What do the guard helpers that RE-001-element-prepare-115 left by
contract actually compute? That packet pinned the acquire/release
pairing at its call sites (acquire with the constant 9, release of
the same stack slot, release again on the unwind path) but recorded
the internals of 0x607c700/0x607c720 and their helper at
0x607c3b0/0x6078810 as NOT claimed. This packet pins the whole chain
end to end, including the one callee that closes it, the gated
TLS-object getter 0x6078650: the two gates, the atomic exchange,
what the acquire wrapper stores into the caller's slot, what the
release wrapper returns, and every caller of the two wrappers.

## Windows

- Acquire wrapper: 0x607c700..0x607c713 (19 bytes), FDE at
  .eh_frame offset 0x36a184, length 0x18, CIE 0.
- Release wrapper: 0x607c720..0x607c734 (20 bytes), FDE at
  .eh_frame offset 0x75c39c, length 0x18, CIE 0x730230
  (augmentation data present; not decoded — the window has no
  landing pad and its only call targets the core).
- Exchange core: 0x607c3b0..0x607c3e4 (52 bytes), FDE at .eh_frame
  offset 0x369fb8, length 0x1c, CIE 0.
- Exchange: 0x6078810..0x607882c (28 bytes), FDE at .eh_frame
  offset 0x369d00, length 0x18, CIE 0.
- Gated getter: 0x6078650..0x607867e (46 bytes), FDE at .eh_frame
  offset 0x369bdc, length 0x14, CIE 0.
- Artifact: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.

## Semantics (literal)

Let TP be the thread pointer (the %fs:0 value). The chain exchanges
one 32-bit value with a dword field of a per-thread object, under
two gates. No window calls anything outside the chain; there are
no PLT calls.

Gated getter 0x6078650 (no arguments used, returns a pointer or 0):

1. obj = the qword at TP - 0x38.
2. If obj == 0, return 0.
3. If the byte at obj + 0x00 == 0, return 0.
4. Otherwise return obj. It reads nothing else and writes nothing.

Exchange 0x6078810 (value in esi; rdi is forwarded to the getter,
which ignores it):

1. obj = getter() (call at 0x6078817).
2. If obj == 0, return 0 and write nothing.
3. Otherwise swap the value with the dword at obj + 0x30 (xchg at
   0x6078823; an xchg against a memory operand is always locked)
   and return the previous dword.

Exchange core 0x607c3b0 (value in edi):

1. gate = the qword at TP - 0x30.
2. If gate == 0, return 0; the object is not read and nothing is
   written.
3. Otherwise tail-jump (at 0x607c3d2) to the exchange with
   rdi = gate and esi = value. The gate qword is never
   dereferenced by the core or by the exchange.

Acquire wrapper 0x607c700 (slot in rdi, value in esi): stores the
core's result into the dword at [slot]. The stored dword is the
value the exchange displaced from obj + 0x30, or 0 when either
gate is closed.

Release wrapper 0x607c720 (slot in rdi): returns the core's result
for the dword loaded from [slot]. The slot itself is not written.

Pairing consequence, as written: with both gates open,
acquire(slot, v) followed by release(slot) restores obj + 0x30 to
its pre-acquire value, and the release returns v. With either gate
closed, the acquire stores 0 into the slot and neither wrapper
ever touches the object's field.

## Callers (real e8 calls, confirmed from their containing FDE
starts; only the call sites, the slot setup immediately preceding
the acquire calls, and the return-consumption check after the
release calls are claimed — full table in records.json)

- Acquire 0x607c700: 11 direct calls. At every traced site the
  slot is a stack slot whose address is formed by an lea
  immediately before the call. The value is traced at two sites:
  9 at 0x5f13343 (element prepare, RE-001-element-prepare-115) and
  5 at 0x5e00207 (immediate mov esi, 5).
- Release 0x607c720: 22 direct calls, including the element
  prepare normal-exit call at 0x5f133a7 and its unwind-cleanup
  call at 0x5f132e9. At all 22 sites the return value is not
  consumed: the instruction after the call does not read eax (in
  20 cases it reloads the qword the caller keeps in its
  stack-canary slot; in 2 cases it continues with an unrelated
  load or compare).
- Core 0x607c3b0: exactly 2 direct calls, both in-window
  (0x607c70a, 0x607c72a).
- Exchange 0x6078810: no direct calls; reached only by the core's
  tail jump at 0x607c3d2.
- Getter 0x6078650: 8 direct calls — the in-chain call at
  0x6078817 plus seven calls in neighbouring small wrappers
  (0x6078680, 0x60786b0, 0x60786d0, 0x6078710, 0x6078740,
  0x6078760, 0x60787b0), whose internals are not claimed here.

## Census (whole-file scan, see census.py)

- 0x607c700: 11 direct calls (listed in records.json); 0 tail
  jumps, 0 qword hits, 0 RELATIVE addends.
- 0x607c720: 22 direct calls; 0 tail jumps, 0 qword hits,
  0 RELATIVE addends.
- 0x607c3b0: 2 direct calls, both in-window; 0 tail jumps,
  0 qword hits, 0 RELATIVE addends.
- 0x6078810: 0 direct calls; 1 tail jump (0x607c3d2, in-window);
  0 qword hits, 0 RELATIVE addends.
- 0x6078650: 8 direct calls (1 in-chain, 7 in neighbouring
  wrappers); 0 tail jumps, 0 qword hits, 0 RELATIVE addends.

## Evidence notes

- The packet's JSON (records.json) holds semantic records only.
  All instruction-level detail lives in the whole-function
  verbatim excerpts function_0x607c700.txt, function_0x607c720.txt,
  function_0x607c3b0.txt, function_0x6078810.txt and
  function_0x6078650.txt, produced by running, from the repository
  root: `objdump -d --start-address=<start>
  --stop-address=<end> work/hl-node-115.bin` (see
  export_excerpts.py; running objdump from the repo root with the
  canonical relative path keeps the header byte-identical).
- Mnemonics such as `endbr64` in the excerpts are genuine
  instructions present in the target binary, not placeholders:
  verify.py checks sampled instruction bytes against the raw
  binary, and the excerpts regenerate byte-for-byte from a fresh
  objdump run.
- No window uses the %fs:0x28 stack canary. The only %fs accesses
  are the thread-pointer loads (mov %fs:0x0,%rax) in the core and
  the getter. The nopw at 0x607c3d7..0x607c3e0 inside the core
  window is alignment padding between the tail jump and the
  gate-closed return; it executes on no path.

## Model and tests

- tools/guard_exchange_c700_115.py implements the semantics
  above: the two gates, the gated getter, the exchange, the core,
  and the acquire/release wrappers over an explicit thread-state
  dict and caller slot dicts.
- tests/test_guard_exchange_c700_115.py covers the open-gate
  acquire/release round trip (the field is restored and the
  release returns the acquired constant), each closed gate
  separately (gate qword 0, object slot 0, flag byte 0 — the
  acquire stores 0 and the field is never touched), a nested
  two-guard sequence restoring in LIFO order, sequential
  exchanges, the exchange's displaced-value returns, the model
  range guards, and the packet records.

## Unknowns

- Names/meanings of the two thread-pointer slots (the gate qword
  at TP - 0x30 and the object qword at TP - 0x38), of the object,
  of its flag byte at + 0x00 and of the exchanged dword at
  + 0x30; what domain value the exchange carries (the two traced
  acquire callers pass the small constants 9 and 5).
- What the gate qword at TP - 0x30 identifies: it is forwarded to
  the exchange as its first argument but is never dereferenced
  anywhere in the chain.
- Caller internals beyond the call sites, the slot setup
  immediately preceding the acquire calls, and the
  return-consumption check after the release calls.
- Internals of the seven neighbouring wrappers that call the
  getter (0x6078680, 0x60786b0, 0x60786d0, 0x6078710, 0x6078740,
  0x6078760, 0x60787b0): they form a visible sibling family
  around the same gated object and are not claimed here.
- Whether any of the five windows is reached through indirect
  branches beyond the scanned census is not claimed; the census
  covers direct calls, tail jumps, qword references, and
  RELATIVE relocations only.
