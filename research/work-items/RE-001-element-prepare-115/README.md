# RE-001: map node #115 element prepare 0x5f13310 with its two callers and per-element callee

## Bounded question

What does the element-prepare function at 0x5f13310 do to each element
of a two-array collection, and what do its two callers pass it? This
packet pins the whole function end to end — not a lone-window fragment:
the guard acquire/release pairing, the count formula, the two-array
element selection, the per-element zero store and prepare call, the
holder counter and ready byte, the two confirmed callers, and the
unwind cleanup that releases the guard when the function exits by
exception.

## Windows

- Element prepare: 0x5f13310..0x5f133da (202 bytes), FDE at .eh_frame
  offset 0x745ed4, length 0x44, CIE 0x730230 (LSDA augmentation
  present; the call-site table is not decoded).
- Unwind cleanup: 0x5f132e6..0x5f1330b (37 bytes), FDE at .eh_frame
  offset 0x745f1c, length 0x20, CIE 0x730230. The in-function landing
  pad at 0x5f133ce moves the exception value to rbx and jumps here.
- Artifact: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.

## Semantics (literal)

The function takes a holder (rdi) and a collection (rsi). The holder
carries a ready byte at + 0x00 and a signed 32-bit counter at + 0x10.
The collection carries a qword at + 0x00, a first element-array pointer
at + 0x48, a second element-array begin pointer at + 0x50, and a second
element-array end pointer at + 0x58.

Guard:

1. On entry it calls 0x607c700 with (guard slot, 9), where the guard
   slot is the 4-byte slot at rsp + 4 (the stack canary sits at
   rsp + 8).
2. On normal exit it calls 0x607c720 with (guard slot). On unwind, the
   landing pad at 0x5f133ce jumps to 0x5f132e6, which calls 0x607c720
   with the same slot, checks the saved canary, and resumes the unwind
   with the original exception value. The guard helpers' underlying
   mechanism is by contract only (see Unknowns).

Count and element selection:

1. total = arithmetic_shift_right(second_end - second_begin, 3) +
   qword_at(collection + 0x00), computed in 64-bit wrapping arithmetic
   exactly as written (subtraction, then sar $3, then add).
2. total == 0 skips the loop entirely.
3. Otherwise the loop runs index 0, 1, ... until the index reaches
   total. Index i < 8 reads element i from the first array
   (first_array[i]); index i >= 8 reads element i - 8 from the second
   array (second_begin + i * 8 - 0x40, i.e. second_array[i - 8]).

Per element, in order:

1. Store two zero bytes at element + 0xa88 (a 16-bit zero store).
2. Call 0x5f54ee0 with element + 0xa98 (by contract only).
3. Increment the holder counter at + 0x10 by 1 (32-bit).

After the loop (or at once when total == 0):

1. Store byte 1 at holder + 0x00 (the ready flag).
2. Release the guard (0x607c720), check the canary, and return void.
   The function returns no value; its observable effects are the
   per-element zero stores and prepare calls, the holder counter, and
   the holder ready byte.

Callers (both real e8 calls, confirmed from their containing FDE
starts; only the call sites and the argument offsets below are
claimed, not the callers' internals):

- 0x5de6e58, in 0x5de44c0..0x5de7ed0: holder = an element pointer
  plus 0x8f0, collection = another element pointer plus 0x570.
- 0x5ed6895, in 0x5ed5df0..0x5ed88be: holder = the qword at object
  + 0x48 plus 0x8f0, collection = the object plus 0x570.

## Census (whole-file scan, see census.py)

- 0x5f13310: exactly 2 direct calls, at 0x5de6e58 and 0x5ed6895;
  0 tail jumps, 0 qword hits, 0 RELATIVE addends.
- 0x5f54ee0: exactly 5 direct calls, at 0x5f1337c (in-window) and
  0x5f1442c, 0x5f160d5, 0x5f161fd, 0x5f5c1f6 (callers not read);
  0 tail jumps, 0 qword hits, 0 RELATIVE addends.
- Guard acquire 0x607c700: 11 direct calls including the in-window
  0x5f13343; guard release 0x607c720: 22 direct calls including the
  in-window 0x5f133a7 and the cleanup 0x5f132e9.

## Evidence notes

- The packet's JSON (records.json) holds semantic records only. All
  instruction-level detail lives in the whole-function verbatim excerpts
  function_0x5f13310.txt and function_0x5f132e6.txt, produced by
  running, from the repository root:
  `objdump -d --start-address=<start> --stop-address=<end> work/hl-node-115.bin`
  (see export_excerpts.py; running objdump from the repo root with the
  canonical relative path keeps the header byte-identical).
- Mnemonics such as `endbr64` in the excerpts are genuine instructions
  present in the target binary, not placeholders: verify.py checks sampled
  instruction bytes against the raw binary, and the excerpts regenerate
  byte-for-byte from a fresh objdump run.
- The main window's only PLT call is to __stack_chk_fail@plt on the
  canary-failure arm; the cleanup window's PLT calls are to
  _Unwind_Resume@plt and __stack_chk_fail@plt. Both windows use the
  %fs:0x28 stack canary.

## Model and tests

- tools/element_prepare_115.py implements the semantics above: the
  count formula, the two-array selection, the per-element zero store
  (recorded on the element dict) and prepare callback standing in for
  0x5f54ee0, the holder counter and ready byte, and the guard
  acquire/release pairing (recorded, by contract).
- tests/test_element_prepare_115.py covers the empty total, the
  first-array-only run, the second-array run past index 7, the exact
  index-8 boundary, call order, the counter and ready byte, the
  guard pairing, a negative total raising instead of looping forever,
  and the packet records.

## Unknowns

- The domain meaning of the collection fields (the qword at + 0x00,
  the two element arrays, and what an element is) is not claimed;
  only the count formula and the selection rule are. Note the literal
  consequence: a qword at + 0x00 other than 8 would shift which
  second-array slots the loop reaches, exactly as the code is written.
- The internals of 0x5f54ee0 are NOT claimed: it is modelled by
  contract only (called once per element with element + 0xa98 after
  the 0xa88 zero store). A first read shows a large reset/clear body.
- The internals of the guard helpers 0x607c700/0x607c720 and their
  helper at 0x607c3b0/0x6078810 are NOT claimed; only the
  acquire-with-9 / release pairing and the unwind release are.
- Whether 0x5f13310 is reached through indirect branches beyond the
  scanned census is not claimed; the census covers direct calls, tail
  jumps, qword references, and RELATIVE relocations only.
- A negative total never equals a rising non-negative index, so the
  binary would not terminate that loop; the model raises instead of
  looping forever, which is a stated boundary control, not a binary
  behavior.
