# Static model and proof boundary

This packet translates a fixed decoded instruction sequence into mathematical
expressions. It does not execute machine code or claim a verified x86 ISA
implementation. The authenticated input, pinned decoder, narrow transfer
functions, solver, Python and analyst interpretation are trusted. GNU exports
provide a second decoder view for review; they are not an automatic ISA proof.

## Admission

The complete input's SHA-256, ELF class, machine and endianness are checked
before analysis. Each of four body hashes is pinned independently. A unique
FDE at that entry must have the exact selected extent. Executable-section and
PT_LOAD mappings must agree. Linear decoding must consume the entire extent;
unrecognized instructions or unsupported addressing fail. The next FDE and
INT3 gap are recorded. Raw CIE/FDE bytes retain the original unwind evidence.
Assertions are explicit exceptions and survive `python -O`.

FDE/CFG closure is scoped to these bodies and the stated normal-path contract.
The caller's failure tail is retained. The only branch must target the admitted
stack-check failure PLT call. Its path condition is checked independently for
each caller; the analysis does not silently assume the branch away. The normal
return is accepted only immediately before that failure tail. Helpers must end
at their final return. No indirect call, computed jump, loop, alternate entry,
RIP-relative data operand or undocumented instruction is supported.

## Registers, flags and memory

- Integer data registers are 64-bit bitvectors. A 32-bit destination zeroes
  its upper 32 bits. An 8-bit write preserves the other 56 bits. `movzx` is
  explicit zero extension. XMM values are 128-bit bitvectors.
- Integer add/subtract/multiply/negate wrap at the operand width. Right shifts
  are logical, and shift counts use x86's 64-/32-bit count masks. Observed
  shift counts are nonzero. Only the live ZF and unsigned CF consumers are
  modeled; unsupported flag dependence is rejected. `sete`/`setb` produce
  one byte from those flags. No floating-point arithmetic is involved.
- Input, output, stack and TLS are disjoint abstract pointer regions. Input
  has exactly ten symbolic u64 slots; reads of uninitialized slots fail. TLS
  offset `0x28` is one stable symbolic canary. Output/stack writes are tracked.
  The memory model permits qword and paired-qword vector accesses only.
- Pointers cannot become arbitrary numeric data or be partially overwritten.
  Constant stack-pointer add/subtract and displacement addressing are allowed.
  Vector copies split/concatenate little-endian qwords. This models their
  values, not alignment faults, speculative effects or access timing.
- At a call the abstract stack gains the known return address. The decoded
  helper is expanded with the same registers/memory and a new stack offset.
  Its stack balance and untouched return address are checked. No function
  summary is used in place of its instructions.
- Every normal return must restore RSP. The six callee-saved GPRs are checked
  by universal disequality queries against their unconstrained initial values.
  Caller-saved GPRs, flags and XMM values have no preservation claim.

Assumptions: valid readable input and TLS, valid writable output/stack,
appropriate entry stack alignment for the vector instructions, valid ordinary
return setup, stable TLS, and no asynchronous memory mutation or fault. Input,
output and live/saved stack memory do not alias. No exception, signal, unwinder,
red-zone, invalid-pointer, malicious-stack or overlap behavior is proved.

## Statements checked

Each caller has an unconstrained ten-u64 input, unconstrained initial data
registers and an unconstrained canary. Its lifted output is compared with a
separately written five-limb wrapping-arithmetic normalization and packing
specification. Disagreement must be UNSAT for all eight output words jointly.
The inlined field arithmetic is therefore checked as well as the helper path.

Separate 320-bit expressions prove packing preserves the bounded radix value
and that magnitude-64 normalization has its exact quotient identity and range.
All five-u64 weighted input values fit in fewer than 273 bits; possible
quotient products fit below 2^273. Thus the 320-bit identity cannot conceal a
large-integer wrap. The finite integer oracle uses Python integers and `% p`.
No query says that the actual callers establish the input bounds.

The two encoded shift controls alter decoded bytes and compare against the
unchanged specification. Their fixed input has limb 1 equal to one and all
other limbs zero. The expected first output qword is `1<<52`; the counterfactual
is `1<<53`. This checks that the path from a decoded immediate through symbolic
register/memory handling to output comparison detects a real dataflow error.
It does not certify every transfer function or solver implementation.

The result is conditional on this reviewed static model. It is not captured
runtime evidence, a machine-checked ISA semantics theorem, a compiler proof or
a claim that either body is a safe general-purpose cryptographic API.
