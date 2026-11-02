# RE-001: map node #94 WAL replay step 0x520ad30

Task: RE-001 (#94 function map). Bounded question: given an out status
struct, a context struct, a filename string, a fourth argument, and an
out-pointer slot, what exact sequence of entry calls, state building,
column-family filtering, single-record reading, and dispatch does node
#94's WAL replay step run, and what does it write into the out struct
and the out-pointer slot?

- Component: node #94 WAL replay step, window `0x520ad30..0x520c053`
  (4899 bytes, single FDE).
- Target release and full SHA-256: node #94, `work/hl-node-94.bin`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Claim status: observation for the argument roles, the entry-call
  register setup and their observable outputs, the state-object fields,
  the basename rule, the filter rule, the reader-construction arguments,
  the single record read (mode 0, null transform), the short/long
  dispatch at length 11, the short-record log call, the long-record
  apply and out move, the teardown rule and order, and the two-caller
  census; inference for the "WAL replay step" naming and the
  "context / state / record-state" readings (offsets and uses are
  pinned, source-level names are not); unresolved for the entry virtual
  calls' internals, the CF predicate's internals, the singleton's
  meaning, the -0x7f/-0x7d teardown flags' producers, the formatted
  status text, and every callee's internals beyond its pinned contract.
- Scope included: the whole replay-step function, its two direct
  callers (census only), and the call contracts of the reader, the
  detail builder, the formatter, the log dispatcher, the record-state
  constructor/apply/reset/head-reader, and the singleton getter.
  Scope excluded: the internals of every callee, the behavior of the
  two callers beyond their call setup, and the enclosing driver
  `0x520c120..0x520d31d`.

## Answer

`replay_step(out, ctx, filename, arg4, arg5_out)` returns void. The
phases below run in order; shared_ptr-style traffic (increment on
copy, decrement with destroy-on-last-release, atomic vs plain variant
selected by a global flag) is described generically, not byte-pinned,
because the function inlines both variants at many sites.

1. Entry: two vtable-dispatched calls on the context +0xa8 object.
   The first (vtable +0x188) takes the -0x210 stack slot, the +0xa8
   object, and context + 8; afterwards the -0x210/-0x208 slots hold
   the (begin, end) element vector walked below. The second (vtable
   +0xa8) takes the -0x220 scratch, the +0xa8 object, the filename
   string, the -0x210 slot, the -0x268 slot, and 0; it fills the
   -0x220 scratch status, which is copied into `out` (u32 at +0,
   u16 at +4, pointer at +8). The -0x268 slot afterwards holds an
   object released at teardown. Both calls' internals are contracts.
2. State object (0xa8 bytes, operator new): +0 holds the address of
   its own +0x10 field; +0x10 is a copy of the filename string;
   +0x20 is 16 bytes from context +0x158/+0x160; +0x30 is the static
   base 0x575f690 + 0x10; +0x48 is 16 bytes copied from state +0x20;
   +0x58 is the first qword of the singleton from 0x5242050;
   +0x60/+0x68/+0x70 is the basename string (inline buffer at +0x70,
   heap arm over 15 bytes, NUL at buffer + length); +0x80..+0x98
   is a zeroed element vector.
3. Basename: `find_last_of("/\\")` (charset at 0x1f3693, count 2)
   on the filename; the basename is the substring after the last
   separator. If position + 1 exceeds the length, the substr
   out-of-range throw fires (format at 0x7d66e0).
4. Filter: walk the entry vector (stride 0x10). Keep an element
   only when its vtable +0x140 method differs from 0x4fa4610 AND
   that method, called on the element, returns nonzero. Kept pairs
   go to the state +0x88 vector in walk order (grown through
   0x4fa5eb0 when full). Afterwards every input element is
   released and the input vector buffer is freed.
5. Gate: if the byte at `out` +0 is nonzero, jump straight to
   state teardown (step 9's state part); the reader is never
   constructed and arg5 is never written.
6. Reader: copy 16 bytes from the object at context +0, offset
   +0x30, into scratch -0x220; its second qword is the log-call
   logger; its byte at +3, xored with 1, is the inverted flag.
   Construct the WAL reader 0x51632f0 with (reader, options at
   &-0x220, state slot at &-0x260 holding the state pointer,
   pair at &-0x210 holding {0x575be38, context +0xa0}, 1, arg4),
   then release the reader's -0x218 shared object.
7. Read one logical record: 0x51618e0(reader, out slice at -0x250
   starting {pointer 0x1e629b, length 0}, accumulator string at
   -0x170 with inline buffer at -0x160 and length 0, mode 0, null
   transform). Success is a nonzero return; the record length is
   the out slice length at -0x248.
8. Dispatch on the record length:
   - Length <= 11 (short path): build a status with the detail
     builder 0x542f040 (code 2, message "log record too small",
     20 bytes) and render it with the formatter 0x542f8a0 into a
     string; log at level 2 through 0x522e770 with format
     "[%s:461] [WalManager] %s%s: dropping %d bytes; %s",
     file "db/wal_manager.cc", prefix "(ignoring error) " when
     the inverted flag is set else the empty string, the filename
     pointer, the record length, and the formatted string pointer.
     The formatted string buffer is then freed. When the `out`
     byte is 0, the status field copy runs (u16 from scratch
     -0x220 to out +0; u8 from -0x21e to out +2; u16 from -0x21d
     to out +3; u8 from -0x21b to out +5; pointer from -0x218
     to out +8, freeing the old out +8 buffer, copying the
     record string into it through 0x542efe0 when the scratch
     pointer is nonzero). When the `out` byte is nonzero, the
     copy is skipped and the scratch pointer buffer is freed.
     Control then reaches the teardown rule.
   - Length > 11 (long path): construct a record-state object
     with 0x5219960 (all zero arguments) and apply the record
     with 0x521cbf0 (replaces the record-state +0x40 string with
     the record bytes, sets record-state +0x24 to 1, zeroes the
     -0x220 scratch). Move the zeroed scratch into `out` (u32
     at +0, u16 at +4, pointer at +8, freeing the old out +8
     buffer; the scratch fields are zeroed as moved). Because
     `out` +0 is now 0, store 0x521b610's value — the first qword
     of the record-state +0x40 string data, i.e. the first 8
     bytes of the record — into arg5. Reset the record-state
     object with 0x52178b0, then run reader destroy and state
     teardown (the teardown rule is skipped on this path).
   - Read returns 0: no detail, format, log, or apply; control
     reaches the teardown rule directly.
9. Teardown rule (all paths except the gate path and the long
   path): arg5 is 1 if and only if the `out` byte read at rule
   time is 0 AND the flag byte at -0x7f is 0 AND the flag byte
   at -0x7d is nonzero; otherwise arg5 is 0. On the short path
   the byte read here is the POST-copy byte: the status field
   copy overwrites `out` +0 with the scratch u16's low byte, so
   a nonzero scratch low byte forces 0 even when both flags are
   set for 1. The producers of the -0x7f/-0x7d flags are not
   pinned. Teardown order: accumulator string disposed
   (heap buffer freed when the stored pointer differs from the
   saved inline-buffer address); WAL reader destructor 0x5162ed0;
   handle dispose stub 0x5160f20 on the -0x210 slot object;
   state teardown (state vector elements released in order,
   state +0x50 sub-object released, state +0x40 virtual call at
   vtable +0x8, state +0x28 sub-object released, state +0x00
   virtual call at vtable +0x8, state object freed with size
   0xa8, state +0x30 restored to the static base + 0x10);
   trailing object at -0x268 released via vtable +0x8 when
   nonzero; canary check; return void.

## Notes on the evidence

- Instruction-level detail lives only in the raw disassembly
  excerpts (`window.txt`, `caller-site-1.txt`,
  `caller-site-2.txt`), kept verbatim and whole-function. The
  JSON in this packet holds semantic records only: no
  per-instruction mnemonic list. `endbr64` and the other
  mnemonics in the excerpts are genuine instructions present in
  the target binary, not placeholders.
- `verify.py` re-runs objdump from the repository root and checks
  every excerpt byte-for-byte, checks the pinned rodata strings,
  samples three instructions against the raw binary, and
  reproduces the caller census.
- `export_excerpts.py` regenerates the excerpts. Run it from the
  repository root: the objdump header spells the binary path
  exactly as given on the command line, so the relative path
  matters.
