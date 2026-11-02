# Static stack-policy and worker-handoff argument

This argument concerns the two complete node94 FDEs identified in README.md.
It assumes valid ordinary pointer/length arguments, stable readable bytes from
the environment/text helpers, successful allocations, normal helper returns,
and the x86-64 calling convention. Source types, exceptional edges, concurrent
external mutation and operating-system success are not supplied by those
assumptions. This is static disassembly reasoning, not target execution.

## Stack-size precedence and cache representation

The constructor preserves incoming RCX as the explicit size. At `0x14482a5`
it tests **only bit 0 of DL**. If set, it goes directly to `0x144835b` with
that size; it does not read the stack-size cache or environment on this path.
Thus zero is a possible explicit request, not an instruction-level refusal.

Otherwise slot `0x576f5b0` resolves to the cache word at `0x5788588`.
A nonzero cached word C is decoded as C-1 and used immediately. Zero enters
the environment request at `0x14482c6`; that request passes the 14 exact bytes
`RUST_MIN_STACK` to `0x4edcc10`. No host environment is read by this packet.

The first returned word equal to `0x8000000000000000` selects the default
`0x200000` (2,097,152). Otherwise the returned pointer/length is sent to
`0x157a200`. A first DWORD tag of 1 or a returned length of zero also selects
the default. The selected nonempty bytes are parsed below. This proves the
caller decisions on these raw helper outcomes; the complete environment,
text-validation and allocation contracts are outside the selected bodies.

On a normally returning uncached path, `0x1448352..0x144835b` writes
`(selected_size + 1) mod 2^64` to the cache. Consequently:

| Selected value | Stored cache word | Later nonexplicit call |
| --- | --- | --- |
| 0 | 1 | Reuses 0 |
| 2,097,152 default | 2,097,153 | Reuses default |
| 2^64-2 | 2^64-1 | Reuses 2^64-2 |
| 2^64-1 | 0 | Takes the environment-request path again |

The maximum parseable value is **not** rejected solely to protect this cache
sentinel. No general once-only environment-read guarantee follows. These are
observed ordinary load/store instructions, not proof of a race-free cache.

## Accepted decimal text and overflow

For a helper-supplied stable valid nonempty span, the result relation is:
optional one leading ASCII `+`, followed by at least one ASCII digit, with
mathematical value <= 2^64-1. Leading zeros are accepted. Negative signs,
whitespace, trailing characters and any nondigit select the default; no trim
or sign negation occurs. The argument is from these exact branches:

1. At `0x144831e..0x1448339`, a one-byte `+` or `-` goes to the default.
   For other one-byte text or any longer text, `0x14485d1..0x14485e5`
   advances the pointer and reduces the count by one iff the first byte is
   `+`. An initial `-` in longer text is left in the digit stream.
2. The remaining digit count is compared unsigned with 17 at `0x14485ee`.
   Counts 1..16 use the short loop. Its byte classifier computes
   `(zero_extended_byte - 48) mod 2^32` and rejects unsigned results above 9.
   The LEAs update accumulator A to 10*A+d. Since 10^16-1 < 2^64, every
   valid prefix of these lengths fits without a separate overflow check.
3. Counts >=17 use `0x1448644..0x144867d`. MUL by 10 is followed by JO;
   unsigned MUL sets OF exactly when its high half is nonzero. The addition
   then saves carry in AL before the digit-range comparison changes flags.
   Both multiplication overflow and addition carry select the default, as
   does an invalid digit. The loop ends after the declared count.
4. Accepted values rejoin the buffer cleanup and cache write. The zero-count
   arm at `0x1448682` is retained but is not a claimed acceptance of empty
   text: ordinary empty input and a lone `+` were rejected earlier.

For q=floor((2^64-1)/10), the checked update fits iff A<q or
(A=q and d<=5). This supplies the boundary proof for the long loop; arbitrary
leading zeros do not force rejection. For example `18446744073709551615`
fits and encodes cache zero; `18446744073709551616` selects the default.
`+0` and `0000` select zero. These examples are consequences of the static
argument, not executed target fixtures.

`arithmetic.py` checks the byte classifier for all 256 byte values, the 16
short-length bounds, 60 checked-prefix/digit pairs, 4,101 cache encodings and
nine decimal boundaries using arbitrary-precision arithmetic. It does not
implement the target parser or interpret captured instructions. The loops,
branches and constants are separately bound to actual captured bytes.

## Construction and result projection

The next stage obtains an identifier with LOCK CMPXCHG on `0x5788580`,
retrying on comparison failure. An observed old value of 2^64-1 requests
`0x4eeb8a0` instead of incrementing it. This binds local atomic arithmetic,
not a whole-program uniqueness or concurrency theorem. The optional name
conversion and ownership helpers remain explicit boundaries.

On the allocation-success path, let M be the first 48-byte allocation,
J the second 48-byte allocation, W the 40-byte allocation, and E the final
24-byte allocation. Their relevant construction stores are:

| Object | Observed stores / relation |
| --- | --- |
| M | First two qwords initialized to 1; identifier at +0x10; name-conversion pair at +0x18/+0x20; zero DWORD at +0x28 |
| J | First two qwords initialized to 1; incoming R9 at +0x10; zero qword at +0x18 |
| W | First 32 bytes copied from the hook record; J at +0x20 |
| E | M at +0; W at +8; table 0x566a860 at +0x10 |

The initial J copy also includes two payload words that this body has not
initialized. Do not describe the complete 48-byte allocation as zeroed or
fully initialized. The zero tag and later conditional use are observed
separately. Reference increments and guarded slow release calls are retained;
source-level Arc/JoinHandle ownership has not been independently recovered.

The hook record is selected by the low byte of incoming R8. Nonzero supplies
words `(0,8,0,0)`; zero requests `0x4eedf00` with an output record and M's
local pointer slot. W copies the resulting 32 bytes on either path. This is
a request/byte-copy relation, not a claim about framework hook semantics.

At `0x1448555`, the selected stack size is passed in RDI and E in RSI to
slot `0x576f5d0 -> 0x4ee4ab0`. The shared native adapter and native entry are
already studied in PR #1640; they are not newly recovered or included in this
packet's body denominator. Here the new constructor's result test is exactly
`TEST AL,1`, not a generic AL!=0 test:

- Bit 0 set: write output+0=0 and output+8=native RDX; output+16 is not
  written on this normal failure route. Release the local J and M references
  under their zero-count guards, then return the output pointer in RAX.
- Bit 0 clear: write `(M,J,native RDX)` to output+0,+8,+16 and return the output
  pointer. This is the handle projection consumed by the earlier #1409 path.

No native thread is created by the reproducer. The actual size accepted by the
OS, stack rounding, scheduling, allocation errors and native result meanings
remain dependent on the shared adapter and external environment. Repeating
#1640's native minimum-size/retry recovery is explicitly out of this scope.

## Fixed worker callback and completion words

Table `0x566a860` has a RELATIVE drop entry `0x14529f0`, size 40, alignment 8,
and a RELATIVE callable entry `0x1451a90` at +24. These bind the constructor's
40-byte W to the selected callback. The native envelope consumer is prior
#1640 context, not a new function-recovery claim here.

The complete callback `0x1451a90..0x1451bed` performs two ordered requests on
its normal path:

1. Copy W[0..32] to a stack record and call `0x13ffc40` through `0x576f028`
   with that record pointer.
2. Call fixed target `0x1400e90` through `0x576ef58`.

It then loads J from W+0x20. If J+0x18 is nonzero and J+0x20 is nonzero,
the previous payload may be destroyed through its table's first word, then
released according to that table's size/alignment words. The normal completion
stores J+0x18=1 and J+0x20=0, stores the live R15 word at J+0x28, and decrements
J's first qword with a guarded call to `0x4f581b0`. **R15 is not initialized on
this normal path**, so this is not a promise of a zero second payload word.
The packet preserves raw stores rather than inventing a completely initialized
Rust Result value or a worker return value.

The path at `0x1451bad` requests conversion through `0x576e718`, assigns its
RAX/RDX to R14/R15, adjusts global/TLS counters and rejoins the completion
stores. Its bytes are retained, but LSDA call-site/type/action tables are not
decoded here. Therefore no assertion is made that every worker exception
selects it, or that arbitrary cleanup cannot unwind. The first helper, fixed
work target, drop implementation and error-payload contracts remain open.
The worker's application purpose is not inferred merely from the callback.

## Evidence scope

Both entire FDE extents, including exceptional cleanup, are retained. GNU
and LLVM agree on all 1,805 bytes and 442 instruction starts; readelf agrees
on FDE headers. Only literal LOCK prefix rows printed separately by LLVM are
joined; no bytes or operands are masked. All local branch destinations resolve
to decoded instruction boundaries. Every explicit call is recorded, including
qualified dynamic payload-destructor and PLT unwind boundaries.

The `.text` E8 and RIP-relative FF15/FF25 census finds constructor calls at
`0x1487403` and `0x14b8988`, each qualified by decoding its full owning FDE.
There is no RELATIVE pointer to the constructor; `0x566a878` is the sole
RELATIVE pointer to this callback. Arbitrary indirect calls, reachability,
full helper closure, cross-release behavior and runtime equivalence remain open.
