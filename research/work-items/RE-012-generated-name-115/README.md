# RE-012: node #115 generated output name: source, formatting and byte transform

Target Linux x86-64 node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base main `05bc2de303c05525b71e7e257426e741bc66a390`. Bounded RE-012
startup/filesystem helper question; foundation utility with a selected output
caller. New research/scripts/docs MIT; captured bytes retain their original
rights. No inferred unlicensed source copied.

## Gap and result

The existing utility/output packets bind `0x64e0978 -> 0x1501360` but leave
what name it constructs opaque. This packet resolves the complete 912-byte
function `0x1501360..0x15016f0`: it retains a TLS random state, draws one
buffered u32, obtains a 12-byte date/time-like value, formats its display plus
an underscore plus unsigned decimal u32, then allocates an equally long output
and replaces exactly ASCII spaces with underscores. It releases the formatted
temporary and the retained TLS reference on the normal and applicable unwind
paths. The routine itself contains no filesystem write or network operation.
The selected caller at `0x15024cf` consumes its returned three-word buffer;
this packet does not recover that caller's entire output operation.

Before: an opaque helper edge. After: explicit input provenance, two actual
format argument records and order, exact compact template, byte-preserving
transform, allocation/length branches and cleanup, with preserved external
boundaries. This is substantive static recovery, not a full RNG, clock or
formatter implementation. No new Rust implementation is claimed.

## Retained windows and bindings

`scope.json` labels the primary function separately from 14 supporting contexts.
`records.json` binds all 15 exact FDEs and full instruction bodies: 7,617 bytes,
1,888 instructions total. Only 912 bytes are the primary-name function; the
6,705 context bytes include already studied generic formatting runtime and
shared dependency helpers, and do not constitute new first-party-byte credit.
Raw GNU/LLVM instruction partitions agree with Capstone, while GNU readelf
independently confirms FDE extents. No operand masks are used.

| Role | ELF virtual interval |
| --- | --- |
| Primary generated-name function | `0x1501360..0x15016f0` |
| Selected real caller context | `0x15024a0..0x15026d1` |
| 12-byte time producer | `0x1629690..0x1629795` |
| Date/time display adapter | `0x156d7f0..0x156d838` |
| Date display context | `0x1628bc0..0x1628dcf` |
| Time display context | `0x162a760..0x162a996` |
| Unsigned u32 decimal formatter | `0x1688a20..0x1688b1b` |
| Existing format-buffer and consumer contexts | `0x141e3a0..0x141e538`, `0x1680500..0x16806c0` |
| TLS lazy acquisition | `0x5bb9340..0x5bb9622` |
| Selected refill boundaries | `0x5bb9850..0x5bb99ad`, `0x5bba800..0x5bbb030` |
| Conditional last-reference drop | `0x5bb99c0..0x5bb99dd` |
| Clock and timespec difference contexts | `0x5c842e0..0x5c843a9`, `0x5c84210..0x5c842d6` |

Every relevant RIP-relative relocation writer is retained with its raw entry,
addend and dynamic symbol name. In particular, `0x64e1248` is a symbol-indexed
`R_X86_64_GLOB_DAT` for `clock_gettime`, rather than an invented local target.
There is no whole-ELF caller census. The existing RE-015 flag-group-format and
write-target packets own prior generic formatter observations; they are reused
as contexts here, not presented as newly discovered runtime functions.

## Observations: word source and lifetime

At `0x150136e`, the ready byte is `fs:-0x4a0`. Its associated descriptor begins
at `fs:-0x4a8`. A non-ready state calls `0x5bb9340`; a null result reaches the
failure boundary through slot `0x64e09a8`. The retained initializer requests
32 bytes through `0x64e22f8 -> 0x17718f0`, constructs state with an allocated
size of `0x170`, initializes the word cursor to 64 at object+0x110, and writes
two 0x10000 fields and a zero field at +0x150/+0x158/+0x160. Seed acquisition,
exact generator family and complete refill/reseed behavior remain open.

The primary helper loads the state pointer and increments its first qword at
`0x1501390`; wrapping to zero traps at `0x1501478`. It retains this reference
through formatting and output copying. It reads the cursor at +0x110 and,
when cursor <64, loads the selected u32 at `state+0x10+cursor*4`, increments
and stores the cursor. When cursor >=64, it calls a refill boundary, resets
the local cursor to zero, then takes the same u32 load/increment path. This is
one 32-bit draw, not a 64-bit or cryptographic uniqueness claim.

The fast refill selection requires signed +0x158 >0 and a clear sign bit of
the wrapping subtraction `state[+0x160] - global[0x64fff30]`. That exact sign-bit
condition must not be silently replaced with an overflow-correct signed
comparison. This arm subtracts 256 from +0x158 and calls
`0x64e0980 -> 0x5bba800` with argument register ESI=6; the other arm calls
`0x64e0988 -> 0x5bb9850`. The roles of the global and the number six beyond
these observed argument values are not established here. Full refill bodies
are retained for future analysis, without claiming a recovered RNG algorithm.

Normal completion decrements the retained first qword. Zero calls
`0x64e09a0 -> 0x5bb99c0`; this helper conditionally decrements the +8 qword and
frees size0x170 on its own last-reference path. The unwind cleanup similarly
releases the formatted temporary when allocated, then the retained state.
Native drop/panic ABI and process behavior after traps remain unresolved.

## Observations: time and actual format arguments

The primary function passes a local address to `0x64e0990 -> 0x1629690`.
That producer calls `0x5c842e0` with EDI=0; its actual dynamic edge is
`clock_gettime`. It forms a zero seconds/nanoseconds comparison origin,
calls the retained timespec-difference function, performs 86400-second day
arithmetic and constructs three dwords: packed date-like word, seconds-of-day,
and fractional seconds. These roles are inferences from arithmetic and the
actual display consumers, not a recovered Rust type/version. OS clock failure,
pre-origin result and out-of-range date construction have failure paths.
No OS clock, TLS initializer or captured code is executed by this packet.

The two 16-byte format argument records are built at `0x150141b..0x150143d`:

1. Pointer to the 12-byte value, formatter slot `0x64e0998 -> 0x156d7f0`.
2. Pointer to the drawn u32, formatter slot `0x64e0270 -> 0x1688a20`.

The five actual template bytes at `0x439955` are `c0 01 5f c0 00`.
The selected consumer branch at `0x1680590..0x16805b0` makes c0 the next
sequential argument, not argument number zero encoded in the next byte. Its
argument counter starts at zero and advances after a successful formatter
call. Positive byte01 copies one literal byte, 5f; 00 ends the template.
Thus the order is display(value), `_`, decimal(u32). It is not a colon or a
hex suffix. The unsigned formatter loads a dword and uses the retained
00..99 digit-pair table at `0x46ea12`; no leading sign is supplied by this
selected default format phrase.

The first display adapter calls the date display, emits one ASCII space, then
tail-calls time display on value+4. The date context emits hyphens and decimal
date fields; the time context emits colon-separated fields and optional
fractional formatting with the actual selected templates at
`0x46c7a4`, `0x46c7ae`, `0x46c7b8`. For ordinary supported dates the inferred
shape is `<date>_<time>_<decimal u32>` after replacement. This is a structural shape,
not a literal sample or a claim that every full calendar/fraction edge has
been reconstructed. No synthetic timestamp is passed off as captured output.

## Observations: output, vector/scalar agreement and boundaries

The format-buffer result supplies an allocated-byte count, pointer and length.
At `0x1501468`, a negative signed length reaches allocation failure. Zero length
returns pointer1 and zero capacity/length without allocating the new output.
Positive length allocates exactly that many bytes. A null allocation enters
the size/alignment failure path. Returned capacity and length both equal the
original formatted length; no NUL terminator or length change is added here.

The scalar branch at `0x15015c0` compares each input byte only with 0x20 and
selects 0x5f on equality. It preserves every other byte. The unrolled four-byte
branch repeats that same condition. The 32-byte loop uses two 16-byte loads,
actual sixteen-space and sixteen-underscore constants at `0x456a60` and
`0x454290`, byte equality masks and bitwise selection. The eight-byte loop uses
eight corresponding bytes and zero high lanes at `0x456360`/`0x453360`.
`derive.py` proves the per-lane identity for all 256 byte values using pure
bitwise algebra. It is not an instruction emulator. UTF-8 decoding, Unicode
whitespace folding and case normalization are absent from this byte loop.

Vector selection first checks length>=8 and an unsigned wrapping pointer
difference >=32. For nonnegative length n, masks select floor(n/32)*32 and
floor(n/8)*8. Subsequent scalar prefix/unrolled loops partition the remainder
by four. The integer interval identities are checked through 4,096, around
powers of two through the signed length bound, and at `2^63-1`. These checks
establish the stated arithmetic identities, not allocator address behavior,
asynchronous fault visibility or every property of the original pointer ABI.

## Reproduction, negative controls and limits

With Python3.14.5, Capstone5.0.7, GNU binutils2.45 and LLVM23.1.4,
source `work/environment/new-three-env.sh`, then from repository root:

```sh
python3 -B research/work-items/RE-012-generated-name-115/verify.py
python3 -B research/work-items/RE-012-generated-name-115/derive.py
```

The verifier regenerates and compares all retained full FDE bodies, native
exports, unwind records and relocation bindings. Forty-two individual actual
instruction/data anchors are each mutated below whole-image identity checking;
all are rejected. Wrong/truncated captures are separately rejected. These are
focused evidence-integrity controls, not semantic equivalence tests. The first
collector attempt assumed an unexposed `sections()` link field and failed
with `KeyError: 'link'`; it was corrected to use the capture's `.dynstr` table.
The completed collection and replay both pass. No target facts were changed.

No new implementation, captured execution/emulation, live OS/TLS/network or
filesystem effects, matched compiled bytes, complete date/time/RNG recovery or
whole-node equivalence is claimed. Full component gates and byte counts remain
unchanged. The next integration step is to join this output-name contract to
the caller's path construction/write operation after their data and failure
contracts are established; shared RNG/calendar runtime remains a separate
licensed dependency-recovery question.
