# Conditional typed-prefix relation

This is manual static branch reasoning over the complete extents listed in
[README.md](README.md). It is not instruction evaluation, target execution or a
proof of the original source ABI. [VALIDATION.md](VALIDATION.md) separately
records actual static qualification; examples below are manual consequences.

## Reader and memory premises

The reader fields used here are a mode DWORD at+0, limit u64 at+8, input pointer
at+16, remaining u64 at+24 and charged count u64 at+32. Native equality to mode1
enables charging; other DWORDs bypass it in the selected bodies. This observation
does not identify the set of valid source enum constructors.

Require live, suitably sized reader/output/frame storage; a readable remaining
slice; disjoint input and writable state/output spans; nonwrapping pointer
advances; stable input except for the stated cursor/count writes; and ordinary
ABI preservation across the bound scalar calls. A canonical limited/unlimited
safe view would be a chosen policy, not a claim about every native state.

Only fields active under a returned tag are projected. Uninitialized padding,
inactive union storage and caller scratch registers are excluded. In particular,
early Boolean errors may copy BL before any input byte was loaded, and variant
errors copy inactive stack/register bytes. Merely retaining those stores does
not give them semantic meaning.

## Boolean admission and charging

At `0x2ce159d` the mode DWORD is compared with1. In mode1:

1. `0x2ce15a2..0x2ce15ac` tests the old charged count against u64::MAX.
   Equality returns tag2 without storing a new count or reading input.
2. Otherwise `0x2ce15b2..0x2ce15b6` stores old+1. The unsigned comparison at
   `0x2ce15ba..0x2ce15bd` then rejects old>=limit. Since overflow was excluded,
   this is new>limit. The failed increment remains; input is untouched.

After that admission, `0x2ce15bf..0x2ce15c6` tests remaining. Empty input
returns tag0 with additional-needed1 at output+8. A present byte is loaded at
`0x2ce15cc`; pointer increment and remaining decrement are stored at
`0x2ce15d5/0x2ce15d9`. Only afterward does `0x2ce15df..0x2ce15e2` require the
byte to be unsigned<2. Rejection returns tag8 and the offending byte at+1.
Thus budget failure precedes shortfall, and byte consumption precedes Boolean
validity. No logical truthiness interpretation of other bytes is admitted.

## Credited scalar dependency

Both direct calls, at `0x2ce15ef` and `0x2ce1662`, target the complete u32
wrapper `0x2cd79c0..0x2cd7ab3`. [PR2412](https://github.com/lalalune/hyperliquid-source/pull/2412)
provides this primitive's prior proof. Its actual selected bytes and data are
retained as dependency evidence here.

At `0x2cd79c1..0x2cd79df`, mode1 rejects old>u64::MAX-4 without a store.
Otherwise it adds4, stores at+32, then compares new<=limit. Failure returns tag2
and retains the increment without consuming input. Other mode DWORDs bypass
charging. The selected slow helper receives only the pointer/remaining pair;
it does not make an additional charge.

`0x2cd79ed..0x2cd79f1` uses the fast route only when remaining>4. Its four-entry
signed-relative table at `0x60be7c` selects the following branches:

| Marker | Fast result and consumption |
| --- | --- |
| `00..FA` | Success with marker value; consume1 |
| `FB` | Success with u16 little-endian payload; consume3 |
| `FC` | Success with u32 little-endian payload; consume5 |
| `FD` | Tag3, raw fields2/3; consume0 |
| `FE` | Tag3, raw fields2/4; consume0 |
| `FF` | Tag3, raw fields2/12; consume0 |

There is no minimality check on FB/FC payloads. Both representable small and
large u32 values are handled by the same successful branches.

At remaining<=4, `0x2cd7a57..0x2cd7a60` passes reader+16 and EDX=0 through
slot `0x64e7f70`, whose symbol0 RELATIVE record selects
`0x5822490..0x58225b5`. EDX=0 selects the little-endian value. The slow table
at `0x935c14` binds the corresponding four marker arms.

The short reader returns tag0/additional1 on an empty slice. On nonempty input,
`0x58224a9/0x58224ac` stores pointer+1 and remaining-1 before marker dispatch.
An incomplete FB reports3-total; an incomplete FC reports5-total, where total
is the original remaining length at the scalar call. These errors consume only
the marker and preserve available payload bytes. FD/FE/FF also consume their
marker before returning the same raw tag3 fields as the fast path. Complete FB
consumes3. The retained general short body has a complete-FC consume5 branch,
but this wrapper only delegates at remaining<=4, so that success arm is not
reachable through these calls.

The raw constructor is the complete14-byte `0x5822700..0x582270e`, selected
by slot `0x64e7f78`: it returns the output pointer, stores tag3 at+0, low ESI
at+1 and DL at+2. The baseline u32 packet historically credits this shared constructor to
[PR2300](https://github.com/lalalune/hyperliquid-source/pull/2300). The recorded
current direct remote lookup returned404/unavailable; no live status is claimed.
No opaque
formatter or allocator is needed to form these scalar active fields.

## Composition and active results

After the Boolean, the first scalar result must have tag0x12
(`0x2ce15f9..0x2ce15fc`). Other tags go through the active-field copy at
`0x2ce1631..0x2ce1653` and `0x2ce1700..0x2ce1716`, with no cursor/count rollback.

On scalar success, `0x2ce1602..0x2ce1609` accepts only index0 or1. A different
u32 reaches `0x2ce16e8..0x2ce1716`: tag5, found index at+4, literal
`BroadcastGroup` at address `0x606dc4` with length14, and descriptor
`0x451270`. The branch excludes the second scalar call. The numeric test,
not a guessed descriptor structure, establishes the accepted set.

After group acceptance, `0x2ce1662` invokes the same scalar reader. A failed
scalar is forwarded through `0x2ce1698..0x2ce16e3`. On success,
`0x2ce1675..0x2ce167a` requires the u32 to equal0. Other values form tag5,
found index, literal `TcpId` at `0x60f742` with length5 and descriptor
`0x4553c0`. The copied inactive bytes are not projected.

The success stores at `0x2ce171f..0x2ce1729` are output+1=original Boolean,
output+2=group0/1 and output+0=0x12. TcpId0 has no additional success payload.
The active result possibilities of this closed inner call chain are:

| Raw tag | Projected active information |
| --- | --- |
| 0 | Additional-needed u64 at+8 |
| 2 | Charge refusal; no additional field assigned meaning |
| 3 | Raw expected/found marker fields at+1/+2 |
| 5 | Found u32 at+4, field-name pointer/length at+8/+16, raw descriptor pointer at+24 |
| 8 | Invalid Boolean byte at+1 |
| 0x12 | Boolean0/1 at+1 and group0/1 at+2 |

The first failure ends the composition, retaining all earlier and current
reader mutations. Successful mode1 calls added1+4+4=9 without overflow; final
charge equals9 only if initial charge was0. Each scalar may use1,3 or5 encoded
bytes, so the possible successful lengths are exactly3,5,7,9,11 bytes. The
complete inner body returns without
testing remaining==0. Arbitrary trailing bytes within the valid slice therefore need not be consumed.

## Conditional fresh-reader caller

The retained complete wrapper is `0x2700010..0x27005d1`. The theorem here
restricts its incoming instrumentation argument to R8D=0. At
`0x27000d1..0x27000e9` it constructs the supplied input pointer/length, mode1,
supplied RCX limit and charged0; `0x27000fc` invokes the inner reader.

After success, `0x2700118..0x270011d` requires remaining<=original length.
This bounds subtraction/cursor accounting; it is not an exhaustion condition.
The active result is placed in stack storage at `0x270021a..0x270025a` and
copied to the output at `0x27002bc..0x27002ca`.

This route is not helper-free. It calls `0x5c842e0` before and after decode
and `0x5c84210` afterward. Require these helpers to return normally with ABI
preservation and to preserve the live input, saved arguments, stored result,
output destination and surrounding frame except for their permitted result
spans. Their internal behavior, exceptions and timing effects are opaque.
Normal return alone does not establish that noninterference premise.

Nonzero instrumentation routes prepare the same reader but also access TLS,
perform guard/init/restore operations and call further helpers. Their full
bytes are retained to show the boundary; neither their effects nor all their
failure routes are closed. The live outer caller zero-extends a byte into R8D;
this does not justify arbitrary high-bit argument states.

## Credited outer handoff and cleanup boundary

The complete outer reader `0x2b79e30..0x2b7a0a3` is prior
[PR2572](https://github.com/lalalune/hyperliquid-source/pull/2572) evidence.
Given its valid completed lower-buffer state and ordinary helper premises,
`0x2b79f70` passes the original frame pointer/length, configured limit and
context byte to the wrapper. Accepted tag0x12 at `0x2b79f75` forwards the two
active bytes. Output word+8 at `0x2b79fb8` receives the original frame length,
not the inner consumed prefix or its logical charge. A claim using the narrow
wrapper relation additionally requires that supplied context byte to be0.

Other decoder tags pass through `0x2b7a0b0..0x2b7a140`. That helper calls
formatter `0x2b41590` before reading its input tag for cleanup selection; it
returns the formatter's word on ordinary return. Formatting, type ownership,
destruction and error-object ABI are opaque. The outer frame-release request
is conditional on original capacity after either decode outcome. The selected
call operands do not prove actual memory reclamation. Pending/transport-error,
async reentry and unwind behavior remain credited context, not newly closed
runtime semantics.

## Manual consequences and counterclaims

These examples follow from the branches above; they are not executed tests.
Unless a limit is stated, use unlimited mode with sufficient valid storage.

| Input bytes | Consequence |
| --- | --- |
| `00 00 00` | Success Boolean0/group0; consume3 |
| `01 01 00` | Success Boolean1/group1; consume3 |
| `02 00 00` | Consume1, then invalid Boolean tag8 |
| `00 02 00` | Consume2, then group index2 tag5; no TcpId read |
| `00 00 01` | Consume3, then TcpId index1 tag5 |
| `00 FB 01 00 FB 00 00` | Nonminimal successful fields; consume7 |
| `00 FD 00 00 00` | Group has4 bytes: consume Boolean and FD; tag3 |
| `00 FD 00 00 00 00` | Group has5 bytes: consume only Boolean; tag3 |

For a fresh limited reader, `00 00 00` with limit8 consumes two bytes then
stores charge9 and refuses the last scalar. Limit9 succeeds. Empty input with
limit0/count0 first stores charge1 and returns tag2, rather than the shortfall
tag0. An initially maximal count refuses without a store.

These cases refute reading before charging, treating a nonzero Boolean as
true, accepting every u32 index, consuming all trailing bytes, treating charge
as encoded length, or assuming failure cursor state is suffix-invariant.
Static operand/corruption checks can bind those decisive branches to the
capture. They do not provide a second behavioral oracle or establish native
execution equivalence.

## Remaining work and attribution

This is a complete conditional inner relation plus a deliberately narrow
caller projection. It adds no Rust implementation, component completion,
progress gate, new byte coverage or whole-network claim. The u32 implementation
in open [PR2902](https://github.com/lalalune/hyperliquid-source/pull/2902) remains
protected. A later source consumer should reuse its real API only after merge
or a separately reviewed ownership/reuse decision.

New proof/checking work uses root MIT; credited MIT helpers and packets retain
their provenance. Disassembly is evidence derived from the pinned capture,
not copied unlicensed inferred source. Timer/TLS, formatting, allocation and
unwind closure are future questions only where a concrete caller requires them.
