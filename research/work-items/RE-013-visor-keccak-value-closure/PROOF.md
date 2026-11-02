# Conditional Visor Keccak-256 value closure

For the exact capture and ordinary-return premises below, `0x396750` hashes the
bytes supplied by its opaque reader using Keccak-256: rate 1,088 bits, capacity
512 bits, 24-round Keccak-f[1600], byte delimiter `01`, and 32 output bytes.
This closes a value dependency left opaque by the existing updater work. It
does not establish what a filesystem operation returns, runtime provenance,
signature verification, collision resistance, or a general streaming API.

`BASIS-PINS.json` binds the 8,305,392-byte Visor capture with SHA256
`89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`.
All target facts come from this single captured implementation. GNU and LLVM
are independent decoders, not independent target provenance. The theorem is
manual; scripts bind bytes and finite mathematical checks, not x86 execution.

| Body | Complete half-open extent | Bytes / decoded rows |
|---|---|---|
| Wrapper | `396750..3968c3` | 371 / 83 |
| Permutation | `6bc8a0..6bce22` | 1,410 / 354 |
| Update | `6bce30..6bd25a` | 1,066 / 269 |
| Finalize | `6bd260..6bd55d` | 765 / 171 |

These are four complete raw FDE extents, not contiguous-window guesses.
`observed/records.json` retains raw FDE/CIE/index and cleanup LSDA relations,
all 35 calls, 71 direct branches, the round table, and actual RELA bindings.
Complete dual-decoder exports cover all 3,612 bytes and 877 rows. The raw
4-function evidence is credited to the prior RE-013 capture/lifecycle work;
there is no new byte-recovery claim.

## Domain and frame assumptions

The machine is little-endian x86-64 with the displayed integer/SSE bitwise
semantics and ordinary call/return convention. Relocations resolve as recorded;
imports and opaque callees preserve callee-saved registers and the live storage
specified below. No concurrent mutation, signal-frame clobber, unwind, fault,
or nonreturn occurs along the claimed path. This is not a claim that a host
operating system or a deployed binary satisfies those assumptions.

All pointer additions are nonwrapping; every accessed span is mapped and has
the required read/write permissions. Input bytes remain stable and disjoint
from writable state, output, and live stack. The output has at least 33 writable
bytes. A zero-length input need not supply a dereferenceable byte; the helpers
do not dereference it on that path. Valid positive-length buffers supply every
byte in `[p,p+n)`, for finite `0 <= n <= 2^64-1` and nonwrapping address spans.
This is a hardware value domain, not an assertion of an original Rust type.

With wrapper entry RSP `S`, working RSP is `W=S-520` after five pushes and
`sub rsp,0x1e0`. Its local area is `[W,W+480)` and saved registers occupy
`[S-40,S)`; return reads `[S,S+8)`. It uses 16-byte-aligned `movaps`, so `W`
must be 16-byte aligned. The read-result pointer `W+0x100` and the path words
`W+0x20/+0x28` escape to the reader; later the state and copy pointers escape
to qualified helpers and `memcpy`. Escapes alone do not prove preservation.

Update entry RSP `U` pushes seven words, working at `U-56`. Its permutation
call enters at `U-64`. Finalize entry `F` saves 48 bytes and reserves 232,
working at `F-280`; its local copy starts there plus 8. Its permutation enters
at `F-288`. A permutation entry `P` saves 48 and reserves 96, working at
`P-144`, and its lowest spill at `[rsp-0x80]` reaches `P-272`. It is a leaf:
the 128 bytes below its working RSP must remain valid and untouched by signals
or other agents. There are no calls within that red-zone lifetime. The deepest
captured local access when composed with wrapper/finalize is `S-1088`.
Opaque reader/error/deallocator/import frames can extend further and require
their own valid storage; the bound does not describe those implementations.

`memcpy` is required to copy exactly the requested nonoverlapping bytes and
preserve other live storage. The reader must return one of the following
records at `W+0x100`, preserving wrapper output, saved registers, and path
storage needed by the error branch. No filesystem/UTF-8/open/probe/close
semantics are inferred from this premise:

* Success: first word `c != 0x8000000000000000`, second word `p`, third word
  `n`, with the valid stable byte span above. If `c != 0`, the deallocator call
  `(p,c,0)` must be valid, return normally, preserve output and live stack, and
  perform only its admitted allocation side effects. No meaning such as
  alignment or capacity is inferred solely from its third argument being zero.
* Error: first word is exactly `0x8000000000000000`, second word `e`. The
  opaque conversion at `3a0df0`, called with `(W+0x20,e)`, must return normally,
  preserve output/live saved storage, and return some word `q` in RAX. It may
  use its supplied scratch/path object according to an external valid-object
  premise. No error-object representation or nonzero property is required for
  the raw tagged output claim.

## Wrapper: initialization, output, and cleanup order

`396774` calls slot `7e5e60 -> 68e9c0`. `39678d` negates its first word and
`396790` branches on overflow. Two's-complement negation overflows only for
`0x8000000000000000`, establishing the exact branch partition without relying
on a source enum name. Any other first word takes the success branch, so
well-formedness of that branch's pointer/length remains a premise.

`39679e..3967fb` zeroes the 32-byte digest scratch at `W` and bytes `0..207`
of the state at `W+0x20`. The first 200 bytes are 25 lanes. The cursor at state
offset `0xc8` is zero; `396800` writes rate 136 at offset `0xd0`; `39680c`
writes the word `1` at offset `0xd8`, giving delimiter 1 and phase 0. State
bytes `218..223` are tail padding: the wrapper has not initialized them here.
They are mapped readable bytes that the two subsequent 224-byte copies may
transport, but no semantic operation reads them as state, length, or control.
No source-language claim about copying uninitialized padding follows.

`39681e` calls update with `(state,p,n)`. `396839` copies all 224 bytes to
`W+0x100`; `39684a` finalizes that copy into the 32 bytes at `W`. Finalize
itself copies those 224 bytes again into its own frame. All copies are disjoint.
`396850..396861` stores the digest into `[out+1,out+33)`, high 16 bytes first.
`396864` sets success tag register BPL to zero. If `c != 0`, `396873` calls
slot `7e4b80 -> 714530` with `(p,c,0)`; if zero, `396869` skips that call.
Only after normal cleanup does `396879` store tag byte zero. RAX then equals
the original output pointer. A deallocation failure/nonreturn is not a completed
success, even though digest bytes have already been written.

On error, `396897` calls the opaque converter, `39689c` stores its returned
word at `[out+8,out+16)`, and BPL is set to 1 at `3968a0`; the common tag store
then writes `[out]=1`. No digest bytes are generated. Under the preservation
premises, other output bytes retain their entry values. The error branch does
not call the success deallocator. Neither a successful read nor a digest result
is inferred from an arbitrary nonzero error payload.

The cleanup LSDA associates only the update-call corridor `396816..396824`
and finalize-call corridor `39683f..396850` with landing pad `3968a5`. That
pad conditionally calls the same deallocator and then `_Unwind_Resume` through
the recorded PLT/slot binding. We retain and decode this entire tail but make
no ordinary-return or unwind-success claim for it.

## Update: exact rate blocks and tail

The one-shot initial state has phase 0, cursor 0, rate 136. Consequently
`6bce4b` skips the phase-reset/permutation path `6bce4d..6bce78`. At `6bce88`
the remaining rate is `136-0`, with no borrow. Let `k` complete blocks have
been consumed. At loop entry `6bcf14`, RBP is `136k`, R15 is `n-136k`, R13
is 136, and RDI is zero. The entry is taken only if remaining length is at
least 136. All four bounds checks (`6bcf1a/27/38/41`) are false: consumed
does not exceed `n`, cursor is zero, 136 does not exceed 200, and a full input
block exists. No unsigned addition overflows because the next consumed count
is at most `n`; pointer spans separately have the nonwrap premise.

The unrolled SSE path `6bcf84..6bd087` processes successive 32-byte chunks;
for 136 it processes exactly 128 bytes. The 4-byte loop `6bd0b0..6bd0bf`
processes the remaining 8 bytes. The possible byte tail `6bd0e0..6bd0ee`
is empty for a 136-byte block. XORPS is used as a bitwise instruction and
introduces no floating-point value/rounding dependence. Source and destination
spans are disjoint; each loaded bit is XORed into the corresponding state bit
once. `6bcef3` permutes the 200-byte state. `6bcef9..6bcf0e` increases consumed
by 136, reduces remaining by 136, and repeats only while another block exists.
This strictly decreases the finite remaining count.

When remaining `t < 136`, either the initial short path or `6bd103..6bd11c`
enters the common tail path. The `AL` validity indicator is zero under the
loop invariant; cursor is zero and the source length is sufficient. The vector
tail `6bd150..6bd17a` XORs `32*floor(t/32)` bytes; the 4-byte loop
`6bd1a0..6bd1af` extends through `4*floor(t/4)`; the byte loop
`6bd1c0..6bd1cf` extends through `t`. These are exact disjoint intervals, no
overread. For `t=0`, `6bcec4` directly reaches the cursor store. `6bd1d4`
writes cursor `t` and returns. Rate, delimiter, phase, and padding remain
unchanged. State equals the permuted full-block prefix with exactly the tail
bytes XORed into positions `0..t-1`; bytes beyond the tail retain their
previous state values, rather than being zeroed.

Every panic call in the full update body is therefore excluded on this domain.
The phase-nonzero branch and arbitrary invalid cursor/rate behavior remain
retained context, not an independently qualified resumable-input contract.

## Finalize: delimiter, final bit, and first 32 bytes

The copy's phase is zero, so `6bd293` enters `6bd2d5`, sets local phase 1,
and loads cursor `t` (`0..135`). All `cursor >= 200`, zero-rate, and
`rate-1 >= 200` failures are excluded. `6bd307` XORs delimiter 1 into state
byte `t`; `6bd32a` XORs 128 into byte 135. If `t=135`, the same byte is XORed
with `0x81`. This is byte-aligned `pad10*1`, including the required new block
for empty input and input lengths exactly divisible by 136. Padding is XORed
into an existing sponge state; it is not a replacement of the tail state.

`6bd334` performs one permutation, then cursor is zeroed. Output length 32 is
less than rate 136, so `6bd356` takes the short-output path to `6bd41c`, with
R12=RDX=32, R15=RDI=0. Both final bounds checks are false (`32 <= 200` and
`32 <= 32`). The `memcpy` at `6bd44b` copies exactly the first 32 state bytes
to the supplied output and returns. On little-endian x86-64 these are the
low-to-high bytes of lanes 0,1,2,3. The passed-in 224-byte source is only read;
all padding, phase and cursor writes occur in finalize's private copy.

The phase-1 path, repeated squeezing (`6bd38e..6bd414`), and all panic calls
are present in the complete FDE but not reached by this initialized 32-byte
projection. The indirect `call rbx` at `6bd3f9` is nevertheless bound to the
`6bd3b7` slot load (`7e80a8 -> 6bc8a0`), with RBX preservation across the
intervening memcpy as an external ABI premise. No general squeezing guarantee
is needed to establish the selected value.

## Complete permutation correspondence

Use lane index `L=x+5y` and bit index `z`, with `a[x,y,z]` the bit of weight
`2^z` in lane L. The formal Keccak reference defines this serialization and
24 rounds for width 1600. The bit convention is LSB-first within each byte.
[Keccak reference 3.0, §§1.2–1.3](https://keccak.team/files/Keccak-reference-3.0.pdf),
[authors' bit/byte conventions](https://keccak.team/keccak_bits_and_bytes.html).

At `6bc980`, lanes 0..24 occupy, in order:

```text
r8, [rsp-30], [rsp-28], [rsp-68], [rsp-38],
[rsp-60], rbp, r11, r13, [rsp-08],
r12, [rsp-58], r15, [rsp-70], rbx,
r10, rcx, rsi, [rsp-20], r9,
[rsp-18], [rsp-48], [rsp-10], [rsp-40], [rsp-80].
```

All offsets here and below are hexadecimal. Prologue `6bc8b1..6bc975` loads
each original qword from `8L`, with the original pointer saved at `[rsp+30]`.
The loop restores exactly this lane-location map before its backedge.

Theta computes column XORs C[x]. The final C0..C4 values are respectively
RAX at `6bca0a`, R11 at `6bca0d`, R8 at `6bca4f`, RDI at `6bca12`, and RBX
at `6bca23`; their five contributing lanes are x,x+5,x+10,x+15,x+20. The
dependent scheduling saves original lanes before register reuse. D[x] is
`C[(x+4)%5] XOR rol64(C[(x+1)%5],1)`. D0..D4 finish in R11 (`6bca28`), R8
(`6bca5b`), RDX (`6bca1d`), RBX (`6bca55`), RAX (`6bcab2`). The XOR ranges
`6bca2b..45`, `6bca5e..73`, `6bca78..90`, `6bca95..ad`, `6bcab5..d4`
apply these to all five lanes of the corresponding column. Call these lanes T.

The following table binds every rho operation and its destination in the
mathematical pi output `B[y,(2x+3y)%5]=rol64(T[x,y],r[x,y])`. L0 is unchanged.
The rotations are exactly the triangular offsets generated by the 24-step
coordinate orbit starting at (1,0), not an assumed algorithm label.

| Source L | Native rotate | Bits | Pi destination L |
|---:|---|---:|---:|
|0|none (`[rsp+10]`)|0|0|
|1|`6bcc88`|1|10|
|2|`6bcaf8`|62|20|
|3|`6bcb98`|28|5|
|4|`6bcc43`|27|15|
|5|`6bcc35`|36|16|
|6|`6bcb05`|44|1|
|7|`6bcc8b`|6|11|
|8|`6bcad9`|55|21|
|9|`6bcbb3`|20|6|
|10|`6bcb8f`|3|7|
|11|`6bcc25`|10|17|
|12|`6bcaf1`|43|2|
|13|`6bcc9d`|25|12|
|14|`6bcafc`|39|22|
|15|`6bcae8`|41|23|
|16|`6bcba6`|45|8|
|17|`6bcc2e`|15|18|
|18|`6bcad0`|21|3|
|19|`6bcc94`|8|13|
|20|`6bcca6`|18|14|
|21|`6bcae0`|2|24|
|22|`6bcbaf`|61|9|
|23|`6bcc51`|56|19|
|24|`6bcae4`|14|4|

Chi is `A'[x,y]=B[x,y] XOR ((NOT B[x+1,y]) AND B[x+2,y])`, all x modulo 5.
For each row, the source-T lane order after rho/pi and the final native XOR
site for its five output lanes are:

| Output row | Rotated T sources in x order | Final XOR sites in x order |
|---:|---|---|
|0|0,6,12,18,24|`6bcd31`, `6bcb2d`, `6bcb1f`, `6bcbec`, `6bcbf4`|
|1|3,9,10,16,22|`6bcbc0`, `6bcbd1`, `6bcc0a`, `6bcc0d`, `6bcc10`|
|2|1,7,13,19,20|`6bccd9`, `6bccdc`, `6bccbc`, `6bccd1`, `6bcced`|
|3|4,5,11,17,23|`6bccf5`, `6bccfd`, `6bcc80`, `6bcc72`, `6bcd0b`|
|4|2,8,14,15,21|`6bcb4c`, `6bcb70`, `6bcb62`, `6bcc18`, `6bcd27`|

Each site is preceded by the appropriate NOT/AND of the two subsequent row
values, with copies/spills preserving values needed by later expressions.
For row0/x0, the NOT/AND is saved at `[rsp]` by `6bcb09..6bcb12`; Iota is
XORed into that intermediate at `6bcd1b`, before the unchanged T0 term is
added at `6bcd31`. XOR associativity gives precisely Chi then Iota. This
explains the interleaving rather than treating a recognizable pattern as proof.

`6bcd10` addresses the 192 bytes at `c11c0`. The counter starts at zero
(`6bc97a`), selects eight-byte constants, advances by 8 (`6bcd36`), and stops
at 192 (`6bcd3a/41`), exactly 24 rounds. Every table word equals the RC derived
from the reference polynomial `x^8+x^6+x^5+x^4+1`, with injection positions
`2^j-1` for j=0..6. The independently generated full table is in the finite
certificate and is compared to the ELF bytes; none is inferred from a provider
constant name. `6bcd4c..6bce0c` stores all 25 final lanes to offsets `8L`
exactly once. No call, other external read, or external write occurs in this
leaf apart from the constant table and the state span; stack/saved-register
accesses are those described above. Return restores the saved register frame.

Theta's linear single-bit basis (1,600 vectors), all 32 Chi row bit patterns,
all 25 rho/pi coordinates, 24 generated constants, and all 136 padding tails
are checked mathematically. These finite certificates support the algebra;
they neither run nor interpret captured instructions. Address-to-expression
mapping remains the explicitly reviewable manual argument above.

## Consequence, credit, and limits

Combining the block invariant, padding, complete permutation and output order
gives Keccak-256 over the supplied bytes. SHA3-256 instead uses delimiter `06`;
the older lifecycle packet's “SHA-256-shaped” inference is superseded only for
this exact helper and captured identity. The old prose is preserved as history.
PR45 owns the earlier lifecycle/read/hash-equality discovery. PR1394 owns its
metadata/download publication relation. This packet supplies the missing digest
value relation and credits their evidence; it does not redo their caller proof.
External PR1607's adjacent file-read envelope `68e5b0..68e9b9` and all of its
UTF-8/open/read/probe/close behavior remain outside this packet. Our reader
slot points to `68e9c0`, itself still an opaque producer under this theorem.

The merged MIT provider `src/node94-action-signable::keccak256` already has the
same byte contract and a real crate. Its exact pre-existing source graph is
pinned here; no new wrapper or library is proposed. The independent 64-plane
oracle predates any new qualification client but does not predate that existing
provider. Agreement with official vectors corroborates the mathematical oracle,
not the binary provenance. A later source/build gate must separately admit the
actual existing provider and an input-only client before any compilation. This
pre-code packet makes no compiled-provider, target-runtime, or deployment claim.
