# Ordered byte-image refinement of the wrapping subtract

Target: node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`,
complete FDE `[0x32d8310,0x32d8361)`. Existing `subtract_words` computes the
numeric relation for two independent values. Its documentation explicitly
excludes mutation/copy order, pointer aliases and RAX. The new image module
closes those exclusions on the admitted ordinary-memory domain; the existing
function, vector corpus and client are preserved.

## Domain and observed order

One mutable byte image represents stable ordinary mapped memory. The 32 bytes
at left and right must be readable; the left 32 bytes and destination 33 bytes
must be writable. Offsets and every effective address must be representable and
nonwrapping in the target address space; accessed intervals lie within the image.
No alignment or disjointness restriction is imposed on these data ranges.
There is no concurrent mutation, volatile/MMIO effect, code/control-state alias,
nonstandard stack behavior or fault. Arbitrary overlap between input/output
bytes, including all three bases equal, is within this domain.

The library admits all three complete spans before mutation. `Unavailable`
is a new atomic safe refusal, not a recovered native return or fault policy.
In particular a native late copy fault could follow earlier minuend writes;
this API instead leaves the entire image unchanged. The pointer ABI, fault
order, register flags, unrelated scratch registers and application type names
are outside the correspondence claim. Return `Ok(value)` represents full RAX.

Offsets below are relative to the bound 81-byte leaf:

- `+0x00..+0x16`: read right word 0, subtract it from left word 0; then
  independently load right words 1 and 2, updating corresponding left words
  with SBB after each load. Prior stores can change these later right reads.
- `+0x16..+0x37`: load the top left word; preserve the lower borrow; subtract
  the live top right word; subtract the preserved borrow; OR the two top-borrow
  sources; store the resulting top left word. All four left words now contain
  the ordered difference, which need not equal subtracting entry snapshots.
- `+0x37..+0x3d`: load the low 16 left bytes into XMM0, then store all 16 at
  destination. Both left words are snapshotted before this store.
- `+0x3d..+0x45`: load the live left word 2 into RAX and store it at destination+16.
- `+0x45..+0x4d`: load the live left word 3 into RAX and store it at destination+24.
- `+0x4d..+0x51`: store the saved borrow byte at destination+32 and return.
  The last store may overwrite other data, but it does not change RAX.

The complete body is straight-line, with no call or branch and a single final
RET. Exact FDE/CIE records, full bytes, 15 following INT3 bytes and both direct
sites `0x32994ed/0x3299579` in full caller `[0x3299180,0x32996b6)` are retained.
The incoming edges establish reachability, not the complete caller's meaning.
Relocation and E8 scans are bounded evidence rather than all-indirect-reference
claims. No imported instruction bytes are executed.

## Arithmetic recurrence with live source aliases

Let B=2^64. Each source word is little-endian. The Rust loop reads the current
right word and current left word, computes `(partial, first)=left-right`, then
`(value, second)=partial-borrow`, each with unsigned wrapping arithmetic and
its overflow bit. The next borrow is `first OR second`. This is precisely SUB
or SBB: subtracting a one-bit borrow from the already wrapped difference either
underflows or does not, and either underflow source makes the combined borrow.
For the first limb the incoming borrow is zero.

The top native sequence loads left before right, while the source reads right
first. Both are ordinary stable loads with no intervening store, so their
ordering has no data effect even when their byte ranges overlap. The ADD CL,0xff
restores CF exactly when the captured lower borrow is one. The subsequent SBB
subtracts this bit; the OR with the captured top SUB borrow equals the same
Rust `first OR second` relation. Hence the loop covers all four native limbs.

Induct on limb index: before limb i the image and incoming borrow agree, so
the two live operand words agree. The arithmetic recurrence yields the same
word and outgoing borrow, and the same eight-byte left range is written.
This proves all byte offsets, including unaligned right/left overlap and
subtrahend ranges containing a mixture of earlier updated and entry bytes.
Left's own consecutive word intervals are disjoint, so a lower-limb update
cannot change a later left word before its subtraction.

The independent oracle uses this last fact differently. A is the entry left
256-bit integer. For each i, obtain effective right word Ri from immutable
byte overlays of the already determined lower difference words. Define
`Bi=sum(Rj*B^j, j<=i)` and `Pi=(A-Bi) mod B^(i+1)`. Word i is `floor(Pi/B^i)`.
This whole-prefix integer equation determines each stored word without tracking
machine registers, CF or a borrow loop. Since `A mod B^(i+1)` is exactly the
relevant minuend prefix, elementary long-subtraction proves that its top word
and induced borrow equal the source recurrence. After all four words the
borrow is `A < B3`, even though the effective right words themselves depend
on lower writes. No original-input right snapshot is substituted.

Concrete witness: left words `(10,20,30,40)` at 64 and a right base at 56 with
initial word 5 produce `(5,15,15,25)`. Each next right word reads the updated
previous left word. Subtracting entry snapshot integers would give a different
result `(5,10,10,10)`; the existing value API does not claim to handle this case.

## Copy overlays and exact RAX

After subtraction, the first 16-byte source snapshot is stored at destination.
The next eight-byte read at left+16 must use that updated image, and its store
must precede the final read at left+24. The Rust implementation follows those
three stages and stores the borrow last. For each stage the oracle constructs
an immutable byte overlay, selecting the most recent covering write or the
entry byte. Induction over the three copy stages and final flag store proves
the complete resulting image, including every otherwise unchanged byte.

For example, a difference `(1,2,3,4)` at left 64 copied to destination 72 yields
output words `(1,2,2,2)`: the 16-byte store changes the later third-word read,
and the third-word store changes the last-word read. Raw RAX is 2, not the
pre-copy high difference 4, a borrow Boolean, or the output pointer. The final
borrow-byte store cannot change the saved register, even when it aliases the
left or right data. The Rust return is exactly the live final read's u64.

## Bounds, controls and limits

All offset additions used after admission are bounded by checked endpoints
for 32- or 33-byte spans. Fixed-width conversions cannot fail, arithmetic
uses explicit wrapping/overflowing operations, and shifts are not used. A
single mutable slice permits internal aliases without violating Rust reference
rules. All four subtraction stores and four copy/flag stores remain in the
admitted ranges. The operation needs no allocation or arbitrary size cap.

The frozen corpus includes every partial right/left displacement -31..31
jointly with every output/left displacement -32..31, four entry patterns,
bit-basis perturbations at all alignments, directed carry cases, seeded complete
images and exact/missing spans. Native clients receive only inputs and emit
status, full RAX and every backing byte without a mask. The old numeric unit
corpus remains part of the library tests. Finite observations support the
implementation; the induction and overlay argument establish the complete
admitted relation. Neither proves native compiled-byte identity, actual caller
input restrictions or whole-node equivalence.
