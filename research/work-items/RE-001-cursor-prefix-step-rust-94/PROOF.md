# Cursor-prefix transition, memory order and image admission

The complete linked-VA body `[0x47d6b90,0x47d6be2)` is bound to node #94,
SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Its 82 bytes decode to 19 instructions, without calls. The full FDE inventory
has exactly its own FDE overlapping this range. Names below describe observed
operations; the source identity, marker meanings and dispatcher remain unknown.

Let S be RDI. The flag is the byte at S+0x1f0, marker at S+0x1f3, counter the
little-endian qword at S+0x1e0 and cursor the qword at S+0x1d0. Under stable,
ordinary mapped memory, the body has exactly these paths:

| Guard, in priority order | Stores | RAX at return |
|---|---|---|
| flag = 0 | marker = 0x67 | unchanged from entry |
| flag != 0 and counter <= 1, unsigned | marker = 0x50 | counter |
| flag != 0 and counter > 1, unsigned | counter = counter-2; cursor = cursor + signed prefix + 2 modulo 2^64 | new cursor |

No flag is coerced to a boolean with a restricted 0/1 domain. Every nonzero
byte passes the first gate. Counter comparison is unsigned; bit63 does not
select the short-counter path. Under the advance guard, counter-2 does not
underflow. Only the two marker paths write the marker; advancement preserves
it. The no-flag path never loads counter/cursor. RAX observations do not
establish any source return type. `Unchanged` describes the entry RAX relation,
not a guessed numerical value. Other registers/flags are outside the API.

## Prefix and ordering

Advance stores the decremented counter at 0x47d6baa, then loads the cursor at
0x47d6bb1, then the word through that cursor at 0x47d6bb8. Counter and cursor
fields occupy distinct nonwrapping intervals, so the counter store cannot
change the cursor field. Rust can therefore read the cursor during preflight,
before the counter store, without changing its value. The prefix itself may
alias **any** state bytes.
If it overlaps counter bytes, it observes the newly stored counter. It may
also cross either end of that eight-byte field. Assuming an entry prefix
snapshot without this update is incorrect.

MOVZX word followed by ROL16 8 converts the two memory bytes b0,b1 to
`256*b0+b1`. MOVSX16->64 gives `s=256*b0+b1` if b0<128, otherwise that value
minus 65536. Hence the prefix is a signed big-endian i16 for all 65,536 byte
pairs, not an unsigned length. The displacement is s+2, ranging from -32766
to 32769. Both additions wrap at 64 bits. The resulting cursor is only stored;
it is **not dereferenced or range-checked** in this body. A negative step, a
cursor outside the image, or a wrapping final cursor is not an error here.

A concrete alias witness: counter=256, prefix address=S+0x1e0. The old first
two counter bytes are `00 01`, but after decrement they are `fe 00`. The body
uses signed -512, so the cursor moves by -510. An entry-snapshot model would
incorrectly move by +3. The frozen oracle accounts for this through an
immutable byte overlay: at each prefix index inside the counter interval,
select the corresponding byte of counter-2; elsewhere select the entry image.
It then constructs the final image from simultaneous field replacements.
This algebraic oracle does not replay instructions or import the Rust code.

## Safe image API

`step(image: &mut [u8], base: u64, state_offset: usize)` gives an explicit,
independently chosen memory representation. Image byte i represents target
address base+i; S corresponds to base+state_offset. The recovered field offsets
are used inside this image. There is no unsafe code, pointer cast or FFI ABI.
All prefix/state overlaps within this one image are preserved.

The image's last byte must have a nonwrapping u64 address. The image may end
at address u64::MAX; an exclusive endpoint of 2^64 is allowed. For a marker
path, the accessed flag/counter and marker must fit. No prefix mapping or
resulting cursor validity is required on these paths. For advancement, state
fields must fit and the **old** cursor's two-byte prefix must be mapped wholly
inside the image. The prefix bounds check precedes any mutation, but the actual
prefix-byte read follows the counter write. These distinct operations preserve
both rejection atomicity and successful-path alias semantics.

After admission, the API performs the observed stores in native order. All
other image bytes remain unchanged. There is no additional condition on the
new cursor, and no counter range narrowing. Invalid image-address range, state
bounds or prefix bounds returns an explicit error with the entire image
unchanged. These refusal branches are added safe-API policy. In particular a
native prefix fault can occur after a counter store; this error policy does
not reproduce native partial writes or fault order.

Correspondence requires the image to describe ordinary stable readable/writable
mapped memory for accesses taken, with nonwrapping addresses for the state and
prefix reads. It excludes concurrent observation/mutation, MMIO/volatile effects,
faults, unmapped memory outside the image, raw ABI and register state beyond
RAX. Prefix aliases are included rather than excluded. The symbolic image can
represent high u64 addresses arithmetically without claiming any particular OS
maps those addresses or that wrapped pointers are safe to dereference.

## Finite comparison

Before Rust existed, oracle.py and 4,646 full-image inputs/expectations were
SHA-256 frozen. Cases include both marker paths, all flag-byte classes,
unsigned counter endpoints, positive/negative prefix boundaries, byte order,
low/high address arithmetic, every counter-overlap offset (including crossing
ends), cursor-field aliases, short images and invalid prefix addresses. The
input-only native client reports the result and every changed byte relative
to its input image. It compares every byte when constructing that sparse
representation: an omitted index means unchanged, not masked. The oracle uses
the same canonical output format, so exact agreement compares the entire
observable image. Raw output plus frozen input reconstructs each final image.
These runs corroborate this proof; they do not execute the captured target.
