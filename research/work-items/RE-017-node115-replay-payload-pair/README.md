# ClientBlockWireOrTx payload provenance into the replay slot

This packet identifies the two words previously traced from an opaque decode
result into the shared replay slot. They are ownership pointers selected by
the native `ClientBlockWireOrTx` decoder, not a proven height/root pair. This
advances the replay integration prerequisite by specifying the payload family
and the still-required child contracts.

Target `artifacts/node/115/hl-node`: 105896032 bytes; SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Static analysis only; the captured executable was never run or emulated.

## Prior work and bounded addition

#7057 establishes the actual producer/consumer shared slot allocation and
sequence identity, but leaves `0x5860bb0` opaque. #3980 supplies the slot
constructor/reader contract. #2916 owns the Block decoding grammar, and #7047
owns the cumulative-budget attachment vector. Those child semantics and the
slot mechanics are reused, not claimed as new here. The additional result is
the actual decoder-wrapper-to-slot composition and its two output families.
All-state PR and current-main searches for `0x4e49490`, `0x4eff5f0`, and
`0x4e052f0` found no prior semantic packet for this scope before publication.

## Decoder identity and results

`0x5860bb0` constructs an input descriptor from its pointer, length, and a
pointer to its auxiliary limit argument, and invokes `0x4e49490`. That wrapper
has mode-dependent TLS/instrumentation paths; all three normal decoding
sites initialize the same reader shape: active budget flag1, supplied limit,
input pointer/length, charged0. Each calls `0x4eff5f0`.

The latter reads compact-u32 through `0x5821150`. Its invalid-variant output
references the exact 19-byte label **ClientBlockWireOrTx** at `0x919611`.

| Wire discriminator | Successful pair at result+8 / result+0x10 |
| --- | --- |
| 0 | Block owner pointer; optional attachment-vector owner pointer, or null |
| 1 | null; raw length-prefixed byte-vector owner pointer |

Tag0 invokes existing Block decoder `0x4fb7760`. On its inline-success arm,
the decoder builds a 0x368-byte owner with the two leading reference counts
set to1 and the decoded Block following. The native result also contains a
sentinel/tag arm that is retained in the transcript; this packet does not
assert that every syntactically present arm is reachable. It then invokes
`0x4e052f0` with the **same reader**, preserving cursor and cumulative budget.

`0x4e052f0` charges1 before reading its option byte. Byte0 returns a null
second pointer. Byte1 invokes `0x5824840` with callback `0x4e04e90`, the exact
attachment-vector child used by #7047; on success it wraps the vector in a
0x28-byte owner with two leading reference counts1. Other bytes return an
invalid-variant result after consuming the byte. Budget/input exhaustion and
child failure propagate; the Block owner is decremented on a later option
failure. No claim about every destructor or unwind path is made here.

Tag1 invokes the existing length-prefixed raw-blob reader `0x5824b60` with
byte callback `0x5b56950`, wraps its vector in a 0x28-byte owner, and sets the
first pointer to zero. The native enum label supports calling this the Tx
wire alternative; it does not prove the bytes form a valid transaction or
that any downstream component has accepted them.

Both alternatives return byte tag0x12 and the two pointers. Child errors
retain their failure rather than entering the successful-pair path. Native
allocation failure is a non-returning boundary, not a successful empty item.

## Wrapper and actual producer

On successful decoding, `0x4e49490` computes original length minus reader
remaining, preserves the pair at output+8/+0x10, and also returns a consumed
count at+0x28 and a flag at+0x20. **It does not require remaining length zero.**
`0x5860bb0` forwards only the first32 bytes of that result: the success tag
and pair survive, while the consumed-count fields are not part of its output.
Consequently this path cannot be cited as a full-input-consumption check.

At the selected `0x5a806f0` producer path, call `0x5a80de7` invokes exactly
`0x5860bb0`; only tag0x12 reaches the pair path. Result+8 becomes R15 and
result+0x10 becomes R14. These same words are placed at stack+0x30/+0x38,
then passed as RDX to `0x5963aa0` at `0x5a80ede`. The writer loads the two
words and stores them at slot+0x10/+0x18. #7057 supplies the separate proof
that this writer and the selected consumer share the same slot allocation.

The first successful payload is therefore conditionally a Block plus
optional attachments **or** a raw Tx byte owner, according to the decoded
discriminator. This is not proof of which alternative occurs in a real
checkpoint, that a record is the first record after a restored height, or
that any payload/hash matches a trusted expected root.

## Validation and next consumer

`verify.py --target <captured-file>` verifies six full FDEs and one bounded
producer window,892 instructions,167 selected witnesses, the memcpy import,
the native enum label, and12 negative controls. Wrong variant, child callback,
reader identity, ownership shape, producer word, and slot offset alternatives
are rejected. These are static evidence checks, not execution or an automatic
semantic proof.

The intended downstream consumer is an independently checked replay fixture
that supplies the existing Block/attachment/raw-blob contracts and feeds the
identified shared slot. A new stand-alone decoder was not added: the reusable
attachment API is in an open prior PR, and the existing main Block API does
not independently expose this child. Copying those implementations would
duplicate ongoing work. Remaining work includes concrete input provenance,
child-contract integration, first-record/checkpoint relation, and root
validation; no full replay gate is claimed complete.
