# Paired fixed-byte source relation

The independent pre-Rust `preparation/independent-PROOF.md` establishes the
complete native relation of 102-byte `[0x466c140,0x466c1a6)` and 115-byte
`[0x466c1b0,0x466c223)`. Their combined extent is 217 bytes/69 instructions.
This proof relates the new safe Rust functions to that relation; it does not
recover original source types, Rust enum layout, pointer ABI or caller semantics.

The normal domain supplies a valid immutable slice of initialized bytes and
separated initialized writable result storage: exactly the selected 21-byte
or 33-byte projection. Native reader/control/code/data storage has separated
valid roles and nonwrapping address formations; slice length is at most
isize::MAX. No fault, unwind, concurrent change, arbitrary alias or observation
of uninitialized caller bytes is admitted. This stronger supplied-buffer
domain makes every untouched result byte observable as its supplied value.

Native mode is the dword at reader+0, not a full qword. `mode: u32` supplies
exactly that word, with all bit patterns admitted as machine-state controls.
It does not assert which values were valid source enums. Bytes+4..7 are not
accessed by either native leaf and do not enter the portable interface. Limit
and charged count correspond to unsigned64 fields at+8/+32. The slice covers
the pointer/length projection at+16/+24, without exposing native addresses.

`charge_permitted` first bypasses every mode except exactly1. For mode1,
`checked_add(N)` fails precisely when C>u64::MAX-N, without storing C. Otherwise
the sum is stored before comparison with limit. Thus a limit error retains
the charge, as does every later length error. The three charge cases partition
all u32/u64 inputs, including initially over-limit counts; no relation between
budget and slice length is assumed. Existing kind5 Reader Rust already covers
the analogous charge8 pattern; this new family does not claim that policy's
discovery or reuse an unrelated varint operation as a fixed-byte substitute.

After a permitted charge, `input.len()<N` produces a shortfall in1..N and
leaves the slice unchanged. Conversion to u64 is exact because N is20 or32.
The complementary length case makes every copied source index valid. The
fixed destination ranges are valid by the array types. Payload bytes retain
their original order, and the slice advances exactly N. Source copy/tag/cursor
store order differs from native order but has the same final state under the
separated initialized roles and no-fault/concurrency premises.

The two result write sets are intentionally distinct. `read_20` writes only
out[0]=2 on charge; on shortage it writes0 at+0 and little-endian needed at
+8..16; success writes18 at+0 and the20-byte prefix at+1..21. `read_32` writes
outer1 at+0 and nested2 at+8 on charge; shortage writes outer1, nested0 and
little-endian needed at+16..24; success writes outer0 and32 payload bytes at
+1..33. `copy_from_slice` and `to_le_bytes` implement these exact final bytes.
There is no clearing of any other byte. Their equality with the native complete
write sets proves preservation for every supplied initial result bit pattern.
It does not claim that real callers' inactive bytes were initialized.

`Outcome` is an own logical route enum. Its representation is never treated as
native output. The observer formats that route together with the actual safe
result array, charged count and residual slice; it receives only the raw eight
stimulus fields. Induction applies the same per-call relation to every residual
state, including repeated errors, successful-prefix retention and eventual
charge overflow. The frozen finite protocol limits calls to1..4; the per-call
source theorem is not restricted to the finite corpus's allocated lengths.

The library is no_std, allocation-free and dependency-free. The observer and
ordinary test harness use std. Their concrete compiler/provider recipe is a
research build, with no original toolchain, freestanding integration, target
byte-identity, whole-codec/node or full-component gate claim.
