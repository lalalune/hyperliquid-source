# Node #94 bincode varint component

This directory contains an independently authored Rust implementation of the
bounded integer-varint behavior established by the static RE-005 evidence. It
targets Linux x86-64 node #94, SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The unlicensed reference tree was not used as implementation source.

## Evidence-backed contract

The retained packet at
`research/work-items/RE-005-bincode-varint/` establishes these operations:

- u32 encoding and size selection at virtual addresses
  `0x27ab0a0..0x27ab2f5` and `0x4aa9ae0..0x4aa9c86`;
- u64 encoding and size selection at `0x27ab300..0x27ab64b` and
  `0x4aa9f80..0x4aaa2cb`;
- the u64 slice decoder fast path at `0x466bd10..0x466bdf5`, with a second
  inlined copy at `0x2558ee0..0x2559404`.

The observed encoding is minimal:

| value | bytes | encoded length |
| --- | --- | ---: |
| `0..=250` | the value byte | 1 |
| `251..=65_535` | `0xfb` + u16 payload | 3 |
| `65_536..=u32::MAX` | `0xfc` + u32 payload | 5 |
| `u32::MAX + 1..=u64::MAX` | `0xfd` + u64 payload | 9 |

The encode bodies conditionally byte-swap each multibyte payload. The Rust API
therefore exposes explicit little- and big-endian payload order. Marker bytes
do not change with payload order. The size operation is order-independent.

Only the little-endian u64 *slice fast path* is qualified for decoding. It is
entered only when `input.len() > 8`. It accepts tags below `0xfb`, reads u16,
u32 or u64 payloads for `0xfb`, `0xfc` or `0xfd`, and reports 1, 3, 5 or 9
consumed bytes. The observed straight-line arms perform no minimal-encoding
check, so non-minimal representations are accepted on this path. Markers
`0xfe` and `0xff` reach distinct target error construction paths; this
component reports both as rejected without assigning an unproved target error
type.

## Deliberately unsupported behavior

The existing `decode_u64_slice_fast` API returns `FastPathUnavailable` before
reading a tag when eight bytes or fewer remain. Its contract stays limited to
the fast slice path. Separate `read_u32` and `read_u64` APIs implement the Reader
paths established by the merged `RE-005-bincode-slow-widths` packet, as described
below; they do not silently change the older API's domain or error protocol.

The component does not implement u16/u128 decoding, signed/zigzag encoding,
fixed-width mode, serde integration, the
target error enum's Rust layout or caller/type mappings. It makes no binary-identity or
full-serialization-recovery claim and does not advance a progress gate.

## Established Reader paths

`read_u32(&mut &[u8], PayloadOrder)` and `read_u64(&mut &[u8], PayloadOrder)`
implement the direct Reader bodies `0x466d850..0x466d975` and
`0x466d980..0x466dabc`, plus the value effect of their shared 14-byte error
builder. Both little- and big-endian payload orders are qualified. Non-minimal
representations are accepted. An empty input needs one byte and consumes none.
For nonempty input the marker is consumed **before** payload checks and errors.
Short payloads remain unread; `UnexpectedEnd.needed` is the missing-byte count.
Success consumes the marker and the complete payload and retains the suffix.

The u32 Reader rejects markers `0xfd/0xfe/0xff`, with expected code 2 and found
codes 3/4/12. The u64 Reader accepts `0xfd` and rejects `0xfe/0xff`, with expected
code 3 and found codes 4/12. `ReaderError` is an independently authored research
representation of those payloads, not a recovered Rust enum layout. Notably,
the original u64 slice **fast** arm passes expected code 2 for `0xfe`, while its
Reader passes 3. Calling the Reader at every length is not a reconstruction of
that wrapper's length-dependent error selection.

The [Reader Rust packet](../../research/work-items/RE-005-bincode-reader-rust-94/README.md)
retains the pre-implementation fixture, complete-body hashes, real two-profile
build/comparison results, cursor/suffix checks and compiled corruption controls.
No captured node is executed or emulated by the new component runner:

```sh
python3 tools/bincode_reader_rust.py --rustc /path/to/rust-1.94.1/bin/rustc \
  --output /new/output/directory --controls
```

## Qualified slice-wrapper state

`SliceDecoder::from_state(input, mode, limit, charge)` is an own safe state
representation for the complete little-endian u32/u64 wrapper relation.
Its `read_u32` and `read_u64` methods preserve the observed error, remaining
slice and charge effects; `remaining()` and `charge()` expose the resulting
state. This does not recover the original state constructor or enum layout.

Raw mode 1 charges 4 or 8 before reading input. Overflow leaves charge unchanged;
exceeding the limit retains the increment. Both fail without consuming input.
Other raw modes bypass charging. Decoding errors do not roll charge back.
The counter is not a consumed-byte count.

More than 4/8 remaining bytes selects the u32/u64 fast relation. Rejected fast
markers remain unread; an available marker on the short Reader path is consumed.
Both fast wrappers report expected code 2, whereas the u64 Reader reports 3.
Successful fast inputs have the same value/suffix relation as the existing
little-endian Reader, which the safe implementation reuses after handling the
fast rejection distinction. No call-trace or target ABI identity is implied.

The [wrapper packet](../../research/work-items/RE-005-bincode-wrapper-state-94/README.md)
qualifies the charge prefix, full dispatch/error state and one existing request
caller's composition. Its 4,726 expectations were frozen before implementation.
The comparison adapter's request mode is not a public network decoder API.

## Intended API and build scope

The component is a standalone, dependency-free library crate rather than a
root workspace. Its public surface is limited to:

- `encoded_len_u32` and `encoded_len_u64`;
- `encode_u32` and `encode_u64`, appending to a caller-owned `Vec<u8>`;
- `decode_u64_slice_fast`, returning the decoded value and consumed length;
- explicit `PayloadOrder` and `DecodeError` types.
- direct `read_u32` and `read_u64` Reader relations with a separate `ReaderError`.
- `SliceDecoder` methods and `SliceError` for the qualified wrapper state relation.

The crate uses the repository-pinned Rust toolchain. Once the implementation
is present, build it from the repository root with:

```sh
cargo build --locked --manifest-path src/bincode-varint/Cargo.toml
cargo test --locked --manifest-path src/bincode-varint/Cargo.toml
cargo clippy --locked --manifest-path src/bincode-varint/Cargo.toml --all-targets -- -D warnings
```

The integration vectors are not produced by the reconstructed encoder. Their
expected marker, width, byte order and consumed length are transcribed from the
following independently verified node #94 instructions:

| property | target evidence |
| --- | --- |
| value `< 251` is one byte | `0x27ab0aa..0x27ab0c3`, `0x27ab30b..0x27ab325` |
| `0xfb` + u16 payload | `0x27ab0cf..0x27ab0fc`, `0x27ab331..0x27ab36f` |
| `0xfc` + u32 payload | `0x27ab128..0x27ab13a`, `0x27ab397..0x27ab3b9` |
| `0xfd` + u64 payload | `0x27ab3d4..0x27ab3f7` |
| 1/3/5/9 size thresholds | `0x27ab5b1..0x27ab623` |
| little-endian u16/u32/u64 loads | `0x466bd76`, `0x466bd8e`, `0x466bd82` |
| consumed 1/3/5/9 | `0x466bd53`, `0x466bd7a`, `0x466bd91`, `0x466bd86` |
| fast path requires more than 8 bytes | `0x466bd3d..0x466bd41` |
| `0xfe` and out-of-range error arms | `0x466bdc5`, `0x466bddd` |

`research/work-items/RE-005-bincode-varint/verify.py` authenticates those bytes
against the captured artifact before the Rust test results are interpreted.
