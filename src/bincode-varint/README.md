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

When eight bytes or fewer remain, the target branches to a reader-based slow
path whose semantics are not established by the retained evidence. The Rust
decoder returns `FastPathUnavailable` before reading a tag in that case. This
includes empty and apparently truncated inputs: classifying them as EOF,
truncation or another target error would extend the claim beyond the binary
evidence.

The component does not implement u16/u32 decoding, u128 or signed/zigzag
encoding, fixed-width mode, serde integration, the reader slow path, target
error enum values, or caller/type mappings. It makes no binary-identity or
full-serialization-recovery claim and does not advance a progress gate.

## Intended API and build scope

The component is a standalone, dependency-free library crate rather than a
root workspace. Its public surface is limited to:

- `encoded_len_u32` and `encoded_len_u64`;
- `encode_u32` and `encode_u64`, appending to a caller-owned `Vec<u8>`;
- `decode_u64_slice_fast`, returning the decoded value and consumed length;
- explicit `PayloadOrder` and `DecodeError` types.

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
