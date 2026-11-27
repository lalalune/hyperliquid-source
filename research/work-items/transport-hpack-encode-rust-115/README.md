# transport-hpack-encode-rust-115: encoder-only HPACK Rust reconstruction for node #115

- Component ID: `transport`
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Base commit: repository `6a6033dff2faf2f0dc7f3dcd5f9cead63d472b54`
- Source commit / reference commit: encoder evidence source `0781ce04826eeefd89fe336cb8ea073be0c1de30` (PR #5981); no reference source was copied.
- Claim status: observation / inference / unresolved, separated below.
- Scope included and excluded: see the explicit lists below.

This packet records the independently authored, encoder-only Rust crate
`src/node115-hpack/` and its frozen comparison data. It reconstructs the three
observed HPACK encoder functions and the Huffman code table used by node #115.
It does not reconstruct the decoder, the dynamic table, or the header-block
encoder, and it does not claim binary equivalence.

**No component gate change is requested or made.** This packet does not modify
`src/net-utils/`, `research/progress.json`, or `research/components.json`.

## Observation

- Target artifact SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- `huffman_encode` at `0x179d760`, FDE end `0x179d8fc`, 412 bytes.
- `encode_str` at `0x17acf90`, FDE end `0x17ad371`, 993 bytes.
- `encode_literal_name_index` at `0x17ad380`, FDE end `0x17ad504`, 388 bytes.
- Huffman table at `.rodata` `0x487490`: 257 entries, each a 16-byte record
  `(bits, code)` as two little-endian `u64` values. The table's Kraft sum is
  exactly 1, its left-aligned codes are prefix-free, and its anchors include
  symbol 0 = 13 bits `0x1ff8`, `' '` = 6 bits `0x14`, `'0'` = 5 bits `0x0`,
  `'a'` = 5 bits `0x3`, and EOS = 30 bits `0x3fffffff`.
- The observed encoder behavior is:
  - Huffman codes are appended most-significant bit first; complete bytes are
    flushed; the final partial byte is padded with one bits.
  - An empty string literal is the single byte `0x00`. Otherwise the Huffman
    body is prefixed by `0x80 | len` when `len < 127`, or by `0xff` followed by
    a 7-bit continuation varint of `len - 127` when `len >= 127`.
  - A literal with an indexed name uses the low 4-bit prefix: index `<= 14` is
    one byte (`0x10` set when sensitive); index `>= 15` writes `0x0f`/`0x1f`
    followed by a 7-bit continuation varint of `index - 15`; the value follows
    as a length-prefixed Huffman string.
- The PR #5981 evidence packet reports 10,139 generated cases, 109 controls,
  104 detected, 5 explained equivalents, and 0 unexplained mismatches.
- The frozen `cases-sample.tsv` used by this packet has 3,932 sampled cases
  (every second case with input at most 60 bytes and output at most 64 bytes).
  Its SHA-256 is
  `aa5f3ff5a3b66a60e886d136c1a54872cab525ec4b2e900b8a18d6e1870a497f`.
- The source `huffman-table.tsv` SHA-256 is
  `8e49043b29f18281f49a1047b6fb6ce9aa81f7024e1cdfda8d4b17987b26cefa`.

## Inference

- The Rust function names `huffman_encode`, `encode_str`, and
  `encode_literal_name_index` are descriptive names for the observed behavior;
  they are not recovered symbol names.
- The Rust crate is an independent MIT implementation of the observed wire
  behavior. It is not a source transplant and has no target ABI or binary
  equivalence claim.
- The public API is append-only over `Vec<u8>`; the destination prefix is
  preserved, matching the sampled BytesMut append behavior.
- The Rust implementation is encoder-only. It does not infer or implement the
  decoder, dynamic-table state, or the header-block encoder.

## Unresolved

- The full 10,139-case set has not been rerun against the Rust crate. Only the
  3,932 sampled cases were executed.
- `artifacts/node/115/hl-node` is a Git LFS pointer and has not been
  materialized as the 105,896,032-byte target. No live target execution,
  byte-window comparison, or whole-binary comparison was performed.
- Runtime reachability, caller-side header-block behavior, dynamic-table
  interactions, and end-to-end HTTP/2 behavior remain outside this packet.
- No component gate, byte-coverage credit, or binary-equivalence claim is made.

## Scope included and excluded

Included:

- `huffman_encode` `0x179d760`
- `encode_str` `0x17acf90`
- `encode_literal_name_index` `0x17ad380`
- Huffman table `0x487490` (257 entries)
- The independent Rust crate `src/node115-hpack/` and its frozen comparison
  data

Excluded:

- Encoder dynamic-table functions `0x17aca30`, `0x17acc80`, `0x17ac730`
- Header-block encoder `0x17ad510`
- Every decoder function, including the PR #5998 decode path
- HTTP/2 I/O, async runtime, logging, allocation strategy, and live target
  execution
- Any change to `src/net-utils/`, `research/progress.json`, or
  `research/components.json`

## Reproduce

From the repository root:

```sh
cargo test --offline --manifest-path src/node115-hpack/Cargo.toml
cargo fmt --check --manifest-path src/node115-hpack/Cargo.toml
(cd research/work-items/transport-hpack-encode-rust-115 && sha256sum -c MANIFEST.sha256)
```

The crate is standalone, has no dependencies, uses edition 2024 and
`rust-version = "1.95"`, and contains `[workspace]` to isolate it from any
parent workspace. The test harness reads the frozen sample at
`research/work-items/transport-hpack-encode-115/cases-sample.tsv` and checks
the appended bytes, the unchanged destination prefix, RFC 7541 Appendix C.4
vectors, empty/literal boundaries, and Huffman-table anchors.
`MANIFEST.sha256` covers this packet and the crate files through
`../../../src/node115-hpack/...` paths.

Observed test result: 4 tests passed, 0 failed. The sampled-case test covers
3,932 of 3,932 sampled cases. The full 10,139-case set is not rerun because the
target artifact is still a Git LFS pointer. See [comparison.tsv](comparison.tsv)
and [test-output.txt](test-output.txt).

## Evidence

| Role | Entry | FDE end | Bytes |
| --- | --- | --- | --- |
| `huffman_encode` | `0x179d760` | `0x179d8fc` | 412 |
| `encode_str` | `0x17acf90` | `0x17ad371` | 993 |
| `encode_literal_name_index` | `0x17ad380` | `0x17ad504` | 388 |

The 257-entry table at `0x487490` is recorded in the PR #5981 packet's
`huffman-table.tsv`; the Rust crate embeds the same `(bits, code)` entries and
asserts the public anchors. The table is not re-derived from a running node.

The frozen [vectors.tsv](vectors.tsv) contains 31 representative sampled cases
from `cases-sample.tsv`, including single-symbol Huffman, prefixed
`huffman-random` output, empty and multi-byte strings, indexed-name literals at
index 0/1/2/14/15/143, sensitive flags, large indexes, and destination
prefixes. It is a review subset, not a replacement for the full sample.

## Implementation and comparison

- Crate: `src/node115-hpack/`
  - `Cargo.toml`
  - `README.md`
  - `src/lib.rs` (`#![forbid(unsafe_code)]`, `pub mod encode;`)
  - `src/encode.rs`
  - `tests/frozen_cases.rs`
  - `Cargo.lock`
- The Rust encoder has no dependencies and no unsafe code.
- `comparison.tsv` records per-family sample counts: 839 huffman-random, 128
  huffman-single, 60 literal-boundary, 1,268 literal-random, 450 literal-sweep,
  1,156 string-random, and 31 string-sweep cases.
- All 3,932 sampled cases match; there are no mismatches in this run.
- RFC 7541 Appendix C.4 vectors and the literal index boundaries 14/15 and
  143 are independently frozen in the test.
- The full 10,139 cases and the target binary comparison are not measured here.

## Results and limitations

- Sampled encoder cases: 3,932 / 3,932 passed, 0 failed.
- Full PR #5981 cases: 10,139 / 10,139 not rerun against Rust.
- Rust tests: 4 passed, 0 failed.
- No target execution and no binary equivalence claim.
- The target artifact is a Git LFS pointer; `artifacts/node/115/hl-node` was not
  materialized.
- The packet requests no component gate change and makes no progress/catalogue
  edit.
- Next question: after the target artifact is materialized, can the full
  10,139-case stream be regenerated and compared against this crate without
  changing the observed encoder semantics?
