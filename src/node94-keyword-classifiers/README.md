# node94 keyword classifiers

One dependency-free, safe `no_std` Rust component reconstructs three
existing classifier leaves with their shared two-byte output contract:

| Selector | Leaf start | Tag 0 | Tag 1 |
|---|---|---|---|
| `UntilRequiredMatches` | `0x1437b90` | `until` | `required_matches` |
| `VipMm` | `0x1e6d560` | `vip` | `mm` |
| `InputGasLimit` | `0x25903d0` | `input` | `gas_limit` |

Every other input has tag 2. Full 64-bit length tests precede input
access; other lengths do not require readable input memory. The API
classifies the initial selected bytes, then writes `[9, tag]`, and returns
the exact numeric output address corresponding to RAX.

```rust
pub fn classify(
    image: &mut [u8], image_base: u64, output: u64,
    input: u64, length: u64, classifier: Classifier,
) -> Result<u64, AccessError>;
```

One nonwrapping numeric image supports arbitrary input/output overlap.
Required input and output spans must fit contiguously. Every error leaves
the image unchanged; this is a new safety policy, not captured fault
behavior. The library allocates nothing and forbids unsafe code. The
[proof](../../research/work-items/RE-004-keyword-classifiers-rust-94/PROOF.md)
gives the full domain, exact bytes/constants, SIMD equality argument,
memory relation and ABI limits.

The actual qualification pins rustc 1.94.1 commit
`e408947bfd200af42db322daf0fadfe7e26d3bd1`, its executable hash and the
aarch64-apple-darwin host. From the repository root with a fresh output
directory:

```sh
python3 -B research/work-items/RE-004-keyword-classifiers-rust-94/verify_rust.py \
  --rustc /path/to/1.94.1-aarch64-apple-darwin/bin/rustc \
  --out work/keyword-classifiers-rust/replay
```

This directly builds the library and a separate input-only std client
at opt-level 0 and 3, with warnings denied and overflow checks enabled.
No invented workspace, dependency lock or captured execution is needed.
The client consumes 98-byte rows: classifier byte, four u64 values
`(image_base, output, input, length)`, admitted image length byte and 64
backing bytes. It emits a tag byte, u64 result and complete 64-byte image.
Error tags 1/2/3 denote ImageRange/Input/Output with numeric zero as a
placeholder. Malformed rows are refused before any output; the client
does not receive expected answers.
