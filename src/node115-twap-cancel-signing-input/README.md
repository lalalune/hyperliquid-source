# node115-twap-cancel-signing-input

Owned Rust model of the node #115 function at `0x36aa9a0` on its `twapCancel`
path (raw action tag `0xa9`). One call takes a valid `twapCancel { a: u32, t: u64 }`,
the suffix record (nonce, optional 20-byte vault, optional expiry) and the chain
selector, and returns what the native function returns: the 32-byte inner
Keccak-256 digest, the one-byte chain tag (`0x61` when the selector's low byte is
3, otherwise `0x62`) and the record constant `0x539`.

```rust
use node115_twap_cancel_signing_input::{signing_input, Cancel, Suffix};

let out = signing_input(
    Cancel { asset: 1, twap_id: 2 },
    Suffix { nonce: 0x0102030405060708, vault: None, expires_after: None },
    3,
);
assert_eq!(out.tag, 0x61);
// digest = Keccak-256 of
// 83a474797065aa7477617043616e63656ca16101a17402010203040506070800
// = 5f07dac3d5e01782799cf9f3260ae8ce3d00107075fbef13fae3266c6abf38de
```

* `preimage` returns the exact bytes the native code hands to its Keccak update
  call (23 to 35 byte cancel map, then a 9, 18, 29 or 38 byte suffix; at most 73).
* `keccak256_short` is Keccak-256 (domain byte `0x01`) for messages shorter than
  the 136-byte rate; it composes the existing `node115-sponge-permutation`.
* `SigningInput::record_words` gives the 0x58-byte returned record as eleven
  little-endian words; the caller supplies the allocator-owned tag pointer.

No signing, outer EIP-712 hash, wire decoding or execution is modelled. Native
allocation, buffer growth, the `Result::unwrap` panic path and the register/stack
ABI are not reproduced; valid typed inputs and normally returning helpers are
premises.

## Credit and relation to earlier work

* `src/node115-sponge-permutation` (RE-009): the Keccak-f[1600] permutation, used
  unchanged as a path dependency through `permutation-adapter`.
* `RE-005-node115-rmp-signable-layout`: the 9/18/29/38-byte suffix rule; it left
  the writer-produced prefix open, which is closed here for `twapCancel`.
* `RE-001-node115-noop-preimage`: the one-block absorb/finalize reading, here
  re-checked for every input length below the rate. Its `Preimage` type is
  private to that crate, so the suffix is written again here.
* `src/node115-twap-action-wire`: models the cancel action through the *other*
  writer copy (`0x46ac020`). It is used only as a dev-dependency consistency
  check, not for production bytes, because the two copies are different code; see
  the evidence packet.

## Verification

`tests/oracle/corpus.tsv` (665 rows) was generated and hashed by an independent
Python oracle (`oracle.py` in the packet) before this source existed.

```sh
cargo test --offline --locked --manifest-path src/node115-twap-cancel-signing-input/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-twap-cancel-signing-input/Cargo.toml
```

Evidence, static target checks, the mutation harness and limits:
[`research/work-items/RE-005-node115-twap-cancel-signing-input/README.md`](../../research/work-items/RE-005-node115-twap-cancel-signing-input/README.md).
