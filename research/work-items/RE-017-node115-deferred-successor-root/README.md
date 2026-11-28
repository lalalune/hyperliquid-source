# Defer reconstruction of the successor root until the root gate

The integrated offline engine takes a supplied successor digest. Callers with reconstruction logic now have a separate entry point that asks for the digest only after the block advances, the comparison stage returns and the resulting height qualifies for root capture. The source receives read-only access to the updated fixture state. The existing input form still supplies its optional digest through the same path.

On the selected node #115 route, Begin writes height and round at `0x54838e5` and `0x54838f1`. The comparison call at `0x5a05c5e` precedes the finalizer's selector call at `0x5a05fc9`. The selector loads the current state and height at `0x5a07ed7`. Its eligible control flow calls the root helper at `0x5a07fce` and then uses the digest for the history write. [PR #7753](https://github.com/lalalune/hyperliquid-source/pull/7753) modeled H capture at construction. This change uses the existing fixture guards and its post-comparison root stage for H+1.

The synthetic test rejects a mismatched restored pair without calling the source. The same fixture then advances and computes a root from one reconstructed reduction row inside the deferred callback. The digest is checked against the hash of independently specified MessagePack bytes. A following ineligible height also avoids the source. This covers normal offline placement of root computation. It does not reconstruct all live state mutations, load a historical reference, or establish real H/H+1 parity.

## Reproduce

Linux x86-64 node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`. Run from the repository root.

```sh
python3 -B research/work-items/RE-017-node115-deferred-successor-root/verify.py
cargo test --offline --locked --manifest-path src/node115-abci/Cargo.toml
cargo test --offline --locked --release --manifest-path src/node115-abci/Cargo.toml --test deferred_successor_root
```

The [offline log](offline-log.txt) records the actual tests and static checks. No captured executable was run.
