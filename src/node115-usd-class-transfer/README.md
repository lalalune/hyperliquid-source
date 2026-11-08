# node115 UsdClassTransfer signed-action body

This standalone crate implements the signed-action body at VA `0x240ad50` in
`research/work-items/RE-015-signed-action-rmp-encoders-115`. The bound target is
node #115 SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

The packet records this field order: `signatureChainId`, `hyperliquidChain`,
`amount`, `toPerp`, `nonce`. Map mode includes the enum tag and field names;
array mode omits those keys. The action label `UsdClassTransfer` is inferred
from the packet. The API leaves the tag and variant values caller-supplied and
accepts the chain ID in the target's 32-byte little-endian storage form.

Tests compare complete output bytes against packet cases 0 and 25. The expected
output SHA-256 values are `d5b390ac8e27e870b881645332abad0da9c4020d2c648f8f3d926eed98efcfaf`
and `a0aa47b509fb8bc9c093540a483c299d2d36090fc3bc68ab246a8d62339d1326`.
These vectors come from the committed static evidence packet; the captured
binary was not executed or emulated by this crate. This crate covers only this
body, not the remaining signed-action bodies or the signing/hash path.

Run from the repository root:

```sh
cargo test --manifest-path src/node115-usd-class-transfer/Cargo.toml
```
