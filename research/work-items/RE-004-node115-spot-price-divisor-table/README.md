# Spot price decimal divisors in node 115

The single-price and dual-price conversion paths subtract the base token's byte at offset 0x48 from the quote token's byte at 0x49. On the successful path they zero-extend the difference and index a binary64 divisor with an eight-byte stride. The existing integrated asset API rejected exponents 20 through 255. In particular a quote with 20 wei decimals and a base with zero size decimals failed before either price could be converted.

| Consumer | Index | Divisor table |
| --- | --- | --- |
| Single price | 0x50bea47 | 0x91b7c0 |
| Dual, first price | 0x22f5e78 | 0x5ed748 |
| Dual, second price | 0x22f5f01 | 0x5ed748 |

Both 2,048-byte table ranges are identical. Repeated multiplication by ten in binary64 reproduces every entry. Rounding the exact integer power once matches only 61 entries. The integration regression passes each of the 256 exponent values to the metadata accessor and both conversion methods. Existing coverage exercises the zero fast paths, invalid pair and token bounds, and decimal underflow.

From the repository root, run the following commands.

```sh
path=research/work-items/RE-004-node115-spot-price-divisor-table
python3 "$path/replay.py" | diff - "$path/result.json"
cargo test --locked --manifest-path src/node115-assets/Cargo.toml
```

This describes the conversion routines on a supplied metadata row. It does not establish which token metadata combinations are admitted by the exchange. The packet uses the signed artifact as data.
