# RE-017 · Node #115 replica action metadata scalar projection

The replica bundle, signed-action, and signature field names are established in [#4154](https://github.com/lalalune/hyperliquid-source/pull/4154), [#4160](https://github.com/lalalune/hyperliquid-source/pull/4160), and the [signature field evidence](../RE-017-node115-replica-signature-json/README.md). This packet follows the additional scalar value writers and projects an archived record into an ordered fixture. The mainline archive tools select/count JSONL records and retain JSON text. Comparing their per-action values against a typed replay fixture requires a separate, lossless conversion of the supported metadata.

The selected #115 `broadcaster_nonce` call at `0x53cafae` and `nonce` call at `0x5923464` both reach `0x5079ee0`, which loads a qword at `0x5079f8c` and calls `0x4dfe400`. That formatter uses unsigned comparisons and writes decimal digits with up to 20 places. The present `expiresAfter` path selects `0x50796a0`, loads its qword from `+8` and calls the separate unsigned decimal formatter `0x595a3b0`. All three fields accept a JSON integer in the unsigned 64-bit range in the fixture.

The `broadcaster` and present `vaultAddress` paths pass width 20 and capacity 42 to `0x4e1c250`. The selected fixed-width adapter clears the trim input before resolving the hex formatter through `.rela.dyn`, and the formatter's table is lowercase. This retains leading address zeroes, just as the enclosing 32-byte bundle key path retains all its digits. The present `isFrontend` path tests the low bit at `0x5079d6c` and writes the JSON literal `true` or `false`. An omitted field remains distinct from a false boolean or a zero expiry.

[project.py](project.py) consumes one selected, decompressed JSON record as bytes and returns ordered `Bundle` and `SignedAction` values. Bundle and action order stay stable. Compact signature integers expand to 32-byte big-endian values and `v` retains its observed byte value. The opaque `action` JSON values use exact decimal parsing and are not transcoded into a native action. Optional fields omitted by the native writer become `None`. The reader expects the native observed scalar spellings and can reject provider-specific projections that omit required fields or replace omitted fields with explicit nulls.

This intermediate fixture does not reproduce a signed preimage, cryptographic validation, native replay framing, or a state root. The verifier uses synthetic JSON controls and pinned native bytes. A sourced raw H+1 JSON line and matching checkpoint/root evidence remain separate inputs.

## Reproduce

Linux x86-64 #115 artifact SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, based on `2da45cb0a761cff6b478e40421699857d87a94df`.

From the repository root, use the digest/FDE verifier and checked fixture controls:

```sh
python3 -B research/work-items/RE-017-node115-replica-typed-bundles/verify.py
```

See [offline-log.txt](offline-log.txt) for the actual run. The verifier reads the target ELF but executes only the Python verifier and projection.
