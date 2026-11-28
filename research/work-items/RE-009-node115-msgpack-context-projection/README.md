# RE-009 · Stream a named node #115 MessagePack checkpoint into Context root comparison

The native periodic checkpoint path produces named MessagePack. This adapter reads its selected `exchange.locus.ctx` map and projects all 13 root-comparison fields without materializing unrelated state. The checkpoint SHA-256 is measured on the stream supplied to the parser. The requested height must equal the decoded Context height, and the parser must consume exactly one top-level object.

The scanner skips unselected values and checks retained-field duplicates. The named reader maps `initial_height` and `hardfork_height` to one field, distinct from the checkpoint height. The two Context round names share another field. The `hardfork` child supplies two separate words; both `time` and `prev_time` keep exact nanoseconds and signed epoch seconds. Nil transaction index remains absent and zero remains present. The pinned [#7368 Context normalizer](https://github.com/lalalune/hyperliquid-source/pull/7368) applies the same typed ordinary-clock contract to the streamed values.

[#7320](https://github.com/lalalune/hyperliquid-source/pull/7320) extracts height and round in the named MessagePack fixture. [#7368](https://github.com/lalalune/hyperliquid-source/pull/7368) covers all root fields in the JSON form. The [native MessagePack clocks](../RE-017-node115-messagepack-context-clocks/README.md), [hardfork pair](../RE-017-node115-checkpoint-hardfork-pair/README.md), and [binary Context reader](../RE-009-abci-binary-context-115/README.md) supply the relevant field boundaries. The new adapter covers the complete normal Context input for [#7352](https://github.com/lalalune/hyperliquid-source/pull/7352) from the decoded periodic archive payload. It also supplies the restored-side input for [#7420](https://github.com/lalalune/hyperliquid-source/pull/7420).

Supply the decoded ordinary named `.rmp` artifact, such as a payload extracted by [#7317](https://github.com/lalalune/hyperliquid-source/pull/7317). Positional checkpoints, alternate codec extensions, leap-second captures, full checkpoint acceptance and provenance remain outside the adapter. Only synthetic fixtures were available. No actual H/H+1 equality is claimed.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Base `2da45cb0a761cff6b478e40421699857d87a94df`.

## Reproduce

From repository root, the default verifier reads only the pinned ELF. The fixture checks use `msgpack 1.1.2`, the [#7368 helper at its published head](https://github.com/0xQueenQ/hyperliquid-source/blob/5d79a3479712e0db9cc61ff1ff7e788b566254be/research/work-items/RE-009-node115-checkpoint-context-projection/project.py), and Rust 1.95 for the optional Context comparison.

```sh
packet=research/work-items/RE-009-node115-msgpack-context-projection
python3 -B "$packet/verify.py"
python3 -B "$packet/verify.py" --normalizer PATH_TO_7368_PROJECTOR --root-packet PATH_TO_7352_PACKET
python3 -B "$packet/project.py" PATH_TO_7368_PROJECTOR CHECKPOINT.rmp \
  --sha256 CHECKPOINT_SHA256 --height HEIGHT
```

The [measured offline log](offline-log.txt) records the native joins, a synthetic checkpoint with more than two megabytes of skipped auxiliary state, exact field projections and the actual downstream Context comparison. It also records selected invalid-input controls.
