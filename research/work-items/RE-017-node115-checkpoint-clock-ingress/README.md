# RE-017 #115 checkpoint clock text ingress

The [positional Context adapter](https://github.com/lalalune/hyperliquid-source/pull/7536) obtains two exact checkpoint clock strings and leaves native word construction open. The existing [checkpoint clock crate](../RE-009-node115-render-checkpoint-clock/README.md) implements the reverse conversion. This patch gives the crate a text-to-words entry and stages both clocks into a decoded restore fixture in the observed order.

The [MessagePack clock path](../RE-009-node115-msgpack-clock-text-path/README.md) and [JSON clock path](../RE-009-node115-json-time-format-items/README.md) converge on the same constructor. The [constructor analysis](../RE-009-node115-time-component-projection/README.md) separates the packed date, seconds of day and nanosecond words. `parse_checkpoint_clock` uses the existing target-validated CE-day constructor for the date. It accepts the selected positive four-digit Gregorian year, uppercase `T`, and optional one-to-nine-digit fraction. The second-60 arm retains second 59 and adds one billion nanoseconds, as in the selected native arithmetic. This does not validate an actual leap-second occurrence.

`stage_decoded_clock_pair` uses a caller-pinned `0x27a8`-byte fixture and checks its height at `+0x28`. It validates both clock strings before writing their three little-endian dwords to `+0x60` and `+0x6c`. No other bytes change. [The positional clock evidence](../RE-009-node115-positional-context-clock-pair/README.md) and [compact assembler](https://github.com/lalalune/hyperliquid-source/pull/7375) establish the selected transfer into the compact state.

```sh
python3 -B research/work-items/RE-009-node115-msgpack-clock-text-path/verify.py
python3 -B research/work-items/RE-009-node115-time-component-projection/verify.py
python3 -B research/work-items/RE-009-node115-positional-context-clock-pair/verify.py
python3 -B research/work-items/RE-009-node115-render-checkpoint-clock/verify.py
cargo test --offline --locked --manifest-path src/node115-checkpoint-clock-text/Cargo.toml
```

The log includes native static controls, Rust regression tests, and a composition from the exact two positional MessagePack texts through the Rust stager and compact assembly. The selected text syntax, source provenance and synthetic output support a bounded fixture transition. Full native calendar parser acceptance, historical clock values, and checkpoint/replay root parity remain open. No captured instructions are executed.
