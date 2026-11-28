# RE-017 #115 replay begin rotates the restored clock pair

The [checkpoint reader](../RE-017-node115-messagepack-context-clocks/README.md) restores Context `time` and `prev_time` as consecutive 12-byte values. The [selected begin-path evidence](../RE-017-abci-preflight-result-115/README.md) identifies the comparison and rotation. The existing Rust checkpoint-clock crate rendered a single supplied clock. It now has an offline adapter for applying the replay input to the whole restored pair.

Target Linux x86-64 node #115 with SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. The two wrapper calls at `0x5a04fe9` and `0x5a067ad` enter begin functions at `0x5483850` and `0x5483f50`. The 100-byte pair-update windows at entry `+0x1f..+0x82` are byte-identical in both layouts. The verifier checks the original bytes, five branch targets and both wrapper call edges.

The selector compares the packed date as signed, then seconds and nanoseconds as unsigned. Only a strictly later input copies all 12 current bytes at state `+0x60` to previous at `+0x6c` and installs the incoming clock at `+0x60`. An older or equal input bypasses every field store before reaching the ordinary height-advance instruction. The Rust comparator keeps the full packed date word and uses the same order.

## Reproduce offline

```sh
python3 -B research/work-items/RE-017-node115-replay-clock-rotation/verify.py
cargo test --offline --locked --manifest-path src/node115-checkpoint-clock-text/Cargo.toml
```

Tests start with both restored clocks and apply synthetic replay input. They check equal input, older inputs at each of the three comparison levels, a nanosecond advance, a date advance and dates on opposite sides of the signed date boundary. The existing formatter reads one advanced value back as canonical text. The [instruction windows](instructions.tsv) and [offline log](offline-log.txt) include the pinned evidence, base diagnostic and new behavior. The adapter applies the two clock stores only. Other begin effects and H/H+1 root equality remain outside this check.
