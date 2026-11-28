# RE-017 · Keep the collected #115 result prefix before the end marker

The [ABCI result bridge](../RE-017-abci-result-bridge-115/README.md) identifies the indexed input result rows and the native collector at `0x5b785d0`. The collector strips the input ordinal from each emitted row, keeping its reference and outcome vector. In an acquired offline observation, an empty ordinary group's outcome count and an end marker are different. The fixture can preserve the emitted prefix and its source ordinals without synthesizing absent responses.

| Selected collector input | Native result |
| --- | --- |
| First fetch's capacity equals `0x8000000000000000` | The first guard writes the empty descriptor of capacity 0, pointer 8 and count 0. |
| First ordinary row | A 56-byte output row includes the reference and the outcome descriptor. The output count initializes to 1. |
| Subsequent ordinary row | The output count increments and the append cursor moves by 56 bytes. An inner count of zero remains a field in the ordinary row and keeps its position. |
| Subsequent sentinel comparison or ring exhaustion | The collector exits the append loop and returns the previously saved capacity, pointer, and count through the result descriptor. |

The later sentinel and ring-exhaustion paths differ in how they reach cleanup. Neither path resets the accumulated count. `collect_full` takes caller-supplied observations in logical iterator order, returns the rows before the first explicit end, and records the source ordinals and stop position outside the JSON. The ordered source positions are fixture inputs. The code does not reconstruct the upstream sorter, in-memory layout, allocation, or cleanup. Its output feeds the existing Full JSON writer.

The offline fixtures emit an ordinary empty group following a nonempty group, then encounter the explicit end and preserve both rows. The second fixture shows how an immediate end and an empty supplied iterator yield the same JSON while retaining distinct evidence. The inputs are synthetic and make no H/H+1 state-root claim.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source base `2da45cb0a761cff6b478e40421699857d87a94df`.

## Reproduce

```sh
python3 -B research/work-items/RE-017-node115-replica-result-prefix/verify.py
cargo test --locked --offline --manifest-path src/node115-replica-response-json/Cargo.toml
```

The [raw offline log](offline-log.txt) contains the selected native branch checks and the crate tests.
