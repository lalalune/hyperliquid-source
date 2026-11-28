# RE-017 · Align #115 archived Full results with an offline replay fixture

A `resps.Full` record can provide a secondary first-block outcome check before the project has a matching state-root reference. The archive's signed-bundle keys identify the rows, and individual results retain their order within each group. [Dwellir documents the bundle alignment](https://www.dwellir.com/docs/hyperliquid/data-catalog/node-feeds/blocks#important-fields).

Linux x86-64 #115 artifact SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, local base `3fb51aa8615503a2b8467f27978e87fe92e6e674`.

The [replica bundle](../RE-017-node115-replica-bundle-json/README.md), [response JSON](../RE-017-node115-replica-response-json/README.md), and [action result](../RE-017-node115-replica-action-response-status/README.md) packets describe the separate field shapes. [The existing Rust crate](../../../src/node115-replica-response-json/src/lib.rs) emits the response side. This packet implements the inverse comparison boundary from archive row and separately produced local response bytes, with checks that prevent confusing unavailable outcomes with empty successful comparisons.

The selected `signed_action_bundles` writer and the `Full` response-row writer both pass 32 bytes to the fixed-width lowercase hex adapter. In `Full`, each response row supplies its action-array pointer and count from `+0x28/+0x30`. The row stride is `0x38`, while the independently emitted action results use `0x40`. The selected result formatter writes `user` as 20 fixed bytes, with `res.status` selecting either a text `err` response or a structured `ok` response. The archive `null`, `Hash`, and `Full` arms remain distinct.

`compare(archive_line, replay_resps_json)` in [compare.py](compare.py) consumes one decompressed archive line and one independently produced local response value. It compares groups by exact bundle key, preserves the archive's deterministic reporting order, and compares each group's entries by action index. To ensure the comparison covers every action, it requires a unique matching set of keys and validates each group's individual count against the archived signed actions. These are comparison prerequisites for an unambiguous fixture. They do not assert that every valid archive producer always supplies a complete `Full` result. Differences identify the bundle, action index and changed fields. Numeric response fields retain exact decimal values, and JSON booleans remain distinct from numbers.

An empty `Full` response can match an empty bundle list. The `null` and `Hash` variants instead report the side on which per-action outcomes are unavailable. Outcome alignment is independent of archive-height selection, receipt derivation and state-root verification. This verifier uses synthetic comparison inputs. It makes no inference about the response hash preimage or execution of any genuine block.

## Reproduce

```sh
python3 -B research/work-items/RE-017-node115-replica-full-response-alignment/verify.py
```

The verifier reads the pinned ELF as data, checks the selected FDE-contained instructions, size operands, literal/relocation targets and call edges, and exercises complete, partial and differing synthetic results. See the [raw offline run](offline-log.txt).
