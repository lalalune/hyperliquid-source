# Level replacement record to selected tag-2 consumer

Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; base `a8616af9432b8d8517b2af677880e117b7c28ef3`. Partial RE-006 advance of HL115-092. The captured program was never executed or emulated.

[#2249](https://github.com/lalalune/hyperliquid-source/pull/2249) maps the equality gate, quantity store, append, and aggregate updates of `0x25da200`/`0x25da3e0`, explicitly leaving record schema and consumers open. This packet does not repeat the arithmetic. It binds the initialized record-prefix bytes to their sources and follows the selected tag-2 record through the corresponding spot and perpetual flushers. TWAP's distinct tag-4 cleanup is treated separately in #6637.

## Producer fields

Both producers compare new RDX to object `+0xe0`; equality returns before a record. Otherwise they write the new quantity first, stage the following fields and append a 712-byte (spot) or 696-byte (perpetual) record. The table gives offsets from the outer record start:

| Offset | Selected initialized bytes | Observed source |
| --- | --- | --- |
| `+0x00` | qword 2 | outer raw tag |
| `+0x08` | qword 2 | nested raw tag |
| `+0x10`, `+0x18` | two qwords | old `object+0xe0`, new RDX |
| `+0x20`, `+0x28`, `+0x30` | three qwords | `object+0xb0`, incoming RSI, `object+0xf0` |
| `+0x38..+0x4b` | 20 bytes | `object+0xf8..+0x10b` |
| `+0x4c` | byte | `object+0xd2` |

Bytes `+0x4d..+0x4f` and the remaining record are not asserted initialized. The words and identity bytes are not assigned semantic field names beyond their proven origins.

## Selected downstream handoff

The original flushers use indexed signed-relative tables: tag 2 selects `0x241a500` for the 712-byte route and `0x241997c` for the 696-byte route. Each copies the 72-byte payload beginning at record `+8` into a selected stack result, retaining the tag and the fields above; this byte-copy includes three unqualified trailing bytes, not evidence that those bytes have values. On the subsequent normal-return path the flushers call `0x282bee0` and `0x282c3a0`. Their tag-2 table entries point directly at return blocks (`0x282c31f` and `0x282c7df` respectively), with no memory write or call in the selected return blocks. Intervening constructors, preceding bounds checks, other event tags, allocation and cleanup/unwind effects remain outside this result. In particular, the early quantity store and the later aggregate update do not establish outer commit or rollback.

`src/node115-level-change-record` projects the selected initialized prefix using `Option<u8>` so no value is invented for the three unqualified bytes. Its `replacement` returns no record on equality and otherwise records the explicit field provenance; `selected_consumer_payload` supplies the 72-byte projection. It does not model native allocation, vector growth, helper effects, full event layout or the previously proved aggregate arithmetic. The selected downstream immediate return is a control-flow observation, not a claim that the entire flusher has no effects.

The static verifier binds 11 windows (1,155 bytes / 231 instructions), 97 facts and 40 changed-byte controls to the full target digest, including both producer copies, four jump-table entries and selected consumer return blocks. Two Rust tests cover both route widths, exact field offsets, equality, all 160 individual identity bits and inactive-byte masking. These check the logical projection, not native runtime equivalence. No full component/backlog gate is advanced.

```sh
PYTHONPATH=/path/to/capstone python3 research/work-items/RE-006-node115-level-change-record-handoff/verify.py --target /path/to/original/hl-node
cargo test --offline --manifest-path src/node115-level-change-record/Cargo.toml
cargo test --offline --release --manifest-path src/node115-level-change-record/Cargo.toml
```
