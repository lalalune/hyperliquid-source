# RE-017 · Project a decoded #115 replay Block into replica header values

The offline wire decoder and replica archive reader expose separate representations of the first replay Block. The selected native conversion ties them together. It preserves the decoded clock and proposer, projects the parent certificate's hardfork pair and saturated successor, and uses the replay worker's separate conversion cutoff for the archived `parent_round`.

Target Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source base `2da45cb0a761cff6b478e40421699857d87a94df`.

| Replica header field | Native route on the selected ordinary conversion |
| --- | --- |
| `time` | The wire Header decoder writes a qword and dword at Header `+0x110/+0x118`. The Block/owner copies move them to first owner `+0x120/+0x128`. Converter `0x4fad300` copies the 12 bytes to ABCI block `+0x38..+0x43`. |
| `proposer` | Header `+0x11c..+0x12f` becomes owner `+0x12c..+0x13f`. The converter's split 16+4-byte copy writes ABCI block `+0x44..+0x57`. |
| `hardfork.version`, `hardfork.round` | The converter chooses the same parent certificate offsets as the existing replay identity projection and stores its selected 16-byte pair at block `+0x28`. |
| `round` | The converter uses the saturated successor of the same basis as the existing replay parent projection, then stores it at block `+0x18`. |
| `parent_round` | The converter saves its incoming third argument (RDX) and stores it at block `+0x20`. The worker passes its retained cutoff in R15. The decoded parent certificate supplies a separate round for earlier receive classification. |

The worker copies the converted block from stack `+0x4f8` to `+0x320`. The selected record assembly stages the fields into an aggregate at `+0x1b0`, then moves them through `+0x60` into the record at `+0x290` without changing their relative offsets. The sink passes that record to the line and block serializers. The native archive's top-level sequential height is a distinct coordinate supplied outside this header projection.

The [wire grammar](../RE-001-node115-client-block-success-grammar/README.md), [parent selector](../RE-017-node115-replay-parent-projection/README.md), [converter cutoff state](../RE-017-node115-replay-cutoff-state/README.md), and [replica JSON fields](../RE-017-node115-replica-json-schema/README.md) establish the separate parts. The new result checks their byte-for-byte header joins and exposes `DecodedPrefix::project_replica_header` in the existing completed replay crate. The method takes an explicit conversion cutoff. The caller selects the ordinary conversion path before using the result. The existing record and attachment decisions remain independent inputs. No real archive block or root match is established here.

## Reproduce

```sh
python3 -B research/work-items/RE-017-node115-replay-wire-archive-header/verify.py
cargo test --locked --offline --manifest-path src/node115-replay-completed-payload/Cargo.toml
```

The verifier reads the pinned ELF as data, checks FDE boundaries, field names, calls and copy displacements. The Rust test passes the same synthetic Block through the plaintext and size-prefixed LZ4 paths and compares the resulting header values, including an exact nanosecond field. Changing only the supplied cutoff changes only the projected archive parent round. The Tx and decoder-error controls return no header. See [the actual run](offline-log.txt).
