# Named oracle admission projection

`project_payload` projects four count lanes from an already successfully decoded payload; `project_tagged_action` also checks the selected 0x9e action tag and its eight-byte payload offset. The optional scalar fields distinguish the signed-minimum absent marker from a present zero-length descriptor. This small model does not decode the wire format, validate descriptor pointers, reproduce the prior admission gate, invoke its converter, or write oracle state. The existing admission work has no reusable source module in this baseline; its bound and gate evidence is credited in the companion packet. Original instruction and field provenance are in `research/work-items/RE-010-node115-oracle-named-admission`.

Run `cargo test --manifest-path src/node115-oracle-named-admission/Cargo.toml`.
