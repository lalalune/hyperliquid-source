# RE-005: join selected node 115 Gossip response decoders

This partial #3907 contribution joins previously separate logical decoders for
three outer response routes into `src/node115-gossip-response-composed`.
Nested Result success remains an explicit selection boundary: its payload is
not decoded, so this is not a complete response or issue closure. All full
component gates remain false.

Target Linux x86-64 node #115, 105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`.

## Raw tags and existing work

The parent `0x5aac7c0..0x5aacc22` calls the u32 reader `0x5821150` at
`0x5aac7d5`. On its success tag 0x12 it loads the decoded u32 at output+4.
Raw 0 branches at `0x5aac7ec` to nested Result selection; raw 1 branches at
`0x5aac7f5` to `0x5aac8fb`, which calls the address-vector decoder
`0x4de6210` at `0x5aac901`; raw 2 enters the existing option/record path.
At the nested selection, raw 1 branches to the ClientBlocksError decoder and
raw 0 enters the separately delegated success payload. The fast u32 path's
byte load and output+4 store are retained to distinguish raw wire tags from
local labels. The existing u32 reader supplies the corresponding slow path.

This corrects the historical outer-tag labels in #2795 and #2790: their
inner decoder APIs start after outer selection and are unchanged. #2784 owns
the variant-2 envelope; #2795 owns the full selected vector payload; #2790
owns the seven-arm nested error payload. This contribution reuses their real
source and behavior rather than reimplementing those children. See the crate
README for the byte-identical reader-adapter and Cargo path-collision details.

## Evidence and tests

`records.json` retains five selected instruction windows: 303 bytes and 76
instructions, with enclosing FDE ranges and exact bytes. The verifier checks
21 facts and rejects seven independent in-memory semantic corruptions with the
whole-image/window checks bypassed during each control. These are static
checks; neither captured instructions nor emulation run. Full enclosing FDEs,
complete error-object ABI, allocation/unwind, networking, all response
payloads and integrated node behavior are not claimed. Descriptive type names
come from earlier packets and do not establish field units.

```sh
python3 research/work-items/RE-005-node115-gossip-response-composition/verify.py
cargo +1.95.0 test --locked --offline --manifest-path src/node115-gossip-response-composed/Cargo.toml
```

The verifier requires the hydrated target and existing Capstone 5.0.7; the
Rust build uses only local path dependencies and an installed Rust 1.95.
Tests cover raw tag routing, actual vector and error children, all seven nested
error variants, charge/cursor on failures, and unconsumed suffixes.
