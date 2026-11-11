# RE-001: node115 gossip variant JSON writer — ClientBlocks object form versus Peers and GossipStatus string forms

Component: consensus / gossip. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, 105,896,032 bytes.
Base main: `05bc2de303c05525b71e7e257426e741bc66a390`.

The serializer body at `0x5a80370` reads the eight-byte discriminant at its input
object and selects exactly one of three JSON text forms. A zero discriminant
takes the object form: it writes `{`, `"`, the exact 12-byte name `ClientBlocks`,
`"`, `:`, `{`, then serializes two fields in fixed order through helper
`0x50783d0` — first the field at input+0x8 under the exact 11-byte key
`start_round`, then the field at input+0x10 under the exact 9-byte key
`end_round` — and closes both braces. A discriminant whose low 32 bits equal 1
writes only the quoted 5-byte string `Peers`. Every other discriminant value
writes only the quoted 12-byte string `GossipStatus`. The zero test is on the
full 64-bit value while the `Peers` comparison reads the low 32 bits, so a
discriminant of 0x100000000 takes the `GossipStatus` form, not the object form.
No source-level type name is invented for the enum; the three names above are
the exact emitted literals.

Each field serialization receives a scratch cell whose tag word is 0x100 and
which points back at the serializer state. When the byte the field helper
leaves at the cell base equals 1, the body calls the panic entry bound to slot
`0x64df730` (RELATIVE target `0x1680e60`) with the exact 40-byte message
`internal error: entered unreachable code` and a Location in the vendored
serde_json source `/home/ubuntu/hl/code_Mainnet/z_vendor/serde_json/src/ser.rs`
— line 747, column 42 for `start_round` and line 768, column 42 for
`end_round`. A nonzero return from the field helper is instead returned to the
caller unchanged. After the `end_round` call, the inner brace is written only
when the scratch cell's second byte is nonzero; the outer brace follows on the
shared path. Buffer space is reserved one byte at a time through helper
`0x5963a10` (arguments 1, 1, 1) at ten sites, and the two unit-variant names
share the string-writer tail at `0x5a80537` through helper `0x50a3510`. The
sole qualified direct caller in `.text` is the E8 site at `0x50e985d`, owned by
the FDE at `0x50e94a0`; no RELATIVE relocation slot names this body.

Relations project the emitted token skeleton from the native operands alone:
the discriminant mapping above, the two brace bytes, the quote and colon bytes,
the 0x100 field tag and the five name literals. Mutations change the actual
compare immediate, brace byte, colon byte and `Peers` literal. Prior work is
distinguished as follows. RE-005 gossip-response-record and
RE-005 gossip-rpc-request pin the binary record layout of gossip messages at
0x5821150..0x5aac7b7, a different encoding layer. RE-001
gossip-peer-status-report covers report-builder bodies at
0x4e06b40/0x4fac310/0x5a61e40. RE-001 consensus-local-delivery cites the same
rodata block only as a context literal for its routing bodies at
0x5a7c4d0/0x5a7f3a0 and makes no claim about this writer. Open PR #2916
recovers the binary wire structure of the ClientBlocks payload and open PR
#2790 the ClientBlocksError payload decoder; neither addresses this JSON text
serializer. The sibling serializer at `0x5a80250` (keys `tx_hash` and
`signed_actions`) is a separate body and is intentionally out of scope.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| writer | `0x5a80370..0x5a806ea` | 890 | 208 |

The denominator is 1 complete FDE, **890 bytes / 208 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies the encoded incoming E8 site. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds the actual FDE/CIE record, the complete body hash, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **29 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-gossip-variant-writer/export_disassembly.py
python3 research/work-items/RE-001-node115-gossip-variant-writer/verify.py --controls
python3 research/work-items/RE-001-node115-gossip-variant-writer/relations.py
python3 -m unittest discover -s tests -p test_node115_gossip_variant_writer.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python 3.12.3, Capstone 5.0.7, GNU binutils 2.42, LLVM 18.1.7-rust-dev on Linux x86-64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain the actual checks run in this environment, including the environment gaps (no git-lfs, Rust 1.95.0 toolchain or Ghidra; the visor artifact remains an LFS pointer) that keep a full local `make doctor verify test` run from completing here; no full-suite result is claimed. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper boundaries (0x50783d0 field serializer, 0x50a3510 string writer) before implementing a replacement.
