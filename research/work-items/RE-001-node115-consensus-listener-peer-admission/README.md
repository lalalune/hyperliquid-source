# RE-001: node115 consensus listener peer-address and request-class admission

Component: consensus. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The listener continuation at `0x2af8be0` receives a framed buffer and calls decoder `0x27005e0` with raw budget0xa7d8c0. After the decoder's error route is excluded, its address policy compares the stored four bytes with the exact little-endian integer0x0100007f, corresponding to bytes127.0.0.1. Only that exact value bypasses the lookup. No claim about the entire127/8 subnet or IPv6 loopback follows.

For other addresses, the exact label `server_listen_get_node_ip` is passed to wrapper `0x29b4360`. Its packed result is interpreted at this call site as a low-byte presence value and an expected IPv4 value obtained by shifting right8. Admission requires the observed address to equal that expected DWORD **and bit0 of the low byte to be set**. Other nonzero low-byte values do not automatically pass. Lookup internals and identity provenance remain unresolved, so this is caller policy rather than an authentication guarantee.

The next limiter boundary `0x595ec00` receives different numeric inputs for two decoded classes. When the decoded first qword is signed minimum, the supplied amount comes from a nested object+0x20 and the budget is10,000. Otherwise the supplied amount is the received buffer length and the budget is1,000,000. Nonzero AL from the limiter takes the rejection path. Zero AL allows the subsequent dispatch. The two classes are intentionally left as raw classifications: no wire enum names, elapsed-time units or limiter algorithm are invented.

Relations distinguish exact loopback, optional-address bit0/equality, request class budgets and limiter AL. Mutations change the actual loopback constant, bit-test instruction and class budget. #970 inventories the listener's source path/labels. #1912 covers client greeting/reply handling and #1778 lower framing deadlines. This packet addresses the server-side caller policy between decoding and dispatch; it does not recover decoder acceptance, cryptography, transport or runtime rate guarantees.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| listener | `0x2af8be0..0x2af9c09` | 4137 | 727 |

The denominator is 1 complete FDEs, **4137 bytes /727 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **41 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-consensus-listener-peer-admission/export_disassembly.py
python3 research/work-items/RE-001-node115-consensus-listener-peer-admission/verify.py --controls
python3 research/work-items/RE-001-node115-consensus-listener-peer-admission/relations.py
python3 -m unittest discover -s tests -p test_node115_consensus_listener_peer_admission.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
