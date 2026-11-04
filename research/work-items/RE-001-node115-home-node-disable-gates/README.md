# RE-001: node115 home-node disable predicate precedence

Component: node-runtime. One bounded preparatory boundary/xref research question.
Target: Linux x86-64 node115, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,105,896,032 bytes.
Base main: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

The primary gate `0x4faca70` takes a four-byte key pointer in RDI, an optional twenty-byte identity record in RSI and state in RDX. It first searches the tree rooted at state+0x1c20, height+0x1c28. Keys are four bytes at node+8, count is u16 at +0x36 and child pointers begin +0x38. Both operands are BSWAPed before unsigned comparison: the ordering is the lexicographic order of the four bytes, not host little-endian numeric order. An equal key reaches the diagnostic immediately.

Only after a membership miss does optional byte 1 return without identity checks. Other encodings copy twenty bytes from optional+1. The gate walks candidates using `0x5138730` and resolves each through RELA slot `0x64e4f48` (target `0x3c3f5a0`) with state+0x18f8. A result WORD other than **0x1a2** takes the cleanup/continue path. For 0x1a2, exactly twenty result bytes at +2 are compared with the captured identity: 16 PCMPEQB lanes plus a zero-extended four-byte tail, PAND, and PMOVMSKB==0xffff. A match reaches the second diagnostic; mismatches continue. Candidate ordering and resolver semantics are supplied boundary facts.

Both diagnostics carry the authentic format bytes containing ` Home node is disabled: ` and the `CONFIGURATION ERROR` label. Their separate Rust Locations are bound to `node/src/node.rs`; the complete records retain line/column values. The call resolves to `0x1680e80`. This packet does **not** claim that it exits the process, sends an alert or has a particular public Rust panic type: that helper is not closed.

The additional complete bodies establish provenance. Periodic poll `0x5a6d200` supplies `node_disabler` and binary64 10.0 to its wait path. Tracing wrapper `0x4f28340` reaches timing wrapper `0x4fc8640`, which calls the primary gate on both its timing paths. Their full exports and edges are retained; timing units, actual scheduling, metrics and whole-wrapper semantics are excluded.

Relations check membership/optional precedence for all256 optional byte encodings, candidate early match behavior, every single-byte replacement of the twenty-byte identity and boundary key ordering. Three real operand changes distinguish the skip value, resolver tag and equality mask. This is a static result, with no target/emulator execution.

Prior #1138 only binds the `node_disabler` name in a node94 inventory. #1154 documents governance writes to disabled sets. #2520 filters five-byte node IP records and report gates; it does not establish this four-byte home-key/identity diagnostic predicate.

## Evidence and reproduction

| Role | Linked ELF VA, half-open | Bytes | Instructions |
| --- | --- | ---: | ---: |
| gate | `0x4faca70..0x4facd09` | 665 | 139 |
| periodic | `0x5a6d200..0x5a6d385` | 389 | 87 |
| tracing_wrapper | `0x4f28340..0x4f28c71` | 2353 | 457 |
| timing_wrapper | `0x4fc8640..0x4fc8bc6` | 1414 | 299 |

The denominator is 4 complete FDEs, **4821 bytes /982 instructions**. It measures exported evidence, not reconstructed code or runtime coverage. GNU and LLVM independently decode every byte; Capstone qualifies encoded incoming E8 and RELATIVE-slot FF15/FF25 sites. Arbitrary register/vtable callers and E9 tail calls are not included in that incoming census. Selected local E9 edges are visible in the full exports. No normalization masks are used.

`verify.py` authenticates the entire input before producing observations, then binds actual FDE/CIE records, complete body hashes, instruction obligations, source Locations, calls, RELA targets and selected data/imports. `controls.json` records **74 rejected real-byte corruptions**, tested with whole-image/body/export guards bypassed so local obligations must detect them. Separate tests exercise those outer guards. `relations.json` contains operand-derived local projections and counterfactuals; these are not a second implementation or a target differential oracle.

```sh
python3 research/work-items/RE-001-node115-home-node-disable-gates/export_disassembly.py
python3 research/work-items/RE-001-node115-home-node-disable-gates/verify.py --controls
python3 research/work-items/RE-001-node115-home-node-disable-gates/relations.py
python3 -m unittest discover -s tests -p test_node115_home_node_disable_gates.py -v
make doctor verify test catalogue-check reproduce
```

Recorded tools: Python3.14.7, Capstone5.0.7, GNU binutils2.47.20260726, LLVM18.1.4 on macOSarm64. Native exporters operate on a private non-executable copy. `validation.json` and compressed logs retain actual baseline/check results and documented skips. The unchanged-base full baseline is reused with disclosed provenance; a fresh doctor/verify run passed before this batch. `scope-check.json` and the compressed all-state PR census retain overlap evidence and API/search limits.

Before this packet, main had no target-bound derivation for this question. Afterward the stated native relationships, exact source/data bindings and negative controls can be regenerated. No Rust implementation/build, byte equivalence, original public ABI, whole-component completion, hosted CI or live operational behavior is claimed. All progress gates remain unchanged. New analysis/checkers are independently authored under root MIT; ELF readers/export scaffold reuse is credited in verify.py. No unlicensed inferred implementation was copied, and imported files/pins are unchanged. The next step is closure of the specifically named opaque helper/runtime boundaries before implementing a replacement.
