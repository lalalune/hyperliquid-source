# RE-001 · InvalidParityValue formatter callback contract

- Component: foundation
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`
- Scope: one FDE, `[0x14c2530,0x14c2658)`, and its selected argument literals. Addresses are linked virtual addresses.
- Status: observed instruction flow. Callback identities and source type remain unresolved.

## Evidence

The function saves the first input's qword and loads the second input's qwords at offsets 0 and 8. It calls the method at table offset `+0x18` with the first of those second-input qwords as context and `InvalidParityValue` as an 18-byte slice. A nonzero low return byte sends control to the common epilogue with EAX set to 1.

The high bit at second input `+0x12` selects two paths after that initial callback returns a zero low byte:

| Bit | Opening bytes and callback site | Payload delegate | Subsequent calls after a zero low-byte delegate return |
| --- | --- | --- | --- |
| Clear | `(` at `0x14c2591` | `0x15ea8f0` at `0x14c25a0`, with the original second input | Reloads the callback context and method from the original second input, then calls with `)` at `0x14c264e`. |
| Set | `(\n` at `0x14c25c8` | Same target at `0x14c2611`, with a stack-backed context initialized in this arm | Calls through the staged table at `0x14c2634` with `,\n`, then uses the originally saved callback context and method for `)` if the prior call returns a zero low byte. |

The early exits test AL and preserve the EAX=1 result. The final close callback instead moves its full EAX into EBX for the common return. These are local return-width observations. Callback writes, actual output, meaning of the flag, and the payload delegate's behavior are open.

PR #2813 records caller sites `0x14ca646` and `0x14ca6b7`. It supplies caller context. This packet verifies the called function body and the seven internal call sites.

## Reproduce

From the repository root with the pinned artifact present and LLVM objdump 23.1.4:

```sh
python3 research/work-items/RE-001-node115-invalid-parity-formatter/verify.py --llvm-objdump llvm-objdump
llvm-objdump -d --start-address=0x14c2530 --stop-address=0x14c2658 artifacts/node/115/hl-node
readelf -wf artifacts/node/115/hl-node
```

`llvm.txt` retains the full disassembly. `frame.txt` retains the selected GNU readelf header and initial CFA rows as independent extent evidence. The verifier checks the full target digest, uniquely parses the FDE with repository tooling, checks complete byte continuity, validates seven call coordinates and both rel32 targets, and reads five literal slices from the ELF. The negative control flips one bit of the displacement at `0x14c25a0` in a temporary in-memory window and verifies rejection.

## Results and limits

296 bytes, 79 instruction rows, seven call sites, five literal slices. Body SHA-256 `cd9d5b09d2205e15f1f1723bfbb1ef3b02cdb918a8a9a55499feae84cf383226`. The negative control rejected the changed window at the expected call site. Static analysis only. No Rust implementation, runtime fixture, equivalence comparison, or gate advancement. The next bounded question is how the staged table at `0x64078f8` binds the alternate payload context.
