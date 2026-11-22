# RE-005: trace the node #115 `d1` action-method call context

This packet follows the `0xd1` action-method slot from the action-wire dispatcher into its method body, records its register and stack arguments, maps the nested indirect-call boundary, and follows the output into the SendToEvmWithData digest wrapper. It extends the next-step pointer in [PR #7082](https://github.com/lalalune/hyperliquid-source/pull/7082) and the action-signing scope in [issue #3912](https://github.com/lalalune/hyperliquid-source/issues/3912). It does not resolve the nested callback target or claim a production digest.

## Target and source evidence

- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: original ELF virtual addresses; the file-backed `.text` section begins at VA `0x1419300`, file offset `0x1418300`.
- The existing action-wire-variant packet maps index 75 / tag `0xd1` to call site `0x36c36af`, slot `0x64e8e48`, relocation addend `0x442d000`. The independently retained [action-admission binding](../RE-017-node115-action-admission-binding/bindings.tsv) maps index 75 / tag `0xd1` to `SendToEvmWithData` / `sendToEvmWithData`.
- The existing [typed-data builder packet](../action-wire-typed-data-structs-115/eip712.tsv) maps builder `0x44290c0` to the 12-field `SendToEvmWithData` type, including `bytes data`; the digest-wrapper packet maps the selected wrapper to hash function `0x4428520` and builder `0x44290c0`.

## Observed path

The unwind parser reports FDE extents `[0x36c3180,0x36c5348)`, `[0x442d000,0x442d480)`, `[0x46e6d30,0x46e6f78)` and `[0x4433f90,0x443431f)`. These are unwind ranges, not claims that every range is one source function.

At the `0xd1` arm, code at `0x36c3696` advances the payload pointer in RSI by eight bytes, stores R14 at the outgoing stack-argument slot, zero-extends DL into EDX, sets RDI to a local output record at `rsp+0x20`, and preserves RCX, R8 and R9 in callee-saved registers. The indirect call at `0x36c36af` uses slot `0x64e8e48`; its `.rela.dyn` entry is a symbol-free `R_X86_64_RELATIVE` relocation to `0x442d000`. After the call, the arm reads a 16-bit result at `rsp+0x20` and compares it with `0x1a2`.

At `0x442d000`, the seventh incoming argument is read at `rsp+0x1d0` after the function prologue. The method also reads its input pointer from RSI into R12. At `0x442d192` it loads a call target from `[r12+0x60]` and invokes its first qword with:

| Register | Value at the indirect call |
| --- | --- |
| RDI | local output at `rsp+0x50` |
| RSI | address `r12+0x78` |
| RDX | qword `[r12+0x68]` |
| RCX | qword `[r12+0x70]` |

The method copies 32 bytes from that local output into its local record at `rsp+0x118..0x138`. At `0x442d31f` it calls `0x46e6d30`, passing the original seventh argument as RSI and the local record at `rsp+0xb8` as RDX. That intermediate caller invokes wrapper `0x4433f90` at `0x46e6d4c`. The wrapper calls relocated digest slot `0x64ea978 -> 0x4428520`; the hash function reaches builder slot `0x64ea980 -> 0x44290c0`.

The observed wrapper-result branch in `0x442d000` routes tag 1 through status `0x7e`, and other tags through a record path with status `0x1a2`. This packet records those branch values only; it does not assign source-level error names or prove production reachability. The outer dispatcher compares the method result with `0x1a2` before following its success arm.

## Unresolved boundary

The callback pointer loaded from input `+0x60`, its concrete producer, and the meaning of its 32-byte output remain unresolved. The type builder confirms that this action's typed-data schema has a `bytes data` field, but this trace alone does not prove that the callback output is the encoded `data` field or its hash. Runtime field values, the production digest, signature verification, and replay/nonce behavior are outside this packet.

## Reproduction and controls

From the repository root:

```sh
python3 tools/action_wire_d1_method_context_115.py --out research/work-items/RE-005-node115-d1-method-context
python3 -m unittest tests.test_action_wire_d1_method_context_115 -v
sha256sum -c research/work-items/RE-005-node115-d1-method-context/MANIFEST.sha256
```

The collector authenticates the complete target size and SHA-256, parses `.eh_frame` and `.rela.dyn` without running the target, checks all four FDE extents, verifies exact instruction-byte witnesses for the call arguments and handoffs, and checks the three relocated targets. Six focused tests compare the regenerated record, reject a wrong target identity, and reject changed relocation, nested-call, direct-handoff and FDE evidence. `disassembly.txt` retains GNU objdump output for the selected ranges. Captured code was not executed or emulated.
