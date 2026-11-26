# RE-005: map node #115 tag-4/tag-5 bridge caller input spans

This packet follows the two caller-side inputs left open by [the bridge request input-producer packet](../RE-005-node115-bridge-input-producers/README.md): the distinct tag-4 path and the tag-5 `requestWithdrawal` path. It records which bytes of incoming register `R8` each caller copies into a helper input or tagged record before calling the shared bridge helper. The field names and public meanings are unresolved.

- Component: `bridge`, issue [#3917](https://github.com/lalalune/hyperliquid-source/issues/3917); bounded caller evidence only.
- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source revision: `8f8a38d0d44f0c41a94aa156bb4274777f20fd4d`; no reference source was used.
- Coordinates: linked ELF virtual addresses and file offsets; selected extents are complete FDE ranges.
- Claim status: observation for bytes, FDEs, calls, relocation entries and copy spans; inference for the roles `tag4` / `tag5`; unresolved for field types, names and the semantics of helper outputs.
- Excluded: full request schema/hash interpretation, tag-4/tag-5 helper internals, nonce or authorization policy, persistent mutation, rollback and runtime reachability.

## Reproduce

From repository root with Python 3 and Capstone 5.0.7:

```sh
python3 tools/bridge_caller_source_fields_115.py --out research/work-items/RE-005-node115-bridge-caller-source-fields
python3 -m unittest tests.test_bridge_caller_source_fields_115
(cd research/work-items/RE-005-node115-bridge-caller-source-fields && shasum -a 256 -c MANIFEST.sha256)
```

The collector hashes the complete artifact before analysis, reads FDE extents and relocations, disassembles only the two selected FDEs, checks every instruction boundary through each FDE end, and emits deterministic files. The captured node is read as bytes only; it is never executed, loaded or emulated. The collector requires Capstone 5.0.7.

## Evidence

The two complete extents contain 680 instructions across 3,696 bytes:

| Caller path | FDE range | Bytes | Instructions |
| --- | --- | ---: | ---: |
| tag 4 | `0x44d69f0..0x44d7210` | 2,080 | 368 |
| tag 5 | `0x44d7210..0x44d7860` | 1,616 | 312 |

`functions.tsv` gives file offsets and body hashes. `instructions.tsv` contains every instruction byte and decoded instruction. `source-spans.tsv` contains both the load and store anchors for every copied span. The collector also confirms the `.rela.dyn` bindings `0x64eaae8 -> 0x4526e40` (shared bridge helper) and `0x64eab68 -> 0x4526230` (tagged-record constructor), each an `R_X86_64_RELATIVE` relocation with symbol index zero.

At entry to the tag-4 FDE, `R13` retains incoming `R8`. The seven source spans are copied to these stack-relative destinations:

| Incoming source | Destination from post-prologue `RSP` | Length |
| --- | --- | ---: |
| `R8+0x00` | `+0x1d0` | 16 |
| `R8+0x10` | `+0x1e0` | 16 |
| `R8+0x20` | `+0x230` | 16 |
| `R8+0x30` | `+0x240` | 16 |
| `R8+0x40` | `+0x210` | 16 |
| `R8+0x50` | `+0x220` | 16 |
| `R8+0x60` | `+0x250` | 8 |

The first two spans form the 32-byte region at `RSP+0x1d0`; the other five are stored at the listed, different offsets. At `0x44d6ad6` the caller loads `RSP+0x1d0` into `RSI`; the actual call at `0x44d6ade` goes through relative relocation slot `0x64e8cb8 -> 0x364cc80`, with `RDI=&[RSP+0x10]`. This is not the call to `0x46e1cb0`. On the selected result-tag `0x1a2` route, the later direct call at `0x44d6d2e` targets `0x46e1cb0` with `RDI=&[RSP+0x10]` and `RSI=&[RSP+0x170]`. The packet records these call boundaries and raw spans only; helper semantics remain unresolved. On the selected constructor route it writes tag byte 4 into a separate local record and calls the shared helper through `0x64eaae8` at `0x44d6cd8`.

The tag-5 caller builds a 64-byte local record with tag byte 5. Its initialized source spans are:

| Incoming source | Local record destination | Length |
| --- | --- | ---: |
| `R8+0x58` | `+0x01` | 16 |
| `R8+0x68` | `+0x11` | 4 |
| `R8+0x6c` | `+0x15` | 16 |
| `R8+0x7c` | `+0x25` | 4 |
| `R8+0x00` | `+0x30` | 8 |
| `R8+0x08` | `+0x38` | 8 |

The local record bytes `+0x29..+0x2f` are not initialized by these stores and are not interpreted. The tag-5 caller passes the record to the same relocated helper at `0x44d72ed`. Credited prior evidence follows the helper's tag-5 constructor arm, its 32-byte output, and the downstream 52-byte builder/digest path; this packet adds the caller's raw source offsets, not another claim over that digest implementation.

No source type or economic meaning is inferred from matching byte ranges. In particular, the tag-4 and tag-5 layouts remain separate. The outer helper, validation helpers and any state changes are not reconstructed here.

## Implementation and comparison

There is no Rust implementation or target execution claim. The output is static evidence tied to the full node digest. Six focused tests check the two full extents, the tag-4 source projection, the tag-5 source projection, both relocated helper targets, the digest guard and byte-identical repeated packet generation.

## Results and limitations

The packet covers 3,696 bytes / 680 decoded instructions in two complete FDEs; it does not claim a full bridge component denominator or a component gate. Helper contracts, semantic field names, caller authorization, nonce lifecycle, persistent writes, error rollback and real request hashes remain open.

Next question: join one of these raw caller layouts to a reviewed request schema and trace the resulting accepted/rejected branch into its actual state mutation.
