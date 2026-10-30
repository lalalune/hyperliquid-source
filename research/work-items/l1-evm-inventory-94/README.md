# l1-evm-inventory-94: execution-side Location census

- Component `evm`, path rule `l1/evm/*`; bounded RE-011 lead, not a full RE-011 gate or the separate `evm_rpc` work.
- Target `artifacts/node/94/hl-node`, Linux x86-64, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f` ([provenance](../../../provenance/artifacts.json)). All addresses refer only to this artifact.
- Reference lead: unlicensed can1357 tree; [source provenance](../../../provenance/sources.json) records revision `999556f6e0a474b8312db96ec3149e1c44e97c23`. Revision of this checkout and reference working-tree cleanliness cannot be checked because Git metadata is absent. The references are inferred, not original source, and are not an implementation input.
- Status: static observations and a direct call; five semantic constant names remain unverified. See [RESULT.md](RESULT.md).

## Reproduce

From repository root, Python 3 standard library (observed 3.13.5, Linux x86-64):

```sh
python3 tools/l1_evm_inventory.py --out research/work-items/l1-evm-inventory-94/
python3 -m unittest tests.test_l1_evm_inventory -v
python3 research/work-items/l1-evm-inventory-94/verify.py
```

The generator checks the complete binary digest before parsing or writing. It writes the JSON and raw excerpts; it does not regenerate this document, RESULT, verifier or manifest. `MANIFEST.sha256` covers every packet file other than itself; verifier requires an exact whitelist including RESULT. Generator SHA-256 `c8b2b5a53880854759b7b3abc29470893764e51a96cda899128d2175d8d4a9eb`; shared ELF helper SHA-256 `ffe4f98ba84648f6ffa1fdaca288799cc62d51fa7d089c82fb28cba77c1d88d1`. Generated JSON SHA-256 `1cfe4d1be30790b7c7805251789e36dc9345c236583d974d651788500b3448e4`; excerpts SHA-256 `70fc02918e66416f81b41b0b340926dd4beb5990485411a19c0a0d5a949fb084`. No network, runtime state, or target execution is needed. JSON and excerpts are deterministic. GNU objdump 2.44 was used only for independent instruction-boundary cross-checks: `objdump -d --start-address=START --stop-address=END artifacts/node/94/hl-node` for each FDE in JSON. Disassembly starts at each FDE start, not at the candidate opcode. Those checks are reproduced in the unit tests when objdump is present.

## Evidence and method

`tools/info_request_path.py` provides ELF program/section mapping, `.rela.dyn` type-8 RELATIVE relocation handling, Location shape decoding, `.eh_frame_hdr` and FDE range parsing, and an exhaustive `.text` RIP-relative LEA byte-pattern scan. We select all its first-party `/home/ubuntu/hl/code_Mainnet/l1/src/evm/*.rs` records; that build path corresponds to the catalogue's `l1/evm/*` rule. The Location layout here is relocated path pointer, u64 byte length, u32 line and u32 column. The pointer field in the on-disk record is zero and the relocation addend supplies its path address. The machine-readable packet retains each slot, path, raw bytes, reference site and FDE interval. Byte scan sites are pinned and independently disassembled from the start of every owning FDE; a byte pattern by itself is not an instruction-boundary proof. The scan covers RIP-relative LEAs only: other reference forms and Location structures outside the selected layout or sections are not inventoried. The two duplicate source coordinates in hyper_evm are distinct slots and counted separately.

FDE intervals are decoded extents, not proof of source-function identity, ownership of every inlined instruction, CFG completeness, or complete node function coverage. Their ends are exclusive. File offsets are translated through PT_LOAD segments; VAs are linked ELF VAs, not rebased analysis addresses. The excerpt preserves original Location and instruction bytes, and the call's signed rel32 bytes. No LEA disassembly label or can1357 name is treated as a symbol. `0x810` copy lengths visible in the hash-associated FDE do not by themselves establish either proposed hash constant.

## Implementation, comparison and limitations

No Rust is implemented or compared. Compiler flags, helper/call closure, relocation and vtable/data closure, raw/normalized body comparison, behavioral coverage, state-transition inputs, and whole ELF remain unmeasured. The single call is not a complete call graph. This is not a dependency/fork matrix and no revm/reth paths are claimed from this scoped set. No #115 or visor claim. No progress gate is requested or changed. A useful next question is whether code around the hash-associated FDE's three 0x810-byte copies can establish field widths and the relationship to the candidate 2048-byte payload through validated data flow.

## Validation observed in this checkout

The three commands above pass, including 10 focused unit tests and GNU objdump instruction-boundary checks. `make doctor`, `make reproduce`, and `make catalogue-check` pass. `make verify` authenticates all listed binary hashes and signatures but then fails because the imported `research/imported/visor.dis.txt` is absent. The combined `make verify test catalogue-check` therefore stops at verify; the other checks were invoked separately. No captured executable was run.
