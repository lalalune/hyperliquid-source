# RE-004: read precompile gas: one length cap and one rule, 1000 + 33 per byte, in 12 of 20 functions

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference has no code for these functions.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included are the rows of 12 precompile functions from entry to the input decoder call, plus the final gas rows read from bytes. Excluded: all work inside each function after the decoder, including output values. Precompiles `0x802`, `0x803`, `0x806`, `0x807`, `0x808`, `0x80a`, `0x80e`, `0x80f` are named only by number. Their functions are rows in other packets, so this packet reads no bytes of them and makes no claim on them.

## Reproduce

From the repository root:

```
python3 tools/read_precompile_gas.py --out research/work-items/RE-004-read-precompile-gas-94
python3 -m unittest tests.test_read_precompile_gas
```

The tool takes about 60 s on a loaded server. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `address-scope.tsv`, `family.tsv`, `gate-outcomes.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs.

`.rodata` holds 20 byte constants with values `0x800` to `0x813`, 20 values, each loaded by exactly one `lea` in `.text` (`address-scope.tsv`, `family.tsv`). The FDE around that `lea` is the function for that number.

Every one of the 12 functions has the same gate, in this order (`family.tsv` gives each site):

1. Search the 20 byte key set at `*(ctx +0x38)`. A hit returns word 2 = `2^63`, words 0 and 1 = 0.
2. Input length above 2000 returns the same form.
3. `1000 + 33 * n > limit` returns the same form. An equal limit passes.
4. Call the input decoder.

102 cases per function, 60 of them vectors, run the real rows and match a rule list on the whole fixture heap: 48 returns and 54 decoder calls per function (`gate-outcomes.tsv`). The stub at the decoder also checks where the input pointer and length arrive. Four functions pass a 21 byte label, `utils::abi_decode_raw`, and the stub checks that too.

Final gas, read from rows and bytes. All 12 give `1000 + 33 * (n + out)`:

| Form | Precompiles | Rows |
| --- | --- | --- |
| fixed | `0x800`, `0x801`, `0x805`, `0x809`, `0x810`, `0x813` | `add S,N` then `add $imm,N`, `imm = 1000 + 33 * out` |
| runtime | `0x804`, `0x80b`, `0x80c`, `0x80d`, `0x811`, `0x812` | `mov $33,%edx; mul; jo; add rax,Y; mov $-1,rax; cmovae; cmovae; cmp; jbe` |

- Fixed form: `N` holds n and `S` holds `n << 5`, so the sum is `33n + imm`. A walk over every path from the decoder call to those rows proves that neither register is written on the way. `imm` minus 1000 is a multiple of 33 and of 32, and the same output size appears as an allocation immediate. The values are 160, 96, 128, 32, 32 and 160 bytes.
- Fixed form has no saturation rows. With n at most 2000 it cannot wrap.
- Runtime form saturates both the product and the sum to `u64::MAX`. `Y` is the base gate sum: the same register, or a stack slot with one store from it (`sum_source` in `family.tsv`). `0x80d` overwrites the register and reloads it from such a slot, and the walk handles that reload.

`research/upstream-docs/docs/for-developers_hyperevm_interacting-with-hypercore.md` line 19 gives `2000 + 65 * (input_len + output_len)`. `family.tsv` has both for a 32 byte input. For `0x809` that is 3112 here and 6160 in the docs.

## Implementation and comparison

Not yet implemented in Rust. The tool holds a separately written rule list (`spec_run`) and an x86-64 evaluator of the real bytes. The shape checks in `final_shape` refuse anything else, so a function with a different gas form stops the tool.

## Results and limitations

- 355 of 355 mutants on the gate rows are killed, 0 survive.
- Final rows are checked by shape and path walk, not by a run, because reaching them needs each precompile's state. Calls are taken to keep callee-saved registers, as the ABI says. Dead ends in the walk include cold blocks that the row decoder does not cover.
- Mutants do not swap arithmetic operators, and they cover only the gate rows, not the final rows.
- The cost column assumes a 32 byte input for comparison. Real input sizes depend on each decoder.
- Inference: the set at `ctx +0x38` is the same for all functions, because each loads it from the same field. Its meaning is unknown.
- Inference: the docs formula may be out of date or for another network. This packet only reports that this build uses other constants.
- Open PR #660 reads rodata words with these values as a system user table. This packet reads only how each function uses its own constant and takes no position on that table. Whether the set at `ctx +0x38` relates to it was not read.
- Unresolved: the eight out of scope functions, who fills the set, how the caller charges gas on the error forms, and the output length of the six runtime functions.
