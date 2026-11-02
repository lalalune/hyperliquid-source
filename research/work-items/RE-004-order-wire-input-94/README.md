# RE-004: order wire quantity input and failure order

This packet identifies how the `p`/`limitPx`, `s`/`sz`, and nested `triggerPx` inputs reach the same quantity converter, enabling the reconstruction to preserve their distinct parsing and conversion failure order.

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `e5c9b6436876b2a4a39daef813171f9879317699` / `999556f6e0a474b8312db96ec3149e1c44e97c23`
- Claim status: observed instruction and data bytes, FDE ranges, relocation addends and branch targets; inferred field roles and ownership; unresolved items below.
- Scope included and excluded: one selected order-wire map path, two wrapper call sites, the nested trigger value, the shared two-value adapter and their selected failures. The general reader, sequence representation, complete order-type dispatch, converter internals, floating-point rounding, downstream validation and node #115 are excluded. The reference tree supplied search clues only.

## Reproduce

Run from the repository root on Linux x86-64 with Python 3.12.3 and the captured artifact installed at its repository-relative location. The extractor uses the standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`. It checks the complete input digest before examining metadata or writing output; it never executes the artifact. It requires no binutils and writes only into the supplied output directory.

```sh
python3 tools/artifacts.py verify
python3 tools/order_wire_input_94.py --out <tmp-dir>
python3 -m unittest tests.test_order_wire_input_94
python3 tools/catalogue.py --check
```

Compare `evidence.json`, `fields.tsv` and `branches.tsv` in `<tmp-dir>` with the retained files. `MANIFEST.sha256` covers the retained README and generated evidence, and can be checked from this work-item directory with `sha256sum -c MANIFEST.sha256`. The JSON records raw window bytes and section-relative file offsets, complete FDE-range SHA-256 values, relocation-derived targets, tables and selected conditional targets. The TSVs are deterministic projections of the JSON. No disassembler output is a generator input.

## Evidence

All addresses below are ELF virtual addresses before load bias; file offsets and raw byte windows are in `evidence.json`. The twelve listed FDEs describe unwind ranges, not necessarily complete functions or CFGs. The target's executable mapping and each selected instruction window are checked against those ranges. This is a focused path analysis, not a whole-node call census.

| Role in the observed path | FDE start | End, exclusive | FDE address |
| --- | --- | --- | --- |
| First order wrapper | `0x1ee0760` | `0x1ee09a6` | `0x105530c` |
| Order field reader | `0x20e08a0` | `0x20e24e9` | `0x107f25c` |
| Map-key iterator | `0x1ed8740` | `0x1ed88d5` | `0x105440c` |
| Order key classifier | `0x2163dc0` | `0x216409c` | `0xd2e980` |
| Two-value conversion adapter | `0x330e700` | `0x330e887` | `0x11684ec` |
| Nested order-type reader | `0x208b7d0` | `0x208bccc` | `0x107bd60` |
| Nested value reader | `0x21272a0` | `0x2128068` | `0x1080ee0` |
| Nested conversion adapter | `0x2197ca0` | `0x2197e46` | `0xd3008c` |
| Nested key iterator | `0x1ec84b0` | `0x1ec8645` | `0x105252c` |
| Nested key classifier | `0x2152440` | `0x21526dc` | `0xd2dbc0` |
| Second order wrapper | `0x34f51b0` | `0x34f53f6` | `0x117eff8` |
| Second order field reader | `0x3adcca0` | `0x3ade8e9` | `0x11d2c6c` |

The first wrapper supplies the literal `OrderWireSerde` and a 14-entry descriptor to its field reader at `0x1ee0823`, then gates the adapter call at `0x1ee0863` on the reader's result. The second wrapper independently supplies the same type literal, calls its distinct reader at `0x34f5273` and reaches the same adapter slot at `0x34f52b3`; equivalence of the readers is not asserted. ELF relative relocations resolve adapter slot `0x57732b8` to `0x330e700` and converter slot `0x5773898` to `0x3330210` before load bias. These are relocation addends, not observations of a running loader.

The first wrapper's input and result checks form the following bounded path. The marker is a byte in the selected entry; the count and cursor are fields of the incoming iterator, not quantities:

| Entry condition | Cursor advance | Effect |
| --- | --- | --- |
| Buffer word zero or cursor equals end | 0 | Return with output byte `+0x36` set to 2. |
| Present entry has marker `0x16` | `0x20` bytes | Return with output byte `+0x36` set to 2. |
| Other marker and counter equals `0xffffffffffffffff` | `0x20` bytes | Branch to `0x1ee097e`, which calls an indirect slot followed by `ud2` if it returns. |
| Other marker and counter below maximum | `0x20` bytes | Increment counter and call the order reader. |

If the order reader returns the error sentinel, the wrapper returns the copied error payload with output byte `+0x36` set to 3. If the two-value adapter returns a non-`0x186` tag, the wrapper passes its error payload to `0x17042b0`, then returns through the same short-output path. The meaning of these wrapper discriminants and the indirect overflow callee is not inferred.

The map arm calls the key iterator and then indexes a signed relative jump table. The short and long spellings below reach the same index, as shown by the selected classifier instruction arms and the table bytes:

| Field spelling | Key index | Reader arm | Reader output on successful map path | Adapter input |
| --- | --- | --- | --- | --- |
| `p`, `limitPx` | 2 | `0x20e0bf7` | three words at `+0x00`, `+0x08`, `+0x10` | first value at input `+0x00` |
| `s`, `sz` | 3 | `0x20e0c81` | three words at `+0x18`, `+0x20`, `+0x28` | second value at input `+0x18` |

The reader uses the same value-reader call for both fields. A second occurrence after the relevant slot is occupied branches to a field-labelled error path: `p` at `0x20e1e62` and `s` at `0x20e1cec`. On absent slots, the reader calls a field-labelled helper with `p` or `s` and tests its result before continuing. This evidence does not assume that every possible helper implementation must fail for a missing field.

The same key classifier maps `t` and `orderType` to index 5, whose table entry is `0x20e0dae`. For the selected nested order-type branch, that arm calls `0x208b7d0`, which calls `0x2197ca0`. That adapter first calls `0x21272a0`. Its map-key iterator invokes `0x2152440`; the byte comparisons for the nine-byte name `triggerPx` produce key index 1, whose table entry points to `0x2127420`. That arm reads the same kind of three-word value and detects a duplicate via the `triggerPx`-labelled path at `0x2127dff`. On its successful input-reader path, `0x2197ca0` passes the value to converter slot `0x5773898`; tag `0x186` writes the returned word at output `+0x08` and sets the adapter's byte tag to `0x09`. A converter failure goes to `0x2197d4e`. The enclosing order reader checks the nested reader result before it can return a successful parsed order, so this nested conversion can fail before the outer two-value adapter is entered.

At `0x330e700`, the first converter call receives the first three-word value; only tag `0x186` permits the second call with input `+0x18`. On two successes, its returned words are stored at adapter output `+0x18` and `+0x20` and the adapter writes tag `0x186`. The two error-copy instruction sequences are identical for 73 bytes. The selected branch behavior is:

| First converter tag | Second converter tag | Calls | Result | Second value cleanup-like call |
| --- | --- | --- | --- | --- |
| non-`0x186` | not observed | 1 | first error copied | only if input word at `+0x18` is nonzero |
| `0x186` | non-`0x186` | 2 | second error copied | none on this error arm |
| `0x186` | `0x186` | 2 | two returned words and success tag | none on this success arm |

The nonzero check and call arguments are observed; calling the words string capacity and pointer, and identifying the call as deallocation, are ownership inferences. The code does not independently establish the external helper's accepted decimal grammar or output scale.

The previously retained `research/work-items/RE-004-decimal-scaled-u64-94` evidence separately records a call from the converter's FDE to the decimal scaler with mode 0 and exponent 8. Combining that prior result with this packet links that existing arithmetic finding to these wire fields; this packet does not re-analyse or claim new coverage of the converter or scaler.

## Implementation and comparison

Rust implementation: not yet implemented. Target execution and whole-binary comparison: not yet implemented/measured. The generator's small interpreter is limited to the two selected classifier arms and does not execute native instructions. Its separate adapter model takes supplied 16-bit helper tags and models only the identified branches; it does not manufacture numeric converter results. No normalization masks, rebuilt binary, helper closure or equivalence claim are supplied.

## Results and limitations

Generation records 12 selected FDE ranges, 39 exact instruction windows, 18 direct or relocation-resolved call sites, 12 conditional targets and 14 descriptor entries. The seven unittest methods passed with no skips. Tests cover all 256 one-byte names, all 65,536 two-byte names, all 1,785 single-byte mutations of `limitPx`, and each of the 65,536 possible values of each adapter return tag with the other tag fixed at success. All 3,072 combinations of wrapper presence, end condition, marker byte and the three selected counter boundaries are checked. Tests also check the zero/nonzero cleanup branch, invalid tags, a corrupted instruction, wrong artifact hash, bad table target, ambiguous or non-file-backed VA mapping and out-of-range addresses. These are checks of the selected control-flow model and byte decoder, not target execution or an exhaustive test of numeric inputs.

We have not proved the full sequence-input path, exact ownership types, all indirect-call consumers, arbitrary load-time interposition, the arithmetic helper's behavior, any semantic property of the alternate order-type branch, or the correctness of a Rust reconstruction. The 12 FDEs are a selected set, not a coverage denominator. No milestone gate is requested.

Next question: which enclosing order action calls these wrappers and what input representation reaches the separately mapped sequence arm?
