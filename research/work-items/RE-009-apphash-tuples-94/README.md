# RE-009: app-hash grouped serialization inputs

Node #94 serializes the three previously mapped grouped app-hash inputs as ordered 15-, 16-, and 8-element sequences, with concrete network-name, optional-value, boolean and numeric writer decisions that a reconstruction must preserve when building these hash preimages.

- Component ID: RE-009, storage and state roots.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `be793270252fa744d42e5bd520534cbd4ffad7fa`; inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23` was not used as source code.
- Claim status: observations are the selected calls, pointer offsets, control transfers, literal bytes and fixed instructions; sequence and scalar meanings are inferences based on those bytes and the previously mapped serializer helpers. Input type names, all nested payloads and complete hash preimages remain unresolved.
- Scope included and excluded: the three tuple writers and selected integer, boolean, floating point and option leaves; contextual call edges join them to rows 38, 39 and 40 of the existing app-hash packet. That earlier packet owns the closure and hash construction analysis. This packet does not reanalyse its functions, prove the semantic names of the state fields, recover every nested writer, claim a complete snapshot schema, or execute a capture.

## Reproduce

From the repository root, using Python 3 and the repository's shared ELF and FDE parsers:

```sh
python3 tools/apphash_tuples94.py --out work/apphash-tuples-check
python3 -m unittest tests.test_apphash_tuples94
cmp work/apphash-tuples-check/evidence.json research/work-items/RE-009-apphash-tuples-94/evidence.json
cmp work/apphash-tuples-check/fields.tsv research/work-items/RE-009-apphash-tuples-94/fields.tsv
(cd research/work-items/RE-009-apphash-tuples-94 && sha256sum -c MANIFEST.sha256)
```

The generator authenticates the entire input first, uses `tools/elf_index.py` and `tools/fde_extents.py`, rejects mismatched FDE extents and body hashes, and extracts fixed instruction shapes, signed relative calls and branches, and literal data directly from file-backed ELF sections. It invokes no external program and does not execute the capture. GNU objdump 2.42 was used only for manual inspection; its output is not a generator input. Addresses are unrelocated ELF virtual addresses; FDE ends are exclusive. An FDE is unwind metadata, not independent proof of every boundary or cold fragment. No operand masks are applied. Output hashes are in the manifest; no time, host path or environment ordering is embedded in generated records.

## Evidence

The prior [app-hash builder packet](../RE-009-app-hash-builder-94/README.md) establishes the 41 closure rows and their low-lane captured-field order. The three newly decoded contextual calls below connect those rows to the present writers; they are call-site evidence only, not new claims about the already studied parent bodies.

| Prior row | Contextual call | Writer FDE | Header count | First item |
| --- | --- | --- | ---: | --- |
| 38 | `0x281796c` | `0x1e5e450..0x1e5e764` | 15 | four-way name selected by a byte |
| 39 | `0x281861c` | `0x1e5ed40..0x1e5f00f` | 16 | eight-byte scalar passed in `xmm0` |
| 40 | `0x281754c` | `0x1e5d9b0..0x1e5de4c` | 8 | zero/nonzero optional-value route |

All three initialize the serializer configuration to `0x01000400`, pass the count to the same header helper and stop on a failed header. The prior packet establishes their captured source offsets; `fields.tsv` supplies every subsequent pointer load and child call in slot order. For rows 38 and 39, the 29 child calls following item zero each check for sentinel `0x8000000000000004`; a mismatch branches to the respective shared error result at `0x1e5e709` or `0x1e5efb4`. This is the local error path; it does not establish higher-level propagation or rollback.

### Row 38: name and 14 child items

The first pointer addresses a byte used directly to index the signed relative jump table at `0x3bd290`. Entries 0 through 3 lead to string-writer calls with these exact data bytes:

| Byte value | Text |
| ---: | --- |
| 0 | `Local` |
| 1 | `Sandbox` |
| 2 | `Testnet` |
| 3 | `Mainnet` |

No bounds check is present in the selected dispatch window, so no behavior is claimed for other byte values. The remaining pointers are read from box offsets `0x08` through `0x70` in increments of eight. Slots 3 and 4 call `0x1e0f310`, which loads an eight-byte value and passes it to the previously identified unsigned-integer writer. Slot 8 calls `0x1e0f450`, which loads an eight-byte scalar into `xmm0` and calls the floating-point writer. Slot 9 calls `0x1e0ef60`: a 32-bit tag equal to one selects its eight-byte payload at offset eight and the integer writer; the other path emits byte `0xc0`. Slot 12 calls `0x1e0fed0`, which ORs the input byte with `0xc2` before writing a marker; inputs zero and one therefore select the two boolean markers. Other byte values are outside the admitted boolean model. Other child bodies are not interpreted here.

### Row 39: scalar and 15 child items

The first pointer supplies an eight-byte scalar to the floating-point writer. The remaining box offsets run from `0x08` to `0x78`; `fields.tsv` preserves the exact 15 calls and each failure edge. Slots 1 and 2 use `0x1e0fcc0`, which has the same observed tag-one/eight-byte payload versus `0xc0` decision as the row-38 optional integer leaf. Slots 3, 6 and 14 use the boolean leaf. Slot 7 uses `0x1e10960`: its 32-bit tag equal to one selects an eight-byte scalar at offset eight and calls the floating-point writer; the other path emits `0xc0`. Slot 15 uses `0x1e0e190`, which loads an eight-byte value and calls the unsigned-integer writer. The first scalar's meaning and all unexamined nested payloads remain open.

### Row 40: optional routes and later fields

The first pointer supplies a 32-bit tag: zero takes the inline `0xc0` path, while nonzero invokes a child writer, with a separate failure return. Item 1 uses the boolean leaf. Item 2 goes through `0x233e900`; its intermediate buffer-flush and child-error routes are retained as selected calls and branches, but its payload is not decoded. Item 3 uses the following byte decision, followed by the string writer and its error check: zero selects `disabled`, one selects `reduceOnly`, and any other byte takes the `enabled` arm. The latter is an observed default arm, not proof that arbitrary tag values are valid input.

Items 4 through 7 call the functions listed in `fields.tsv`. Items 5 and 7 use the integer leaf. Item 6 uses `0x1e0f820`: a tag byte equal to one passes the following 20 bytes to an indirect helper with a 42-byte output buffer, then passes the result to a string writer; the other arm emits `0xc0`. The existing app-hash packet associates that helper slot with a hex conversion, but its full contract is not re-established here. Child failures take the recorded branches; allocation, nested child semantics and all exceptional cleanup behavior remain outside the model.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Build, raw and normalized comparisons, masks, complete helper/data/relocation closure, fixture execution and runtime behavior: not yet measured. The nine focused tests exercise the real capture and include wrong input digest, altered code after identity checking is bypassed, altered literal after identity checking is bypassed, invalid instruction shapes, shifted extraction range, signed branch displacements, unmapped address and fileless `.bss` controls. These tests validate the static extractor and its declared decisions, not the target's runtime behavior.

## Results and limitations

The generated evidence records 11 selected FDE-described bodies, three contextual call edges, 35 ordered child-call rows and the first-item branches. The row-38 and row-39 child paths include 29 decoded error edges; the six selected later row-40 child calls also record their error destinations. These are selected sites, not whole-program coverage. The array interpretation uses the previously established serializer-helper role; no complete concrete preimage or state root is computed. No full-scope progress gate is requested.

Next question: recover the nested writers for the remaining boxed fields, join their actual field identities to the captured offsets, and validate a complete preimage with an explicitly authorized offline fixture.
