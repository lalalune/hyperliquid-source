# RE-004: precision byte in a PDI-indexed output row

The collector preserves an asset row's byte at `+0x2a` in output row `+0x2d`, and a separate compatible row writer passes that output offset under the `szDecimals` key, allowing a reconstruction to preserve the full byte instead of inventing a clamp at this boundary.

- Component ID: RE-004, quantities and decimal-place representation.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663` / `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference is a lead only; no reference implementation was copied.
- Claim status: observations for exact instruction windows, FDE records, immediate branches, key bytes and direct calls; inference for shared row identity and its association with a size-decimal field. A live producer-to-writer handoff is unresolved.
- Scope included and excluded: collector allocation, its row iterator and row builder, plus a separate compatible list and keyed writer; checked identifier overflow branches and key-writer error edge. Excluded: callers already in other packets, writer callees, allocator behavior, malformed object memory, actual serialized bytes, admitted decimal ranges, node #115 and target execution.

## Reproduce

From the repository root, use Python 3.12 and its standard library. The extractor imports the repository ELF and FDE parsers, checks the complete target SHA-256, excludes NOBITS sections from file mapping, and reads bytes only. It does not invoke a disassembler or run the node. Outputs contain no host-specific paths or time values.

```sh
python3 tools/artifacts.py verify
python3 tools/perp_precision_row94.py --out research/work-items/RE-004-perp-precision-row-94
python3 -m unittest tests.test_perp_precision_row94
python3 tools/catalogue.py --check
python3 tools/perp_precision_row94.py --out <tmp-dir-a>
python3 tools/perp_precision_row94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
(cd research/work-items/RE-004-perp-precision-row-94 && sha256sum -c MANIFEST.sha256)
```

`evidence.json` records complete FDE bytes and hashes, file offsets, exact decision windows, decoded direct calls and selected branch targets, and the literal bytes. `byte-domain.tsv` compares a fixed-opcode transfer replay with a separate identity model for all byte values; it is not target execution. `branches.tsv` records the 28 decoded branch targets. `outer-fields.tsv` records the three outer field names, and `fields.tsv` records the nine byte-read key names, row offsets and selected presence conditions. `identifier-boundaries.tsv` is an integer model of the checked multiply and add. The byte windows are fixed instruction encodings, not parsed disassembler output.

## Evidence

All addresses are #94 linked ELF virtual addresses. FDE ranges are unwind-described ranges, not proof of all function entries or complete semantic ownership. The complete bytes and file offsets are retained in `evidence.json`.

| Role | FDE range | Observed relationship |
| --- | --- | --- |
| collector allocation | `0x2a10590..0x2a10682` | Calls the iterator and returns its collected vector. |
| row iterator | `0x2a22520..0x2a2273a` | Reads a byte at source row `+0x2a`; supplies a copied row to the builder; stores a 48-byte result. |
| row builder | `0x2a2baa0..0x2a2bcd9` | Reads argument byte `+0x2a`, later stores it at output `+0x2d`. |
| outer writer | `0x2a2bce0..0x2a2be57` | Passes the outer record to the `universe` adapter, followed by optional margin tables and collateral token fields. |
| universe adapter | `0x29fc340..0x29fc571` | Calls the list writer with the outer record pointer. |
| list writer | `0x29f6160..0x29f638e` | Advances its input by 48 bytes and calls the keyed writer for each element. |
| keyed writer | `0x2a2be60..0x2a2c0e3` | Passes the address of row `+0x2d` with ten literal bytes `szDecimals` to a field-writing callee. |

The direct calls checked from rel32 bytes are collector to iterator, iterator to builder, outer writer to universe adapter, universe adapter to list writer, and list writer to keyed writer. These are two separate call chains. Matching output/input stride and field offsets supports a shared representation; it does not establish that a vector from this collector reaches that list writer in a live invocation.

On a normal iterator path, the source byte passes through a one-byte stack slot and the builder argument at stack-relative `+0x2a`. The builder saves it in another one-byte slot and stores it at output `+0x2d`. The named windows bind both loads and both stores. A `movzx` of a byte followed by byte stores retains all eight bits, so for every input octet the stored byte is the same, assuming valid non-aliasing objects and callees that obey the ABI. The 256 generated rows replay the four fixed transfer encodings against an independent identity model; that replay does not execute the captured executable and does not model the intervening callees.

The iterator constructs an identifier with unsigned `dex * 10000 + local` before reading the byte. Its multiply overflow reaches `0x2a226d8`; its addition carry reaches `0x2a226e7`. The row is written before the increment of the local index, whose wrap branches to `0x2a226f6`. The extractor checks the actual branch encodings and targets. The model records the maximum successful identifier arithmetic and the first addition and multiplication overflow cases; it does not model allocation or claim that a maximum local index finishes the loop, since the subsequent increment can fail. The full-domain arithmetic bound follows directly: `dex * 10000` fits exactly when `dex <= floor((2^64-1)/10000)`, and, for a fitting product, the addition fits exactly when `local <= (2^64-1) - dex * 10000`. The model boundary cases do not establish that these extreme inputs occur in valid state.

The selected control-flow edges include the following; `branches.tsv` gives their byte-decoded targets, including the five optional-field skip edges and nine field-call result edges:

| Condition | Observed edge |
| --- | --- |
| Source row span is empty | Skip the row loop. |
| A row name length is zero | Skip its allocation arm. |
| Nonempty row name allocation returns null | Enter the allocation-failure arm. |
| Builder lookup has no initial entry or misses | Follow the respective default/miss edge before the output store. |
| The keyed writer's context helper returns null | Enter its context-failure arm; helper effects are unresolved. |
| A keyed field writer returns nonzero | Enter the shared `0x2a2bf6c` error path. |
| The list writer receives the error sentinel | Enter the list error arm. |

The omitted branches include allocator cleanup and other lookup internals. The field-writing callees and the rest of their failure handling are not modeled.

The keyed writer passes nine field names and row offsets in this order (`fields.tsv`):

| Key | Row offset | Condition to call its field writer |
| --- | ---: | --- |
| `szDecimals` | `0x2d` | always |
| `name` | `0x00` | always |
| `maxLeverage` | `0x2c` | always |
| `marginTableId` | `0x18` | always |
| `onlyIsolated` | `0x28` | byte at `0x28` is nonzero |
| `isDelisted` | `0x29` | byte at `0x29` is nonzero |
| `marginMode` | `0x2a` | byte at `0x2a` is nonzero |
| `growthMode` | `0x2b` | byte at `0x2b` differs from 1 |
| `lastGrowthModeChangeTime` | `0x1c` | 32-bit word at `0x1c` is nonzero |

The outer writer first supplies the literal `universe` and the outer-record pointer to its adapter. The adapter passes that pointer to the list writer, which reads the vector pointer and length at `+8` and `+0x10`. The outer writer next attempts `marginTables` only when the word at `+0x28` is nonzero, then always attempts `collateralToken`; the key names are in `outer-fields.tsv`. Each stage stops its field sequence on an error result.

A nonzero writer result takes the shared error path; a failed earlier call prevents later calls. This is call order and pointer evidence, not proof of each callee's encoded bytes. The row builder also uses a lookup and traversal to populate other fields; those callee effects are not reconstructed here.

The literal and pointer passed by the keyed writer give a strong field-name clue for this layout. The previously recorded PDI display research independently associates an asset row's `+0x2a` with a decimal index. No numeric limit, power-of-ten operation, rounding rule, or actual JSON bytes are established by these seven ranges alone. No conclusion is drawn about what a consumer does for bytes outside an independently admitted range.

## Implementation and comparison

Independent Rust implementation: not yet implemented. There is no source build, code comparison, relocation normalization, target execution or end-to-end behavior claim. The mathematical identity follows the checked byte loads and stores; the small integer model follows the checked multiply and carry guards. The byte replay recognizes exactly four byte-transfer encodings and models only those transfers; it is not a complete machine-code interpreter or differential target test.

Eleven focused tests check the authenticated input, seven FDE/body fingerprints, five rel32 calls, 28 selected conditional branches, nine keyed fields, all 256 identity inputs, arithmetic boundaries, and rejection of a changed hash, instruction byte, branch, call or unbacked address. No test is skipped.

## Results and limitations

Seven FDE ranges, five direct calls, 28 conditional edges, nine row fields, three outer fields and the complete 256-value byte domain are recorded. The collector and writer are linked by compatible layout, not by a demonstrated target call or runtime object handoff. Only selected edges are decoded; other branches, helper effects and invalid pointers remain unresolved. No component progress gate is requested.

Next question: identify an address-disjoint caller that passes this collector's actual vector to the list writer, and trace the independent admission rule that bounds the source decimal byte.
