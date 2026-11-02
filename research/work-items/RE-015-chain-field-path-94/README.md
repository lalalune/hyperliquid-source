# RE-015: trace the SendAssetAction network field from action input to encoded output

The selected node #94 action-reader arm identifies `SendAssetAction`, accepts a four-name network field into record byte `+0xb8`, and has a matching-layout writer that emits its `+0xb8` byte as a length-prefixed name; the distinct missing, duplicate, invalid-name and buffer-growth routes give a reconstruction concrete field and error boundaries without treating the `AwsName` default as a network value.

- Component ID: `constants`, task RE-015; the action record is the downstream consumer of the four-network discriminator.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; inferred, unlicensed `can1357-hl` reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only for leads. No reference implementation is copied.
- Claim status: observations are selected ELF bytes, RELA records, FDE ranges, direct transfers and fixed table entries; the type and record names are inferences. Captured execution, helper behavior and object identity across calls remain unresolved.
- Scope included and excluded: the selected field-key, normalized-value and output-buffer path, including local missing, duplicate, bad-name and growth boundaries. Existing `/static_config` and `/cham` template callers, the 76-entry `AwsName` inventory, the global initializer, unrelated fields' full decoding, generic error/growth helpers, node #115, visor and the rest of the component are excluded. No component gate is requested.

## Reproduce

From the repository root with the pinned #94 artifact present, using Python 3.12.3 on Linux x86-64:

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/config_chain_field94.py --out <tmp-dir-one>
PYTHONHASHSEED=983 TZ=Pacific/Honolulu python3 tools/config_chain_field94.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
python3 -m unittest tests.test_config_chain_field94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
(cd research/work-items/RE-015-chain-field-path-94 && sha256sum -c MANIFEST.sha256)
```

Substitute two distinct empty writable directory names for the placeholders and compare their generated files with the same-named files in this work item. `README.md` and `MANIFEST.sha256` are authored metadata, not generator outputs; the manifest records the SHA-256 of every other work-item file. The collector authenticates the complete artifact size and SHA-256 before parsing. It uses Python's standard library and the repository `elf_index` and `fde_extents` readers, excludes NOBITS mappings, and reads RELA records and fixed instruction operands directly. It does not run captured code, invoke external tools, access the network or read a clock. GNU objdump 2.42 was used only for human inspection; no objdump text is a generator or test input. The two output trees and focused tests were also checked with a PATH containing Python but no binutils, using different hash seeds and time zones.

## Evidence

All addresses are linked ELF virtual addresses before load bias. Ends are exclusive; actual file offsets, FDE/CIE/LSDA coordinates and full raw body bytes are in `functions.tsv`. An FDE describes an unwind interval, not a verified source boundary or a complete function census. `windows.tsv` retains the selected byte windows. `transfers.tsv` decodes only the listed direct calls and branches; `tables.tsv` reads signed table offsets from the ELF. These are selected claims, not an instruction or whole-program CFG census.

| Selected FDE | Bounded role |
| --- | --- |
| `0x2880830..0x288303d` | Decode an action header and dispatch the selected action record, then package success or failure |
| `0x20dc8c0..0x20df3b0` | Read a tagged record, dispatch fields, store the network byte and route local failures |
| `0x1ecdb10..0x1ecdca5` | Pull the next key representation and invoke the key adapter |
| `0x21540c0..0x2154321` | Dispatch a normalized key representation |
| `0x1e71e80..0x1e72003` | Compare field names and return their field indices |
| `0x1e719c0..0x1e71e71` | Independently compare field-name bytes and return field indices |
| `0x208d290..0x208d6c0` | Route a normalized network-field value to the wrapper |
| `0x22e9610..0x22e9710` | Adapt the network dispatch result |
| `0x21db5f0..0x21db8b9` | Dispatch selected numeric and string representations |
| `0x22edb60..0x22edbf6` | Compare four network spellings with packed loads |
| `0x22ed9b0..0x22edb55` | Compare the same spellings byte by byte |
| `0x1e89990..0x1e89e2b` | Write the matching-layout record, including its network field |
| `0x22e6160..0x22e6411` | Write a network marker, name bytes and buffer length |

### Action entry and selected arm

The entry `0x2880830` supplies the length-delimited bytes `type` and `internally tagged enum Action` to an external header helper. After one return arm, it zero-extends the helper's byte at output `+8` and uses it to index the relative table at `0x3f34f0`. The selected index 69 points to `0x2880fb9`, which supplies `SendAssetAction`, the descriptor table `0x568f248` and count 9 to the record reader at `0x20dc8c0`. `action-entries.tsv` and `action-route.tsv` retain the name slices and selected immediate operands. The 69 is an internal helper result, not a proven wire tag. To locate the one selected slot, the collector scans the range addressable by a byte; it does not assert that every scanned word belongs to the table or that every byte value is a valid helper result.

For a non-overflowing negation of the reader's first result word, the selected caller copies `0x88` record bytes, sets variant `0xb9`, and enters a shared packager. The packager requests `0xf0` bytes through an indirect call, copies the constructed payload, and stores output tag 9 when that call returns non-null. A null result branches to an indirect failure call followed by `ud2`. The selected record's network-value error route stores first word `0x8000000000000000`; negating that word sets overflow and takes the caller's `0xcc` error join instead. These observations do not describe the allocator's implementation or exception effects.

### Field identification and flow

The nine descriptor entries at `0x568f248` contain relocated pointer/length pairs. `fields.tsv` cross-checks their bytes against the independent comparison immediates and success stores in `0x1e71e80`; the 12-slot length dispatch is extracted from the code-referenced table. The field indices are `signatureChainId` 0, `hyperliquidChain` 1, `destination` 2, `sourceDex` 3, `destinationDex` 4, `token` 5, `amount` 6, `fromSubAccount` 7 and `nonce` 8. Both field matchers pass the same full descriptor table to an external error constructor on their unknown-name routes; the returned error object is not reconstructed here. In the other field matcher, `field-byte-checks.tsv` reconstructs all 16 byte comparisons and their branches for `hyperliquidChain`, and independently verifies its tag-9, index-1 success store. It does not claim full byte-level reconstruction of that matcher's other eight names.

For the selected map-like input arm, `0x20dc9b6` calls the key iterator, which reaches the packed field matcher through `0x1ecdc1d` and `0x2154119` or `0x215418a`, and reaches the byte matcher through `0x215412b` or `0x215414c`. The adapter's internal tags 1 and 4 instead select byte-sized and 64-bit numeric field indices: 0 through 8 store tag 9 and that index; 9 or higher takes an error-construction route. These key indices and the network-value indices below are distinct domains. `field-numeric-cases.tsv` contains synthetic probes, while `tables.tsv` retains both nine-slot dispatches.

The key iterator advances its current pointer at `+0x28` by `0x40` before checking the pulled item's `0x16` sentinel. For a non-sentinel item, it compares its counter to all ones before incrementing and storing it at `+0x40`; equality branches to an indirect call followed by `ud2`. An empty iterator or a sentinel item returns tag 9 and index 9. `iterator-state.tsv` and `transfers.tsv` pin these local stores and branches; allocation, unwind and indirect-call effects remain external.

Field index 1 selects `0x20dccd6` from the 10-slot record table at `0x3c73d8`. The value reader `0x208d290` forwards internal input tags `0x0c` and `0x0d` to the network wrapper; tag `0x15` follows a separate sequence-shaped arm, while other tags take a local error-construction path. A value that reaches the wrapper proceeds through `0x22e9610` and `0x21db5f0`; after a tag-9 result, the discriminator is saved locally and eventually stored at `0x20de008` into output byte `+0xb8`. The writer independently forms its input pointer plus `0xb8` at `0x1e89af0` and calls `0x22e6160` at `0x1e89b43`. The matching field name, order and offset support a common record layout; the static evidence does not prove that a particular output object is subsequently passed to that writer.

### Network names, descriptors and bounds

Both selected name matchers reference the four complete 16-byte descriptors at `0x56a0fc0`: their error-path RIP-relative LEAs start at `0x22edbdc` and `0x22edad3`. The descriptor RELA addends point to length-delimited bytes beginning at `0x3dff5e`; the same underlying `Local` bytes have appeared in other work, so this is a newly examined descriptor reference and path, not a claim to have discovered a new spelling. `networks.tsv` records both matcher result stores, relocation and file offsets, writer table arm, marker and extracted name bytes. The packed and byte comparisons, the descriptor bytes, and the writer's independent immediate stores all agree:

| Discriminator | Name | Writer bytes, hex |
| ---: | --- | --- |
| 0 | `Local` | `a54c6f63616c` |
| 1 | `Sandbox` | `a753616e64626f78` |
| 2 | `Testnet` | `a7546573746e6574` |
| 3 | `Mainnet` | `a74d61696e6e6574` |

The packed matcher tests exact lengths 5 or 7 and complete overlapping comparisons. Other lengths, including the nine bytes `NvTestnet`, take its external unknown-name helper. The byte matcher independently compares every byte and has the same four success values. `name-cases.tsv` contains synthetic exact and changed-input probes, not target executions.

In the selected normalized-value dispatcher, internal tag 1 reads a byte and tag 4 reads an unsigned 64-bit word; each checks the unsigned value against 3 before a four-entry table. Values 0 through 3 store result tag 9 and that value. An internal numeric value 4 or 32 goes to a range-error construction route, rather than being locally converted to another network value. These are **internal tags**, not raw wire marker bytes; the outer decoder is outside this packet. `numeric-cases.tsv` is an explicitly synthetic model of those two bounded paths. The writer indexes its four-arm table directly; no behavior is claimed for an invalid writer input.

The prior `constants` and `constants-aws-name-parse-94` packets establish the separate `AwsName` fallback value 32 and the `/static_config` and `/cham` full template entries. The separate `RE-015-hlchain-reader-94` packet maps a different decoder from wire markers through cursor and depth changes; it already establishes the same four names and a bound of 3 for that reader. This packet instead traces an unowned nine-field record specialization, its normalized-value dispatcher and its matching-layout writer, and examines their distinct descriptor array. It does not repeat the previously owned function bodies or assert a conversion from the `AwsName` fallback to the action's network byte. The reference's `chain_hint` is not used as evidence for such a conversion.

### Failure and buffer boundaries

| Condition | Selected local route |
| --- | --- |
| Field 1 appears after a prior value | The temporary byte was initialized to 4; the check at `0x20dccd6` branches to `0x20de5bb`, which passes the `hyperliquidChain` slice and the `duplicate field` template to an external helper. |
| Field 1's value representation is absent | The tag-`0x16` branch at `0x20dccf3` reaches `0x20de2b4`, passing the 44-byte `MapAccess::next_value called before next_key` diagnostic to an external helper. |
| The value reader sees other than internal tags `0x0c`, `0x0d` or `0x15` | It branches to `0x208d5c4`, calls an external detail helper and then an error constructor. |
| The `0x15` value arm has no item, a sentinel first item, or a non-sentinel second item | The first two cases branch to `0x208d472`; the last branches to `0x208d4f3`. Both routes call an external error constructor and perform different local cleanup. |
| End of the selected field walk with temporary byte 4 | `0x20dd636` selects the `missing field` template and the same field slice. A non-tag-9 helper result takes `0x20ddaee`; the meaning of any other helper result remains external. |
| Network reader result is not tag 9 | The record reader routes through `0x20dd474` and copies the returned payload into its error-shaped result. |
| Network output helper returns a non-success representation | The writer compares its result with `0x8000000000000004` at `0x1e89b48`; the other route at `0x1e89cf2` copies the returned three-word payload. |
| Prefix or name does not fit the current buffer | Each name arm has one reserve call before the marker and a separate reserve call after that marker but before name bytes. The buffer length is already incremented when the latter call is reached. Effects of a helper that unwinds or fails are not assumed. |

The diagnostic templates are retained as complete byte entries in `templates.tsv`; the length-delimited missing-value diagnostic is in `diagnostic.tsv`. For writer mode-byte inputs 0 and 1, the initial container marker is respectively `0x9a` and `0x8a`; `mode-markers.tsv` derives these from the XOR, shift and OR operands. Treating them as MessagePack array and map markers is an inference from their bytes and subsequent writes. For the four valid names, the first output byte is `0xa0 | name_length`, followed by the shown ASCII. The capacity cases in `growth-cases.tsv` model only the local branch order and assume a successful reserve supplies the requested capacity; they are not allocator or captured-runtime tests.

### Inferences and unresolved links

The binary passes the `SendAssetAction` slice to the reader; treating that slice as a source-language type name and identifying it with the `SendAsset` material in `bridge-user-signed-types-94` remain inferences from its nine fields and matching offsets, not recovered symbols. The four names and their order agree with the prior four-network reader and the `HlChain` reference lead; identical spellings alone do not prove source-type identity. No selected body establishes how an `AwsName` determines a node network, or how the node network is supplied to an action. The generic decoder, error builders, reserves, allocator, remaining record fields and full reader-to-writer object lifetime are boundaries.

## Implementation and comparison

Independent Rust implementation: not yet implemented. A component manifest, lockfile, compiler/linker flags, two-build comparison and captured-runtime fixtures are not yet implemented or measured. No raw or normalized source-built comparison is claimed and there are no normalization masks. Helper, dynamic-call, relocation outside the selected descriptors, vtable/data, exception action and whole-ELF closure remain open. Raw FDE bytes are research evidence, not transplanted implementation code.

## Results and limitations

The deterministic evidence covers 13 selected FDE extents and 28,327 bytes, 35 selected byte windows, 21 direct calls, 41 direct branches, 16 selected RIP references, 95 retained table slots, nine field entries and four network descriptors. It also includes 16 byte-comparison records, 28 synthetic name probes, 20 synthetic network-numeric probes, 24 synthetic field-numeric probes and 20 synthetic buffer-control probes. These are scoped denominators only. The focused suite passes 53 tests with no skips, including digest, selected-byte, branch, table, descriptor/relocation, range, NOBITS, missing-name, overflow-branch and buffer-boundary controls. Full test discovery was not run under the memory constraint. Artifact authentication, catalogue consistency and existing inventory/literal reproduction passed.

No captured node or visor was executed, no network or chain action occurred, and no reconstruction or equivalence gate is advanced. The global configuration component remains 0/4. Next, independently trace an unowned producer of the node network byte and its comparison with this action field, without treating the separate `AwsName` default as the same discriminator.
