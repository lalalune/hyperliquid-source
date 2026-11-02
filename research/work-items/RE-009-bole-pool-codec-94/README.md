# RE-009: BolePool state codec and user-entry path

This packet establishes the ordered BolePool fields, accepted aliases and absence behavior, including the nested user-entry encoding, so a reconstruction can distinguish compatible state inputs from different serialized state bytes.

- Component ID: RE-009, storage and state serialization.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `e5c9b6436876b2a4a39daef813171f9879317699` / `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is not used as authority or copied into the tool.
- Claim status: byte observations and bounded static inferences; no target execution or equivalence claim.
- Scope included and excluded: the writer, its key helpers, the reader's named-map path and finalization, and the `u` collection's writer, pair and entry-value path. Hash composition, durable database framing, nested `r`, `b`, `bog`, `uobc`, and `t` values, sequence-reader parity, all other releases and runtime fixture behavior remain outside this packet.

## Reproduce

From the repository root, with Python 3.12.3 on Linux x86-64 and the pinned artifact present:

```sh
python3 tools/bole_pool_codec_94.py --out research/work-items/RE-009-bole-pool-codec-94
python3 -m unittest tests.test_bole_pool_codec_94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

To compare separate regenerations, substitute two distinct relative output directories for `<out-a>` and `<out-b>`:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/bole_pool_codec_94.py --out <out-a>
PYTHONHASHSEED=617 TZ=Pacific/Honolulu python3 tools/bole_pool_codec_94.py --out <out-b>
diff -r <out-a> <out-b>
```

Placeholders denote directory arguments; replace them before running the commands. The extractor reads ELF bytes and does not execute the target or invoke external programs. It checks the complete input SHA-256 before parsing and imports the repository's `elf_index` and `fde_extents` readers. It resolves only unique file-backed sections and excludes `SHT_NOBITS`. It checks pinned body digests and FDE records, then decodes selected x86-64 relative operands, constant comparisons, relocation entries, and table entries. No general instruction decoder is implied. The generated TSV files and their hashes are recorded in `MANIFEST.sha256`. The commands change only the selected output directory; artifact and catalogue checks are read-only.

## Evidence

All VAs are original ELF virtual addresses before load bias. File offsets are recorded separately; several code file offsets differ from their VAs. The ranges in `functions.tsv` are FDE-described unwind extents, end-exclusive, not proof of all reachable blocks or complete source function boundaries. Each row carries the FDE address, file offset, size, and full body digest. Analysis is bounded to the selected static paths; it did not time out.

The reader at `0x198bad0` references a relocated descriptor whose exact bytes are `struct BolePool with 21 elements` (`type-record.tsv`). Its field-classifier call reaches `0x22e3620`; that classifier's 13-entry length table and 20-entry single-byte table, comparison immediates, and return tags recover 28 accepted spellings for 21 field indices. At `0x198f087`, a 22-entry relative jump table dispatches those 21 indices and the unknown index. This identity attaches directly to the reader; identifying the separate writer as the same BolePool codec is an inference from the complete matching field set, order and object layout.

The writer's FDE begins at `0x232ad20`. Its configuration byte at offset `0xb` chooses header calls, each supplied count 21. At configuration value 1 the field-name paths emit the compact keys below in this order; at value 0 the sequence path suppresses those names. Behavior for other configuration values is not established. `fields.tsv` ties every name literal and object access to the corresponding reader case, its duplicate guard, and a direct value-helper call. `accepted-keys.tsv` records all classifier spellings, including the seven alternate spellings. Missing behavior describes the selected map-finalization path, not the separate sequence reader. These outcomes follow when each internal presence slot retains its initial sentinel; the nested decoder invariants for a present value are not proven here. For paired defaults the two numbers are decoded representation words; their domain names and units are not established.

| Writer key | Object offset | Additional accepted spelling | If absent in the map path |
| --- | --- | --- | --- |
| dp | 0x118 | - | 0 |
| du | 0x119 | - | 0 |
| o | 0x11a | opmb | 0 |
| pmmt | 0xa8 | - | 10 |
| pmmu | 0xb0 | - | 100000 |
| e | 0x11b | enabled | 0 |
| pmv | 0xb8 | - | 0 |
| pma | 0xc0 | - | 0 |
| r | 0xc8 | reserves | missing-field diagnostic |
| p | 0xe8 | usdt_usdc_px | missing-field diagnostic |
| n | 0xf0 | enp | missing-field diagnostic |
| b | 0x0 | bl | missing-field diagnostic |
| bog | 0x40 | - | delegated default |
| pmdl | 0x50 | - | (86400000, 50000) |
| pml | 0x60 | - | (60000, 10) |
| uobc | 0x90 | - | delegated default |
| ubgl | 0x70 | - | (60000, 100) |
| ubul | 0x80 | - | (60000, 10) |
| bwo | 0x11c | - | 0 |
| mbs | 0xf8 | - | missing-field diagnostic |
| u | 0x100 | user_to_state | missing-field diagnostic |

`default-branches.tsv` records 13 direct default decisions and two calls whose default results remain opaque; `missing-fields.tsv` records six missing-field diagnostic paths. The five boolean defaults arise from an initial sentinel of 2 and final bit mask 1. There is a duplicate guard for each of the 21 field indices; both spellings of an alias select the same guard. Each taken duplicate branch and each missing diagnostic references its field name and calls the constructor at `0x1704040`, which writes tag 6 on its normal return. The unknown-key branch calls a separate value handler and checks its return before continuing. These are static control-flow findings, not exercised corrupt snapshots.

The `u` writer tail-calls a collection wrapper. That wrapper calls a collector and then a list writer; the collector allocates 16-byte entries and records pairs of addresses. The list writer advances by 16 bytes per pair and routes each to the pair writer. The pair writer has a two-element sequence-header path and a fast path with marker `0x92`, and passes the first and second pair pointers to separate helpers (`edges.tsv`, `anchors.tsv`). It forwards a non-success helper result instead of continuing the loop. The first-component writer passes input length 20, output capacity 42 and mode 0 through the relocated formatter slot (`indirect-edges.tsv`). Together with the separately established prefixed-hex primitive in `research/work-items/RE-005-prefixed-hex-rust-94/README.md`, this supports the inference that this component becomes a 42-byte `0x`-prefixed lowercase hexadecimal string. The pair-order and collection-order policies beyond the observed traversal have not been proven.

For the second component, the two statically selected value-writer variants each pass a count of either 1 or 2. In the variant at `0x28d3d30`, key `t` is emitted from object offset `0x18`; key `o` at offset 0 is omitted when four checks all hold: qword `+0` is zero, dword `+8` equals the nonzero return of the relocated helper called with immediate `0xaf93b`, and dwords `+0xc` and `+0x10` are zero. The helper is called once for the count and again for the emission decision. The corresponding date-constructor and epoch interpretation are covered independently by `research/work-items/RE-001-daycount-date-94/README.md`; this packet records its call edges, not that helper's implementation. Count and emission agreement assumes the two helper calls return the same value. Nested payload internals remain unresolved.

Raw, deterministic evidence: `functions.tsv`, `fields.tsv`, `accepted-keys.tsv`, `default-branches.tsv`, `missing-fields.tsv`, `nested-fields.tsv`, `dispatch-tables.tsv`, `edges.tsv`, `indirect-edges.tsv`, `type-record.tsv`, and `anchors.tsv`. The conditional-branch and comparison bytes are retained with the applicable linked addresses; direct and indirect calls retain their operands and relocation coordinates. No objdump text is parsed to generate these records.

## Implementation and comparison

Independent Rust implementation, build scope, Cargo lockfile, compiler/linker settings, two-build comparison, normalized machine-code comparison, masks and target fixtures: **not yet implemented or measured**. The Python predicate model is a static interpretation of pinned bytes and a supplied helper result; it is not execution of the target. Error, byte-corruption, out-of-range address, NOBITS and digest controls exercise the evidence extractor rather than claim runtime protocol parity. Calls to generic writers, the two delegated-default providers, the formatter/date helpers already documented elsewhere, and nested values are external closure gaps.

## Results and limitations

The packet binds 22 distinct FDE extents, 21 writer fields and duplicate guards, 28 accepted classifier strings, 15 absent-field default paths (13 direct and two delegated), six missing-field diagnostic paths, two nested value fields, 26 selected direct edges and eight selected relocated indirect edges. These counts describe this selected path, not a complete node or component census. The focused suite has 17 tests with no skips; two differently seeded and time-zoned regenerations must match byte for byte. No full-scope progress gate is requested. The committed state-root association, hash preimage/framing and all omitted nested value semantics remain unresolved.

Next question: independently bind the selected `u` collection to the relevant state-root preimage, then recover the nested `t` value and the delegated defaults without assuming that an inferred source name proves ownership.
