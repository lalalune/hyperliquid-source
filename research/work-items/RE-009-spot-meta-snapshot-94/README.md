# RE-009: node #94 spot metadata state codec

The selected node #94 spot-metadata codec writes 14 fields in a fixed order, and both examined readers route an omitted `ta2` through a two-word zeroing path; a reconstruction can preserve that compatibility distinction while leaving the field's underlying type unresolved.

- Component ID: RE-009, storage and state serialization.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `966865f1637a29ce75b019e1bf11d5529cc6f519`; unlicensed `can1357-hl` revision `999556f6e0a474b8312db96ec3149e1c44e97c23` supplies naming leads only.
- Claim status: observation for selected original bytes, FDE-described ranges, call and branch destinations, labels and offsets; inference for the spot-metadata identity and MessagePack/JSON format labels; unresolved for child encodings and on-disk use.
- Scope included and excluded: two writers, one field-name classifier, two readers, selected field helper bodies, field order, input offsets and selected failure/default paths. Child codec internals, complete reader control flow, runtime I/O, actual snapshot fixtures, hashing, version-to-version compatibility, other releases and the visor are excluded.

## Reproduce

Run from the repository root using CPython 3.12.3 or a compatible Python 3 with only the standard library and the repository's `tools/elf_index.py` and `tools/fde_extents.py`:

```sh
python3 tools/spot_meta_snapshot94.py --out research/work-items/RE-009-spot-meta-snapshot-94
python3 -m unittest tests.test_spot_meta_snapshot94
(cd research/work-items/RE-009-spot-meta-snapshot-94 && sha256sum -c MANIFEST.sha256)
```

For an independent determinism check, run the generator twice into distinct empty directories under a scratch directory and compare them:

```sh
python3 tools/spot_meta_snapshot94.py --out <tmp-dir-a>
python3 tools/spot_meta_snapshot94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
```

Compare the four generated files against the files in this work item. The generator authenticates the target digest before ELF parsing, opens the target read-only, and does not invoke external programs or run the binary. It extracts sections and FDEs through the shared parsers, decodes only explicit byte patterns, and rejects changed selected body hashes, ambiguous addresses, unsupported instruction forms and inconsistent field or branch facts. The classifier control evaluates a small fixed grammar against synthetic byte strings; it does not run the node. Outputs do not contain host paths or timestamps. GNU objdump 2.42 was used to inspect bounded windows by hand, and its text is not consumed by the generator or tests.

## Evidence

All addresses are unrelocated ELF virtual addresses. `evidence.json` includes file offsets and bytes for 174 selected windows, 19 FDE records with body hashes, the length and dispatch tables, and the selected branches. FDE endpoints are exclusive unwind-described ranges, not proof of complete function boundaries or cold-part closure. `fields.tsv` holds the individual name, offset, callee, duplicate and missing sites; `json-diagnostics.tsv` holds the separately selected JSON-shaped diagnostic blocks. These are selected windows, not a whole-node inventory.

### Writers and field layout

The compact writer `0x2390b60..0x2390eb4` checks serializer byte `+0xb`. For values 0 and 1 it selects, respectively, a positional-container helper or a named-container helper, both with count 14. Named mode supplies a label before each child. The JSON-shaped writer `0x23907f0..0x2390b53` emits an opening `{`, field labels, separators and the corresponding child calls in the same order. The MessagePack interpretation of the compact helpers is supported by the existing RE-009 EVM-state codec packet, but a file entry point and actual serializer configuration are not established here.

| Tag/order | Field label | Argument passed to child, relative to input |
| ---: | --- | ---: |
| 0 | `spot_infos` | `+0x160` |
| 1 | `token_infos` | `+0x178` |
| 2 | `token_id_to_token` | `+0x1a8` |
| 3 | `canonical_tokens2` | `+0x190` |
| 4 | `allow_duplicate_token_names` | byte at `+0x280` |
| 5 | `token_to_approx_usdc_pxs` | `+0x1c0` |
| 6 | `liquid_base_tokens` | `+0x1d8` |
| 7 | `token_name_to_canonical_deployer` | `+0x1f0` |
| 8 | `token_to_first_time_enabled_as_quote` | `+0x208` |
| 9 | `quote_token_to_aligned_quote_token_info` | `+0x220` |
| 10 | `liquid_quote_tokens` | `+0x238` |
| 11 | `quote_token_to_status` | `+0x250` |
| 12 | `outr` | input base |
| 13 | `ta2` | `+0x268` |

The `outr` helper receives the input base; this is not a claim that its entire value starts at offset zero. The two writers agree on each listed label and argument setup. The call targets and checked non-success exits after all 14 child calls are in `evidence.json`. For example, a non-success result from a compact child reaches one of `0x2390e77` or `0x2390ea1`; a nonzero JSON child result branches to `0x2390aa6`. The header calls have their own return checks. These observations do not establish child formats or side effects.

### Reading, duplicate fields and omission

The compact-shaped reader `0x178bea0..0x1791ccc` calls classifier `0x22e06e0..0x22e11e3`; the latter's length table covers byte lengths 3 through 39 and selects byte comparisons. For the 14 labels above it returns tags 0 through 13 in writer order. Other tested strings return tag 14. The reader's 15-entry dispatch table sends each known tag to a seen-state test and a field-specific `duplicate field` diagnostic branch. Tag 14 reaches a separate helper call with a checked return; the helper's behavior is outside this packet.

On the selected map-completion path, the first 13 labels have missing-field diagnostic paths. Their presence gates, labels and destinations are individually recorded. The `ta2` case differs: the reader tests the same stack presence slot used by its duplicate gate and, when it is zero, branches `0x178f731 -> 0x178f89c`, zeroing two registers before two words are assembled. The other word, its type, and complete success/error precedence remain unresolved. These are static paths conditional on reaching the map-completion checks; they are not execution observations.

The JSON-shaped reader `0x1c39a20..0x1c3df96` has selected entry branches for `[` and `{`. Within its FDE, the bounded pattern scan identifies 14 duplicate-field diagnostic blocks and 13 missing-field diagnostic blocks for the same names; no `ta2` missing diagnostic is found under this matcher. A separately checked `ta2` seen-slot comparison branches to its duplicate diagnostic at `0x1c3c810`; its zero-presence branch goes to `0x1c3c594`, where two registers are zeroed before two assembled-word stores. The scan does not claim complete JSON grammar or prove all diagnostic blocks reachable on arbitrary inputs.

### What is inferred

Field names, argument relationships and the match with the reference's spot metadata support the component label. Map/array and JSON terminology is an interpretation of helper identity and marker/separator bytes. The exact source type, ownership, collection element schemas, field aliases, and whether either observed writer is used for a particular snapshot file remain open. No bytes are copied from the reference implementation.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No Cargo build, original/rebuilt byte comparison or normalization masks are claimed. The generated classifier cases exercise a bounded model of the captured compare grammar, not the live target or its nested decoders. No fixture from a real database or node execution was used. The tests reject a bad input digest, modified FDE extent/body, corrupted calls, branches, name references and field-offset instructions, unmapped ranges and a fileless `.bss` read. They also test all 70,890 possible single-byte substitutions across the 14 labels against the selected classifier, and test truncated and extended labels.

## Results and limitations

The packet records 14 ordered fields, 14 compact-reader duplicate branches, 13 compact missing-field diagnostic paths, two selected `ta2` omission branches, and 27 JSON diagnostic blocks. The generated case table has 320 selected exact, changed-byte and length cases. These are counts within the selected code, not function coverage, target/rebuild equivalence or a component completion percentage. No full-scope progress gate is requested.

The readers' full sequence paths, unknown-value helper, nested field codecs, actual disk format, source build and any relation to a particular state root or snapshot version remain unverified. Next question: trace the enclosing state serializer to the snapshot entry point and validate a sanitized fixture under a separately authorized offline execution harness.
