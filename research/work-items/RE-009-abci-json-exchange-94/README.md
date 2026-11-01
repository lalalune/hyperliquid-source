# RE-009: ABCI JSON Exchange field dispatch and compatibility names

The node #94 ABCI JSON state reader sends three alternate Exchange field names to the same value and duplicate-check slots as their current names, so a reconstruction can preserve those aliases and reject a second spelling when the first value has been accepted.

- Component ID: RE-009, storage and state snapshots.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; inferred, unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23` used only for leads.
- Claim status: observations are the selected bytes, table entries, labels, and branch destinations; the field, codec and compatibility interpretations are inferences described below.
- Scope included and excluded: the selected JSON reader's outer `exchange` field, its nested object dispatch, classifier, selected scalar value path, duplicate and missing diagnostics. Excluded are full nested value schemas, complete arbitrary-input JSON parsing, MessagePack, runtime filesystem behavior, other releases and target execution.

## Reproduce

From the repository root, Python 3.12.3 and the standard library; the generator imports the repository ELF and FDE readers. It first authenticates node #94 and reads it as data. It never executes the artifact or invokes an external program. Only the chosen output directory is written.

```sh
python3 tools/artifacts.py verify
python3 tools/abci_json_exchange94.py --out work/abci-json-a
python3 tools/abci_json_exchange94.py --out work/abci-json-b
diff -r work/abci-json-a work/abci-json-b
python3 -m unittest tests.test_abci_json_exchange94
python3 tools/catalogue.py --check
```

The four generated files are `evidence.json`, `fields.tsv`, `names.tsv`, and `missing.tsv`. The latter two tables are projections of the JSON; the generator reconstructs all four. Run `sha256sum -c MANIFEST.sha256` from this work-item directory to check its manifest. No captured program, network, or chain data is used. The generated files do not contain disassembler output; GNU objdump 2.42 and Capstone 4.0.2 were used for bounded, human inspection during analysis.

## Evidence

All addresses below are linked ELF virtual addresses with load base zero; file offsets, full body hashes and raw selected windows are in `evidence.json`. FDE ends are exclusive. An FDE is unwind metadata and does not alone establish a complete function boundary. The decoder checks the target digest, file-backed section mapping, actual FDE records, fixed instruction forms, relative displacements and the indicated relocation records. It excludes `SHT_NOBITS` from file reads. All bytes and table entries are unmasked; there is no normalized binary comparison.

The existing `RE-019-rmp-json-loader-94` packet ties a JSON decoding arm of the state-path loader to a reader. This packet starts at the reader below and does not reanalyse that loader. A vtable relocation on its type-error path reaches an expected-value formatter that names `struct AbciStateDe`. The child has a separate expected-value formatter naming `struct Exchange`.

| Selected role | FDE extent | Bounded observation |
| --- | --- | --- |
| Outer state reader | `0x315ba80..0x315c41b` | `{` and `[` routes; the map route compares the eight bytes `exchange` and calls the same child as the sequence route. |
| Nested Exchange value reader | `0x3182d10..0x318656f` | `{` invokes the nested map visitor; `[` follows a distinct sequence route. |
| Nested map visitor | `0x2fe5290..0x2ff55de` | Classifier return byte selects a 61-entry relative table at `0x57b1fc`: 60 field arms and a separate unknown-field arm. |
| Field classifier | `0x36ee4d0..0x36eefc6` | A 50-entry length table handles lengths 2 through 51; the unsigned outside-range branch returns tag 60. |
| Selected boolean child | `0x3094420..0x30945f9` | The selected byte parser checks `true` and `false`, produces values 1 and 0 on the shown success branches, and takes separate error paths. |

For the outer map route, length and byte comparisons identify `exchange`. Its first selected child result is kept in a presence slot. A later `exchange` key branches to the `duplicate field` diagnostic before invoking the child again; a map completion with the slot absent supplies `exchange` to the `missing field` diagnostic. The empty sequence takes a separate error path; a nonempty sequence invokes the same child. Other outer keys invoke a shared helper; its complete handling is not established here. These statements are conditional on the preceding JSON parsing and child results.

`fields.tsv` records all 60 duplicate-label arms, their guard bytes, conditional transfers and error-label addresses; tag 60 is separately recorded in JSON. Each arm's selected conditional reaches a construction that supplies its label to the same `duplicate field` template. `missing.tsv` records 35 distinct labels from a fixed-pattern scan for the `missing field` template and preceding pointer/length setup within the nested visitor. This is a census of those matched instruction patterns, not proof that the other 25 fields have defaults or that the 35 failures are all reachable under every surrounding state. Instruction alignment for those 35 candidates was checked independently by a complete linear decode of this one FDE; the generator itself uses the explicitly checked byte patterns, not a general disassembler.

`names.tsv` associates 63 selected comparator names with all 60 tags and the corresponding duplicate labels. The tool reconstructs names from checked immediate comparisons, overlapping SIMD constants, fixed-length equality operands and the short-name cases; it checks the length table, relevant branch destinations, the dynamic equality-helper relocation and uniqueness. It verifies all 60 labels have a same-named comparator. These are selected pattern matches, not a proof of the complete classifier CFG or all possible names. In particular, tag numbers are internal to this one compiled reader, not a persisted on-disk discriminant.

Three selected pairs converge on the same tag and the same guard:

| Duplicate diagnostic label | Additional matched name | Tag | Evidence of selected length routes |
| --- | --- | ---: | --- |
| `default_hip3_limits` | `default_perp_dex_limits` | 43 | Lengths 19 and 23 select different comparator chains, which both reach the same tag. |
| `hip3_no_cross` | `hip3_isolated_only` | 47 | Lengths 13 and 18 reach the immediate and SIMD comparisons respectively. |
| `last_aqa_sample_time` | `last_aligned_quote_token_sample_time` | 50 | Lengths 20 and 36 reach different comparisons and the same tag. |

For tag 43, the accepted child result is stored at the same nonzero-tested local used by its duplicate guard; zero takes an error branch. For tag 47 the selected boolean child returns 0 or 1 on the shown success routes, and the caller stores that byte into the guard whose absent sentinel is 2. For tag 50 a selected successful child result sets the guard to 1; a child error takes a separate branch. Thus, after a successful first value, either spelling of the same row reaches its duplicate diagnostic when encountered again. This is a static control-flow conclusion, not an execution fixture. `bcmp` is identified through the dynamic relocation and symbol name, not by a guessed address.

### Inferences and unresolved points

The literal type names and call chain support treating this as an ABCI state JSON `exchange` reader. The diagnostic label and additional name do not establish their chronology or producer versions. The three names are compatibility alternatives on the selected map route, but this does not prove a whole snapshot can be loaded, that aliases are emitted by any writer, or that releases are compatible. The exact language of all child parsers and ignored values, field defaults, all malformed-input precedence and complete classifier reachability remain open.

## Implementation and comparison

Independent Rust implementation: not yet implemented. No Cargo build, target execution, database fixture, raw/normalized source comparison, helper closure, vtable/data closure or whole-ELF comparison is claimed. Input identity is the authenticated node binary. The 13 focused unittest methods include digest, NOBITS/unmapped addresses, altered table targets, branch opcodes, literal setup, diagnostic targets, SIMD data and instruction pins; alias-pair tests check the static tag model. These controls validate extraction and the stated model, not execution of a recovered node.

## Results and limitations

The extractor records 5 selected unwind extents, 61 visitor table entries (60 labeled duplicate arms and one unknown arm), 63 selected comparator names across 60 tags, three pairs with differing names for one tag, 35 matched missing-field diagnostic sites, and 52 selected code pins plus their raw bytes. Full field-value decoding, the rest of the JSON grammar, runtime reachability and cross-release snapshot compatibility remain unmeasured. No component progress gate is requested.

Next question: close the nested value readers and demonstrate, with an independently authored Rust codec and an authorized offline fixture, whether complete snapshots exercise these aliases and their malformed-input precedence.
