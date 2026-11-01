# RE-009: state context snapshot codec and compatibility alias

The node #94 `ctx` state value has a 13-field serialized order, a two-field nested `hardfork`, and a `consensus_round` read alias for `round`; a reconstruction can preserve this part of the hash-input field order and recognize the snapshot alias.

- Component ID: RE-009, storage and state roots.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; unlicensed inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23` was used for leads only.
- Claim status: observations are the selected bytes, field names, offsets, direct calls, classifier and branches; interpreting these as a snapshot context and MessagePack/JSON-shaped forms is an inference. Runtime reachability and complete input grammar remain unresolved.
- Scope included and excluded: the compact and JSON context writers and readers, their selected parent call sites, two field classifiers, the nested hardfork JSON writer, compact nonce helper and compact timestamp formatting route. Excludes full parent functions, timestamp and primitive codec bodies, hash algorithm internals, on-disk data, binary execution, other releases and visor.

## Reproduce

Run from the repository root with Python 3.12.3 and the standard library; `tools/elf_index.py` and `tools/fde_extents.py` are the repository's shared parsers. GNU objdump 2.42 was used only for human inspection of bounded windows. The extractor checks the input digest first, reads file-backed ELF sections and FDE records, and invokes no external program or captured executable. Linked virtual addresses (VA) are used throughout; file offsets and raw bytes are retained in `evidence.json`. No operand normalization or masks are used.

```sh
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 -m unittest tests.test_context_snapshot94
python3 tools/context_snapshot94.py --out <tmp-dir-a>
python3 tools/context_snapshot94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
cmp <tmp-dir-a>/evidence.json research/work-items/RE-009-context-snapshot-94/evidence.json
cmp <tmp-dir-a>/fields.tsv research/work-items/RE-009-context-snapshot-94/fields.tsv
(cd research/work-items/RE-009-context-snapshot-94 && sha256sum -c MANIFEST.sha256)
```

The two output directories are placeholders for separate writable directories. Reproduction was also checked with different hash seeds and time zones and with no binutils on `PATH`. The manifest covers the three other files in this work item; it is not a signature.

## Evidence

The contextual direct call at `0x2755813` enters the JSON writer after its parent emits the three bytes `ctx`; the compact writer is called at `0x28194d0`. The existing app-hash builder packet associates that latter enclosing job with the context hash input. The compact and JSON reader call sites `0x17362e0` and `0x1bf0a1d` enter the two selected readers. These are checked contextual edges, not a new analysis of their enclosing functions or proof of every checkpoint entry path.

| Selected role | FDE start | FDE end, exclusive |
| --- | --- | --- |
| compact writer | `0x2218e60` | `0x22192c9` |
| JSON writer | `0x2218b30` | `0x2218e5c` |
| compact reader | `0x18571b0` | `0x185976a` |
| JSON reader | `0x1cbf300` | `0x1cc09ee` |
| compact key classifier | `0x21e4170` | `0x21e4663` |
| JSON key classifier | `0x21e4870` | `0x21e4a6a` |
| nested JSON writer | `0x21f6110` | `0x21f6347` |
| compact nonce field writer | `0x22bdd40` | `0x22bddd1` |
| compact timestamp field writer | `0x22bdee0` | `0x22bdf3d` |
| timestamp type gate | `0x1e4fc10` | `0x1e4fcbc` |
| timestamp formatter and string writer | `0x1dfca40` | `0x1dfcb91` |

The bounds are actual unwind FDE extents and the generator checks complete body hashes. An FDE alone does not prove a complete source function or all cold parts.

For serializer mode byte `+0xb` equal to 1, the compact writer selects the map helper with 13 entries; for 0 it selects the array helper with 13 entries. Under those same two modes `hardfork` is a nested map or array of 2 with `version` and `round` in that order, read from context offsets `+0x18` and `+0x20`. The JSON writer emits the named fields in the same order. `fields.tsv` gives byte-derived literal addresses, selected writer sites, offsets and compact-reader dispatch arms:

| Position | Field | Value offset |
| --- | --- | --- |
| 0 | `initial_height` | `+0x10` |
| 1 | `hardfork` | `+0x18` |
| 2 | `height` | `+0x28` |
| 3 | `tx_index` | `+0x00` tag, `+0x08` payload |
| 4 | `round` | `+0x30` |
| 5 | `time` | `+0x60` |
| 6 | `prev_time` | `+0x6c` |
| 7 | `next_oid` | `+0x38` |
| 8 | `next_lid` | `+0x40` |
| 9 | `next_twap_id` | `+0x48` |
| 10 | `system_nonce` | `+0x50` |
| 11 | `use_system_nonce` | `+0x78` |
| 12 | `mac` | `+0x58` |

For `tx_index`, the compact writer compares the tag with 1; that branch passes the payload to the integer writer, and the other branch calls a separate null-shaped helper. Each selected writer tests child/header results and follows error exits before subsequent fields. Values other than 0 or 1 at the mode byte are outside this analysis.

Both time-field sites call the same compact helper. It supplies the four-byte type name `Time` to a gate that selects an extension-specific arm only for a ten-byte `_ExtStruct` name, so this route instead enters the formatter. The formatter passes a pointer to the first part to one formatting slot, emits ASCII `T`, then passes the value at offset `+4` to another formatting slot and sends the resulting bytes to the string writer. A reported formatting failure reaches a non-returning error call followed by `ud2`; string-writer errors take a separate return path. The exact calendar grammar, time zones and fractional precision are not established here.

The compact reader calls its key classifier at `0x1858cbc`. Its 14-entry dispatch table assigns indexes 0 through 12 to the fields above and index 13 to a separate unknown-value arm. Both the compact classifier and the independently located JSON classifier compare `consensus_round` as an alias of `round`, index 4; the writer emits `round`. Consequently, on the compact map path, after a successfully decoded first value, either spelling reaching that same seen slot selects the duplicate-field branch for the other spelling. The record contains all 13 duplicate-branch sites and destinations. Unknown-value helper behavior is not characterized.

The compact reader's end-of-map checks and the JSON reader's corresponding checks route missing `initial_height`, `height`, `time`, `prev_time`, `next_oid` and `next_lid` through field-specific missing-field diagnostics, in that order conditional on earlier decoding. The saved branch records identify the names and both destinations. The compact reader also has conditional moves that supply zero for several absent optional slots, and a distinct absent `tx_index` tag. This packet does not claim every default's source type or interpret the timestamp encoding. In the selected sequence route, the first five positions are individually attempted in order, and an early count or child failure takes an error route; later short-sequence behavior is not fully modeled.

`evidence.json` retains 11 FDE extents and body hashes, 13 writer/reader field rows, 14 dispatch targets, 13 duplicate and 12 missing-field branch records, the two container count pairs, raw code windows, 6 contextual call edges, and 4 timestamp-route edges. The key classifier evaluator interprets a restricted set of fixed x86 byte-comparison and branch encodings and fails closed on other opcodes or out-of-range reads. It checks all 13 emitted names and the alias against the actual captured machine bytes. All 32,640 possible single-byte substitutions across those 14 probes fail to produce the original field index. These are static classifier controls, not node execution or a claim about complete malformed snapshots.

## Implementation and comparison

Independent Rust implementation: not yet implemented. No build, native behavior fixture, whole-ELF comparison, normalization, call-target closure, live database inspection or cross-version compatibility result is claimed. The selected body hashes bind this static analysis; they do not establish reconstructed Rust equivalence. The focused tests exercise wrong digests, changed classifier instructions and table entries, an altered body, NOBITS-only and unmapped addresses, wrong instruction prefixes, key substitutions and alias dispatch.

## Results and limitations

Nine focused unittest methods pass with no skips. Two independent generations, under different hash seeds and time zones and without binutils on `PATH`, compare byte for byte. The classifier covers the selected byte comparison routine, not the JSON parser's full escape handling. The two readers are distinct monomorphs; their selected checks do not establish identical malformed-input precedence. Field names and the `ctx` call path support the context interpretation, but neither a real snapshot nor a complete hash preimage has been captured. No progress gate is requested.

Next question: recover the complete timestamp text grammar and verify full `ctx` serialization against an authorized offline snapshot fixture, including truncated sequences and alias duplicates.
