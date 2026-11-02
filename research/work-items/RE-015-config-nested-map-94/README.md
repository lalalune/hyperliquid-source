# RE-015: nested provider-key configuration maps in node 94

The `eth_chain_to_rpc_provider_to_keys` field reaches two levels of byte-keyed map insertion, and duplicate keys at either level replace the earlier value and dispose of it, giving a reconstruction a concrete rule that is distinct from rejecting duplicate struct fields.

- Component ID: `constants`, task `RE-015`, `global_constants/*`.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23` was consulted only for hypotheses and not copied.
- Claim status: byte, relocation and FDE observations for this digest; the source-level names and types are inferences. Runtime behavior, absence defaults, and full component equivalence are unresolved.
- Scope included and excluded: ten newly selected unwind-described ranges covering the binary outer-map reader, JSON inner-map reader, object and sequence steps, two map insertions, and disposal; 38 small instruction windows in previously discussed callers are context only. This follows the existing `RE-015-config-name-field-94` field-dispatch result and does not select its functions, reproduce its field table, or reproduce the 76 AWS-name table. The selected functions' callees, other releases, and the overall configuration initializer remain boundaries.

## Reproduce

Run from the repository root with Python 3.12.3 on Linux x86-64. The producer uses only the standard library and the repository's shared `tools/elf_index.py` and `tools/fde_extents.py`; it authenticates the complete artifact before parsing. Section-to-file mappings exclude `SHT_NOBITS`. The decoder is a restricted instruction-length and control-transfer reader adapted from an independently authored MIT replica-route collector, not a complete x86 semantics engine. No captured binary is executed, and no network service or secret file is accessed.

```sh
python3 tools/config_nested_map94.py --out research/work-items/RE-015-config-nested-map-94
python3 -m unittest tests.test_config_nested_map94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
```

For the independent output check, replace the placeholders with two different writable paths. The generator and test suite also run with a PATH containing Python but no binutils. They do not invoke external programs.

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/config_nested_map94.py --out <tmp-dir-one>
PYTHONHASHSEED=91 TZ=Pacific/Honolulu python3 tools/config_nested_map94.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
```

The producer writes the 16 machine-readable files below; the manifest hashes those files and this README, excluding itself. GNU objdump 2.42 was used only to inspect instructions during research. Its text is not parsed, retained in generated files, or required to reproduce them.

## Evidence

All addresses below are linked ELF virtual addresses, without runtime rebasing. The evidence tables also retain section-mapped file offsets. The FDE ranges are half-open unwind extents; they are not a complete function inventory or proof that all code has been found. `instructions.tsv` is a linear partition under a closed set of admitted encodings; `branches.tsv` and `exceptions.tsv` are distinct normal and exception evidence, not an assertion that every branch is feasible.

| File | Contents |
| --- | --- |
| `evidence.json`, `functions.tsv` | Digest, scope counts, selected FDE/CIE/LSDA coordinates and body hashes. |
| `instructions.tsv`, `branches.tsv`, `calls.tsv` | Selected range bytes, decoded transfer kinds and destinations. |
| `witnesses.tsv`, `prior-boundaries.tsv` | Fixed instruction contracts for selected bodies and the explicitly unselected caller boundaries. |
| `binary-jump-tables.tsv`, `field-dispatch-boundary.tsv` | Signed relative table entries and their computed destinations, including adjacent field-tag controls. |
| `relocations.tsv` | Raw records for selected RIP-relative indirect transfer slots, with symbols where available. |
| `lsda-headers.tsv`, `exceptions.tsv` | Bounded unwind exception headers, ULEB call-site ranges, landing pads and raw actions. |
| `cfg-propositions.tsv` | Selected conservative normal-flow reachability checks. |
| `delimiter-probes.tsv`, `binary-prefix-probes.tsv`, `key-order-probes.tsv` | Finite static models of delimiters, map prefixes and comparison, not target execution. |

### Field identity and function map

The field spelling is present as 33 file-backed bytes at VA and file offset `0x21bb6c`. The previous field-classifier packet identifies that spelling with tag `0x1d`; the context window at `0x13c779d` stores that tag. The previously analyzed binary visitor reads the tag and, for `0x1d`, indexes cell 7 of its relative table at `0x20faa0`: the cell at `0x20fabc` resolves to `0x13ad0d1`, which calls the new binary reader at `0x13ad0fc`. Adjacent indices 6 and 8 resolve to different arms. These are context windows, not a newly claimed visitor or classifier body. The earlier initializer packet places a fixed configuration filename under the existing static-configuration directory. It does not establish that the binary-format selector branch is reachable from that exact formatted path through the external path transformer; this packet does not assume that connection.

The previous JSON field arm calls its existing value boundary at `0x14a3a81`; that boundary calls the selected inner-map reader at `0x14bc53c` and the selected outer inserter at `0x14bc5cf`. The selected inner reader calls a pre-existing value-reader boundary, which calls the selected sequence collector at `0x14bd4ab`. In the binary branch, the selected outer reader calls its pre-existing inner-reader boundary at `0x13bcefa`; that boundary calls the same selected inner inserter at `0x13bbb10`. The intervening bodies are not selected here and their complete contracts are not established by these call sites alone.

| Selected start | Role and selected outgoing edge |
| --- | --- |
| `0x13bcaa0` | Binary outer-map reader; key and value boundaries at `0x13bceb9` and `0x13bcefa`, outer insertion at `0x13bcf7f`. |
| `0x14bc870` | JSON inner-map reader; key step at `0x14bc969`, value boundary at `0x14bca1f`, insertion at `0x14bcac3`. |
| `0x14b6220` | JSON object-key/delimiter step; delegates string decoding. |
| `0x14c0500` | Sequence collection and partial-value cleanup; calls `0x14b64d0`. |
| `0x14b64d0` | JSON sequence delimiter step; delegates the element decoder. |
| `0x14cb400` | Inner map search, insert or replace. |
| `0x14ca9e0` | Outer map search, insert or replace; old inner values can reach `0x14da1e0`. |
| `0x14da1e0` | Iterates and drops an inner map's keys and 24-byte-stride value elements. |
| `0x14cced0` | Iterator used by the selected inner-map drop routine. |
| `0x14c95b0` | Sequence cleanup reached from the selected collector's unwind path. |

### Map decisions and failure branches

Both selected inserters compare key byte sequences using the relocated `memcmp` slot `0x576e488`, then compare lengths when the common prefix compares equal. On equality, `0x14cb52c` copies out the old three-word value before writing the incoming one; `0x14cab16` does the analogous operation for the outer map. The equal-key paths return without the count increments at `0x14cb6ba` and `0x14cac91`. A new item can reach those increments. The JSON inner caller disposes of a replaced value, stepping its elements by `0x18` bytes; the binary outer caller disposes of a replaced inner map. The binary inner boundary likewise calls the inner inserter and has a `0x18`-stride cleanup path. These statements concern equal decoded keys, not equality of distinct raw spellings before the external string decoder. Fifteen finite key-order probes exercise equal keys, unequal prefixes, case differences, embedded zero bytes and unsigned high bytes under the imported comparison function's sign contract; these probes are a model and do not establish which byte strings the external decoder accepts.

| Condition | Recorded branch or boundary | Observation |
| --- | --- | --- |
| JSON has no opening `{` | `0x14bc8fa -> 0x14bcccd` | Enters an error-building boundary. |
| JSON depth before or after decrement | `0x14bc900`, `0x14bc913`, `0x14bcce6` | A zero counter takes an external invariant boundary; decrement to zero takes local code `0x18`. |
| End of input before object key | `0x14b627d` | Object-key step constructs local code 3; end after a comma constructs code 5. |
| Object missing comma or comma followed by `}` | `0x14b63d2`, `0x14b63b8` | Local codes 8 and 21 respectively; the string decoder is not called. |
| Object key is not quoted | `0x14b630f`, `0x14b63c5` | The key step constructs local code 17. |
| Object colon absent or input exhausted | `0x14bccaf`, `0x14bcb3b` | Separate local codes 6 and 3, followed by partial-map cleanup. |
| Value or final object check fails | `0x14bca2c`, `0x14bcc0d` | Error paths reach `0x14da1e0` for the partially built map. |
| Sequence missing comma, comma followed by `]`, or end of input | `0x14b6628`, `0x14b6635`, `0x14b653a` | Local codes 7, 21 and 2; end immediately after a comma instead uses 5. |
| Sequence element fails | `0x14c0598`, `0x14c05ba` | The collector returns an error sentinel and releases already collected elements and storage. |
| Binary map length prefix is incomplete | `0x13bcc30`, `0x13bcbd5`, `0x13bcd11` | The selected short-length paths exhaust remaining prefix bytes and return the local error form. |
| Binary value fails after prior entries | `0x13bcefa -> 0x13bd02d` | The partial outer-map disposal boundary is called. |

The JSON whitespace bitmask at `0x14bc89e` contains bits 9, 10, 13 and 32. The binary reader's fresh-marker paths include fixed map markers `0x80..0x8f` and two- and four-byte count forms `0xde` and `0xdf`, with multibyte counts read big-endian. A zero declared count follows the empty-map arm. Other marker cases reach separate handling or boundaries; this does not claim that all non-map markers are universally rejected. The cached-class and extended-marker table spans are the four-byte cells between adjacent pinned table bases, while the raw-marker span follows the selected byte comparisons; these selected spans do not prove that every cached index is reachable. The 22 prefix probes model only marker/length handling under the fresh-marker precondition. The 23 delimiter probes stop at the external string decoder and do not assert its result.

### Inferences and reference comparison

The observed nested insertions and 24-byte-stride sequence elements are consistent with the inferred reference's chain-to-provider-to-list shape. Exact Rust source types, string validity, provider naming, complete element decoding, allocator behavior, tree splitting, and default handling for an *absent* field are not established. An explicitly encoded zero-entry map is different evidence from an absent-field default. The literal field name, branch constants and encoded-map empty case above come from node bytes; no configured provider, API key, production file, or illustrative reference default is asserted to be present in the binary.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo lock, compiler and linker flags, two-build comparison, raw and normalized binary comparisons, masks, whole-ELF identity, allocator and helper closure, vtable/data closure, and fixture replay: not yet implemented/measured. The finite static models, including the comparator sign model, are not executions of the target and are not evidence of execution equivalence. The previous `b_keys` field packet remains a separate question; its top-level duplicate-field handling must not be conflated with these nested map-key replacements.

## Results and limitations

The generator covers 10 selected FDE extents, 8,226 bytes, 1,974 admitted instruction encodings, 165 selected instruction witnesses, 38 prior-boundary windows, 275 selected jump-table entries, three field-dispatch cells, 15 relocated indirect slots, six LSDA headers, 48 LSDA call-site records, 18 conservative CFG propositions, 23 delimiter probes, 22 fresh-marker prefix probes and 15 key-order probes. Those are denominators for this selection only. The focused suite has 33 tests with no skips, including altered whole-file digest, body, previous boundary, literal, a changed but still instruction-aligned table target, relocation symbol, LSDA header, NOBITS, truncation and delimiter controls. Two independent output directories compared equal under different hash seeds and timezones. Artifact verification, catalogue check and inventory/literal reproduction passed.

Normal CFG reachability assumes calls return and stops at indirect jumps; it is an over-approximation, not a concrete execution trace. Exception action and type-table semantics, all indirect callees and the full parser state are open. No RE-015 or component milestone gate is requested. Next question: establish the absent-field and non-map-value behavior in an unowned entry path, then validate an independently implemented parser against authorized target-grounded fixtures.
