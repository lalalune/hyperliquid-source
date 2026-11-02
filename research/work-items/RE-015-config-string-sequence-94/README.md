# RE-015: configuration string-sequence collection and type failures

Under a fresh binary marker, mode 0, valid slice, successful allocation and normal helper returns, node #94's selected configuration sequence reader accepts an empty byte payload as an empty collection but sends a nonempty payload to an element-type error; a reconstruction must preserve that distinction along with its cursor and cleanup behavior.

- Component ID: `constants`, task `RE-015`, with downstream configuration-value readers used to answer this question.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23`.
- Claim status: static byte, relocation, FDE and exception-table observations; selected normal-return and finite-model consequences under the stated external helper contracts; reachability of the child sentinel and runtime behavior are unresolved.
- Scope included and excluded: nine newly selected FDE extents, five field handoffs, bounded parent-reader context, two collection paths and their local error and cleanup branches. The earlier field visitor, parent reader, element reader, shared error constructor, allocator, formatter, dynamic calls, #115 and visor are boundaries. The 76-name discriminant inventory is not repeated. No full-component gate is requested.

## Reproduce

Use the repository root as working directory. The observed environment was Linux x86-64, Python 3.12.3, and GNU objdump 2.42 for manual inspection only. The producer uses the Python standard library and the repository's shared ELF/FDE/ULEB readers; it verifies the complete input SHA-256 before parsing, excludes SHT_NOBITS from file mappings, and invokes no external program. It does not execute the captured node.

```sh
python3 tools/config_string_sequence94.py --out research/work-items/RE-015-config-string-sequence-94
python3 -m unittest tests.test_config_string_sequence94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
(cd research/work-items/RE-015-config-string-sequence-94 && sha256sum -c MANIFEST.sha256)
```

For the determinism comparison, replace each placeholder with a different empty, writable path relative to the repository root:

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/config_string_sequence94.py --out <tmp-dir-one>
PYTHONHASHSEED=983 TZ=Pacific/Honolulu python3 tools/config_string_sequence94.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
```

The 16 generated evidence files are byte-identical between the two runs. The producer and focused test suite also ran with a PATH containing Python but no binutils. `MANIFEST.sha256` hashes this README and the generated files, excluding itself. The tool and tests do not read configuration files or use actual keys.

## Evidence

Addresses below are linked ELF virtual addresses without rebasing; `functions.tsv`, `anchors.tsv` and the other coordinate tables supply corresponding file offsets. FDE endpoints are unwind-described extents, not proof of a complete function census. `bodies.tsv` contains the selected raw body bytes; 65 fixed byte windows, 46 curated conditional transfers, 40 selected calls or tail transfers, and the bounded tables provide independently inspectable coordinates. No disassembler output is used by the generator.

### Field-to-reader handoffs

The earlier configuration-field contribution identified the literal-to-tag mapping and the visitor; the present collector independently checks each literal, its selected tag-store leaf, the relative dispatch cell, the arm's zeroed mode argument, the call, and the non-9 error edge. It does not re-prove every instruction in the earlier name classifier. The earlier `constants` packet associates the `/cham` and `/static_config` templates and the `NvTestnet` default with the static configuration cell. A separate initializer constructs an `api_secrets.json` path from that cell's directory field. Its binary selector branch was identified in #1554, but that contribution did not establish reachability of that branch from the initializer's fixed `.json` suffix. These are context only: they do not imply a particular field value or runtime name here, and the earlier initializers and file parser remain external boundaries.

The following composition shows the prior boundaries and this packet's selected paths. The first two arrows rely on earlier work; the conditional binary entry is not proven to be selected by the initializer's concrete path. Cursor, depth and collection writes and their local error/cleanup branches are the state changes examined here.

```text
prior static configuration -> prior API-secrets initializer -> prior selector
  -> conditional binary reader -> prior field visitor -> five field arms
     -> prior shared reader 0x13b5630
        -> raw-byte collector 0x14c06a0 -> byte adapter 0x14d2180 -> prior error constructor
        -> counted collector 0x14c08d0 -> prior element reader
        -> type adapters 0x14d0d30 / 0x14d5c10 / 0x14d11f0 / 0x14d4b80
        -> vector cleanup 0x13b42e0 on selected drop paths
```

| Previously identified field | Field literal VA | Tag | Visitor arm VA | Call VA |
| --- | ---: | ---: | ---: | ---: |
| `etherscan_keys` | `0x21bba7` | `0x1f` | `0x13acd78` | `0x13acd97` |
| `etherscan_v2_keys` | `0x21bbb5` | `0x20` | `0x13ad564` | `0x13ad583` |
| `ip_backup_keys` | `0x21bbdc` | `0x23` | `0x13ad3f6` | `0x13ad415` |
| `ip_info_backup_keys` | `0x21bbea` | `0x25` | `0x13acfdf` | `0x13acffe` |
| `zip_and_upload_skip_cp` | `0x21bbfd` | `0x26` | `0x13acacf` | `0x13acaee` |

Each call reaches the earlier boundary `0x13b5630` with `edx = 0`; each checked non-9 result branches to `0x13b0144`. An earlier nested-map contribution also records a different caller of that reader. The parent body is not selected as new work. The current packet binds only the specific parent windows and three table spans needed to connect it to the newly selected callees. The 225 cached-class cells, 18 cached-extended cells and 32 fresh `0xc0..0xdf` cells are bounded data selections, not a claim that all cached indices are reachable or that every target has independently validated instruction boundaries.

For a cached-state value of 1, the selected table cell reaches `0x13b57f7`, which takes one marker byte from the input and updates the cursor. The high-marker comparisons route `0xc0..0xdf` to the 32-cell table at `0x2103ac`; its cells for `0xc4`, `0xc5` and `0xc6` point to one-, two- and four-byte length paths. The fixed windows for those paths retain the length guards, two-byte rotate and four-byte byte swap. An incomplete length takes the tag-1 path after consuming the available prefix; a complete length with too few payload bytes takes the separate tag-1 path without consuming those payload bytes. `branches.tsv` records the selected jump bytes, fallthroughs and targets for these decisions and the counted-sequence depth/error handoffs.

### Selected functions and bindings

| FDE start | New bounded role | Essential observation |
| --- | --- | --- |
| `0x14c06a0` | Raw-byte collector | Reserves 24-byte elements, checks each input byte through `0x14d2180`, publishes or cleans up. |
| `0x14c08d0` | Declared-count sequence collector | Calls the existing element reader, records the remaining count, appends 24-byte elements or cleans up. |
| `0x14d2180` | Byte element error adapter | Supplies the byte as a zero-extended value, descriptor kind 1 and an expected-string descriptor to the prior error constructor. |
| `0x14c3e90` | Expected-sequence callback | Passes the complete ten-byte slice `a sequence` at `0x21c515` to a dynamic formatter. |
| `0x14d4b80` | Map-route error adapter | Supplies descriptor kind 11 and the expected-sequence descriptor. |
| `0x14d11f0` | Extension-route error adapter | Supplies descriptor kind 9 and the expected-sequence descriptor. |
| `0x14d0d30` | First slice error adapter | Supplies descriptor kind 6 and the expected-sequence descriptor. |
| `0x14d5c10` | Second slice error adapter | Supplies descriptor kind 5 and the expected-sequence descriptor. |
| `0x13b42e0` | Vector cleanup | Steps collected elements by `0x18` bytes and conditionally releases the backing allocation. |

The adapters call the previously studied constructor at `0x13b5360`. Prior contribution #1364 establishes its normal-return tag 6; it is not selected again here. `error-descriptors.tsv` binds each of the five adapter kind bytes and both of its RIP-relative LEAs to its expected descriptor and format entry. `relocations.tsv` binds expected-sequence slot `0x566ef88` to the newly selected callback and expected-string slot `0x566f168` to `0x14c3f10`, a callback previously studied in #1531. The 30-byte format entry at `0x20193e` contains the two literal fragments surrounding two argument tokens. The complete formatted message and dynamic sink remain external.

### Length, result and cleanup decisions

The examples in `raw-cases.tsv` are **static models**, not captured executions. They assume a fresh marker, a valid input slice, the indicated mode, normal allocation and normal return from the earlier tag-6 constructor. The field handoffs above use mode 0.

| Input bytes | Selected result under those assumptions | Cursor consequence |
| --- | --- | --- |
| `c4 00` | tag 9, empty collection | advances past the marker and one-byte length |
| `c4 01 00` or `c4 01 41` | tag 6 from the first byte-element error boundary | advances past the complete declared payload before calling the collector |
| `c4 02 41` | local tag 1, incomplete payload | advances past the header, leaving the available payload byte |
| `c5 00` | local tag 1, incomplete length | consumes the available length-prefix byte |

The selected `c5` and `c6` length operands are read as big-endian two- and four-byte lengths; `raw-cases.tsv` includes empty and one-byte examples. An alternate mode reaches the slice error adapter even for an empty payload; this is a separate modeled input, not the mode shown at the five field call sites. Extra bytes following a complete payload are not consumed by the selected reader.

Both collectors cap their **initial reservation** at `0xaaaa` elements and use a 24-byte element stride. The tool extracts these operands from the selected bytes, verifies both implementations agree, and records boundary values in `reserve-cases.tsv`. Thus the maximum initial request represented by these instructions is 1,048,560 bytes; subsequent growth, allocator results and memory limits are not inferred. With a valid nonempty raw slice, the collector requests a buffer before the first element error; on that normal error path, it releases the buffer after propagating the error. Empty input publishes the observed `(capacity, pointer, length)` words `(0, 8, 0)` with tag 9; these are raw machine words, not a claim about a stable Rust ABI.

For a declared element count, `0x14c08d0` writes the decremented count before calling the prior element reader `0x13bdcd0` with flag 1. A tag-9 element with an ordinary first word is appended at 24-byte stride; a non-9 element is propagated and already collected elements and their backing storage are conditionally released. The parent restores its depth word after its successful count check, while the selected non-9 propagation exits without that restore. Initial depth zero reaches an underflow boundary; depth one is decremented to zero and produces tag 8. The element reader's internal UTF-8, ownership and error behavior remain that prior reader's boundary.

If the element reader were to return tag 9 with first word `0x8000000000000000`, the collector takes its separate early-success edge. If a declared count remains, the parent takes a tag-4/cleanup route; if the counter is already zero, the selected normal path can return tag 9 with fewer appended elements. **Whether that child result is reachable is not established.** `sequence-cases.tsv` labels these as abstract child outcomes, not accepted inputs. It also distinguishes a tag-6 child error from this conditional niche case.

### Exception data and inference

The selected FDEs have two LSDAs with nine decoded call-site records. The raw-byte visitor call is within `0x14c0779..0x14c0783` and has landing `0x14c08ba`; the sequence-element call is within `0x14c096c..0x14c097e` and has landing `0x14c0ad7`. Growth-call landings and their locally visible element/buffer cleanup appear separately in `lsda-sites.tsv` and `transfers.tsv`. The records and action integers are decoded from bytes; personality, action semantics, allocator behavior and all runtime unwind paths are not established.

The inferred reference gives several of these fields optional string-list shapes. The separate byte and sequence paths are consistent with a string-list interpretation, while the actual compiled element layout, all valid encodings, absent-field behavior and complete configuration publication require further proof. No contents of a deployed configuration are inferred.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Compiler/linker and Cargo scope, raw or normalized binary comparison, masks, two-build result, helper closure, dynamic formatter behavior, full relocation/data closure and execution fixtures: **not yet implemented or measured**. The output is an evidence collector and finite static models, not a recovered node or a target execution. The unlicensed inferred reference was used only to formulate a question; no reference implementation was copied.

## Results and limitations

The retained selection contains nine FDE extents totaling 1,798 bytes, five field handoffs, 65 byte windows, 46 curated conditional branches, 40 selected transfers, five error-descriptor bindings, 275 bounded table cells, nine selected relocation records and nine LSDA call-site records. The finite probes cover 17 raw-prefix cases, 12 abstract sequence-state cases and seven reservation boundaries. These are selection counts, not component coverage or executed test counts. The focused suite passed 41 tests with zero skips, including altered artifact bytes, FDE ranges, selected body bytes, branch and call displacements, a parent length-path byte, error-descriptor kind and pointer corruptions, literal and dispatch cells, a valid-but-wrong table target, relocation and LSDA bytes, NOBITS and out-of-range controls. Artifact/signature verification, catalogue checking, inventory/literal reproduction and two-run determinism passed.

The collector does not validate a whole-function instruction partition, prove all parent-reader branches, establish that the initializer's `.json` path reaches this binary reader, execute malformed data, recover error formatting or settle runtime reachability of the sentinel. The five field names rely on the earlier classifier's name-to-tag proof. Ownership was checked against the repository and available contribution snapshots; live upstream state was unavailable under the no-network constraint. All four component gates remain false. Next question: can the existing element-reader boundary actually return the tag-9 sentinel, and what does an independently authored parser do on the same authorized offline fixtures?
