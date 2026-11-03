# RE-017: loader-linked result selection and numeric path handoff

On a conditional loader-linked result route, node #115 can retain distinct names through bytewise tree deduplication, turn them into equal unsigned numbers, and pass both numeric arguments to a formatter before the result consumer removes the last returned row from its processing loop; the ordering path's depth fallback uses an unsigned max-heap.

- Component ID: `abci`; this RE-017 question is connected to RE-009 storage and state-root research.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; unlicensed navigation reference `999556f6e0a474b8312db96ec3149e1c44e97c23`. No reference source is copied.
- Claim status: the listed ELF bytes, operands, transfers, relocations and FDE/LSDA records are observations; field names, cross-function data flow and selected branch consequences are conditional inferences. Runtime scheduling, input reachability, complete ordering and file effects are unresolved.
- Scope included and excluded: twelve newly selected unwind extents, the indicated parent and consumer context, two adjacent-row comparisons, two tree cursors, numeric selection, selected sort paths and heap fallback, output-argument construction and failure boundaries. Previously investigated loader, entry, sink, pipeline, formatter and GOT bodies remain context. This is not the complete begin/action/end-block task, a recovered state root, or a component gate.

## Reproduce

From the repository root with the authenticated `artifacts/node/115/hl-node` and the shared `tools/elf_index.py` and `tools/fde_extents.py` present:

```sh
python3 tools/abci_prune_path115.py --out research/work-items/RE-017-abci-prune-path-115
python3 -m unittest tests.test_abci_prune_path115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
PYTHONHASHSEED=1 TZ=Etc/UTC PATH="<python-only-path>" python3 tools/abci_prune_path115.py --out "<tmp-dir>/one"
PYTHONHASHSEED=937 TZ=Pacific/Honolulu PATH="<python-only-path>" python3 tools/abci_prune_path115.py --out "<tmp-dir>/two"
diff -r "<tmp-dir>/one" "<tmp-dir>/two"
diff -r -x README.md -x MANIFEST.sha256 "<tmp-dir>/one" research/work-items/RE-017-abci-prune-path-115
(cd research/work-items/RE-017-abci-prune-path-115 && sha256sum -c MANIFEST.sha256)
```

Replace the placeholders with two empty writable output directories and a PATH containing Python but no binutils. The producer authenticates the whole #115 input before decoding or creating the output directory. It uses Python's standard library and the repository ELF/FDE/CIE readers; file-backed mapping rejects `SHT_NOBITS`, missing mappings and ambiguous mappings. It invokes no external program and does not execute the captured binary. Python 3.12.3 on Linux x86-64 was used; GNU objdump 2.42 was used separately for human inspection and is not parsed or emitted by the producer.

An optional, separately authenticated historical check does not change any generated #115 file:

```sh
python3 tools/abci_prune_path115.py --historical references/can1357-hl/bin/hl-node-mainnet-new --out "<tmp-dir>/historical"
diff -r "<tmp-dir>/one" "<tmp-dir>/historical"
```

`MANIFEST.sha256` records the README and generated-file hashes. Generated records have no timestamps, environment-dependent ordering or host paths.

## Evidence

Coordinates are linked ELF virtual addresses before load bias; the generated TSVs also give file offsets and raw bytes. End addresses are exclusive. `functions.tsv` contains complete bytes and hashes for the twelve selected FDE ranges. The supplied #115 index digest matched the capture and all twelve selected start/FDE/index triples matched that index. An FDE is an unwind-described range, not a complete function census or a proof of source-function ownership.

Earlier, separately proposed RE-017 loader handoff work (#2047) connects the #115 `state.rs:123:37` Location to a selected startup result. The entry/checkpoint proposal (#2471) follows selected copies to a callback and the result sink. The latter's normal route requires a greater computed bucket, a zero mode-derived byte, a nonzero predicate, and successful intermediate operations. Its callback and loader joins remain assumptions here. `windows.tsv` and `edges.tsv` explicitly label the bounded previous functions and call sites as `context`; their bodies and existing slots are not newly owned. The EVM-maintenance proposal (#2134) independently mentions the shared numeric-path entry as a boundary; this packet investigates different selected FDEs reached below that entry.

The separate expanded-result proposal (#2243) describes a loader-fed callback route with a selected state mutation and conditional connection to a root input. It is prior context rather than a new claim here: a shared callback worker does not by itself prove that its selected mutation and the result route in this packet occur together. Complete begin, action and end behavior remains open across these proposals.

### Selected function map

| New FDE start | Selected observation |
| --- | --- |
| `0x150bad0` | A metadata-result tag and mode bits produce an output flag. A subsequent name-conversion result either yields a sentinel or an owned byte sequence and that flag. |
| `0x14994f0` | Consumes 32-byte rows, compares adjacent byte sequences and their flags, and writes rows into nodes with count at `+0x16a`. |
| `0x153b6d0` | Walks the 32-byte tree representation; decrements remaining count, yields a node/index triple, or follows exhausted and diagnostic paths. |
| `0x149bab0` | Consumes 24-byte rows and compares adjacent byte sequences without the extra flag; its node count is at `+0x112`. |
| `0x153c970` | Walks the 24-byte tree representation with the analogous selected count, node and index transfers. |
| `0x1532810` | Pulls 24-byte entries, invokes the numeric parser, appends each accepted eight-byte value, and returns an empty descriptor if none are accepted. |
| `0x1568570` | Checks supplied prefix and suffix bytes, then parses the intervening bytes as an unsigned decimal value with an optional leading plus and overflow checks. |
| `0x15504d0` | For the selected large-sort call, recognizes nondecreasing or strictly decreasing input; other input reaches the partition boundary below. |
| `0x15506d0` | The selected general branch chooses partitioning, recurses, sends counts below 33 to another helper, and uses an indirect fallback if its depth field reaches zero. |
| `0x1550630` | On the depth fallback, constructs an unsigned max-heap and repeatedly exchanges its root with the end of the shrinking range. |
| `0x15331c0` | Checks the input byte-range bound, allocates an output of three times that range, calls the formatter loop, and writes the returned descriptor. |
| `0x1532490` | Supplies a prefix callback, a numeric callback and a suffix callback for each number and writes a 24-byte result row after the formatting call returns. |

The established contextual sequence begins with the two earlier row pipelines and continues through the new bodies. The first pipeline's collector calls `0x150bad0`; its tree constructor calls `0x14994f0`. A later collector invokes `0x153b6d0`, skips selected rows whose flag byte equals 1, and supplies the rest to a second pipeline whose builder calls `0x149bab0`. The parent reached from the sink then calls `0x1532810`; that collector repeatedly calls `0x153c970` and `0x1568570`. After the selected ordering branch, it calls `0x15331c0`, which calls `0x1532490`. The sink receives the returned 24-byte rows. The parent and earlier pipeline calls are context windows, not newly claimed function bodies. Each join assumes normal ABI-conforming calls, the recorded relative relocation values, no conflicting alias writes and the selected branches.

### Decisions and state changes

| Condition | Byte-backed selected consequence |
| --- | --- |
| Classifier input head is zero | `0x150bb66` writes `0x8000000000000000` to the output head and calls a cleanup boundary. The existing collector compares against that sentinel before appending. |
| Metadata result tag is 2 | The classifier sets its local flag to zero, releases the returned object through a helper, and still invokes the name-conversion boundary. Other tags set the flag from `(mode & 0xf000) == 0x4000`. Interpreting this mode as a directory is a Linux ABI inference. |
| Name conversion result tag is 1 | The classifier writes the same high-bit sentinel. On its other branch, a zero length uses pointer value 1; a positive length is copied into a newly allocated buffer. A high-bit length or null allocation reaches a failure boundary followed by `ud2` if it returns. |
| Adjacent 32-byte rows | Equal lengths, equal bytes via imported `bcmp`, and equal flag bytes advance to the later row after releasing the earlier owned byte buffer when its size word is nonzero. A different flag prevents that selected equality branch. |
| Adjacent 24-byte rows | Equal lengths and `bcmp` equality advance to the later row; this selected comparison has no additional flag test. These rules concern adjacent rows and assume the preceding iterator and comparison calls return normally. |
| Either tree cursor has a nonzero count | It decrements the word at `+0x40` before the selected tag check. A tag other than 1 reaches a diagnostic call; a selected missing-parent route also reaches a diagnostic followed by `ud2` if it returns. Exhaustion follows separate cleanup and returns a null leading output word. |
| Parser prefix or suffix differs, or the middle is invalid | The parser returns a zero success flag; the collector resumes the cursor without appending that row. Prefix and suffix comparisons use the recorded `bcmp` import. |
| Parser middle is decimal | At least one ASCII digit is required after an optional single `+`; `-`, nondigits and values above `2^64-1` are rejected. Fewer than 17 post-plus digits use the short arithmetic loop; 17 or more use checked multiplication and addition. Leading zeroes are accepted. |
| First accepted numeric row | The collector requests 32 bytes, initializes capacity to 4 and count to 1. Further accepted values are appended as eight-byte words; capacity exhaustion calls a separate growth boundary. No numeric equality filter appears in the selected append loop. |
| Numeric count is 0, 1, 2–20 or at least 21 | The parent bypasses ordering for 0 or 1, uses the selected unsigned insertion loop for 2–20, and uses the indirect large-sort boundary at 21 or more. The short loop shifts only strictly larger preceding values. |
| Large input is already nondecreasing or strictly decreasing | `0x15504d0` returns without reordering the former and reverses the latter. Mixed inputs, including a descending run containing equality, reach `0x15506d0`; complete mixed-input ordering and its helper closure remain unresolved. |
| Partition count is at least 33 and its depth is zero | The recorded relative relocation for the existing tail-call slot binds to `0x1550630`. Assuming a valid input slice and nonwrapping index arithmetic, its heap fallback orders the words in ascending unsigned order. The slot is a boundary binding, not new GOT ownership; the depth at a particular runtime call is not established. |
| Output input byte range exceeds `0x2aaaaaaaaaaaaaa8` | `0x15331c0` enters a failure call. Under eight-byte alignment, the maximum selected element count is `0x555555555555555`; the normal output request is 24 bytes per element. Empty input uses the pointer value 8 and zero count. |
| Returned path-row count is nonzero | The sink decrements the count, indexes the last 24-byte row and conditionally calls a release boundary for its buffer. It then considers the remaining rows in order, ending early at the high-bit sentinel. Each ordinary row reaches an indirect processing boundary; a selected result byte of 1 causes a first-vtable-entry call before the loop continues. These are conditional static operations, not observed file effects. |

The sink passes zero in the suffix argument register to the contextual parent. That parent checks whether a nonempty base ends in byte `0x2f`; the equality branch reaches the recorded 42-byte assertion literal and a failure call followed by `ud2`. Its prefix descriptor bytes are `c0 01 2f 00`. The formatter loop uses descriptor bytes `c0 c0 c0 00` and pairs its three arguments with the previously investigated owned-buffer callback, the numeric callback bound by `0x64e0a98`, and a pointer/length callback. Interpreting these compact descriptors as formatting placeholders follows the documented formatting lead and is separate from the observed byte values and bindings. The formatter implementation and actual returned text are not recovered here.

The fallback starts a descending cursor at `n + floor(n/2)`. Before the cursor is below `n`, it sifts the subtree at cursor minus `n`; afterward it swaps the first word with the cursor word and sifts only the preceding prefix. Each sift compares unsigned children, chooses the larger existing child, and stops when the parent is at least that large. For a valid nonwrapping slice this builds a max-heap, then moves its maximum to the end on each extraction, producing ascending order. This is a conditional interpretation of the entire selected fallback extent, not a proof of the surrounding partition or its separate small-range helper. The focused test compares the model with an independent unsigned ordering oracle for exhaustive small inputs and selected counts around 33, duplicates and high-bit values.

For a conditional synthetic example, suppose the second tree supplies the two distinct byte strings `base/+01` and `base/1`, both pass the earlier selected flag filter, and the supplied prefix is `base/` with an empty suffix. The adjacent byte comparison does not merge these different strings; the numeric parser maps both to 1; and the short numeric loop retains both values. The formatter loop therefore receives the same selected prefix, number and suffix arguments twice. The example does not establish that either name occurs in an actual node run or that formatting and later processing have any particular external effect.

### Failure and unwind evidence

`exceptions.tsv` preserves the encoded call-site entries for selected FDEs with LSDAs, including raw action values. `unwind-links.tsv` joins 26 selected new calls to these intervals; 21 have a matching encoded row, some with no landing address. For example, metadata and name-conversion calls join to landing `0x150bcde`; the output-builder call to the formatter loop joins to `0x1533286`; the formatter call joins to `0x1532597`. The selected landing windows show conditional cleanup calls and a later unwind-resume boundary. They do not prove an unwind occurs, decode action/type tables, or establish that all cleanup succeeds. Other selected calls have no matching row or belong to FDEs without an LSDA.

### Historical #94 clue

The retired RE-017 state-link record is tied to node #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`. It records caller `0x32725d0`, call `0x3272785` through slot `0x57755a8`, wrapper `0x3273810`, Location `0x56dfbf8` at `state.rs:107:37`, and a comparison against 2. The optional historical check authenticates that separate binary and checks the two FDE/index joins plus the call, relocation, Location reference and comparison bytes. Independently, `location.json` and the contextual #115 window record `0x64767a8`, `state.rs:123:37`, and the comparison against 1 in the #115 wrapper. These observations are release-specific; their different addresses and tags are not treated as equivalent implementations.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo dependencies, compiler and linker settings, two-build results, implementation byte comparisons, normalization masks, dynamic binding, relocation/vtable closure, fixture execution and whole-ELF equivalence: **not yet measured**. Raw captured bytes are evidence only and are not transplanted into an implementation. Synthetic Python models in the tool and tests express conditional branch interpretations; they do not execute target instructions or substitute for target-grounded behavioral fixtures.

## Results and limitations

`summary.json` records 12 selected new FDEs totaling 9,601 bytes, 41 new and 29 contextual byte windows, 91 new and 35 contextual transfers, 28 operands, 14 relocation records, 3 selected data entries, 49 LSDA rows and 26 selected new call links. These are selected-set counts, not whole-function or whole-component coverage. The focused suite passed 23 tests with zero skips, including corrupted input digest, changed selected windows, parser constants and heap comparison branches, out-of-range/NOBITS/ambiguous mappings, bad FDE and unwind-index joins, wrong or duplicate relocations, malformed LSDA rows, numeric boundary and overflow cases, exhaustive one- and two-byte parser controls, duplicate-row counterexamples, unsigned heap and sorting controls and sink sentinel cases. The suite passed with binutils absent from PATH. Two generations under different hash seeds and time zones matched byte for byte, and the separately authenticated #94 check produced the same #115 records. Artifact verification, the catalogue check and inventory reproduction passed.

No component gate is requested. Process-entry reachability depends on the prior proposals; all begin/action/end-block paths, complete mixed-input partition and small-range sorting, external helper and alias effects, actual path text and file operations, state-root inputs, snapshot compatibility and Rust equivalence remain open. The available PR snapshot contains file lists but not every independent contributor's full diff; the submitting account must recheck new FDE ownership against the current full PR bodies. Next question: close the mixed-input partition and its small-range helper, then independently establish the formatter and result-consumer effects under an authorized offline fixture.
