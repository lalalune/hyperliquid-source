# RE-010: node #115 startFeeTrial decoding and guarded state writes

Node #115 places the two cross-rate inputs in floating-point lanes 0 and 2, and its fallback accepts an override only after those lanes match one template and the override value matches both add-rate lanes, giving reconstruction a concrete decision rule.

- Component ID: `action-dispatch` / RE-010.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; historical reference `999556f6e0a474b8312db96ec3149e1c44e97c23` supplied a label only and is not copied or treated as an oracle.
- Claim status: selected byte observations and explicitly bounded inferences; unresolved links are listed below.
- Scope included and excluded: one delayed-action decoding and execute path, selected guards, converter, and record stores; no claim about all action forms, all CFG paths, helper closure, live execution, or the whole component.

## Reproduce

From the repository root with the pinned artifact materialized, on Linux x86-64 with Python 3.12.3 and the repository's `tools/elf_index.py` and `tools/fde_extents.py`:

```sh
python3 tools/re010_fee_trial_115.py --out work/re010-fee-a
python3 tools/re010_fee_trial_115.py --out work/re010-fee-b
diff -r work/re010-fee-a work/re010-fee-b
python3 -m unittest tests.test_re010_fee_trial_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
(cd research/work-items/RE-010-start-fee-trial-115 && sha256sum -c MANIFEST.sha256)
```

The generator verifies the entire input SHA-256 before parsing or writing output. It reads ELF sections, the unwind index and FDE/CIE records with the shared parsers; it uses fixed instruction patterns, signed displacements and ELF RELA entries for the selected observations. It does not call a disassembler or execute the artifact. `--out` writes only the generated files named below. Hashes of the retained files, including this README, are in `MANIFEST.sha256`. The extraction has no binutils, clock, timezone, locale or random dependency.

## Evidence

All addresses are linked ELF virtual addresses (VAs); file offsets are zero-based. Ranges are half-open. `functions.tsv` records each FDE/CIE/LSDA coordinate, file offset, size and body hash, and `bodies.tsv` retains the complete raw bytes of each selected FDE. An FDE and a call to its entry support a bounded function extent; they do not by themselves recover the original source-level boundaries or prove every branch. Labels below are analytical roles, not recovered symbols. `windows.tsv` separately marks previously studied context; those containing functions are not claimed as newly selected work.

| Selected role | FDE VA range |
| --- | --- |
| `ActionDelayer` decoder | `0x1bdd100..0x1bdfada` |
| Delayed-map value decoder | `0x18f38a0..0x18f40b9` |
| Bucket-vector decoder | `0x27ba880..0x27babeb` |
| Bucket decoder | `0x1b447c0..0x1b44f2e` |
| Delayed-record vector decoder | `0x2684690..0x268492d` |
| Queue extractor | `0x3bed8a0..0x3bee39e` |
| Execution adapter | `0x231bf90..0x231c0b3` |
| Action enum decoder | `0x2bd6140..0x2bd8476` |
| Selected payload decoder | `0x2117d20..0x21198c2` |
| Value adapter / nested adapter | `0x2121af0..0x2121bff` / `0x2121060..0x212116f` |
| String-value decoder | `0x200e0c0..0x200e1e8` |
| Rate converter | `0x36a5540..0x36a58c8` |
| State core | `0x3c18390..0x3c18a7e` |
| Checked date adapter / packed-date helper | `0x1506a00..0x1506a2a` / `0x16290d0..0x16292fc` |
| Independent field formatter | `0x36ab000..0x36ab12d` |

### Selected route and ownership

The contextual caller at `0x1851dae` invokes the selected `ActionDelayer` decoder, and its duplicate-field branch identifies the enclosing field as `action_delayer`. In the selected decoder, the `delayed_actions` key maps to field-table index 0 at `0x5a9954`, whose target is `0x1bdd460`; a duplicate goes to `0x1bdf195`. The key comparison slot resolves to the imported `bcmp` symbol. The same field's missing-name path is recorded separately. On the selected map path the direct calls are:

```text
0x1bdd485 -> 0x18f38a0 -> 0x27ba880 -> 0x1b447c0
           -> 0x2684690 -> 0x18edd30 -> 0x2bd6140
```

The sequence path also reaches the map-value decoder. The record descriptor is the relocated string `struct DelayedAction with 6 elements`; contextual map and sequence paths both call the action decoder. The map path has separate duplicate and missing `action` handling. On a contextual normal path the record copy is `0x148` bytes and the action begins at offset `0x10`. The enclosing FDE `0x18edd30..0x18f0390` also appeared in the historical node #115 ISA census `RE-002-target-cpu-features` at commit `07f43c689bd1e24de4f605c297e9faa8dbb8f1f3`; it is therefore context only, excluded from the selected-FDE count and not claimed as newly studied.

In the prior state-decoder context, the selected `ActionDelayer` result is staged at stack offset `+0x848` after the call; the retained copy pairs move `0x78` contiguous bytes from that staging range to the result-base register at `+0x25a0`. `state-copy.tsv` independently decodes all eight source/destination pairs. This establishes a local output transfer, not the identity of a later engine object.

Independently, prior contextual engine code calls the new queue extractor through RELATIVE slot `0x64e4f00`, builds a range using the same `0x148` stride, and calls `0x231bf90`, which calls prior consumer `0x27048a0`. The consumer copies `0xf0` bytes from record offset `0x10` before the prior outer executor; the loaded copy slot resolves to the imported `memcpy` symbol. The extractor's empty-output, lookup, count, allocation and unwind paths are retained as selected windows or branch sites. These observations establish compatible record layout and an execution route, but not that a specific deserialized instance is installed in the state used by the engine.

The independent decoder table at `0x609c20` maps ordinal 55 to **interior block** `0x2bd7fa7`, which calls payload FDE `0x2117d20` and writes internal tag `0xbd` on the selected normal path. The independently relocated action descriptor says `StartFeeTrialAction`; the prior formatter's same ordinal loads `startFeeTrial`. The prior outer and nested execution tables use bias `0x86`, so `0xbd - 0x86 = 55`; their selected arms reach the previously studied wrapper `0x2385530`. Its RELATIVE slot `0x64e50b8` points to the new state-core FDE `0x3c18390`. These table entries, call instructions and relocation addends are retained with raw bytes and file coordinates in `tables.tsv` and `calls.tsv`.

The action arm at `0x2bd7fa7` is an interior switch block, not a standalone function. The selected payload decoder, converter, state core and date helpers have distinct FDE entries. Consequently a reference file named for one handler does not establish one original binary function boundary. Historical #94 material was only a discovery lead; no #94 address, inferred layout or implementation is credited as a #115 observation.

### Payload and conversion

The action descriptor has four field pointers and lengths; each field's actual dispatch arm, duplicate/missing diagnostic and selected return store is tied to the name in `field-routes.tsv`. Converter reads and scalar stores are tied to the same descriptor in `lane-map.tsv`:

| Descriptor index | Field | Payload offset | Conversion order / output lane |
| ---: | --- | ---: | ---: |
| 0 | `perpAddBaseRate` | `0x00` | 1 |
| 1 | `perpCrossBaseRate` | `0x18` | 0 |
| 2 | `spotAddBaseRate` | `0x30` | 3 |
| 3 | `spotCrossBaseRate` | `0x48` | 2 |

Each selected input record is `0x18` bytes apart. The converter checks lengths in order 1, 0, 3, 2: length `100` passes this local check and `101` takes raw word `0x158`. For the first three inputs, non-`0x1a2` parser results propagate and a separate failed floating conversion takes `0xaf`; the fourth input uses a different helper and propagates its non-`0x1a2` result. Successful scalar lanes are written at output offsets `+0x08`, `+0x10`, `+0x18`, `+0x20`. This does not establish the full accepted number grammar or the internals of either parsing helper.

### State-core decisions

The following is a reading of selected paths and raw return words, not a claim that semantic Rust error variants have been recovered. Branch order matters.

| Selected condition, after prior conditions pass | Observed continuation |
| --- | --- |
| A prior record exists, its byte 0 and word `+0x70` are nonzero, or state flag byte `+0x188` is nonzero | Returns raw `0x149 + 4 * flag`; the byte is read from state. The all-`ff` and all-`fe` 20-byte keys have separate default paths. |
| Converter returns a word other than `0x1a2` | Copies the selected converter error payload and word to the result. |
| No `0x30`-stride template row matches all four lanes | `0x14a`, unless the fallback below succeeds. |
| A row matches lanes 0 and 2; no row matches all four lanes | Fallback scans `0x10`-stride overrides and requires one override's value at `+0x08` to equal **both** lanes 1 and 3. Otherwise `0x14a`. The pair must come from one template row; an earlier matching pair remains sufficient for the later override scan. |
| Prior record's `+0xc0` date word is nonzero and the checked 90-offset result is signed-greater than the current date word | `0x14c`; equality passes this guard. |
| The date helper for the 14 offset returns zero | Calls the panic path carrying the retained `NaiveDate + TimeDelta` overflow diagnostic. The checked 90-offset adapter also panics on zero. |
| No adjusted lane is an improvement in the selected finite-input path | `0x14b`. |
| At least one lane improves and record-helper calls return | Writes linked and primary records, then returns `0x1a2`. |

Each template comparison is `ucomisd` followed by both unequal and unordered branches. Thus NaN cannot satisfy those equality checks; `+0.0` and `-0.0` compare equal there. The fallback's lane order is established by the descriptor-to-store route above, not by the reference file name.

For finite inputs and an ordered threshold table, the code selects zero when the table is empty or its first threshold exceeds the baseline; otherwise it selects the last threshold not greater than that baseline. Positive request lanes are multiplied by `1 - selected_value`, nonpositive lanes retain their values, and the code checks the positive part of old minus adjusted values. On improvement it retains component minima. NaN behavior and threshold-order invariants outside these preconditions remain open.

The same 11 record-store forms appear in the linked and primary blocks. `write-dataflow.tsv` binds each non-immediate store to its stack load, while the earlier windows retain the producers. The following value roles are inferred from that dataflow:

| Record offsets | Selected stored value |
| --- | --- |
| `+0x00..+0x07` | qword `1` |
| `+0x08..+0x27` | Four minima of the selected baseline and adjusted request lanes |
| `+0x28..+0x2f` | Selected baseline scalar |
| `+0x30..+0x4f` | Four unadjusted request lanes in converter order |
| `+0x50..+0x6f` | Four pre-update baseline lanes |
| `+0x70..+0x73` | Nonzero date-helper result for the 14 offset |
| `+0x78..+0x7f` | Saved prior/default scalar from the selected baseline path |

Offsets `+0x74..+0x77` and the full record's semantic type are not established. The optional linked vector has a selected `0x40` stride; its lookup and allocation helpers remain outside this packet.

### Packed-date fast path

Both date call sites reach helper `0x16290d0`, directly or through `0x1506a00`. From its retained fast-path bytes, for a packed 32-bit input `p` and signed 32-bit delta `d`, let `ordinal = (p >> 4) & 0x1ff`, `limit = 366 - ((p >> 3) & 1)`, and `n = ordinal + d`. If the signed addition does not overflow and `1 <= n <= limit`, the helper returns `(p & 0xffffe00f) | (n << 4)`. Otherwise it takes the distinct slower path. This is a bounded algebraic consequence of the fast-path instructions, not an implementation or validation of the complete date format. The slow path's lookup tables, calendar transitions and panic conditions remain unclosed.

### Evidence files

`functions.tsv` and `bodies.tsv` contain complete selected FDE bytes, not an instruction census. `windows.tsv` retains curated byte windows; `branches.tsv` resolves only selected branch starts and targets; `calls.tsv` retains selected and contextual direct/RELATIVE edges. `fields.tsv`, `field-routes.tsv`, `lane-map.tsv`, `descriptors.tsv`, `tables.tsv`, `stores.tsv`, `write-dataflow.tsv`, `state-copy.tsv`, `imports.tsv`, `immediates.tsv`, `literals.tsv` and `summary.json` contain bounded structured observations. Counts are denominators for these curated selections, not total reachable functions or instructions.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo graph, compiler/linker settings, two-build comparison, normalized masks, binary equivalence and captured-node differential execution: **not yet implemented/measured**. No external source was copied. No artifact, signing key, network or chain action was executed or accessed.

The focused Python suite checks target identity, FDE/relocation links, byte patterns, output file set and selected record offsets. It also exercises synthetic control models with reversed lane interpretation, unequal override values, NaN, signed zero, length 100/101, equal/greater dates, fast-path year bounds and invalid inputs; these are algebraic checks over the stated observations, not executions of the node.

## Results and limitations

The retained selection has 17 FDEs, 92 selected and 28 contextual windows, 122 selected branch sites, 59 selected and 11 contextual call edges, 36 table entries, 22 record-store sites, 20 source-load sites 8 contextual state-copy pairs and 3 imported-symbol sites. The focused suite passed 69 tests with zero skips; the two output directories compared byte-for-byte. `python3 tools/artifacts.py verify` and `python3 tools/catalogue.py --check` passed. These counts are not a full CFG or function-coverage denominator.

The relation between restored state and the engine's concrete queue instance, other action entrypoints, transaction and persistence semantics, helper bodies, allocation failures, unwinding, and cross-release equivalence remain unresolved. An FDE is not proof of a source function and a formatter name is not a live API test. The `action-dispatch` component remains 0/4; no progress gate is requested.

Next question: trace how the decoded `action_delayer` value is installed into the exact state object from which the engine passes its queue to `0x3bed8a0`, including its ownership and error paths.
