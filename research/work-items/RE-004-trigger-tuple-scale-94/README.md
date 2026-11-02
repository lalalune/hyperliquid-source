# RE-004: trigger price tuple input and conversion gate

Node #94 reads the sequence form of a trigger order as `isMarket`, `triggerPx`, then `tpsl`, and calls the existing fixed-eight price converter only after all three elements succeed and no elements remain; a reconstruction can therefore preserve both tuple order and the first failing stage.

- Component ID: RE-004, quantities and rounding.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `e5c9b6436876b2a4a39daef813171f9879317699` / `999556f6e0a474b8312db96ec3149e1c44e97c23`. The unlicensed reference was used only as a search lead.
- Claim status: observed FDE records, bytes, relative branches, data and relocation targets; inferred field roles from the map and tuple data flow; unresolved input and helper semantics below.
- Scope included and excluded: the selected `OrderTypeWire` trigger branch, two corresponding entry/parent/tuple-reader/adapter paths, one map-key classifier used to identify the three tuple positions, and their selected error gates. The earlier converter and its callees are external dependencies. The full map reader, external encoding, other order variants, allocator and cleanup behavior, target execution and node #115 are excluded.

## Reproduce

From the repository root with Python 3.12.3 and the standard library, with the captured node artifact installed in `artifacts/node/94/hl-node`:

```sh
python3 tools/artifacts.py verify
python3 tools/trigger_tuple_quantity94.py --out <tmp-dir-a>
python3 -m unittest tests.test_trigger_tuple_quantity94
python3 tools/catalogue.py --check
```

Compare the generated files with the corresponding files in this work-item directory. To check determinism, use two fresh relative output directories and compare them:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/trigger_tuple_quantity94.py --out <tmp-dir-a>
PYTHONHASHSEED=777 TZ=Pacific/Kiritimati python3 tools/trigger_tuple_quantity94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
```

The extractor verifies the complete input digest before parsing or creating the output directory. It imports the repository ELF and FDE parsers, excludes NOBITS from VA-to-file mapping, reads static file bytes and does not invoke a disassembler or run the binary. `function-bytes.tsv` contains the complete raw bytes of the 12 selected unwind ranges; `evidence.json`, `calls.tsv`, `fields.tsv` and `branches.tsv` retain identities and selected operands. `cursor-cases.tsv` compares a small instruction-byte interpreter with an independent cursor rule. `key-cases.tsv`, `parent-cases.tsv` and `sequence-cases.tsv` are abstract models derived from the pinned decisions; none execute the target. `MANIFEST.sha256` records the README and generated-file hashes. The analysis completed for the stated selected paths.

## Evidence

All addresses are node #94 ELF virtual addresses before load bias. File offsets, FDE record addresses, full-range hashes and exact instruction windows are in `evidence.json`. An FDE describes an unwind range; it does not alone establish a complete source function, a complete CFG, or a census.

### From order-type input to the tuple

The entry at `0x1ee0f10` passes the literal `OrderTypeWire`, its two-entry descriptor, and a present value to `0x20867e0`. The alternate copy `0x34f7670` passes through `0x3a3b920`. The descriptor and classifier bytes identify the labels `limit` and `trigger`; for the selected internal string form the classifier at `0x21d61c0` yields 0 and 1 respectively. Its error result is 2. The parent calls the trigger adapter `0x2198670` only when the classifier result is not 2 and its low bit is set; the other path is a separate external call. A trigger-adapter byte 2 becomes parent error byte 3. The entry converts parent error byte 3 to entry error byte 4. These are internal result bytes, not established network tags.

At the entry, a missing buffer or end cursor returns byte 3 without advancing the cursor. A present marker `0x16` advances by `0x20` bytes and then returns byte 3. For another marker, a counter of `u64::MAX` reaches the overflow call after the cursor advance; otherwise the counter increments and the parent runs. The same byte windows occur in the second entry. The generator checks their raw bytes without masks, but the copies' external call targets and complete bytes are not identical.

### Map labels establish sequence positions

The reader `0x20b3c70` has an internal `0x15` path with `0x40`-byte records and a `0x14` path with `0x20`-byte records. On the former, the selected key iterator `0x1ec9db0` calls classifier `0x2165dc0`. Its table and compare bytes identify `isMarket`, `triggerPx`, and `tpsl` as indices 0, 1, and 2. The reader's three-entry relative table routes those indices to branches that inline the first field's boolean-like decoding and call the same three-word price reader and third-field reader used in the `0x14` path. Thus the map arms supply the field labels for the sequence's three reader positions. This is a static data-flow inference, not a claim that `0x14` or `0x15` is an external wire encoding.

The bytewise classifier arm has individual comparisons for each byte of all three names. The optimized arm compares the same literal bytes via RIP-relative addresses; the generator verifies those addresses and derives the labels from the file. Unrecognized values in the selected string cases select index 3. Other classifier representations and the full map loop are not characterized here.

### Sequence and price conversion

| Position | Observation on the selected `0x14` path | Failure before conversion |
| --- | --- | --- |
| 0 | `0x1ee4160` reads a `0x20`-byte entry, tests its internal type and returns a byte. The caller retains that byte as `isMarket`. | Missing/end or marker `0x16` selects missing index 0; a reader error is propagated. A returned byte 2 is also treated as missing. |
| 1 | The caller advances one `0x20`-byte entry and calls `0x209d1d0`; the three-word successful result is retained as `triggerPx`. | Missing/end or marker `0x16` selects missing index 1. The reader's `0x8000000000000000` sentinel propagates its error. |
| 2 | The caller advances one entry and calls `0x2088b40`; its successful byte is retained as `tpsl`. | Missing/end or marker `0x16` selects missing index 2. A nonzero reader error tag is propagated. |
| Remaining | The code computes the remaining byte span divided by `0x20` and checks the count addition for carry. | Any remaining entry takes the length-error path; count overflow reaches its own non-returning edge. |
| Adapter | Only a successful, exhausted reader reaches the indirect call at `0x21986d6`. The ELF RELATIVE relocation for slot `0x5773898` names `0x3330210`. | A converter tag other than `0x186` takes the error adapter and sets its output byte `+9` to 2. On success, the returned word is stored at `+0`, and the two other field bytes at `+8` and `+9`. |

The first-element cursor interpreter follows the target bytes for the buffer, end, marker and counter checks, stopping before the element value is decoded. Its 3,072 fixtures cover all 256 markers, both buffer and end states, and counters 0, `u64::MAX - 1`, and `u64::MAX`; all agree with the independent cursor rule. The only counter comparison is equality with `u64::MAX`, followed on the other path by one increment, so that cursor rule extends to every u64 counter under the stated memory assumptions. This is a Python interpretation of selected bytes, not native target execution.

The initial tuple counter is set to zero. The separately visible overflow checks at the first, second and third entries describe corrupted or otherwise abnormal iterator states; this packet does not claim they are reachable from an ordinary three-element tuple. Extra entries are counted after the third value even if a later entry contains the marker. The generated model assumes a valid buffer and a nonwrapping, correctly bounded pointer span.

The alternate reader `0x3ad6590` and adapter `0x3b311d0` use the same control and store windows at corresponding offsets. Twenty-six selected windows across the entry, parent, reader and adapter pairs are **raw equal**, with no masked bytes; this is not whole-function equality. Both adapters' indirect call sites resolve to the same converter slot. Their first, second and third reader call targets differ and are retained as separate edges. Helper contents are not compared.

The pending `RE-004-order-wire-input-94` packet maps a different set of order and trigger reader FDEs on the map path and leaves sequence input open. The selected FDEs here are distinct; only the converter is a shared external boundary.

The earlier `RE-004-decimal-scaled-u64-94` packet records the converter's downstream call to a mode-0, exponent-8 scaler and its rejection and width behavior. This packet uses that prior result only as a dependency: the new observation is when this tuple price is passed to it. It does not re-analyze that converter or prove that every supplied text reaches the scaler, and it adds no new rounding or overflow claim for the decimal arithmetic.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Compiler, linker, Cargo lock, two-build results, raw/normalized Rust comparisons, helper closure and binary identity: not yet measured. No normalization is used for the paired windows. The cursor walker interprets the selected first-reader instruction bytes with a synthetic element and stops before value decoding. The generated parent and tuple case tables model only the pinned local gates with supplied abstract reader outcomes; their rows do not execute native instructions and are not accepted-input measurements.

The focused tests include modified SHA-256, FDE extents and duplicate FDE, code bytes and a branch-sense mutation exercised by the cursor walker, a map table displacement, key data, a variant literal, the converter relocation and a duplicate relocation, ambiguous mappings, invalid and NOBITS addresses, all 256 first-entry marker bytes, all 65,536 pairs of parent classifier/adapter bytes, all 65,536 converter tags, absent elements, each early error, a marker at each tuple position, extra elements and the counter boundary. Changes to the target-bound structural inputs are rejected.

## Results and limitations

The generator records 12 selected FDE extents, 39 anchors, 26 raw-equal paired windows, 46 conditional branches, 17 selected call/slot edges, 3,072 cursor fixtures with zero mismatches, 16 key examples, 1,024 parent model cases and 2,304 tuple model cases. The focused suite passed 26 tests with no skips. The case counts describe the chosen abstract grid, not observed live orders or complete input coverage.

The selected byte windows support the described local decisions under the stated valid-iterator and helper-result assumptions. They do not prove arbitrary memory safety, complete map or exception control flow, input producer reachability, the text grammar, the behavior of external helpers, Rust equivalence, or the target's execution environment. This is a partial RE-004 result; no component progress gate is requested.

Next question: establish which outer value producer constructs the internal `0x14` sequence and independently validate its price text against the existing exponent-8 conversion under an authorized offline harness.
