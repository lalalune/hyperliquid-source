# RE-004: TWAP sequence size conversion and failure order in node #94

The sequence form of `TwapWireSerde` supplies its third positional value to the existing fixed-eight size converter only after all six positions and the sequence-end check have been processed; a reconstruction must preserve that order, including the two optional-position defaults and early failures.

- Component ID: RE-004 (quantities and rounding, TWAP size input).
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; inferred, unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23` was a lead only.
- Claim status: bytes, FDE extents, branch destinations, selected relative operands and relocation-backed descriptor bytes are observations. Field names and the connection to the previously analysed numeric conversion are inferences. The complete size-value decoder, formatter/error helper results and externally reachable representations remain unresolved.
- Scope included and excluded: three selected outer readers, three corresponding visitors, and three copies of each of four local step helpers, for 18 FDE-described ranges. The analysis follows the visitors' tag-`0x14` sequence arm and the entry to the size-converter slot. It examines selected internal control blocks and integer-reader arms, not every instruction of the visitors. The tag-`0x15` map arm, underlying size-value decoder and pre-existing converter bodies, pointer validity, allocation and destructor internals, other releases and execution are excluded. This answers a different question from the map-only `RE-004-twap-size-wire-94` work item.

## Reproduce

Run at the repository root on Linux x86-64, Python 3.12.3 and the standard library. The tool imports the repository ELF section and FDE parsers, verifies the complete input digest before analysis, excludes NOBITS from file mappings, and does not execute the captured binary, use the network, invoke binutils or call subprocesses. Outputs depend only on authenticated bytes and stated synthetic fixtures.

```sh
python3 tools/artifacts.py verify
python3 tools/twap_sequence_size94.py --out <tmp-dir-a>
python3 -m unittest tests.test_twap_sequence_size94
python3 tools/catalogue.py --check
PYTHONHASHSEED=11 TZ=UTC python3 tools/twap_sequence_size94.py --out <tmp-dir-b>
PYTHONHASHSEED=992 TZ=Pacific/Honolulu python3 tools/twap_sequence_size94.py --out <tmp-dir-c>
diff -r <tmp-dir-b> <tmp-dir-c>
```

Use three distinct initially empty directories. `evidence.json` preserves each selected FDE's full original bytes, hash, file offset and FDE VA, selected branch and call targets, raw comparison records and local windows. The TSVs project relocation-backed names, calls, branches, numeric table arms, raw and masked copy comparisons, and the replay fixtures. `cases.json` and `sequence-patterns.tsv` are explicitly synthetic branch models, not execution traces. `summary.json` gives generated counts. `MANIFEST.sha256` covers this README and the generated files.

## Evidence

Coordinates are **ELF link-time virtual addresses**, before any load bias. All FDE end addresses are exclusive. An FDE is an unwind-described range; it does not prove that all entries or functions have been found. The selected scope completed without a timeout.

| Role | Copy A | Copy B | Copy C |
| --- | --- | --- | --- |
| Outer entry | `0x221eb40` | `0x336e970` | `0x48fc490` |
| Sequence visitor | `0x212e4a0` | `0x3a66630` | `0x4bcfc70` |
| Asset step | `0x1edd530` | `0x34fe880` | `0x44e13f0` |
| Boolean step | `0x1eee530` | `0x34ffa90` | `0x44df210` |
| Unsigned-value reader | `0x207faf0` | `0x3a37f70` | `0x4b84400` |
| End check | `0x1eb44b0` | `0x3444fb0` | `0x44c3010` |

Each outer entry passes `TwapWireSerde` and a 12-entry descriptor to its selected visitor. The descriptors have the same 12 strings in the same order: `a`, `asset`, `b`, `isBuy`, `s`, `sz`, `r`, `reduceOnly`, `m`, `minutes`, `randomize`, `t`. Their pointers are read from relative relocations; their lengths and bytes are read from file-backed ELF sections. A descriptor by itself does not establish a network schema. The observed ordering, copied result fields and separately mapped map arm support the names below; the actual incoming representation and byte-level network format are not established here.

For copy A, the visitor dispatches internal input tag `0x14` to the sequence arm. The selected positional steps are:

| Index | Interpreted field | Local operation and first stopping condition |
| ---: | --- | --- |
| 0 | `a` / `asset` | Call the asset step. A returned non-9 tag propagates; an absent result reaches missing-index 0. The step passes the literal `AssetWire` to an external reader. |
| 1 | `b` / `isBuy` | Call the boolean step. A non-9 tag propagates; payload byte 2 reaches missing-index 1. |
| 2 | `s` / `sz` | Consume one 32-byte record, call the size-value reader and propagate a non-9 tag. A returned first word `0x8000000000000000` reaches missing-index 2. Other returned three-word carriers are retained. |
| 3 | `r` / `reduceOnly` | Call the boolean step and propagate a non-9 tag; its byte is retained with bit 0 only. The step's absent value 2 therefore becomes 0. |
| 4 | `m` / `minutes` | Consume one record, call the unsigned-value reader and propagate a non-9 tag. An absent record reaches missing-index 4. |
| 5 | `randomize` / `t` | Call the boolean step and propagate a non-9 tag; retain bit 0, so its absent value 2 becomes 0. |

After these steps, the visitor calls the end checker. With no unconsumed records it returns tag 9. With remaining records it first computes their count from the byte difference shifted right by five and adds the current counter. If the u64 addition carries, it branches to a separate indirect call; otherwise it calls a result constructor with the sum and a pointer to the current counter, and the visitor checks the returned tag. The three end-check copies each contain the carry branch. Its destination call is a stopping boundary in the model; its eventual effects and any return are not established. The synthetic model treats this constructor as returning an error, an explicit assumption rather than a property independently proved for that callee. Under that assumption a seventh record, including a marker, stops the path before size conversion. The end checker calls a cleanup helper before making its remaining-count decision; effects of that helper are outside this packet.

A step with a null buffer or cursor at end returns an absence result without advancing. When a record is present, it first advances the cursor by 32 bytes and inspects the leading tag. Tag `0x16` returns absence without incrementing the count. Any other tag increments the u64 counter before invoking its value reader; a prior counter of `u64::MAX` branches to a failure call after the cursor advance. This sequence is observed in both step helpers and the two inline size/minutes steps. A missing optional index 3 can therefore precede a later index 4 only when an actual marker record occupies index 3; simply ending at index 3 also leaves index 4 absent. An absent final index 5 can be produced by the end of the input.

For direct boolean input tag 0, the boolean step copies its payload byte. Other tags are passed to an external decoder, whose result is not established. At index 1, byte 2 takes the missing branch, while the two optional output bytes are masked to their low bit. These are facts about internal byte values; they do not prove that an upstream decoder can produce every byte.

The unsigned-value helper's jump table distinguishes eight internal tags. Tags 1 through 4 load unsigned 8-, 16-, 32- and 64-bit values; tags 5 through 8 load signed values of those widths and branch to a separate error constructor when negative. A nonnegative value is zero-extended into the returned u64 slot. Other tags take the type-error constructor. The model assumes those constructors return error tags and does not execute them. The 24 table entries across the three copies are resolved directly from signed relative data, and the corresponding load/sign-test encodings are checked. The two 16-bit tag arms were checked across their entire 16-bit payload domains in the focused test; this is not a test of a real network decoder.

### Size-converter boundary

The selected outer entry calls the converter slot only after its visitor returns a non-sentinel result. The entry for copy A tests the converter's 16-bit result tag: `0x186` stores the returned word in its output payload, while the other arm delegates error construction. Relative relocation resolves the slot to the previously studied converter. The separately retained `RE-004-decimal-scaled-u64-94` work item records that the converter can call its mode-0 scaler with exponent 8; that scaler rejects a fractional scaled Decimal, a negative sign at its check, and values above `0x7ffffffffffffffe`. This packet does not re-analyse that converter, establish its full preceding input checks, or assert that all theoretical Decimal values reach its scaler. The sequence-to-carrier edge is new evidence; the downstream numerical rule is a conditional reference to the earlier packet.

### Copies and normalization

Eight selected visitor windows and five helper windows are compared across three copies. `raw-copy-differences.tsv` records 158 differing byte positions when comparing each of the two variants with copy A. `copy-masks.tsv` identifies 69 four-byte operands across the copies: direct-call displacements, RIP-relative LEA displacements and one RIP-relative call operand. Masking only these operands makes each selected window equal across the three copies. This is an original-to-original comparison of selected windows; it does not prove whole-body equivalence, the equality of the referenced callees or data, or equivalence to a Rust build. Original full body bytes and the unmasked differences are retained.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. Cargo lockfile, compiler and linker settings, two-build result, rebuilt byte comparison, helper/data/relocation closure and target differential behavior are not yet measured. No captured binary was executed.

The extractor checks selected full-body hashes, FDE/index agreement, file-backed address resolution, relocation targets, exact window masks and branch/call encodings. It performs narrow instruction-pattern replays for the boolean step, the inline size/minutes cursor guards, aligned-record end-count addition and the unsigned integer load/sign branches. It uses controlled decoder outcomes and a separate abstract sequence model; it is not a general x86 interpreter. The 729 present/marker/error patterns compare that abstract model with a first-stopping-position rule under normal helper returns. Missing/error-formatting helpers, the size converter and data ownership are not simulated as native target code.

The focused suite tests damaged input digest, altered code, table and descriptor bytes, changed unmasked copy bytes, malformed opcodes and out-of-range or non-file-backed addresses. It checks the cursor overflow and marker ordering, every byte value for the modeled boolean payload, and both complete 16-bit numeric payload spaces. The model intentionally admits synthetic internal values beyond a proven caller domain; its results do not establish their runtime reachability.

## Results and limitations

The generated summary records 18 FDE ranges, 36 descriptor entries, 33 selected edges, 81 selected conditional branches, 24 numeric-copy table arms and 13 selected copy comparisons. It records 1,536 boolean-cursor replays, 3,072 inline-cursor replays and 2,650 numeric-arm replays, with zero disagreements against their separate predicate models. It also records 16 aligned-record end-count boundary replays with zero disagreements, 182 synthetic sequence fixtures and 729 abstract presence/marker/error patterns. The end-count cases include synthetic counters whose upstream reachability is unknown. These denominators describe selected analyses, not whole-node coverage. Twenty-one focused unit tests passed without skips. Two independently regenerated output directories matched under different hash seeds and time zones with a binutils-free executable search path.

The additional `python3 tools/verify_imports.py` check failed because Git LFS could not create a temporary file in the read-only submodule Git metadata. The ordinary reference `git status` and reference revision read succeeded. No milestone gate is requested. The finite tests are not a target differential run; the other input representation, full size-reader grammar, converter's prior failure paths, error-constructor contract, floating-point environment, ownership effects and valid upstream input domain remain open. Next question: identify an address-disjoint producer of the internal sequence and prove which textual size values actually reach the existing fixed-eight scaler.
