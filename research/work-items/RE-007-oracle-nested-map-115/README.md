# RE-007: nested clearinghouse collection iteration, filtering and bounds

The #115 bytes establish how a two-phase nested collection exposes 20-byte outer keys and u64 inner keys, sums inner lengths with unsigned saturation, filters on an inner value field and computes remaining-length bounds, enabling an independently authored reconstruction of this bounded flow; 12,908 comparisons and 344 corruption controls passed, while economic units, callers' complete behavior and a Rust port remain unresolved.

- Component ID: `risk` (clearinghouse/oracle context; component ownership is an inference).
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit: `a8616af9432b8d8517b2af677880e117b7c28ef3`; no #94 material or reference-source implementation was used.
- Claim status: byte observations and tested executable Python models; source and economic interpretations are inferences, and uncovered paths are unresolved.
- Scope: ten FDEs in the nested length, forward iterator, filtered iterator and size-hint family; caller ownership, updates to the underlying maps, allocation, unwinding and the larger oracle or liquidation path are excluded.

## Reproduce

Run from the repository root with the authenticated target present. The generator accepts only the destination folder, derives all generated files directly from the ELF and shared parsers, and never starts the captured node.

```sh
python3 tools/artifacts.py verify
python3 tools/re007_oracle_sum_115.py --out research/work-items/RE-007-oracle-nested-map-115
python3 -m unittest tests.test_re007_oracle_sum_115
python3 tools/catalogue.py --check
```

For manifest verification, change to the work-item directory and run `sha256sum -c MANIFEST.sha256`. Generated files can also be regenerated into two separate temporary folders and compared with `diff -r`; omit this README and the manifest when comparing with the work-item directory. Python 3.12.3 and GNU objdump were used for the recorded checks; the generator and tests require only Python's standard library and the repository's shared ELF/FDE parsers. A timed generation took 85.34 seconds and 238,476 KiB maximum resident memory.

## Evidence

All coordinates below are ELF virtual addresses. `functions.tsv` gives the exclusive FDE ends, file offsets, exact byte lengths and body hashes; `instructions.tsv` contains 2,696 fixed-pattern decoded instructions, including their original bytes and direct targets. `branches.tsv` lists 365 conditional instructions and whether a comparison reached the instruction; reachability does not imply both edges were covered. `call-sites.tsv` records thirteen separately checked rel32 calls into the subject bodies. `source-context.tsv` validates two decoded caller edges and a relocated source-location record ending in `l1/src/clearinghouse/oracle/oracle.rs`, line 433, column 18. A location record is context, not proof that every selected function is exclusively owned by that source file.

| Role | FDE entry VAs | Bytes each |
| --- | --- | ---: |
| Nested-length folds | `0x543d4c0`, `0x543d630` | 354 |
| Outer-map tree step | `0x51356d0` | 552 |
| Inner-map tree steps, 112/96-byte ring rows | `0x5137810`, `0x5139a50` | 534 |
| Two-phase nested walkers | `0x5ab8240`, `0x5ab8bd0` | 2,442 |
| Remaining-length bounds | `0x5ab9560` | 1,628 |
| Value-filtered walkers | `0x5acec10`, `0x5acf070` | 1,113 |

The following independently reviewed objdump excerpt illustrates the unsigned fold. The 56-byte ring row's value begins at offset `0x18`, and its fourth u64 is read at `0x30`:

```text
543d532: 48 03 5a 30    add   rbx,QWORD PTR [rdx+0x30]
543d536: 48 89 da       mov   rdx,rbx
543d539: 48 0f 42 d0    cmovb rdx,rax
543d53d: 48 0f 42 da    cmovb rbx,rdx
```

An independent GNU readelf frame dump confirmed all ten recorded FDE starts and ends. For those ranges, a GNU objdump pass with `-d -M intel --insn-width=15` produced the same 2,696 instruction starts and byte groups as `instructions.tsv`. The raw per-body summary is `127/127, 127/127, 127/127, 93/93, 93/93, 604/604, 604/604, 361/361, 280/280, 280/280`, in the order in `functions.tsv`; there were zero differing starts or bytes. For example:

```sh
readelf --debug-dump=frames artifacts/node/115/hl-node
objdump -d -M intel --insn-width=15 --start-address=0x543d4c0 --stop-address=0x543d622 artifacts/node/115/hl-node
```

For an outer-map tree row the fourth word is at value offset `0x18`; both representations therefore contribute the length field of the same four-word inner collection header. The tested folds make a local copy of their iterator and leave the caller's input and source collection unchanged. The tree step returns key/value pointers in order, updates its cursor and remaining count, and checks an unwrap condition. Structural trees of heights eight and nine exercise the unrolled descent paths; they are synthetic structural inputs, not claims that live state reaches those heights.

The two nested walkers visit the first phase and its supplement, followed by the second phase and its supplement. For each item the output contains a tag, the 20-byte outer key and the u64 inner key. Their internal inner-row sizes differ by phase. The filtered walkers use the first inner-row layout and emit only rows whose value word at offset `0x10` equals the supplied u64; synthetic fixture payloads vary independently of keys. Once the second phase is exhausted, a subsequent call returns no item. If its outer iterator is a ring, repeated terminal calls swap its two empty range pairs even though the returned result remains empty. The filtered iterator has an analogous empty-ring swap.

For each unfinished phase, the size-hint lower bound is the saturating sum of the currently active inner iterator and the supplemental iterator. The upper bound is unknown while outer entries remain or checked addition overflows; otherwise it is the exact sum. Finished phases contribute zero. Combining phases saturates the lower bounds and supplies an upper bound only if both phase upper bounds and their sum exist. The helper is read-only with respect to iterator state.

The sibling body comparisons in `siblings.tsv` mask only the four-byte operand of each verified direct call; target equality is checked before masking. These are within-binary comparisons of paired bodies, not claims about a rebuilt binary. Original unmasked body hashes remain in `functions.tsv`; data, relocations, other indirect references and whole-ELF equivalence have not been compared.

## Implementation and comparison

The independent model and offline interpreter are in `tools/re007_oracle_sum_115.py`. The interpreter fetches target bytes from the verified image, uses the shared ELF and FDE parsers, runs the ten selected bodies and compares outputs and cursor state with separately described logical collections. The only external hook in this bounded path represents the iterator unwrap failure; it does not execute the captured binary. Native Rust implementation: **not yet implemented**.

The 12,908 counted comparisons comprise 6,000 folds, 756 direct outer-tree walks, 520 nested walks, 512 filtered walks and 5,120 synthetic size-hint cases. The nested walks additionally check 3,740 live size hints at intermediate states, which are reported separately and are not included in the 12,908 count. Cases include empty collections, both storage representations, wrapped ring segments, phase transitions, exact and overflowing u64 bounds, matching and absent filter values, and deep synthetic trees. Results are checked immediately; `samples.tsv` is a bounded sample and `measure.json` contains the complete comparison-stream hash.

`controls.tsv` includes every one of the 344 created controls: reached conditional-branch opcode inversions and seven malformed-input/address/digest controls. All 344 were detected; no equivalent or unexplained surviving mutant is claimed. Eight controls are classified as detected because the interpreter reached its step limit; these are bounded observations, not proof of an actual fault or nontermination. The other records retain the specific output, cursor, panic or memory-mapping difference. The target-free unittest module includes 41 tests, including wrong arithmetic, damaged bytes, bad hashes, invalid FDE starts, out-of-range addresses and distinct filter payloads for identical keys.

## Results and limitations

Of 2,696 decoded instruction addresses, 2,491 were reached by the stated comparison and control inputs; 341 of 365 conditional-instruction addresses were reached. These are observed address counts, not function-coverage or equivalence percentages. `branches.tsv` retains the 24 unvisited conditional addresses; neither untaken edges at reached instructions nor malformed raw pointers are proven. The model covers valid, stable synthetic containers and explicitly exercised overflow, empty and unwrap behaviors; it does not claim all possible corrupted-memory or concurrent-state outcomes.

The call-chain and source-location record place the fold in an oracle-related context, but the semantic meaning of the keys, filter word, count limits and any price, position-size or wei units is unresolved. The included Python models are not an independently built Rust node, and the remaining caller paths, helper ownership, data/relocation closure, unwind behavior and integrated node acceptance gates remain open. No progress gate is requested.

Next question: determine which economic or oracle records populate these maps and validate their units and writers against #115 before connecting the collection model to a margin or liquidation decision.
