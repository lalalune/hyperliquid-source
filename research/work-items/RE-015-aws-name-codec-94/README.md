# RE-015: map the plain AwsName recognition and rendering bodies

This packet establishes that the plain AwsName recognizer accepts only exact whole-slice spellings and returns byte 76 on failure, while a separate enum renderer consumes a second spelling pool; reconstruction can keep this failure sentinel distinct from the NvTestnet default and implement the two conversion contracts without guessing from the existing name inventory.

- Component ID: `constants`; task `RE-015`.
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663` / can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23`.
- Claim status: observation of complete selected-body bytes, comparison predicates, branch targets, return bytes, pool references and RELATIVE relocations; inference of source-level `FromStr`/formatting roles; unresolved external formatting effects and surrounding initialization.
- Scope included and excluded: the full FDE bodies beginning at `0x164cdb0` and `0x164c750`, their length/enum dispatch tables, all recognition and rejection routes, all rendering leaves, and an aggregate cross-check against the prior inventory. File reads, trimming, JSON parsing, directory selection, lazy initialization, caller bodies, the external formatting sink, node #115 and visor are excluded. No component gate is requested.

The existing [constants inventory](../constants/README.md) establishes the names and the relocated table. The later [JSON packet](../constants-aws-name-parse-94/README.md) studies a different matcher and the object parser. Neither selected body address occurs in the retained work-item evidence at the source commit. This packet derives predicates from machine code and rendering references from a different dispatch table. It does not re-export the old 76-entry table or claim its discovery again.

## Reproduce

Repository-root working directory; Python 3.12.3 on Linux x86-64. The collector uses only the standard library and the repository's `elf_index.sections` and `fde_extents.eh_frame_records`. It authenticates the complete node #94 input before parsing. It does not run captured code, emulate it on concrete inputs, invoke external programs, use a network, or read runtime configuration.

```sh
python3 tools/aws_name_codec94.py --out <tmp-dir>/one
python3 -m unittest tests.test_aws_name_codec94 -v
PYTHONHASHSEED=7 TZ=UTC python3 tools/aws_name_codec94.py --out <tmp-dir>/two
PYTHONHASHSEED=119 TZ=Pacific/Kiritimati python3 tools/aws_name_codec94.py --out <tmp-dir>/three
diff -r <tmp-dir>/two <tmp-dir>/three
cmp <tmp-dir>/two/evidence.json research/work-items/RE-015-aws-name-codec-94/evidence.json
cmp <tmp-dir>/two/length-dispatch.tsv research/work-items/RE-015-aws-name-codec-94/length-dispatch.tsv
cmp <tmp-dir>/two/conversion-paths.tsv research/work-items/RE-015-aws-name-codec-94/conversion-paths.tsv
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

`<tmp-dir>` denotes an owned temporary directory. For the no-binutils check, set `PATH` to a directory containing only `python3` before the Python commands. The three generated evidence files must compare byte-for-byte; README and MANIFEST are maintained separately. The evidence directory's MANIFEST covers every other file in that directory.

GNU objdump 2.42 was used only for human inspection during preparation. No objdump text, parsed instruction listing or binutils-derived numeric list is an input to the producer or tests. All submitted addresses, counts and tables come from authenticated ELF bytes.

## Evidence

### Function map and boundaries

Addresses are linked ELF VAs. File offsets are resolved through unique file-backed sections, excluding SHT_NOBITS. FDE ranges are unwind-described bounds; the additional restricted decoding below partitions every byte in these two ranges. This is not a whole-node function census.

| Observed role | Half-open VA range | File offset | FDE VA | Bytes |
| --- | --- | --- | --- | ---: |
| Exact string recognizer | `0x164cdb0..0x164d62e` | `0x164bdb0` | `0xd025f4` | 2,174 |
| Enum rendering dispatcher | `0x164c750..0x164cda2` | `0x164b750` | `0xd025e0` | 1,618 |

`evidence.json` carries full-body hashes, the parser's complete 550-instruction partition, each predicate's branch and return sites, and every rendering leaf's bytes. `conversion-paths.tsv` joins independently derived parser predicates to renderer leaves by returned tag. It is a code-path map, rather than a copy of the prior relocated name table.

### Recognition: input slice to return byte

Observed entry registers are a byte pointer in RDI and length in RSI; the result used by the recovered body is AL. Upper return-register bits are not specified by this packet. There are no calls or memory stores in the decoded recognizer.

The entry adds signed immediate -2 to RSI, compares the resulting unsigned value with 11, and sends values above that bound to `0x164d384`, which returns 76. This covers lengths below 2 through wrapping subtraction, as well as lengths above 13. The admitted range indexes the signed-rel32 table at `0x264d18`.

| Input length | Entry VA | Exact accepted predicates | Rejection byte |
| ---: | --- | ---: | ---: |
| 2 | `0x164cdce` | 9 | 76 |
| 3 | `0x164d05b` | 2 | 76 |
| 4 | `0x164ce34` | 1 | 76 |
| 5 | `0x164d384` | 0 | 76 |
| 6 | `0x164d384` | 0 | 76 |
| 7 | `0x164d36d` | 1 | 76 |
| 8 | `0x164d387` | 13 | 76 |
| 9 | `0x164ce43` | 20 | 76 |
| 10 | `0x164d08e` | 11 | 76 |
| 11 | `0x164d1f9` | 11 | 76 |
| 12 | `0x164d4ae` | 6 | 76 |
| 13 | `0x164d45b` | 2 | 76 |

Each equality condition is reconstructed from the comparison instructions, including constants formed by ADD/LEA, overlapping input loads, XOR reductions and OR reductions. Every successful condition constrains every byte of its length bucket. The producer checks that overlapping loads require the same bytes and stay inside the bucket. It rejects unknown encodings, arithmetic on unknown input, unexpected loops, nonterminal branch destinations, uncovered bytes and duplicate predicates.

A JE success goes to a proven constant-return leaf and its unequal path continues the comparison chain. A terminal JNE sends the unequal path to a proven failure return and the equal fall-through to its success return. The three explicit failure leaves are `0x164d384`, `0x164d4ab` and `0x164d55c`; each returns AL=76. Two additional final comparisons fold success/failure into arithmetic:

- `0x164d052`: SETNE AL; shift by 2; OR with 72. Equal returns 72 (`GdHlPerp2`); unequal returns 76.
- `0x164d453`: SETE CL; AL=76; subtract CL. Equal returns 75 (`EbHlPerp`); unequal returns 76.

The successful return values are exactly 0 through 75, with unique exact spellings. The `NvTestnet` predicate is at `0x164ce96`, with success return at `0x164d58f` and value 32. Unknown text is 76, not 32. Leading/trailing whitespace, a terminating NUL included in the slice, case changes, or JSON quote characters are not silently removed by this body. A trimming or fallback policy must live outside it.

### Rendering: valid enum byte to a delegated string write

The renderer loads an unsigned byte from RDI, preserves the formatter argument originally in RSI, and indexes signed-rel32 slots at `0x264be8`. Its 76 leaves partition the entire remainder of its FDE; every leaf consists of a pool-address LEA, a length immediate, argument movement, and a tail jump through `0x576e000`. That slot's RELATIVE relocation resolves to `0x1573450`.

The full instruction partition shows no range check in this renderer. The established input domain is valid tags 0 through 75. The recognizer's failure value must be handled before invoking this contract; no rendering behavior is claimed for other values. This is an enum-domain observation, not a security finding.

The dispatcher itself does not allocate, mutate the enum byte, or replace the result of its tail-called sink. Formatter state changes, errors and unwinding belong to that external sink. They are not reconstructed here; there is no invented successful-write assumption.

The two dispatch tables are adjacent: the renderer's slots end exactly at the parser's length table. After the latter, `0x264d48..0x264f64` holds a second contiguous 540-byte spelling pool. Comparing the code-derived strings against the already inventoried relocation table yields:

- 62 equal spellings at different pointers, spanning that second pool;
- 14 references sharing the original pointer;
- all 76 code-derived spellings and return values agreeing with the prior table.

The new 540-byte pool and the earlier `0x21800b..0x218227` pool have identical bytes and SHA-256 `19286f2906cf2c3606ca2e1e6b2069d5383adcf995b32147416a515154b1c525`. The prior table is read only after both code paths are derived, as a cross-check. Its contents do not drive the symbolic recognizer or rendering decoder and are not re-exported.

### Observations, inferences and ownership boundaries

The exact-match return contract and literal-pointer relationships are observations. Calling the first body a plain `AwsName::from_str` specialization and the second an enum formatting implementation is an inference from those contracts, the names, and the reference lead `global_constants/aws_name.rs`. No source symbol is recovered.

The reference's separate trimming and file-reading helpers must not be folded into this recognizer. Its illustrative bucket classification and chain hints are not established by these two bodies. Likewise this packet does not upgrade the prior JSON packet's missing-key or file-read questions into proven end-to-end behavior.

Existing caller/initialization work is left with its owners. A focused static reference search found the parser reached through its relocated slot from the already studied current-name helper, and the renderer supplied through its relocated slot in an already studied storage/logging caller. Those caller bodies are not new claims or part of this packet's byte denominator. Computed references and a complete call census remain unresolved.

## Implementation and comparison

Independent Rust: **not yet implemented**. Build, lockfile, raw/normalized binary comparison, native execution and runtime differential behavior: **not yet implemented/measured**. No normalization masks or byte transplantation are used.

The active RE-015 question needs reproducible comparison and rejection predicates. The existing `constants_scan.py` inventories literal/table references but has no comparison-chain decoder; disassembler output cannot be the deterministic producer under this task's constraints. This focused collector supplies that missing evidence operation using the existing ELF/FDE parsers, without changing shared tools or infrastructure.

The producer is a bounded static-analysis instrument, not a runnable node substitute. It propagates constants and uninterpreted input-byte XOR expressions through straight-line comparison chains. It never supplies concrete inputs to captured instructions. OR-equals-zero conditions become conjunctions of exact byte equalities. The formatter independently supplies a second description of the accepted names; this is a consistency check between different target code/data paths, not a claim of native behavioral equivalence.

Focused controls cover whole-input digest/truncation rejection; branch direction and return corruption; both folded return formulas; bad length bounds and out-of-range loads; shifted, duplicate and out-of-range dispatch targets; all rendering-leaf lengths; pool-byte changes; relocation removal/invalid targets; shortened FDE bounds; ambiguous/unbacked address mappings; incomplete and contradictory symbolic constraints; and repeated output identity. The boundary corpus checks the extracted contract against the independently decoded rendering leaves. It is explicitly not a target execution test.

## Results and limitations

The machine-readable denominators are the two selected bodies: 2,174/2,174 parser bytes and 1,618/1,618 renderer bytes structurally decoded; 550 parser instructions; 12 length buckets; 76 exact predicates; 76 rendering leaves; 76/76 cross-path spelling/tag agreements. These numbers measure this restricted static analysis only, not rebuilt-byte identity or overall component coverage.

Final validation: 14 focused unittest methods passed, zero failures/errors/skips. Artifact verification, catalogue consistency, and inventory/literal reproduction passed. The additional `verify_imports.py` check failed: its fresh-index Git status invokes an LFS clean filter that tries to write inside read-only Git metadata. A direct reference HEAD read matches the stated pin; no checkout or Git settings were changed. Full repository verification is therefore not claimed green. Two producer runs with different hash seeds and time zones, using a PATH containing only Python, were byte-identical. The repository-wide test suite was not run. No hosted CI, container build or captured-node execution is claimed.

The requested full-component/large-path goal remains incomplete: directory selection, file reads, default selection, lazy publication, and external formatting effects are not closed here and overlap existing work. This packet is a bounded conversion-path contribution, not a claim that those gaps disappeared. All constants milestones remain false (0/4); no gate change is requested.

Next question: with the existing current-name helper's ownership coordinated, trace how the returned failure byte is handled after file-read and trim, including the distinction between a missing field, invalid file contents, and the static-config fallback. That requires a separate review of already-owned caller paths.
