# RE-009: Hyperliquidity snapshot read and write path in node 94

This packet establishes how the `Hyperliquidity` snapshot carries `spot_to_range` and `ensure_order_bucket_guard`, including the omitted-guard fallback, nested duplicate-key rejection and reader/writer field order, so a reconstruction can preserve these compatibility decisions.

- Component ID: RE-009, storage and state snapshots.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `966865f1637a29ce75b019e1bf11d5529cc6f519` / `999556f6e0a474b8312db96ec3149e1c44e97c23`; the unlicensed reference is a lead only, not an implementation source.
- Claim status: observation for the recorded bytes, relocations and conditional edges; inference for the state and field roles stated below; unresolved items are listed under Results and limitations.
- Scope included and excluded: one MessagePack reader path through the nested spot collection and range reader, one JSON reader's selected error/default paths, and one MessagePack and one JSON writer. The complete contents of the guard, spot key, range points and child codec helpers, full malformed-input grammar, other copies and releases, runtime reachability and implementation identity are excluded.

## Reproduce

From the repository root, with Python 3.12 and the pinned artifact present:

```sh
python3 tools/artifacts.py verify
python3 tools/hyperliquidity_snapshot94.py --out research/work-items/RE-009-hyperliquidity-snapshot-94
python3 -m unittest tests.test_hyperliquidity_snapshot94
python3 tools/hyperliquidity_snapshot94.py --out <tmp-dir>
```

Compare the nine generated data files with the corresponding files in the work item. The generator uses the Python standard library and the repository's `elf_index` and `fde_extents` parsers, verifies the full input digest before parsing, and does not invoke external programs. It reads the artifact without executing it. File-backed section resolution excludes SHT_NOBITS, and relocation slots must be unique. Python 3.12.3 on Linux was used for this packet. The recorded data files were generated twice with different hash seeds and time zones, with binutils absent from the executable search path; the two directories were byte-identical. No normalization masks are used.

## Evidence

All addresses are ELF virtual addresses before relocation. `functions.tsv` also gives file offsets, SHA-256 hashes of the full FDE-described byte ranges, and exclusive end addresses. FDE ranges describe unwinding and are not asserted to be complete function boundaries or a global denominator. `anchors.tsv` contains the exact selected instruction bytes, `edges.tsv` resolves selected direct and relocated calls, `branches.tsv` gives taken and fallthrough addresses, and `literals.tsv` and `templates.tsv` resolve field names and diagnostic templates. Disassembly was reviewed with GNU objdump 2.42 as a human aid; its output is neither input to the generator nor a generated evidence file.

### Outer reader and field decisions

The unwind extent `0x195b220..0x195ccd7` references the relocated type descriptor for `struct Hyperliquidity with 2 elements`. The classifier `0x16ce960..0x16ceaac` checks lengths and all individual bytes: `spot_to_range` selects 0, `ensure_order_bucket_guard` selects 1, and other keys select 2. Both key paths at `0x195c534` and `0x195c702` call this classifier. The 38 comparisons and their sites are in `field-comparisons.tsv`.

| Outer input decision | Observed path, conditional on successful child reads |
|---|---|
| Sequence has zero elements | `0x195b7af` branches to the zero-position length-error construction. |
| Sequence has one element | The first element goes to `0x17aa010`; `0x195b7ef` falls through to the shared guard-default call. |
| Sequence has two elements | The first element goes to `0x17aa010`, the second to the guard reader called at `0x195b8d9`, and the length-two branch reaches result construction. |
| Sequence has more than two | After the two child reads, `0x195b949` reaches the extra-element error construction at `0x195b9d1`. |
| Map omits `spot_to_range` | At map completion `0x195bf22` routes to the `missing field` template using that key. |
| Map omits `ensure_order_bucket_guard` | With the first field present, `0x195bf5f` falls through to the same guard-default slot used by the one-element sequence. |
| Either known field is repeated | Presence checks at `0x195c89e` and `0x195c94a` lead to the corresponding `duplicate field` template. |
| Unknown key | Selector 2 reaches a separate value helper at `0x195c8f9`; its complete behavior is outside this packet. |

The JSON reader `0x1c76610..0x1c776bc` separately references the missing-field and duplicate-field templates for the same keys and calls the same relocated default slot at `0x1c76d82`. These selected windows do not establish its full accepted grammar.

### Nested spot collection and range

Both collection arms in `0x17aa010..0x17aa7a9` call distinct entry consumers. The map arm calls `0x264be00`, which supplies the four-byte `Spot` literal to its key reader, then calls the optional range reader. The sequence arm calls `0x267b1d0`, which calls pair reader `0x1854410`; the pair reader's selected sequence path calls its key reader and then that same optional range reader, and checks for exactly two elements. Both entry consumers call the same insertion target and use the returned sentinel to select either continuation or a separately constructed `duplicate key` diagnostic. The diagnostic's bytes are reconstructed from the overlapping immediate stores in both functions, not from disassembler text. This is a branch-level account; it does not prove all key encodings or all value-helper behavior.

`0x168caa0` takes its `0xc0` nil branch to a successful result with first payload word `0x8000000000000000`; its non-nil arm calls `0x175ad70`. The latter references the relocated `struct Range with 2 elements` descriptor. In its selected sequence path, the first and second children are read in that order and the reader checks a two-element count. Its map error constructions name `order_sz` and `points` for both missing and duplicate fields. The child encodings and all possible map forms remain unresolved.

### Default and writers

The default call slots in the MessagePack sequence, MessagePack map and JSON reader all resolve through `0x57725a0` to `0x32636a0`. This function passes `0xafaa8` to a separate date helper, branches to a failure call if it returns zero, performs the recorded integer calculation and returns `3000` in `rax`, with the second result in `rdx`. The date helper and the complete returned value are not reconstructed here. Interpreting `3000` as a millisecond bucket width is an inference supported by the named guard field and the independently studied guard layout, not by the integer alone.

The MessagePack writer `0x3263290..0x32633ba` passes count 2 to one of two header helpers according to a serializer byte. It calls the collection writer with object offset `+0x10`, then the guard writer with object offset `+0x00`. When the serializer byte equals 1, it emits the corresponding field names before the values; the header selection tests zero versus nonzero, so values other than 0 and 1 should not be assumed equivalent to 1. Each selected helper result is checked before continuing. The JSON writer `0x32633c0..0x326369e` names the same fields in the same order and checks results between them. These are code-path observations, not complete byte-for-byte serializers.

## Implementation and comparison

Independent Rust implementation: **not yet implemented**. No compiled comparison, normalization, target execution, real snapshot fixture, full helper closure or runtime behavior is claimed. The tests exercise static byte extraction and a classifier derived from the 38 pinned comparisons; the synthetic inputs are not executions of the captured node. Controls include changed artifact digest, altered classifier opcode, comparison byte and offset, changed conditional branch, altered call opcode, damaged anchor, non-FDE address and out-of-range or NOBITS address.

## Results and limitations

The generator records 13 selected FDE ranges, 48 fixed byte anchors, 25 call edges, 19 conditional edges, 12 literal references and 7 diagnostic-template references. The classifier has 2 accepted key spellings and 38 byte comparisons; the test changes each byte to every other value, checking 9,690 negative inputs, as well as truncated and extended names. The focused suite has 13 passing tests and no skips. These counts describe selected evidence, not complete code coverage. The nested point and spot representations, JSON child behavior, all dynamic call targets, allocator and cleanup semantics, live snapshot compatibility and other releases remain open. No milestone gate is requested.

Next question: trace the `points` child reader and its writer through a non-overlapping path, then compare complete synthetic snapshots in a separately authorized offline harness.
