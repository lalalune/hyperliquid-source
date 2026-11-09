# node-runtime: reconstruct node #115 clap argument Display bodies, name_no_brackets, ArgSettings tables and the three AnyArg method tables

- Component ID: node-runtime
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: 0781ce04826eeefd89fe336cb8ea073be0c1de30 (repository HEAD when this packet was built); no reference source was copied
- Claim status: observation (instruction bytes, tables, interpreted behaviour) with inference only where a body is named after the Rust construct it matches
- Scope included and excluded: the flag, option and positional argument `Display` bodies (0x165bc20, 0x166e3c0, 0x1675ad0), positional `name_no_brackets` (0x1671fe0), the Vec<String> collect (0x1669660), join (0x1669f00) and grow (0x1660680/0x1660590) helpers they call, the value-map iterator (0x166b320), the 20-entry setting tables behind `is_set`/`set` of all three kinds, the visible-alias collector (0x16572b0) and every method-table entry that follows the three Display slots. Excluded: the drop-glue entries (0x163b020, 0x163b130, 0x163b200, which call code outside this packet), the library routines that are stubbed, and every caller of these tables.

With this packet the text a node #115 command-line argument shows for itself (`--long <val>`, `-s=<a>,<b>`, `<name>...`, `<a>|<b>`) can be rebuilt from its record bytes alone: which of the three string pieces are written and in which order, how the value delimiter and `=` separator are chosen, when `...` is added, where the code panics (missing short name, missing value delimiter, empty value map) and what a failing writer leaves behind; the 20 argument settings are mapped to bit positions of the 32-bit settings word, and the 83 trait-object method slots of the three argument kinds are classified and checked one by one. All of it is a pure Python model that is run against the real instruction bytes on 20506 generated records (the binary is never executed).

## Reproduce

From the repository root (Python 3 standard library plus `tools/elf_index.py` and `tools/fde_extents.py`; no binutils, no subprocess, no network):

```
python3 tools/node_runtime_clap_arg_display_115.py --out research/work-items/node-runtime-clap-arg-display-115
python3 -m unittest tests.test_node_runtime_clap_arg_display_115
```

The tool checks the SHA-256 of the binary first and refuses to run on any other file. Output is byte-identical across hash seeds and time zones (two runs compared with `diff -r`). A run takes about two and a half minutes and stays below 0.5 GB. Side effects: it reads the ELF and writes only into the output folder. `MANIFEST.sha256` lists every other file of this folder.

## Evidence

Coordinates are virtual addresses of the ELF; file offsets come from the section table through the shared `Image` parser.

- `function-extents.tsv`: the exact FDE ranges and instruction counts of 13 selected interpreted bodies; other accessor/helper bodies are covered separately and are not all listed here.
- `static-bytes.tsv`: the seven format templates the three Display bodies pass to the formatter (a byte string of length-prefixed literals, `0xC0` = next argument, `0x00` = end, e.g. 0x432903 = `<{}>`, 0x447cc2 = `--{}{}`), the three literals (`" ="` at 0x46d294 selects the separator, `"..."` at 0x46d2f9), the GOT slots the code calls through (allocator, memcpy, fmt::write, alloc::fmt::format, string pad, char Display, panics) and the bytes of the three 19-22 byte argument formatters 0x16697c0 / 0x16697a0 / 0x16717a0.
- `method-tables.tsv`: all 83 method-table entries after the three Display slots (0x6405a60 flag, 0x6405b58 option, 0x6405c50 positional) with the class of each target: aliases 2, const 8, default_value 2, drop_glue 2, fieldptr 4, is_set 3, load 4, nonnull 1, optslice 14, pair 21, set 3, tag 3, taggedptr 2, values_iter 2, zero 12. Parameters (record offsets) are decoded from the instruction operands, not typed in.
- `settings.tsv`: for each kind the 20 settings of the jump table and mask table (0x46cf10/0x46cf60, 0x46d244/0x46d2fc, 0x46d34c/0x46d4ac): index -> bit, mask and result. Flag order index->bit for the flag kind (the option and positional tables are identical): 0->0, 1->1, 2->2, 3->3, 4->4, 5->5, 6->6, 7->7, 8->9, 9->11, 10->12, 11->13, 12->14, 13->15, 14->16, 15->17, 16->18, 17->19, 18->8, 19->10. Indexes 18 and 19 map to bits 8 and 10, so the jump order is not the bit order. The settings word is at +0xa8 of a flag record and +0x1a0 of an option or positional record.
- `accessor-checks.tsv`: one line per checked accessor, value-iterator, default-value and alias body with the decoded offsets.
- `cases.tsv`: a sample of the generated Display cases (input description and the chunks the writer received, `live` = blocks still allocated at return).
- `controls.tsv` / `equivalent-mutants.tsv`: every negative control and its verdict.
- `measure.json`: the counts used below.

Record layouts read from the bytes (offsets in bytes): option record: `Option<BTreeMap<usize,&str>>` value names at +0 (tag byte, root +8, height +0x10, length +0x18), `Option<u64>` value count tag +0x20 and value +0x28, name `&str` +0x170/+0x178, value delimiter `Option<char>` +0xf0 and short `Option<char>` +0x1e0 (0x110000 = none), long `Option<&str>` +0x1c0/+0x1c8, settings +0x1a0. Positional record: same names/name/delimiter/settings offsets, tag stored as a full word. Flag record: long +0xc8/+0xd0, short +0xe8, settings +0xa8. B-tree node: values (16-byte `&str`) from +0, parent +0xb0, keys +0xb8, parent index u16 +0x110, key count u16 +0x112, edges +0x118 (internal nodes only). Vec<String> elements are 24 bytes (capacity, pointer, length); the join helper and the collect helper allocate through the GOT slots 0x64df480 / 0x64df588.

## Implementation and comparison

`tools/node_runtime_clap_arg_display_115.py` carries the shared offline x86-64 interpreter (Image, decode, Memory, Machine) and, below it, the packet part: the pure models (`model_flag`, `model_option`, `model_positional`, `model_name`, `model_accessor`, `model_is_set`, `model_set`, `model_aliases`, `model_values_iter`, `model_default_value`), the rig and the case generators. The libraries the bodies call are conditional fixture stubs: fmt::write interprets the template format above and writes one chunk per literal or argument (failing at a chosen write), alloc::fmt::format builds a heap String, malloc / realloc / free keep a live-block table (free must pass the allocated size, so a wrong size or a leak is a failure), memcpy, and the panic routines raise. The argument formatters are recognised by address and their bytes are in `static-bytes.tsv`. B-tree maps are laid out in interpreter memory: regular trees of up to 173 entries, a deep tree family (height 2 to 9) and irregular trees with empty nodes so that every descent and climb branch of the iterator code runs.

Cases (20506 total, all equal to the models): flag 1800, option 3662, positional 3262, name_no_brackets 2662, accessors/settings/bodies 9120. A third of the Display cases make the writer fail at a random write of the model's chunk list (or one past its end); the return value must be exactly 0 or 1 and the live-block count must be zero afterwards. Each stream starts with deterministic boundary cases: one-key trees of height 2 to 9, trees whose first leaf is empty, value delimiters of 1, 2, 3 and 4 UTF-8 bytes (0x2c .. 0x10ffff) with empty and one-entry value lists, and value counts 1, 2, 3 with the multiple flag.

Negative controls: 342, of which 321 are detected and 21 are listed as equivalent in `equivalent-mutants.tsv`, each with the reason. For the Display, join and name bodies a mutant is only generated at an instruction the baseline sample executes; the 36 jump / immediate sites it never executes are listed in `coverage-gaps.tsv` and are not counted anywhere (they are untested, not equivalent). They are: every conditional jump of the interpreted bodies flipped, +1 on byte immediates of compare / test / shift / mov instructions, deliberately wrong model variants (separator inverted, count off by one, brackets dropped, wrong delimiter handling, wrong offset in each accessor class, wrong bit shift, wrong mask combination, all aliases visible) and a corrupted mask-table byte.

## Results and limitations

Machine-readable counts are in `measure.json`: cases 20506, negative controls 342, detected 321, equivalent 21.

- Observed and reproduced: the output chunk sequence and return value of the three Display bodies for generated fixtures spanning long/short names, separator flags, delimiter flags with and without a delimiter char, value names (absent, empty, one, many, deep trees), counted values 0..4 and the multiple flag, including selected writer-failure positions; the panic sites and what was written before them; `name_no_brackets` (borrowed vs owned result, capacity); the exact setting tables; the accessor classes; the alias collector and its capacity growth; the value-iterator constructor words.
- Inferred: that these bodies are the vendored clap 2.x `Display` impls, `name_no_brackets`, `is_set`/`set` of `ArgSettings`, `aliases`, `val_names` iterator and default-value accessors. The binary's own source path strings point at `z_vendor/clap/src/args/arg_builder/{flag,option,positional}.rs`, which is where the names come from; nothing here depends on them.
- Not claimed: the three drop-glue entries, the callers of these tables, the stubbed library routines, and sizes beyond the interpreter heap. Mutants in code that can only run for sizes or heights outside the fixtures (overflow guards in the join length sum, jump-table bounds, the unrolled eight-step descent for heights above 7) are in `equivalent-mutants.tsv` with the reason; they are "not reachable by any fixture that fits the interpreter", not a proof of identical behaviour. No component gate is requested.

Next question: the drop-glue entries (0x163b020 / 0x163b130 / 0x163b200 and the helpers 0x163ac80 / 0x163aed0 they call) and the callers that build these records (clap `App` parsing, 0x1630c90 is owned by earlier packets), so the whole argument record can be built from the command line.


## Review qualification

The format and writer stubs preserve a bounded fixture contract; they do not
execute or certify the full formatting library. Review added explicit checks
that `fmt::write` receives the fixture writer object in `rdi`, its vtable in
`rsi`, and the fixture `write_str` slot at vtable +0x18; `write_str` also checks
its receiver. Four refusal tests corrupt these arguments/slot directly. The
original stub silently accepted wrong writer-object and vtable inputs. These
checks preserve the original valid-input case outputs and prevent that ABI
corruption from receiving comparison credit. Panic and allocation-error hooks
raise without validating their complete argument/Location payloads; those
argument semantics and the stubbed helper implementations remain outside the
comparison claim.

Review also corrected the flag Display FDE end to `0x165bcc7` (35
instructions) and grow FDE end to `0x166070e` (41 instructions). The old
endpoints included one and two trailing `int3` padding bytes, respectively.
The other eleven listed FDE ranges/counts are unchanged. Only the corrected
extent table and its manifest seal change among the original generated raw
outputs; the semantic cases, controls, equivalent-mutant and coverage-gap
records remain preserved.
