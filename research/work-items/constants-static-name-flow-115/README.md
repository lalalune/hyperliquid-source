# constants: reconstruct the node #115 static-config name path from the document check to the one byte network name

This packet turns the static-configuration name path of node #115 from a map of windows into a checked reconstruction: seven functions of it (the two 79-spelling name classifiers, the Unicode `str::trim`, the missing-`aws_name` fallback reader, the document end check, the quoted-name reader and the static reader that selects the final byte) run as the file's own bytes against a separately written specification, so a Rust port can take the name table, the exact trim and white-space sets, the classifier failure outputs and the end-to-end result rules (name byte, default 33, panic sites) from here instead of from prose.

- Component ID: `constants` (task `RE-015` is at quota for this account, so the packet is filed under the component).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit / reference commit: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference source is used or copied (node #94 appears only through the existing RE-015 packet's text, not as an input).
- Claim status: observation (byte-level results of running the listed functions with contract stubs); inference (names of the roles, the Rust `str::trim` identification); unresolved (document reader 0x17771b0, string parser 0x5c56b60, file read 0x5ca4940, path builders, allocator and panic internals).
- Scope included and excluded: the seven functions in `evidence.json`, every normal and failure branch they reach (read error, trailing characters, document error with three error-box kinds, end of input, not-a-string, string error, unknown spelling, unknown-name panic, read-error panic), their 79 spellings, white-space sets and jump tables. Excluded: the JSON value grammar, the home/directory selector, concurrency of the publication callbacks, every stubbed callee body.

## Reproduce

Run from the repository root on Linux x86-64 with Python 3 (standard library plus `tools/elf_index.py` and `tools/fde_extents.py`) and the pinned #115 artifact. The tool authenticates the whole input before parsing, reads bytes only, calls no external program and never executes the node.

```sh
python3 tools/const_name_flow_115.py --out research/work-items/constants-static-name-flow-115
python3 -m unittest tests.test_const_name_flow_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

Two generations with different hash seeds and time zones are byte-identical (`PYTHONHASHSEED=7 TZ=UTC` against `PYTHONHASHSEED=91 TZ=Pacific/Honolulu`, compared with `diff -r`). The generation takes about two minutes and under 400 MB. Addresses are linked ELF virtual addresses; `.text` bytes and the `.rodata` tables are read through the section headers (SHT_NOBITS sections are never mapped).

## Evidence

| File | Content |
| --- | --- |
| `names.tsv` | the 79 spellings read from the pointer/length array at `0x63f8788` (identical to the array at `0x6410ce8`), their jump slot, and per spelling the executed instruction count and the address of the final `ret` in the plain and in the serde classifier |
| `buckets.tsv` | the 12 length slots (lengths 2..13) of both classifiers' jump tables (`0x481d0c`, `0x481ba0`) with the number of spellings per length |
| `whitespace-table.tsv` | the 256-byte White_Space map reached through the slot `0x64dfc30` (-> `0x479266`); bit 0 is read for U+0080..U+00FF, bit 1 for U+2000..U+20FF |
| `cases.tsv` | every Nth comparison of the full run (family, case number, outcome class, input, result) |
| `outcomes.tsv` | outcome class counts per family over all 45509 cases |
| `coverage.tsv` | instructions of each function's FDE extent against instructions stepped |
| `stubs.tsv` | the contract of every stub (GOT slot or direct call) with its RELATIVE-relocated target |
| `mutants.tsv`, `variants.tsv`, `controls.tsv` | the negative controls |
| `evidence.json`, `measure.json` | counts, digest, function list |

### What the bytes say

The path is `static_reader 0x17783e0 -> (format, read) -> document_end_check 0x1775dd0 -> (document reader 0x17771b0) -> name`. Observations, each exercised by the cases:

- **Name tables.** Both pointer arrays hold the same 79 spellings; `Ec` is 0, `SoloSandbox` 32, `NvTestnet` 33, `NvTestnet2` 34. The plain classifier 0x1775500 and the serde classifier 0x1774100 are the same decision list: a length check `len - 2 <= 11`, an indirect jump through a 12-slot table, then per length a chain of exact comparisons (word compares against 64-bit immediates, overlapping reads at +3 and +5 for lengths 11 and 12, `cmpw`/`cmpl` for the short ones). Anything else returns 79 (plain) or tag 1 plus an error built by 0x1777fd0 from (pointer, length, table 0x6410ce8, 79). The reads never leave the input span (checked by logging every heap read against guard bytes).
- **Trim.** 0x1778840 is `str::trim` over valid UTF-8. It decodes forward and backward, treats 9..13 and 0x20 directly, and for non-ASCII code points reads bit 0 of the table for the `0x00` page, bit 1 for the `0x20` page, compares 0x1680 and 0x3000 outright; an all-white-space input returns (start 0, length 0). The table agrees with the Unicode White_Space property on all 256 entries in both columns.
- **Missing-name fallback.** 0x1773fd0 frees the path buffer before it inspects the read result; a read error panics at Location pair (`0x6411298`, `0x64111d8`) without freeing the file buffer; a trimmed content that classifies as 79 panics at (`0x6411278`, `0x64111f0`) without freeing; success frees the file buffer only when its capacity word is non-zero.
- **End check.** After the document reader, only the bytes 9, 10, 13 and 32 (mask `0x100002600`) may follow the position the reader left; anything else (including 0x0b, 0x0c, U+00A0) builds error code 0x16. A document error skips the check; the reader scratch is freed when its capacity word is non-zero.
- **Quoted reader.** 0x1777080 skips the same four bytes, an empty remainder builds error code 5, a non-quote byte builds the invalid-type error and leaves the position at that byte, a quote stores the position after it, clears the scratch word at reader+0x10, parses the string and classifies it; an unknown spelling is wrapped with the reader position.
- **Static reader.** Format the path, read the file; the 1<<63 sentinel drops the io error and returns 33 (frees the path buffer). Otherwise run the end check; a document value goes out as is (a value of 79 is not rejected here), an error box is released by its kind word (1: io drop of word +8, 0: free of (+8, cap +0x10) when cap is non-zero, other kinds: nothing) followed by a 0x28 byte free, the file buffer and the path buffer, and the result is 33.

## Implementation and comparison

`tools/const_name_flow_115.py` contains an x86-64 evaluator that decodes and executes the function bytes (it raises on any form it does not model), the harness that binds every GOT slot of the path to its RELATIVE target, the contract stubs listed in `stubs.tsv`, a specification written from the 79 spellings and the Unicode property rather than from the code, the case generators, and the negative controls. Cases are produced and compared one at a time; only counts and a sample are kept (maximum resident set about 360 MB).

Case families (comparisons per family): plain 5143, serde 5143, trim 32422, missing-name reader 569, end check 827, quoted reader 834, static reader 571; total 45509. They include every spelling, every single-byte bit/case/high flip at every position, truncations and extensions, adjacent swaps, splices, lengths 0..40, random bytes, all code points U+0000..U+3100 alone and trailing a letter plus a stride through the rest of the planes, mixed Unicode strings, all 256 trailing bytes for the end check, all 256 first bytes for the quoted reader, and every document value 0..78 for the static reader.

Negative controls (153, all detected): 116 byte mutants (return immediates, xor immediates, compare immediates, inverted conditionals, jump-table slots, table entries, mask bytes), 24 wrong specifications (white-space sets with one point added or removed, Python `str.strip`, ASCII-only, end-check masks, case-insensitive / prefix / length-only / last-byte-ignored classifiers, wrong unknown marker, wrong default, wrong entry address, swapped panic sites) and 13 corrupted inputs (flipped binary byte, differing name array, flipped table bits, retargeted GOT slots, entry inside a function, `.bss` address, past-the-end address, narrowed read window, damaged guard byte, missing stubs). Not counted: 4 mutants whose instruction no case executes (unwind landing pads) and 1 survivor(s), listed in `mutants.tsv`.

Function coverage (instructions in the FDE extent / stepped); the unstepped ones are landing pads and one unreachable `expect` call:

| function | extent | instructions | stepped |
| --- | --- | --- | --- |
| `plain_name_classifier` | `0x1775500`-`0x1775dc6` | 564 | 564 |
| `serde_name_classifier` | `0x1774100`-`0x1774be1` | 736 | 736 |
| `name_trim` | `0x1778840`-`0x1778ad7` | 175 | 173 |
| `missing_name_reader` | `0x1773fd0`-`0x17740fe` | 79 | 57 |
| `document_end_check` | `0x1775dd0`-`0x1775ede` | 66 | 56 |
| `quoted_name_reader` | `0x1777080`-`0x17771a3` | 72 | 70 |
| `static_reader` | `0x17783e0`-`0x177858d` | 117 | 94 |

The Rust port is not implemented here; no Cargo graph or build comparison exists for this path.

## Results and limitations

45509 comparisons, 0 disagreements; 153 of 153 negative controls detected. The packet requests no progress gate: it covers seven functions of one path, not the `constants` component. Limits: the stubs fix only what the callers consume (a stub that behaved differently would change the outcome classes, not the byte-level checks); the real document reader, string parser, file read and allocator are not modelled; the trim is only exercised on valid UTF-8 (one mutant in the multi-byte backward arm is equivalent under that contract); the static reader returns through `ebp`, so only the low byte is compared (the upper 24 bits are callee-saved garbage the evaluator seeds); panics are modelled as stops at the first panic entry, not as unwinds. Next question: the document reader 0x17771b0 (object/array dispatch, duplicate-field error, the `0x1777a3b` hand-off to the missing-name reader) with the string parser 0x5c56b60 it calls, so the stubs of this packet can be replaced by bytes.
