# RE-004: TWAP size field to fixed-eight conversion

Node #94 connects the `TwapWireSerde` map field `s`/`sz` to the established fixed-eight conversion, with alias-aware missing and duplicate checks before that conversion.

- Component ID: RE-004 (quantities and rounding).
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; unlicensed reference `999556f6e0a474b8312db96ec3149e1c44e97c23` was used for search leads only.
- Claim status: literal bytes, FDE ranges, selected instructions, table targets, relocation-resolved edges and the stated internal branch predicates are observations. The size and TWAP labels and the connection to prior conversion semantics are inferences. Live reachability and complete external decoding are unresolved.
- Scope included and excluded: seven selected node #94 FDE ranges, the internal map path, its selected key and size-value paths, and the outer result. Previously studied conversion bodies are dependencies, not new subject functions. Sequence input, other key representations, helper internals, callers, floating-point environment and node #115 are excluded. An FDE extent is an unwind range, not proof of every function boundary or basic block.

## Reproduce

From the repository root on Linux x86-64 with Python 3.12.3 and the standard library:

```sh
python3 tools/artifacts.py verify
python3 tools/twap_size_wire94.py --out research/work-items/RE-004-twap-size-wire-94
python3 -m unittest tests.test_twap_size_wire94
(cd research/work-items/RE-004-twap-size-wire-94 && sha256sum -c MANIFEST.sha256)
python3 tools/catalogue.py --check
```

For a byte-for-byte determinism check, replace the two placeholders with fresh output directories:

```sh
PYTHONHASHSEED=1 TZ=UTC python3 tools/twap_size_wire94.py --out <tmp-dir-a>
PYTHONHASHSEED=777 TZ=Pacific/Kiritimati python3 tools/twap_size_wire94.py --out <tmp-dir-b>
diff -r <tmp-dir-a> <tmp-dir-b>
```

The tool verifies the entire target SHA-256 before ELF parsing. It imports the repository's ELF and FDE parsers, excludes non-file-backed sections, and reads relative relocations, instruction bytes and tables directly. It invokes no external program, executes no target code, makes no network access, and writes only the requested output directory. It uses a deliberately limited byte-pattern interpreter for the two bytewise key trees and checks the complete selected packed-comparison body before deriving its predicates; unsupported patterns fail closed.

`evidence.json` records selected FDEs, file offsets, CIE/FDE addresses, table targets, edges and model totals. `windows.tsv` and `error-paths.tsv` retain raw bytes for the selected blocks. `keys.tsv`, `key-representations.tsv`, `key-numeric-model.tsv`, `duplicate-branches.tsv`, `missing-branches.tsv`, `size-type-dispatch.tsv`, `size-reader-paths.tsv`, `size-record-flow.tsv`, `outer-layout.tsv`, and `outer-outcomes.tsv` describe extracted branches and their direct consequences. `presence-model.tsv`, `order-model.tsv`, and `duplicates-model.tsv` are explicitly conditional model results. The manifest hashes this README and all generated files.

## Evidence

Addresses are node #94 ELF virtual addresses before load bias. End addresses are exclusive; corresponding file offsets and FDE identities are in `evidence.json`.

| Selected FDE start | FDE end | Selected role |
| --- | --- | --- |
| `0x336eab0` | `0x336ebe4` | descriptor, visitor call, conversion call and result |
| `0x3aaedd0` | `0x3aafc8a` | value-backed map visitor and selected failure paths |
| `0x34e14e0` | `0x34e166c` | map key cursor and end marker |
| `0x3aebac0` | `0x3aebd6b` | internal key-value dispatch and one bytewise classifier |
| `0x33186c0` | `0x33187b7` | packed byte-comparison classifier |
| `0x33caeb0` | `0x33cb074` | second bytewise classifier |
| `0x3a51070` | `0x3a511ff` | size field's three-word value reader |

### Field keys and dispatch

The outer entry passes the literal `TwapWireSerde` at `0x58c035` and a 12-entry field descriptor at `0x56e9c48` to the visitor at `0x336eae0`. The descriptor's pointers are resolved from `R_X86_64_RELATIVE` records. The map visitor calls its cursor at `0x3aaee9b`; the cursor calls the key classifier at `0x34e15e7`. Its internal end marker selects case 7 in the visitor's table at `0x5aa7d0`, while case 6 handles an unrecognized key and rejoins the loop after consuming its value on normal return.

Four internal byte-string key representations, tags 12 through 15, have the same complete recognized byte language and cases:

| Case | Accepted byte strings |
| --- | --- |
| 0 | `a`, `asset` |
| 1 | `b`, `isBuy` |
| 2 | `s`, `sz` |
| 3 | `r`, `reduceOnly` |
| 4 | `m`, `minutes` |
| 5 | `randomize`, `t` |

Tags 12 and 13 call the packed classifier at `0x33186c0`; tag 14 calls `0x33caeb0`; tag 15 uses the inline tree. Each checks `(length - 1)` as an unsigned 64-bit value against 9, then dispatches through its own length table. Single-byte inputs use a second table; the remaining accepted words are determined by byte comparisons or equality of packed XOR comparisons. The interpreter splits complete 256-value byte domains on every equality branch, and the packed path's OR-of-XOR equality requires each compared byte to agree, including the overlap in the seven-byte comparison. Thus the stated key language covers all byte contents and representable lengths for valid input slices, under normal helper returns. Unknown byte strings select case 6. This does not prove which internal representations an external protocol constructs.

The classifier also has internal tag 1 and tag 4 arms that select case `v` when an unsigned byte or unsigned 64-bit `v` is below 6, respectively, and case 6 otherwise. The byte arm's complete 256-value domain and selected u64 boundaries are tabulated; the unsigned comparison and conditional move establish the same clamp for the remaining u64 values. In particular, an internal numeric value 2 can enter the same case as `s`/`sz`. These are internal discriminants, not asserted network tags.

### Map state, errors and conversion

The six cases keep separate seen states. The required-field tests occur after the map-end marker in the order `a`, `b`, `s`, `m`. Fields `r` and `t` are optional; their absent sentinels become zero after the final one-bit masks. An already-seen case takes the corresponding duplicate formatter before reading the next value: for example, `s` followed by `sz`, or the reverse, reaches the duplicate branch at `0x3aaefdd`, whose error formatter receives the one-byte field name `s`. This assumes the first field's value reader completed normally. Error template bytes and all ten selected missing/duplicate routes are recorded in `error-paths.tsv`.

The branch model assumes a valid internal map and cursor, abstracts individual value readers as successful, and assumes normal cleanup. It checks all 64 presence masks, 24 same-key or alias duplicate pairs, and all 75,973 distinct-field alias and order combinations. Of the latter, 54,144 reach the conversion call; the others first report the missing field shown in `order-model.tsv`. Among six-field inputs there are 46,080 alias/order combinations. These are model predictions from selected branch tables, not node executions or numeric-conversion success counts.

Case 2 calls the value reader at `0x3aaf030`. Its tag dispatch has four selected arms, 12 through 15; the other 252 byte values enter the type-error branch. A selected arm can still fail: the tag-15 helper result equal to 1 reaches a separate error-sentinel store, and a null allocation result reaches a failure helper followed by `ud2`. The 24-byte record from a successful size reader is assembled as three words in the visitor result, then the outer caller passes that result as the conversion argument at `0x336eb1b`; `size-record-flow.tsv` records the source and destination offsets. Value validation, allocation and destructor helpers are not otherwise modeled.

The visitor's error return writes first word `0x8000000000000000`. The outer guard propagates its error payload and writes byte 2 at output offset `0x16`, without calling the converter. Otherwise, its slot `0x5773898` at `0x336eb1e` resolves to the previously studied conversion `0x3330210`. A returned conversion tag equal to `0x186` selects the success stores; another tag goes through an error helper and writes the same byte 2. On success, the converted eight-byte word is at output offset 0, the `m` word at 8, `a` at 16, and `b`, `r`, `t` at 20, 21, 22. These are observed internal output offsets, not a wire layout.

The existing converter has an edge at `0x33304df` through slot `0x5773848` to `0x3750350`, with mode 0 and exponent 8. The previously established `research/work-items/RE-004-decimal-scaled-u64-94` evidence reports that this downstream mode rejects fractional scaled results, a set negative-sign bit at its check, and values above `0x7ffffffffffffffe`. That result is conditional on reaching the edge; earlier decimal parsing, floating-point formatting and equality gates in the existing converter may reject input too. This packet neither reimplements that converter nor proves which decimal strings pass all its gates. The reference's TWAP field description supports the size label, but its comments are not evidence of binary behavior.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Compiler/linker scope, two-build comparison, normalization masks, helper and data closure, and whole-ELF comparison: not yet measured. No normalization mask or byte transplantation is used here. The byte classifiers and abstract state model are static analysis of the selected target bytes, not captured node execution.

## Results and limitations

- Seven selected FDE ranges, 44 selected byte windows, 12 recorded call edges, 12 recognized byte-string keys, six field cases and ten recorded missing/duplicate error routes; these are selection counts, not whole-node coverage.
- Two bytewise trees are symbolically traversed; one packed-comparison body is decoded under an exact byte guard. The tests also check every one-byte and two-byte key in both bytewise trees, every single-byte substitution of each longer accepted key, 256 numeric-byte inputs, jump-table and instruction corruption, a wrong digest, and invalid file ranges.
- The focused suite has 40 tests with no skips. The generator was run twice under different hash seeds and time zones with no binutils in its executable search path; the 16 generated files matched byte for byte. The abstract field-order counts above are not runtime coverage.
- The sequence visitor, noncovered internal key types, actual upstream wire construction, full numeric-string acceptance, allocation/unwind closure, business-level TWAP validity, other releases and any full component acceptance gate remain open. No progress gate is requested.

Next question: trace the external value producer into these internal key and size tags and establish which decimal strings reach and pass all fixed-eight conversion gates.
