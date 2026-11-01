# RE-009: nonempty EVM snapshot block-hash JSON rows

The node 94 JSON path writes each nonempty `block_hashes` entry as a two-item sequence with separately formatted 32-byte values, and its reader uses two distinct item adapters, a radix-aware first-value parser, and a 32-element byte-sequence alternative, giving a reconstruction concrete row structure and size decisions that were previously unresolved.

- Component ID: RE-009, storage and state snapshots.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`; unlicensed inferred reference `999556f6e0a474b8312db96ec3149e1c44e97c23`, used for leads only.
- Claim status: selected byte and branch observations; value roles and JSON interpretation are inferences. Full input language and runtime persistence remain unresolved.
- Scope included and excluded: selected JSON field's nonempty row writer and corresponding row reader, fixed 32-byte output and adapter decisions. Excludes the enclosing functions' analysis, general JSON tokenization, the shared hexadecimal decoder's implementation, ordering and duplicate-key semantics, MessagePack rows, runtime execution and other releases.

## Reproduce

From the repository root, using Python 3.12.3 and the standard library, with the repository's `tools/elf_index.py` and `tools/fde_extents.py`:

```sh
python3 tools/artifacts.py verify
python3 tools/evm_hash_json94.py --out research/work-items/RE-009-evm-hash-json-94
python3 -m unittest tests.test_evm_hash_json94
(cd research/work-items/RE-009-evm-hash-json-94 && sha256sum -c MANIFEST.sha256)
```

The generator verifies the complete binary digest, then reads sections and CIE/FDE records with the repository parsers, checks that selected FDEs are indexed, rejects NOBITS and ranges outside a single file-backed section, and verifies selected byte windows and relative control transfers. The only generated evidence file is `records.json`. It never runs the binary or invokes an external program. GNU objdump 2.42 was used only for manual instruction inspection; its text is not a generator input. All addresses here are linked ELF virtual addresses and FDE ends are exclusive. An FDE extent alone does not prove a complete function boundary or exclude split cold code.

## Evidence

Earlier `RE-009-evm-state-wire-94` established the enclosing writer's field label, the placeholder, and the empty case; it explicitly left nonempty rows open. The connecting call at `0x2206cb7` passes the field at input `+0x1b20` to `0x25e3020`. The previously studied JSON reader's selected field route calls `0x2620800` at `0x1cc7f6e`. These are contextual call sites; this packet does not analyse their enclosing functions again. The new selected extents and body hashes are in `records.json`.

| Stage | FDE extent | Selected observations |
| --- | --- | --- |
| Collect and dispatch | `0x25e3020..0x25e30e6` | Empty and nonempty source setup converge on a collector, then the row writer. The returned collection is freed after the writer returns. |
| Outer JSON and row writer | `0x291d140..0x291d75a` | Writes `[` and `]`; nonempty traversal advances by `0x10`, loading row pointers at offsets `0` and `8`. For each row it writes a nested `[`, calls the first item writer, emits a separator and calls the second item writer, then closes the row. |
| First item | `0x28fac00..0x28fb0be`, `0x21b7410..0x21b7473` | Checks input bytes from offset `0x1f` downward for the first nonzero byte, formats that byte, and walks toward offset zero. The all-zero branch writes the quoted literal `0x0`; the nonzero path uses separate first and later formatting templates. The byte formatter indexes the lowercase hex alphabet. The generator enumerates the 31 nonzero-displacement compares, verifies all 28 lower-offset nonzero branch targets, and separately checks the offset-zero compare. |
| Second item | `0x2806390..0x28064d4`, `0x1f69970..0x1f69aaf` | Prefix `0x` and 32 input bytes become 64 lowercase hex characters in input order; `0x42` bytes are enclosed in quotes. The scalar path indexes the captured alphabet, and the selected vector path masks nibbles, shuffles through the same alphabet and interleaves high and low nibbles. |
| Outer and row reader | `0x2620800..0x262114e`, `0x26a2860..0x26a2a14`, `0x1b7e660..0x1b7ea18` | The selected array route calls the collector, whose loop calls the row reader. That reader expects an opening `[` on the selected route, calls the first and second item adapters in order and then invokes a closing-container helper. |
| Item adapters | `0x1b6c990..0x1b6cb08`, `0x1b9d1a0..0x1b9d317` | A `]` produces a no-item result, while a present value is delegated to distinct first and second item readers. The row reader sends missing first and second values to separate error construction routes with arguments 0 and 1. |
| First value numeric string | `0x28fbe50..0x28fc41d`, `0x28f7cd0..0x28f7f28`, `0x28317c0..0x28318b2` | On the selected quoted-string route the first item reader compares the three bytes `0x0` and takes a special four-word zero result; other selected strings reach the radix parser. Subject to its length and string preconditions, prefixes `0x`/`0X`, `0o`/`0O`, and `0b`/`0B` select 16, 8, and 2, with 10 as the fallback. A digit greater than or equal to the selected radix takes an error route; four 64-bit multiply-and-carry stages also branch to an error if the top carry is nonzero. |
| Second value array alternative | `0x280aae0..0x280ac27`, `0x1b7a6b0..0x1b7a81d`, `0x1bab430..0x1bab5ae` | The `[` dispatch enters a loop that stores 32 byte results, then probes once more. An early end reports the number read; an extra value selects a distinct error with argument 33. The numeric-byte reader checks selected numeric result arms against 256 before storing one byte. |
| Second value decode adapters | `0x2807e70..0x28084cb`, `0x280fe20..0x280fe8b`, `0x28839f0..0x2883a5e` | On the selected quoted-input route, two string representation cases call distinct adapters. Each passes `0x20` as the output length to a shared indirect helper; result tag 3 selects a 32-byte copy, other tags select error construction. |

The output's exact 32-byte second-value rule is conditional on the selected successful paths. For example, a 32-byte input containing `00` through `1f` produces the quoted text `"0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"`; this is a model of the pinned scalar operations, not a captured snapshot or a target execution. The vector instructions support the same nibble ordering for the selected 32-byte case. The first template has literal `0x` followed by tag `0xc0`; the later-byte template has tag `0xc3`, option word `0x69000020`, and a little-endian quantity of 2. The field interpretation follows the existing `RE-001-format-request-controller-94` evidence. The first item's precise nonzero padding depends on downstream formatter behavior, which this packet does not reanalyse or claim to have established.

For the selected array alternative, fewer than 32 present byte results reach the short-length error, and a 33rd present result reaches the extra-length error. These statements are conditional on the item reader returning successful results; they do not cover every malformed token.

The writer tests an outer count of zero before the row loop. Its depth counter has distinct overflow and underflow error routes; a nonzero second-item return leaves the row writer before the normal completion join. In the reader, an unexpected character in the row-opening position goes to an error helper; end-of-input and separator checks have separate branches. A row with zero or one item reaches the missing-item routes after the corresponding item adapter reports no value. These are conditional local control-flow observations, not a complete error-precedence claim or proof of behavior for arbitrary malformed input.

Inference: the 16-byte entries contain pointers to a 32-byte integer-like key and a 32-byte hash-like value, and the descending-byte first formatter suggests little-endian numeric storage. The field label and preceding call supply the `block_hashes` connection. The field's precise source type, collection traversal order, format descriptor padding, and reader acceptance of all alternate strings remain unproven.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Compiled comparison, normalization masks, helper and indirect-call closure, actual checkpoint fixtures and target execution: not yet measured. The binary is the only input fixture. The fourteen focused unittest methods check the selected FDE identities, 21 calls, 43 conditional branches, eight RIP-relative references, 256 scalar nibble pairs, four-word multiplication against an independent Python integer oracle at boundary inputs, wrong digest, modified instruction, invalid call and branch opcodes, unmapped and crossing-section ranges, NOBITS, and ambiguous mappings. The limb-step model covers only the selected multiply/add chain and is checked against unbounded integer arithmetic; it is not a complete parser or target execution. These are extraction controls, not target-runtime tests.

## Results and limitations

The generated record contains 20 FDE-described extents, 53 selected byte windows, 31 byte-scan compare sites with 28 selected branch targets, 21 relative calls, 43 separately selected conditional branches, two array dispatch entries, eight RIP-relative references, two indirect-slot references and seven selected literals. This is a bounded path, not a function-coverage denominator. The reader's indirect 32-byte helper is only identified by its call slot and return convention; its full accepted alphabet, prefix rules and errors are not recovered here. The nonzero first item's exact rendering, the complete numeric string grammar and error precedence, other JSON representations, malformed nested values, row ordering, duplicates, MessagePack encoding, actual disk publication and cross-version compatibility remain open. No full-scope milestone gate is requested.

Next question: trace the two nonzero key formatting templates and the shared 32-byte decode helper in a non-overlapping analysis, then compare complete synthetic records in a separately authorized offline harness.
