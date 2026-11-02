# Frozen input-only value protocol

This protocol is for a later host client of the real `src/visor-readiness-value` crate. There is no candidate implementation or client in this pre-code phase. Expected values and semantic provenance never enter that client. The build/comparison harness alone opens `expected.tsv.gz`.

Each UTF-8/ASCII input line is tab-separated and LF-terminated. The first field is an opaque eight-character lowercase hex ID. Remaining fields use exactly these forms:

| Operation | Input fields after ID | Result |
| --- | --- | --- |
| P | `P year ordinal second nano` | Safe parts admission and raw words |
| C | `C seconds nano` | Safe numeric clock-sample admission and raw words |
| D | `D year ordinal second nano` | Parts admission, then fixed60 deadline raw words |
| R | `R source_year source_ordinal source_second source_nano current_year current_ordinal current_second current_nano` | Parts admission of both, then current strictly past source's deadline |

Spaces above are explanatory; actual separators are TAB. Signed year is i32; sample seconds is i64; ordinal is u16; second and parts nano are u32; sample nano is u64. Numeric syntax is canonical decimal: no plus, leading zeros except `0`, whitespace, or `-0`; minus is allowed only for signed fields. Type representability is protocol validity, distinct from the safe value domain. The client must reject unknown operations, wrong field counts, invalid/duplicate IDs, noncanonical numbers, type overflow, invalid text and absent final LF with nonzero exit and no partial successful output. Empty stream may produce empty output.

Each admitted input emits exactly one ordered line:

- `ID\tOK\tpacked_signed32\tsecond_unsigned32\tnano_unsigned32\n`
- `ID\tBOOL\t0\n` or `ID\tBOOL\t1\n`
- `ID\tDOMAIN\n`

`DOMAIN` is the newly chosen safe API refusal, including invalid P/D input, either invalid R timestamp, and rejected C samples. It is not evidence of the native cold path returning a normal error. The client computes its own values through the public crate API; it receives no expected-output path, lookup fixture, semantic category, candidate truth flag or oracle import. `provenance.tsv.gz` maps IDs to explanatory categories for reviewers only.

Comparison requires exact raw output bytes, ordered IDs, value field shape and cardinality. There is no normalization, ignored line, sorted-output comparison or success marker substituted for value results. Both profiles and every compiled semantic mutant must emit their own entire value stream. Comparator controls must reject altered, missing, duplicated, reordered, extra and malformed rows, even if the original process returned zero.
