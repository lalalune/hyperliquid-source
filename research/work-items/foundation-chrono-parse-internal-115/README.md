# foundation: run the node #115 chrono format-item interpreter (parse_internal 0x1620be0) and its setters from bytes against a written rule list

With this packet the item-list interpreter `parse_internal` at 0x1620be0 can be rebuilt from evidence: the seven item tags and their jump table, the twenty numeric kinds with their digit width, sign rule, range and set-once record offset, the name, am/pm, fraction and zone-name items, the error codes (0, 1, 3, 4, 6) and what the parsed-fields record holds after a failure; 14,724 generated item lists and inputs agree with a separately written rule list on result bytes and on all 0xA8 bytes of the record, and 821 of 821 deliberate mistakes are caught.

- Component ID: foundation (chrono `format::parse` code inside the node; sibling of the RFC 2822 parser work)
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: repository main at 0781ce048 (tools/bole_rate115.py evaluator, tools/elf_index.py, tools/fde_extents.py are imported, not copied)
- Claim status: observation (bytes run and compared) plus inference (names and rule list from documented chrono behaviour)
- Scope: included - parse_internal 0x1620be0 with trim_start 0x16288c0, timezone_name_skip 0x1628740, scan_weekday 0x1625100, scan_month 0x1624fb0, scan_long_month 0x1625680, scan_nanosecond 0x1624bc0, scan_nanosecond_fixed 0x1625550, both weekday-number setters 0x1621900 and 0x1621940 and the eighteen field setters 0x1621980..0x1621d50 run as real bytes. Excluded - the time zone offset items (callee 0x1625210), the RFC 2822 item (slot 0x64e1b00) and the RFC 3339 item (slot 0x64e1b30), which are dispatched to other bodies; inputs that are not valid UTF-8; the second caller of the RFC 2822 parser 0x161ffc0; the consumer of the parsed record. No progress gate is requested.

## Reproduce

```
python3 tools/chrono_parse_internal_115.py --out research/work-items/foundation-chrono-parse-internal-115
python3 -m unittest tests.test_chrono_parse_internal_115
sha256sum -c research/work-items/foundation-chrono-parse-internal-115/MANIFEST.sha256
```

Standard library only; imports `bole_rate115` (evaluator and ELF image helpers, which import `elf_index` and `fde_extents`); no binutils; the node is never executed. The tool refuses a binary whose SHA-256 differs. Run time about 260 s with two runs in parallel, peak memory about 380 MB. Regeneration into two folders is byte-identical.

## Evidence

All numbers below are read from file bytes or counted by the tool; nothing is parsed from objdump or readelf output.

- `functions.tsv`: FDE extent, instruction count, conditionals and calls of the 28 bodies that run as real bytes (parse_internal is 2,888 bytes).
- `dispatch-tables.tsv`: the four relative 32 bit jump tables the interpreter indexes - item tag (0x46b188, 7 entries), numeric kind (0x46b204, 20), fixed kind (0x46b1a4, 19) and internal fixed kind (0x46b1f4, 4) - with the handler address of every entry. Space and owned space share one handler; fixed kinds below 4 take the second-level table and the public fixed kinds 4.. are shifted down by four.
- `setters.tsv`: for each of the eighteen setters the record offset of its present flag, found as the first `cmp dword [rdi+disp], 1` (set_hour12 compares one byte with zero). Field offsets: timestamp 0x0 (flag word 8 bytes), year 0x10, year_div_100 0x18, year_mod_100 0x20, isoyear 0x28, isoyear_div_100 0x30, isoyear_mod_100 0x38, month 0x40, week_from_sun 0x48, week_from_mon 0x50, isoweek 0x58, ordinal 0x60, day 0x68, hour_div_12 0x70, hour_mod_12 0x78, minute 0x80, second 0x88, nanosecond 0x90, offset 0x98 (written by the zone items), weekday byte 0xa0 (7 = none).
- `callers.tsv`, `slots.tsv`: call sites and GOT slots found by byte patterns; the interpreter reaches the weekday, month, nanosecond and long-month scanners only through slots 0x64e1b08, 0x64e1b10, 0x64e1b18, 0x64e1b38, 0x64e1b40, the two setter pointers through 0x64e1b20 and 0x64e1b28, and the RFC 2822 and RFC 3339 parsers through 0x64e1b00 and 0x64e1b30.
- `reach.tsv`: how much of each body the cases reach.
- parse_internal: 561 of 690 instructions reached
- trim_start: 93 of 106 instructions reached
- timezone_name_skip: 86 of 106 instructions reached
- scan_weekday: 76 of 86 instructions reached
- scan_month: 84 of 110 instructions reached
- scan_long_month: 65 of 72 instructions reached
- scan_nanosecond: 163 of 183 instructions reached
- scan_nanosecond_fixed: 50 of 84 instructions reached
- set_weekday_from_sunday: 19 of 19 instructions reached
- set_weekday_from_monday: 16 of 16 instructions reached
- set_hour12: 17 of 17 instructions reached
- set_minute: 15 of 15 instructions reached
- set_second: 15 of 15 instructions reached
- set_isoweek: 16 of 16 instructions reached
- set_isoyear: 16 of 16 instructions reached
- set_ordinal: 16 of 16 instructions reached
- set_timestamp: 11 of 11 instructions reached
- set_nanosecond: 13 of 15 instructions reached
- set_year_div_100: 13 of 15 instructions reached
- set_year_mod_100: 13 of 15 instructions reached
- set_week_from_mon: 15 of 15 instructions reached
- set_week_from_sun: 15 of 15 instructions reached
- set_isoyear_div_100: 13 of 15 instructions reached
- set_isoyear_mod_100: 13 of 15 instructions reached
- set_day: 16 of 16 instructions reached
- set_hour: 31 of 31 instructions reached
- set_year: 16 of 16 instructions reached
- set_month: 16 of 16 instructions reached
- `outcomes.tsv`: outcome counts per first item kind; `sample-cases.tsv`: every 900th case with a digest of its result.

Observations that differ from a plain reading of the chrono documentation, taken from the bytes and kept in the rule list: the timestamp item is unsigned in this build (a leading minus gives tag 3, only year and isoyear read a sign, after which the digits are unbounded); set_hour12 maps 12 to 0 and writes only the hour-of-half-day; the literal item compares length first (tag 4) and content second (tag 3); the space items ignore their text and call trim_start; the pad byte of a numeric item is never read.

## Implementation and comparison

`tools/chrono_parse_internal_115.py` holds the rule list (`Spec`, written from chrono's documented behaviour, not from the instruction stream), the case generators and the byte-edit controls. Each case is an item list laid out as 24 byte items in evaluator memory, an input string and optional pre-set fields; the real bytes run, and the 32 byte result area (rest pointer and length, or a null pointer and the error tag) and the 0xA8 byte record are compared with the rule list. The evaluator needed one addition, the register form of `bt` used by the zone name skipper, added in the tool through a decoder wrapper. The record starts with legal Option encodings (flag words zero, garbage in the value words) because set_hour12 tests a flag byte and a garbage flag is not a state the node can reach.

- 14,724 cases (18 named), 0 mismatches.
- 821 negative controls, 821 detected: 785 byte edits (every reached conditional, immediate and displacement of the 28 bodies) killed by a class-picked subset of 2,037 cases, 22 wrong rule lists, 14 structural controls (a flipped file byte, four addresses that are not function starts, slot target checks, a located versus a shifted call site, a shared-handler check on the space tags, an oversized string, an out-of-domain item, a month-versus-minute rule difference). 108 edits changed no result on the subset and are listed in `byte-mutants.tsv` as survivors (not proven equivalent, not counted as controls).
- 26 unit tests, none skipped.

## Results and limitations

`measure.json`: cases 14724, negative_controls 821, negative_detected 821. Limits: the evaluator is a small instruction subset checked only through these cases; cases are generated, not exhaustive; inputs are valid UTF-8 (the slice-boundary panics of the bodies are outside the domain); time zone offset items and the two date-time item parsers are outside the domain; the second caller 0x161ffc0 and the consumer of the parsed record are not reconstructed; no Rust implementation yet. Next question: reconstruct 0x161ffc0 (3,098 bytes) and the timezone_offset callee 0x1625210 under the item kinds excluded here, then the step that turns the record into a timestamp.
