# foundation: chrono timezone_offset, timezone_offset_2822 and the relaxed date-time tail parser, run from node #115 bytes against written rules

- Component ID: foundation (chrono `format::scan` / `format::parse` third-party code inside the node; consumer components: l1-shared, action-wire)
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository base `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no reference source is copied (the chrono names come from the merged RE-002 reference packets, listed below as hypotheses to check)
- Claim status: observation for every table of bytes and every comparison count; inference for the chrono names and for the rule list being "the documented behaviour"
- Scope included and excluded: included - three bodies run from file bytes, `timezone_offset` 0x1625210 (820 bytes), `timezone_offset_2822` 0x1625790 (1,358 bytes, jump table over the first letter) and the date-time tail parser 0x1621730 (458 bytes), plus the two scanners they call, trim_start 0x16288c0 and the colon-or-space trim 0x1628a40. Excluded - the large `parse_internal` body 0x1620be0 (a recording stub here), the other callers of the zone scanners (0x161fa20, 0x161ffc0, 0x1620be0), and every gate in docs/PROGRESS.md (no gate is requested).

With this packet a Rust reconstruction can write the three functions from a checked rule list instead of from guesses: how a numeric offset or a zone name becomes seconds (sign, hour and minute ranges, the unicode minus flag, the colon/space trim, the missing-minutes flag), which error tag each failure returns (0 out of range, 1 impossible, 3 invalid, 4 too short), where a char-boundary panic is raised, how the date-time tail merges its offset into the parsed state, and which item lists the wrapper hands to `parse_internal`. 78383 generated and named inputs were run through the real bytes and agreed with the rule list on the 32 result bytes (or the panic) every time, 398 negative controls were all detected.

## Reproduce

Working directory: the repository root, platform Linux x86-64, Python 3 standard library only, the tool reads the connected node #115 binary and refuses any other SHA-256 first. It does not run the binary, call objdump or readelf, or use the network.

```
python3 tools/chrono_tz_offset_115.py --out research/work-items/foundation-chrono-timezone-offset-115
python3 -m unittest tests.test_chrono_tz_offset_115
sha256sum -c research/work-items/foundation-chrono-timezone-offset-115/MANIFEST.sha256
```

The generation is deterministic (no clock, no random source, no absolute path in any output) and two runs into different folders are byte-identical. Peak memory is under 1 GB; cases are made, run and compared one at a time and only counts are kept.

## Evidence

All coordinates are virtual addresses of the node #115 ELF; every number below is produced by the tool from file bytes (section headers, `.eh_frame` FDE extents through the shared parsers, `.rela.dyn` RELATIVE addends, and fixed byte patterns for direct calls).

- `functions.tsv` - exact FDE extents, instruction and conditional counts of the five bodies that are run (`timezone_offset` 820 bytes, `datetime_tail` 458, `timezone_offset_2822` 1,358, `trim_start` 382, `trim_colon_space` 380).
- `callers.tsv` - every direct `call` (E8) in `.text` to the parse_internal body, the two trims and the three subject functions, with the owner FDE of each call site. `timezone_offset` has five callers: 0x161ffc0 (three sites), 0x1620be0 and the date-time tail 0x1621730.
- `call-flags.tsv` - the constants loaded into rcx, r8 and r9 before each of those five calls (allow_zulu, allow_missing_minutes, allow_minus_sign): the tail uses 1/0/1, the three sites in 0x161ffc0 use 0/0/1, 1/0/1 and 1/1/1, the site in 0x1620be0 uses 1/0/1.
- `items.tsv` - the two 24-byte-per-entry item lists the tail passes to parse_internal as (begin, end) pointers (DATE 0x6404588..0x6404630, seven entries; TIME 0x6404648..0x6404720, nine entries), decoded with the RELATIVE addends of the literal pointers: numeric(kind 0), space, "-", numeric(kind 6), space, "-", numeric(kind 7) and numeric(14), space, ":", numeric(16), space, ":", numeric(17), fixed(10), space.
- `reach.tsv` - how many instructions of each body the cases reached (timezone_offset 228/233 reached; datetime_tail 118/118 reached; timezone_offset_2822 366/376 reached; trim_start 88/106 reached; trim_colon_space 89/105 reached); the unreached rest are listed by address (for example the error return that needs a null pointer from the colon trim).
- `outcomes.tsv` - cases per function and outcome class (the counts below).
- `sample-cases.tsv` - every 600th case with its outcome class and a result digest; `rule-mutants.tsv`, `byte-mutants.tsv`, `structural.tsv` - the negative controls; `measure.json` - the counts the checker reads.

Observed rules (each is a row of the written rule list and is checked against every case):

- `timezone_offset(out, s, len, allow_zulu, allow_missing_minutes, allow_minus_sign)`: with the zulu flag and a first byte of `Z` or `z` it returns the rest after one byte and offset 0; otherwise an empty input is "too short", the first scalar must be `+`, `-` or (only with the minus flag) U+2212; two ASCII digits give the hours (0-99, no range check); the rest goes through the colon-or-space trim (white space of the Unicode set and `:`); two minute digits whose first digit is 0-5 are accepted, 6-9 followed by a digit is "out of range", anything else "invalid"; fewer than two bytes left is "too short" unless the missing-minutes flag is set and nothing is left. The result is hours*3600 + minutes*60, negated for `-` and U+2212, written as an i32 at +0x10 next to the rest pointer and length. An error writes a null pointer and one tag byte at +8 only.
- `timezone_offset_2822(out, s, len)`: an ASCII letter run is a zone word - length 1: `Z` and the military letters A-I, K-Y (all offset 0, `J` is invalid), length 2: `UT`, length 3: GMT (0) and the eight US names through a first-letter jump table (EST/EDT -5/-4 h, CST/CDT -6/-5 h, MST/MDT -7/-6 h, PST/PDT -8/-7 h), any other word "invalid"; with no letter the form is `+hhmm` or `-hhmm` without colon, the same minute range rules, and U+2212 is not accepted.
- `datetime_tail(out, parsed, s, len)`: parse_internal over the DATE list, then one of `T`, `t` or space, then parse_internal over the TIME list, trim_start, then either the word `utc` in any case (offset 0) or `timezone_offset` with flags 1/0/1; the offset is merged into the parsed state: if the u32 at parsed+0x98 equals 1 the i32 at +0x9c must equal the offset, otherwise the result is tag 1 (impossible); if it is not 1 the state is set to (1, offset). Errors of the stubbed calls are passed through unchanged, nothing after the date is "too short" (4), a wrong separator is "invalid" (3).
- A char-boundary panic is raised in every place the bytes slice `&s[n..]`: the panic arguments (start, length) are compared too. The inputs are well-formed text, plus single stray continuation bytes that are placed only on the byte the body checks (a `&str` cannot carry them; they probe the byte-level check).

## Implementation and comparison

`tools/chrono_tz_offset_115.py` holds (1) the rule list `Spec` written from the observations above and from the documented chrono behaviour, which is a different code path from the bytes; (2) the evaluator harness built on the shared x86-64 evaluator `tools/bole_rate115.py` (imul overflow flags added in a subclass), with the five panic entry points as raising stubs, the white-space map slot as its RELATIVE addend, and `parse_internal` as a recording stub whose result each case chooses; (3) the generators; (4) the controls.

Cases: 78383 (81 named cases, 78302 generated). Per function: timezone_offset - err-0=6124, err-3=22977, err-4=285, ok-negative=6250, ok-positive=3498, ok-zero=463, panic-slice=1178; timezone_offset_2822 - err-0=2084, err-3=22957, err-4=234, ok-negative=1670, ok-positive=1515, ok-zero=581, panic-slice=118; datetime_tail - err-0=379, err-1=643, err-2=2, err-3=3974, err-4=1035, err-5=2, err-6=2, ok-merged=1758, panic-slice=654. Generators: seeded LCG streams of offset strings (leads, hours, separators, minutes, tails), the full hour x minute grid for three signs and all eight flag combinations, every first scalar below U+3100 plus a stride over all planes, every byte value at every position of four full offset strings, all 17,576 three-letter words and all two- and one-letter words in both cases, names behind tails, the numeric grid of the zone scanner, and tail strings built from date, separator, time and offset pieces with every stub result (tags 0-6, consumed lengths 0 and beyond the window) against every parsed-state word.

Negative controls: 398 controls, 398 detected - 356 byte edits of reached conditionals, immediates and displacements of the three subject bodies are noticed by a class-picked subset of the cases (95 edits are equivalent and listed as survived, not counted), 31 wrong rule lists (each differs by one mistake: ignored flags, swapped zone hours, GMT skipped, sign lost, hours scaled, unicode minus accepted, four-letter words accepted, merge ignored, wrong item list in the stub window, and others) and 11 structural controls (flipped file byte changes the SHA-256, non-function addresses refused, wrong call site, an oversized string refused by the evaluator, swapped log entries).

## Results and limitations

- Cases 78383, mismatches 0, negative controls 398, detected 398 (`measure.json`). Tests: `python3 -m unittest tests.test_chrono_tz_offset_115` - 35 tests.
- Not shown: that the rule list is the published chrono function (the names come from the merged RE-002 reference packets for 0x1625210, 0x1625790 and 0x1621730; this packet checks behaviour of the bytes, not source identity); the behaviour of `parse_internal` 0x1620be0 (stubbed), the three callers of timezone_offset in 0x161ffc0 / 0x1620be0 and the RFC 2822 date parser 0x161fa20 that calls the zone scanner; any input that is not text (the bytes decode lead characters without checking the following ones, so only the whole-character leads are claimed).
- No gate is requested; foundation stays unreached as a whole.
- Next question: run the RFC 2822 date parser 0x161fa20 (1,425 bytes, nine trim_start calls, number, comment and weekday scanners) the same way with these two zone bodies real, then the three callers inside 0x161ffc0.
