# foundation: reconstruct the node #115 chrono `format::scan` helpers (number, nanosecond, month, weekday, long month, comment, two trims) as executable rules checked against the ELF bytes

This packet lets a reconstruction write the eight chrono scanner helpers that the #115 RFC 2822 / RFC 3339 / strptime paths call as plain Python (and then Rust) rules: digit runs with a min/max width and a signed 64 bit overflow refusal, the fixed-width nanosecond scale `n * 10^(9 - digits)` with a nine digit ceiling, case-insensitive three letter month and weekday matching with their error codes, long month completion, nested and escaped RFC 2822 comments, and the Unicode White_Space trim with and without ':' - and it shows in which spots the bytes differ from a naive reading (the `max == 0` do-while quirk of `number`, the result niche `7` of `short_weekday`, the different error layouts of the bodies, the char-boundary panics, which only raw bytes reach).

- Component ID: foundation (time and quantity conversion helpers; the chrono library as linked into #115)
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: workspace head `0781ce048`; the chrono behaviour is the documented one of `format::scan` (`number`, `nanosecond_fixed`, `short_month0`, `short_weekday`, `short_or_long_month0`, `comment_2822`, `trim_start`, `colon_or_space`), used only as a list of rules to check against bytes. `RE-002-node115-rust-chrono-parse-references` maps references to chrono parse roots; it does not re-implement any body.
- Claim status: observation for everything in Evidence (ELF bytes plus an evaluator that runs them); inference where marked; unresolved where marked
- Scope included and excluded: included are the whole functions `0x161f900`, `0x1625550`, `0x1624fb0`, `0x1625100`, `0x1625680`, `0x1624e80`, `0x16288c0`, `0x1628a40` (every instruction; the unreached ones are listed with reasons), the GOT slot of the `short_month0` call `0x64e1b10`, the white-space map slot `0x64dfc30`, the five panic slots, the power table `0x46b7a0` and the long-month suffix table `0x64050b0`. Excluded: `timezone_offset` `0x1625210` (820 bytes, next question), the callers (`0x1620be0`, `0x1621730`, `0x161fa20`, `0x161ffc0`), and the panic entry points themselves, which are recording stubs. No component gate is requested.

## Reproduce

From the repository root on Linux with Python 3 and the connected `artifacts/node/115/hl-node`. No network, no key, and the binary is never executed.

```sh
python3 tools/chrono_scan_family_115.py --out research/work-items/foundation-chrono-scan-family-115
python3 -m unittest tests.test_chrono_scan_family_115
cd research/work-items/foundation-chrono-scan-family-115 && sha256sum -c MANIFEST.sha256
```

The tool checks the input SHA-256 first, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, runs the bodies in the evaluator of `tools/bole_rate115.py` (imported, not copied; the one thing this tool adds is the overflow flag of `imul`, which the shared evaluator leaves alone and these bodies branch on), calls no external program and parses no objdump or readelf output. It took about 283 s with a peak of 376 MB on this server. Two runs into different folders are byte equal.

Generated files: `measure.json`, `functions.tsv`, `reach.tsv`, `constants.tsv`, `white-space.tsv`, `outcomes.tsv`, `sample-cases.tsv`, `byte-mutants.tsv`, `rule-mutants.tsv`, `structural.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

Coordinates are virtual addresses of the loaded image; file offsets come from the section headers through `tools/elf_index.py`; function ends from the `.eh_frame` FDEs.

Every body was run on generated inputs. The evaluator places the string at a fixed heap address, fills the 32 result bytes with a known pattern, runs the real instruction bytes, and the rule list predicts the exact 32 result bytes (or the two result registers for the trims, or the panic name with its two argument registers). Nothing outside the result area may change and the callee-saved registers and stack must balance.

| function | VA | result layout read from the bytes |
| --- | --- | --- |
| `number(s, min, max)` | `0x161f900` | ok: ptr, len, value (signed 64); error: ptr = 0 and a tag byte at +8 (0 out of range, 3 invalid, 4 too short); an `assert` panic (message length 28) when `min > max` |
| `nanosecond_fixed(s, digits)` | `0x1625550` | same, value `n * 10^(9 - digits)`; `digits > 9` reaches an index panic (index = digits, length 10) after the digits are read |
| `short_month0(s)` | `0x1624fb0` | ok: ptr, len, byte month 0..11 at +0x10; errors as above |
| `short_weekday(s)` | `0x1625100` | ok: ptr, len, byte 0..6 at +0x10 (Monday = 0); error: tag byte at +0 and the niche 7 at +0x10 |
| `short_or_long_month0(s)` | `0x1625680` | calls `short_month0` through slot `0x64e1b10`; then completes the long name from the 12 entry suffix table; mismatch keeps the three letter reading |
| `comment_2822(s)` | `0x1624e80` | calls `trim_start`, requires '(', counts nested parentheses, one byte after '\' is skipped; ok: ptr, len; end of input is "too short" (4), a first byte other than '(' is "invalid" (3) |
| `trim_start(s)` | `0x16288c0` | returns ptr and len in rax:rdx; UTF-8 decoder plus the 256 byte white-space map and three range compares |
| `trim_colon_space(s)` | `0x1628a40` | the same decoder with ':' (0x3a) accepted besides white space |

Run lengths read from the bytes: the power table `0x46b7a0` is `0, 1e8, 1e7, ... , 1` (index 0 is never read: `digits == 0` skips the multiply and yields 0), the suffix table `0x64050b0` holds the twelve long-month tails (`uary`, `ruary`, `ch`, `il`, empty for May, `e`, `y`, `ust`, `tember`, `ober`, `ember`, `ember`); all rows of `constants.tsv` are `match`. The 256 byte white-space map at `0x479266` has 17 non-zero entries (`white-space.tsv`): value 2 at the low bytes 0x00-0x0a, 0x28, 0x29, 0x2f, 0x5f (read for the U+2000 block, so U+2000-U+200A, U+2028, U+2029, U+202F, U+205F) and value 1 at 0x85 and 0xa0 (read for the Latin-1 block); ASCII 9-13 and 0x20 are compared directly, U+1680 and U+3000 are compared as constants.

Reached instructions, by body (`reach.tsv`):

| function | instructions | reached | unreached |
| --- | --- | --- | --- |
| `number` | 81 | 80 | 1 |
| `nanosecond_fixed` | 84 | 65 | 19 |
| `short_month0` | 110 | 110 | 0 |
| `short_weekday` | 86 | 86 | 0 |
| `short_or_long_month0` | 72 | 68 | 4 |
| `comment_2822` | 79 | 74 | 5 |
| `trim_start` | 106 | 105 | 1 |
| `trim_colon_space` | 105 | 102 | 3 |

Unreached instructions are: in `number` the `jne` after `sub` on the slice path (`i < len` always holds there); in `nanosecond_fixed` the non-digit slice error block (the compare `i < digits` is always true inside the loop, so a bad digit is always "invalid"); in `short_or_long_month0` the index panic for a month above 11; in `comment_2822` the arithmetic-overflow and depth underflow panics and the padding; in `trim_start` alignment padding; in `trim_colon_space` the three `jmp` after `cmp 0x20` on decoded multi-byte values (an overlong form decoding to a space, which valid UTF-8 never contains).

## Implementation and comparison

The rule list (`Spec` in the tool) is written from the chrono rules, not from the instruction stream, and uses its own copies of the month, weekday and long-month names, the power of ten, and the Unicode White_Space set. Per body it predicts the output bytes. `Wrong` holds 25 deliberately wrong rule lists (case sensitive month names, Sunday = 0, the signed ceiling replaced by u64, a missing assertion, ASCII-only trimming, comments without escapes or without nesting, and so on).

Inputs are generated from fixed seeds (no randomness, no clock): digit-heavy strings with every kind of terminator including raw continuation bytes (these are not valid `str` and exist to reach the char-boundary panics, which a valid `&str` never reaches), name families that vary every byte value at every position of every month, weekday and long-month name, a sweep of every code point below U+3100 plus a stride over the other planes plus every white space code point aliased into planes 1..16, and comment strings with escapes and nesting. 78 named edge inputs are checked first.

Counts (all in `measure.json`): 89100 cases, 0 disagreements. Cases by body:

| function | cases |
| --- | --- |
| `number` | 6022 |
| `comment_2822` | 6011 |
| `short_month0` | 13223 |
| `short_weekday` | 8382 |
| `nanosecond_fixed` | 4014 |
| `short_or_long_month0` | 13739 |
| `trim_start` | 18855 |
| `trim_colon_space` | 18854 |

Negative controls (373 counted, 373 detected):

- 338 of 375 byte edits of reached conditionals, immediates and displacements are noticed by the case subset (`byte-mutants.tsv`); the other 37 edits are reported as `survived` in that file and are not counted as controls, see Results.
- 25 wrong rule lists, each contradicted by a named first case (`rule-mutants.tsv`).
- 10 structural controls: a flipped byte of the file changes the SHA-256, four addresses that are no function start are refused, two slots that do not hold the claimed target, two results compared with the rule of a neighbouring body, one string larger than the evaluator memory (`structural.tsv`).

## Results and limitations

Observations: all 89100 generated and named inputs give exactly the predicted 32 result bytes, registers or panic. No claim is made for inputs that are not valid UTF-8 beyond the boundary panics, because the real callers pass `&str`.

Findings that a reconstruction needs and that the bytes settle:

- `number` uses an equality exit (`i == max`), so `max == 0` consumes every digit and then cuts at `min(len, 0) = 0`: the rest is the whole input while the value is the parsed number. A Rust `take(max)` model gets this wrong.
- `number` and `nanosecond_fixed` refuse on the signed 64 bit multiply and the signed add separately (out of range, tag 0); `nanosecond_fixed` reads all digits before it looks at `digits > 9`, so 19 digits of 9 give "out of range" and 10 digits give the index panic.
- `short_weekday` has a different error layout from `short_month0`: the tag is a byte at +0 and the result byte at +0x10 is 7; `short_month0` and `short_or_long_month0` write ptr = 0 and the tag at +8.
- The trims compare decoded code points; the high byte of the code point selects one of three ranges (U+16xx, U+20xx, U+30xx) and the Latin-1 and U+20xx blocks read different bits of the same map; every one of 0x00-0x30ff plus the planes is covered.

Limits and survivors: 37 of the 375 byte edits are not noticed by the case subset used for the edit controls (`byte-mutants.tsv`, verdict `survived`). They are listed, not explained one by one, and they are not counted as negative controls: they sit in the letter chain of the long-month compare, in two immediates of `comment_2822` (the arithmetic-overflow guard compare and the state constant of the escape arm, both with no observable effect on any reachable input) and in the multi-byte decoder constants of the two trims. Some of those may be equivalent edits (for example a compare against `0x80` that is white space under neither value) and some may be gaps of the chosen subset; this packet does not tell which. The full case streams hit every reachable branch (`reach.tsv`). `timezone_offset` is not covered. The panic stubs record only their register arguments; the real unwinding is out of scope. No component gate is requested.

Next question: `timezone_offset` `0x1625210` (820 bytes, calls `number`) and the caller `parse_rfc3339_relaxed` `0x1621730` that threads the results of these helpers.
