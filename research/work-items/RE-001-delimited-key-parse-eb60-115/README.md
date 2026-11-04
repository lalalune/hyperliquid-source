# RE-001: delimited key parse 0x606eb60 (node #115)

## Bounded question

What does the routine at `0x606eb60` compute from an input string and a
bound, and what record does it return?

## Answer

The routine parses a `#`-delimited versioned key. It takes three
arguments: an out-record pointer (`rdi`), a pointer to an input
`std::string` (`rsi`), and a bound (`rdx`, a minimum accepted sequence,
compared unsigned). It returns the out-record pointer.

The out record is 0x20 bytes: a `u64` sequence at `+0x00` and a
`std::string` key at `+0x08` (pointer `+0x08`, size `+0x10`, inline buffer
`+0x18`).

In order:

1. The input string is copied verbatim. The routine calls helper
   `0x61c7e30` with flag 0, whose flag-0 path is a plain whole-content
   copy (see `records.json`); the flag-nonzero transform path is never
   taken here and is not claimed.
2. The first `#` is located with `std::string::find` on the copy, using
   the literal at `0x4393ae` (`"#"`).
3. No `#` found: the sequence is set to `0xffffffffffffffff`, the key is
   left empty, and the routine returns.
4. Otherwise the prefix (input bytes before the first `#`) is parsed by
   helper `0x61d1540`, a decimal parser built on `strtoull`:
   - leading whitespace skipping and an optional `+`/`-` sign apply;
     a leading `-` wraps modulo 2^64;
   - no digits at all throws `invalid_argument` with the `stoull`
     message at `0x434345`;
   - a `strtoull` overflow (`ERANGE`) throws `out_of_range` with the
     same message;
   - the single character right after the consumed digits may be a
     suffix letter, case-insensitive: `K` shifts left by 10, `M` by 20,
     `G` by 30, `T` by 40 (64-bit shift, bits shifted out are lost);
   - any other next character, and any content after the suffix
     character, is ignored: the parser returns the value as computed.
5. Bound gate: if the parsed value is below the bound (unsigned), the
   sequence is set to `0xffffffffffffffff`, the key is left empty, and
   the routine returns.
6. Otherwise the sequence is the parsed value and the key is the input
   suffix after the `#` (empty when `#` is the last byte). The suffix
   extraction carries the `std::string::substr` out-of-range check
   (format at `0x958cf8`, name at `0x43e542`); that check cannot trigger
   from this routine's own find result, because a found position is
   always below the size, and is recorded as observed, not as a
   reachable path.

## Callers (the consumer end)

The routine has exactly two direct call sites, both in the flag-nonzero
insert routine `0x606ef50..0x606f91f` (sites `0x606f07c` and `0x606f1bd`),
which pass a caller stack record, a caller stack string, and the
caller's second argument as the bound. There are no tail jumps to it,
no stored qwords equal to its address, and no `R_X86_64_RELATIVE`
slots for it (see `census.py` output reproduced by `verify.py`).

## Evidence

- `main.txt`: the whole routine body, `0x606eb60..0x606eeac` (the FDE
  range), verbatim as `objdump` emitted it, including the four
  landing-pad stubs at `0x606ee73`, `0x606ee7f`, `0x606ee94` and
  `0x606eea0` that jump to the cleanup fragment. Instruction-level
  detail lives only in these excerpt texts, not in `records.json`.
- `cleanup.txt`: the exception-cleanup fragment at
  `0x606eb0c..0x606eb5a` (its own FDE), which the landing-pad stubs jump
  to. Its four entries dispose the stack strings that are live at each
  throw point and then resume unwinding; it never writes the out
  record. It is emitted ahead of the routine, not inside the FDE
  range, and is included so the exception path is visible in full.
- `frames.txt`: the routine FDE line, the cleanup-fragment FDE line,
  and the caller FDE line, from a fresh `readelf --debug-dump=frames`
  run.
- `relocations.txt`: empty — no `R_X86_64_RELATIVE` record mentions
  this routine.
- `callers.tsv`: both call sites with their caller FDE range.
- `records.json`: semantic records only — branch sites, the bound
  gate, the parser's suffix table, the string constants, the census,
  and the non-claims. It holds no per-instruction mnemonic list.
- `verify.py`: re-checks the artifact digest, the provenance entry,
  the manifest, byte-for-byte regeneration of both excerpts from a
  fresh `objdump` run, every excerpt instruction byte-for-byte against
  the raw binary, the FDE ranges, the empty relocation record, the
  census, the string constants, the records, and the model tests.
- `export_excerpts.py`: regenerates `main.txt` and `cleanup.txt`.
- `census.py`: reproduces the caller census above.

The artifact is `work/hl-node-115.bin`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
bound in `provenance/artifacts.json` (entry `artifacts/node/115/hl-node`).

## Model and tests

`tools/delimited_key_parse_eb60_115.py` models the routine end to end:
input string and bound in, `(sequence, key)` record out, with the
sentinel `0xffffffffffffffff` for the reject paths and the parser's
throws for the invalid/overflowing prefixes.
`tests/test_delimited_key_parse_eb60_115.py` covers the no-separator
and reject paths, the bound equality boundary, all four suffix letters
in both cases, trailing content after the suffix character, non-suffix
trailing characters, empty and non-numeric prefixes, overflow,
whitespace and sign handling, empty and multi-`#` suffixes, and input
guards.

## Not claimed

- What the caller `0x606ef50` does with the returned record beyond
  passing the arguments recorded above.
- What the bound denotes to the caller beyond the unsigned comparison.
- The purpose of the record's key or sequence in any wider subsystem.
- Behavior on dangling or null pointers (the model raises on null
  input, stated openly).
- The flag-nonzero path of helper `0x61c7e30`, which this routine
  never takes.

## Next step

The caller `0x606ef50` itself: the flag-nonzero insert routine that
consumes this parse twice. Its formatted-key construction and the
tree insert around these two parse calls remain unmapped.

## Commands

```sh
objdump -d --start-address=0x606eb60 --stop-address=0x606eeac work/hl-node-115.bin
objdump -d --start-address=0x606eb0c --stop-address=0x606eb5a work/hl-node-115.bin
python3 research/work-items/RE-001-delimited-key-parse-eb60-115/verify.py
python3 -m pytest tests/test_delimited_key_parse_eb60_115.py -q
```

Note on mnemonics: instruction names such as `endbr64` in the excerpts
are genuine instructions present in the target binary, emitted verbatim
by `objdump`, not placeholders.
