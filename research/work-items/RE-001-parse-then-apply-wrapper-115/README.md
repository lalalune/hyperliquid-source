# RE-001: pin node #115 the parse-then-apply wrapper 0x60c1bb0

Resolves the open unknown left by #4349: the map-parse internal call
site 0x60c1c2e is the parse step of the wrapper 0x60c1bb0, not a separate
routine. The wrapper parses an option string into a temporary stack
unordered_map and then applies it to an options struct.

## What is pinned

1. The wrapper (FDE 0x60c1bb0..0x60c1cc5): builds a 56-byte stack
   unordered_map<string,string> (single bucket, count 0, load factor
   1.0f), parses via 0x60c1190 at 0x60c1c2e, on parse failure copies the
   16-byte Status into *out (message ownership transfers) and destroys
   the map, on success applies via 0x60c18b0 at 0x60c1c92 with the exact
   six-arg forwarding, then destroys the map. The temporary map never
   escapes.
2. The three direct callers and their exact arguments: A 0x5e317a0
   (static map 0x6501d20, empty stack string as arg5, null overflow),
   B 0x5e34160 (static map 0x6501ce0, 32-bit tag as arg5, null overflow,
   input with its first 4 bytes stripped), C 0x60c1d50 (prefix-match
   forwarder, fresh stack map as overflow).
3. The apply loop's overflow rule (0x60c18b0, #4237): unknown keys
   divert into the overflow map via operator[] 0x60c0e90 when it is
   non-null; when null they error with kNotFound "Unrecognized option"
   + key unless the options-base byte +0x00 is nonzero (silent skip).
4. The per-entry arg5 rule (0x60bedc0): arg5 is only null-tested; null
   on the value-parse path gives kNotFound "Could not find option" +
   key. At all three observed call sites arg5 is non-null, so that
   branch is defensive there.

## Evidence

- Whole-function objdump excerpts: the wrapper, the parser (re-shipped
  byte-identical from #4349), the apply loop, the overflow operator[],
  and the three callers.
- `records.json`: semantic records only (no per-instruction lists).
- `callers.tsv`: byte-scan censuses (wrapper 3, parser 6, apply loop 2,
  operator[] 2, forwarder 5); `shared-helper-counts.tsv`: map dtor 484.
- `verify.py`: 10 checks (digest, manifest, excerpt regeneration, FDE
  ranges, 14 raw-binary spot bytes, caller census, literals,
  semantic-only records, model tests). Run it from the repo root.

## Model

`tools/parse_then_apply_wrapper_115.py` models the wrapper, the parser
contract (#4320/#4349), and the apply-loop rules; 16 tests in
`tests/test_parse_then_apply_wrapper_115.py`.

## Open unknowns

- The C++ identity of wrapper arg5.
- The owning classes of the static maps 0x6501ce0 / 0x6501d20.
- The C++ names of callers A/B/C and of C's five callers; caller B's
  32-bit tag and the 0x3b9ac9ff magic.
- The 0x30-byte option-group element's +0x00..+0x18 fields and C++ name
  (from #4337); the .bss string at 0x6508980 (from #4328/#4349).

## Environment limits

No cargo/rustc, no git-lfs, no Ghidra on this VM. `make verify`,
`make test`, and catalogue-check were not run in a tooled environment;
the packet's own `verify.py` and the model tests were run here.
