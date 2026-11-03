# RE-001: map node #115 decimal-keyed group sum 0x5eee310 with its parser 0x61d0df0

Task: RE-001 (#115 function map). Bounded question: what does the
getter-shaped function at 0x5eee310 compute end to end, given that it
is a second consumer of the decimal parser at 0x61d0df0 mapped by
#2301, but sums a field over key-matching elements instead of
formatting one group's count? This item maps the caller whole plus
its parser callee whole — one complete behavior, not a fragment:
parse a decimal key, validate it, sum one field over the elements
whose key byte matches, and format the sum into the output string.

Artifact binding: every result below is bound to node #115, provenance
record `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
materialized locally as `work/hl-node-115.bin` (hash verified exactly
before use). The packet's JSON (`records.json`) holds semantic records
only: window identities, branch site→target pairs, census results, and
by-contract callee notes. Instruction-level detail lives only in the
verbatim whole-function disassembly excerpts in this directory,
exported with the commands below. Mnemonics such as `endbr64` in
those excerpts are genuine instructions present in the target binary,
not placeholders: each excerpt regenerates byte-for-byte from a fresh
objdump run (see `verify.py`), and sampled instructions were checked
byte-for-byte against both a fresh objdump run and the raw binary.

## Windows (whole functions)

- Caller, 0x5eee310..0x5eee421 (273 bytes; FDE .eh_frame offset
  0x357850, length 0x30, CIE 0, no LSDA). Args: rdi = outer,
  rsi = output string object, rdx = view pointer, rcx = view length.
  Returns 1 on success, 0 on any failure; the stack canary is checked
  before the normal return and a failure calls `__stack_chk_fail`.
- Parser, 0x61d0df0..0x61d0e87 (151 bytes; FDE offset 0x377a78,
  length 0x10, CIE 0, no LSDA). Args: rdi = pointer to a {cursor,
  remaining} view struct (updated in place as digits are consumed),
  rsi = pointer to the output u64 slot. Returns 1 when at least one
  digit was consumed and no overflow occurred, else 0.

## Semantics, stated literally

```
parse_decimal_u64(view, *out):
  if view.remaining == 0: *out = 0; return 0
  value = 0; digits = 0
  while view.remaining > 0 and *view.cursor is '0'..'9':
    d = *view.cursor - 0x30
    if value > 0x1999999999999999: return 0          # *out unwritten
    if value == 0x1999999999999999 and d > 5: return 0  # *out unwritten
    value = value * 10 + d; digits += 1
    view.cursor += 1; view.remaining -= 1
  *out = value
  return 1 if digits > 0 else 0

keyed_sum(outer, out_string, view_ptr, view_len):
  member = [outer + 0x788]
  sub = [member + 0x30]
  view = {ptr = view_ptr, len = view_len}
  if parse_decimal_u64(&view, &key) == 0: return 0
  if view.len != 0: return 0                     # trailing garbage
  count = (int32)[sub + 0x50]
  total = 0
  if count > 0:
    base = [sub + 0xad8]
    for entry in base[0 .. count):               # 24-byte entries
      for p in [[entry], [entry + 0x8]):         # 8-byte pointers
        element = [p]
        if (uint8)[element + 0xb7] == key:       # byte vs full u64
          total += [element + 0x10]              # 64-bit wrapping
  temp = format_u64(total)                       # helper 0x5d4f970
  out_string.assign(temp)                        # helper 0x5eebb20
  return 1
```

Notes on the observed code, all verifiable in the excerpts:

- The parser's overflow guard is exact u64 arithmetic:
  0x1999999999999999 is (2**64 - 1) // 10 and 5 is the largest final
  digit of 2**64 - 1, so "18446744073709551615" parses and
  "18446744073709551616" fails. Leading zeros are accepted; no sign,
  whitespace, or other prefix is accepted.
- The key comparison is a zero-extended byte against the full parsed
  u64 (`movzbl 0xb7(%rdx),%ecx; cmp %rdi,%rcx`), so a parsed key
  above 255 matches nothing yet still succeeds and formats "0".
  The group loop is bounded by the signed 32-bit count: a
  non-positive count skips the loop entirely and formats "0".
- The third qword of each 24-byte group entry is never read, as in
  the aggregate sums mapped by #2268/#2279; the entry's first two
  qwords are the element-pointer range [begin, end).
- The output string is assigned in full from the formatted temporary
  (helper 0x5eebb20, the same assign helper used by #2301's
  formatter), so a failed call leaves the string untouched and a
  successful call leaves exactly the decimal sum. The temporary's
  heap buffer is freed only when it is not the small-string buffer,
  matching the usual SSO check in the excerpt.

## Census (whole-file scan, see census.py)

- Caller 0x5eee310: 0 direct calls, 0 tail jumps, 0 qword hits, 0
  RELATIVE addends — virtual-getter shape, as in #2228/#2229/#2263/
  #2264/#2265/#2268/#2279/#2293/#2295/#2296/#2298/#2299/#2301.
- Parser 0x61d0df0: exactly 10 direct calls — this caller's site at
  0x5eee343 plus the 9 other sites recorded by #2301 (sites only,
  not claimed; the parser is shared and only this caller's use is
  modelled here). 0 tail jumps, 0 qword hits, 0 RELATIVE addends.

## Left by contract, stated openly

- The other 8 direct call sites of the parser besides this one and
  #2301's are not read; their callers' contracts may differ.
- The integer formatter at 0x5d4f970 (digit-count dispatch, observed
  head only) and the string assign helper at 0x5eebb20 are used only
  through their observed signatures: (temp_string, u64) and
  (out_string, temp_string). Their internals are not modelled.
- The element type is not identified: only the +0xb7 key byte and
  the +0x10 summed field are claimed.
- The outer class is not claimed; the member at [outer + 0x788] and
  its +0x30 sub-object are modelled as opaque field paths.

## Excerpt export commands

Run from the repository root:

```
objdump -d --start-address=0x5eee310 --stop-address=0x5eee421 work/hl-node-115.bin
objdump -d --start-address=0x61d0df0 --stop-address=0x61d0e87 work/hl-node-115.bin
```

`export_excerpts.py` in this directory runs both commands and writes
the two excerpt files; `verify.py` re-runs them and requires a
byte-for-byte match, plus the digest, manifest, frame, census, sampled
instruction-byte, and model-test checks.

## Environment limits, stated honestly

This VM has no cargo/rustc, no git-lfs, and no Ghidra/Java, so no Rust
reconstruction is attempted; the model is Python only, as in the
prior #115 items. `make doctor` fails on missing providers and
`make verify` / `make catalogue-check` fail on the LFS-pointer
artifact here (both pre-existing); this packet binds instead to the
materialized `work/hl-node-115.bin`, whose hash matches provenance
exactly. No pytest is installed, so the pytest-style test file runs
under plain python3 via its `__main__` runner.
