# RE-001: map node #115 decimal-index group-count formatter 0x5eeb9c0 with its parser 0x61d0df0

Task: RE-001 (#115 function map). Bounded question: what does the
getter-shaped function at 0x5eeb9c0 compute end to end, given that it
reads the same outer member at [outer + 0x788] as the getters mapped
by #2293/#2295/#2296/#2298/#2299 but dispatches on a decimal text view
instead of returning a field? This item maps the caller whole plus its
decimal parser callee whole — one complete behavior, not a fragment:
parse a decimal index, validate it, and format one group's element
count into the output string.

Artifact binding: every result below is bound to node #115, provenance
record `artifacts/node/115/hl-node`, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
materialized locally as `work/hl-node-115.bin` (hash verified exactly
before use). The packet's JSON (`records.json`) holds semantic records
only: window identities, branch site→target pairs, census results, the
rodata format record, and by-contract callee notes. Instruction-level
detail lives only in the verbatim whole-function disassembly excerpts
in this directory, exported with the commands below. Mnemonics such as
`endbr64` in those excerpts are genuine instructions present in the
target binary, not placeholders: each excerpt regenerates byte-for-byte
from a fresh objdump run (see `verify.py`), and sampled instructions
were checked byte-for-byte against both a fresh objdump run and the
raw binary.

## Windows (whole functions)

- Caller, 0x5eeb9c0..0x5eebab6 (246 bytes; FDE .eh_frame offset
  0x3571ec, length 0x38, CIE 0, no LSDA). Args: rdi = outer,
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

formatter(outer, out_string, view_ptr, view_len):
  member = [outer + 0x788]
  sub = [member + 0x30]
  view = {ptr = view_ptr, len = view_len}
  if parse_decimal_u64(&view, &index) == 0: return 0
  if view.len != 0: return 0                     # trailing garbage
  index32 = (int32)index
  bound = (int32)[outer + 0x778]
  if index32 >= bound: return 0
  base = [sub + 0xad8]
  entry = base + index32 * 24                    # 24-byte entries
  count = ([entry + 0x8] - [entry]) >> 3         # arithmetic shift
  snprintf(buf[100], "%d", count)                # format at 0x4464ad
  out_string.replace(0, out_string.size, buf, strlen(buf))
  return 1
```

Notes on the observed code, all verifiable in the excerpts:

- The parser's overflow guard is exact u64 arithmetic:
  0x1999999999999999 is (2**64 - 1) // 10 and 5 is the largest final
  digit of 2**64 - 1, so "18446744073709551615" parses and
  "18446744073709551616" fails. Leading zeros are accepted; no sign,
  whitespace, or other prefix is accepted.
- The caller compares only the low 32 bits of the parsed value against
  the bound (`cmp 0x778(%rbp),%eax`, signed `jl`), and sign-extends
  that 32-bit value for the group index. A parsed value whose low 32
  bits are negative (e.g. 2147483648) would index before the group
  array in the binary; the model raises ValueError there instead, and
  likewise when the index names no group. Both guards are model-only
  and are stated as such in the model module.
- The "%d" format truncates the shifted count to 32 bits, which the
  model reproduces. The third qword of each 24-byte group entry is
  never read, as in the aggregate sums mapped by #2268/#2279.
- The output string is replaced in full: `_M_replace(0, size, buf,
  strlen(buf))` on the rsi object, so a failed call leaves the string
  untouched and a successful call leaves exactly the decimal count.
- The 100-byte stack buffer and the snprintf length (100) bound the
  formatted text; a count whose decimal form exceeded 99 chars cannot
  occur for a 32-bit value.

## Census (whole-file scan, see census.py)

- Caller 0x5eeb9c0: 0 direct calls, 0 tail jumps, 0 qword hits, 0
  RELATIVE addends — virtual-getter shape, as in #2228/#2229/#2263/
  #2264/#2265/#2268/#2279/#2293/#2295/#2296/#2298/#2299.
- Parser 0x61d0df0: exactly 10 direct calls — this caller's site at
  0x5eeba04 plus 9 other sites (sites only, not claimed; the parser
  is shared and only this caller's use is modelled here). 0 tail
  jumps, 0 qword hits, 0 RELATIVE addends.

## Left by contract, stated openly

- The other 9 direct call sites of the parser are not read; their
  callers' contracts may differ.
- The group's element type is not identified: only the byte-span
  arithmetic (span >> 3) is claimed, i.e. elements are 8 bytes wide.
- The outer class and the meaning of the [outer + 0x778] bound beyond
  the index check are not claimed; the bound is modelled as an opaque
  signed 32-bit value.

## Excerpt export commands

Run from the repository root:

```
objdump -d --start-address=0x5eeb9c0 --stop-address=0x5eebab6 work/hl-node-115.bin
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
