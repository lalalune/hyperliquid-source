# RE-001: map node #115 decimal-index group ratio 0x5eed240 with its ratio 0x5f6aed0 and parser 0x61d0df0

Task: RE-001 (#115 function map). Bounded question: what does the
getter-shaped function at 0x5eed240 compute end to end, given that it
is another consumer of the decimal parser at 0x61d0df0 mapped by
#2301, but instead of formatting one group's count it formats a
per-group ratio — one field-pair sum divided by another — produced by
its own ratio callee at 0x5f6aed0? This item maps the caller whole
plus its ratio callee whole plus its parser callee whole — one
complete behavior, not a fragment: parse a decimal index, validate it
against the bound, compute the indexed group's ratio, and format the
ratio into the output string.

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

- Caller, 0x5eed240..0x5eed329 (233 bytes; FDE .eh_frame offset
  0x3576f8, length 0x38, CIE 0, no LSDA). Args: rdi = outer,
  rsi = output string object, rdx = view pointer, rcx = view length.
  Returns 1 on success, 0 on any failure; the stack canary is checked
  before the normal return and a failure calls `__stack_chk_fail`.
- Ratio, 0x5f6aed0..0x5f6af99 (201 bytes; FDE offset 0x35dd00,
  length 0x10, CIE 0, no LSDA). Args: rdi = ratio object, esi = index
  (low 32 bits sign-extended). Returns a double in xmm0: the group's
  ratio, or -1.0 when the group range is empty or the divisor sum is
  zero. No stack frame, no canary.
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

group_ratio(obj, index32):
  base = [obj + 0xa98]
  entry = base + index32 * 24
  begin = [entry]; end = [entry + 0x8]     # third qword never read
  numerator = 0; divisor = 0
  if begin == end: return -1.0
  for p in [begin, end) step 8:
    element = [p]
    numerator += [element + 0x90] + [element + 0x98]  # 64-bit wrapping
    divisor += [element + 0x10]                       # 64-bit wrapping
  if divisor == 0: return -1.0
  return (double)numerator / (double)divisor   # signed conversions

indexed_group_ratio(outer, out_string, view_ptr, view_len):
  member = [outer + 0x788]
  sub = [member + 0x30]
  view = {ptr = view_ptr, len = view_len}
  if parse_decimal_u64(&view, &index) == 0: return 0
  if view.len != 0: return 0                     # trailing garbage
  bound = (int32)[outer + 0x778]                 # sign-extended
  if index >= bound as an unsigned compare: return 0
  ratio = group_ratio(sub + 0x40, (int32)index)
  temp = format_f(ratio)                         # helper 0x5eec680, "%f"
  out_string.assign(temp)                        # helper 0x5eebb20
  return 1
```

Notes on the observed code, all verifiable in the excerpts:

- The parser's overflow guard is exact u64 arithmetic:
  0x1999999999999999 is (2**64 - 1) // 10 and 5 is the largest final
  digit of 2**64 - 1, so "18446744073709551615" parses and
  "18446744073709551616" fails. Leading zeros are accepted; no sign,
  whitespace, or other prefix is accepted.
- The bound check is an unsigned compare (`cmp %rax,%rsi; jae`) of
  the full parsed u64 against the sign-extended 32-bit bound, so it
  differs from a plain signed check when the bound is negative; with
  the ordinary positive bounds in this object family it is simply
  index >= bound fails. The ratio callee then takes only the low 32
  bits of the index (`movslq %esi,%rsi`), so the bound check is the
  only guard before indexing the array.
- The ratio's array is the same group array the neighbouring getters
  use: the ratio object is sub + 0x40 and its +0xa98 field is exactly
  [sub + 0xad8], the 24-byte-entry base of #2268/#2279/#2301/#2304.
  The entry's first two qwords are the element-pointer range
  [begin, end); the third qword is never read. The element +0x10
  field reappears here as the divisor, as it was the summed field in
  #2268's aggregate sum; the +0x90/+0x98 pair is new to this item.
- The -1.0 sentinel is a real rodata double at 0x458dc8 (bytes
  `000000000000f0bf`), loaded by `movsd` on both the empty-range and
  the zero-divisor paths — it is not a NaN, and the caller formats it
  as "-1.000000" like any other ratio.
- The format string is the rodata string "%f" at 0x432165, so the
  output is the ratio with exactly six digits after the decimal
  point. The formatter helper at 0x5eec680 is a variadic wrapper
  around `__vsnprintf_chk` (one vector argument, xmm0 = the ratio);
  the caller's load from the .got slot at 0x64ed730 is overwritten
  inside the helper and contributes nothing to the output.
- The output string is assigned in full from the formatted temporary
  (helper 0x5eebb20, the same assign helper used by #2301/#2304), so
  a failed call leaves the string untouched and a successful call
  leaves exactly the formatted ratio. The temporary's heap buffer is
  freed only when it is not the small-string buffer, matching the
  usual SSO check in the excerpt.

## Census (whole-file scan, see census.py)

- Caller 0x5eed240: 0 direct calls, 0 tail jumps, 0 qword hits, 0
  RELATIVE addends — virtual-getter shape, as in #2228/#2229/#2263/
  #2264/#2265/#2268/#2279/#2293/#2295/#2296/#2298/#2299/#2301/#2304.
- Ratio 0x5f6aed0: exactly 1 direct call (this caller's site at
  0x5eed2af) — this caller is its sole consumer. 0 tail jumps, 0
  qword hits, 0 RELATIVE addends.
- Parser 0x61d0df0: exactly 10 direct calls — this caller's site at
  0x5eed27e plus the 9 other sites recorded by #2301/#2304 (sites
  only, not claimed; the parser is shared and only this caller's use
  is modelled here). 0 tail jumps, 0 qword hits, 0 RELATIVE addends.

## Left by contract, stated openly

- The parser's other 9 direct call sites besides this one are not
  read; their callers' contracts may differ.
- The formatter at 0x5eec680 (variadic `__vsnprintf_chk` wrapper,
  "%f" at 0x432165; 5 direct calls file-wide, this site 0x5eed2cf
  plus 4 sites only) and the string assign helper at 0x5eebb20 are
  used only through their observed signatures; their internals are
  not modelled beyond the format string and the assign effect.
- The element type is not identified: only the +0x10 divisor field
  and the +0x90/+0x98 numerator fields are claimed.
- The outer class is not claimed; the member at [outer + 0x788] and
  its +0x30 sub-object are modelled as opaque field paths, and the
  relationship between the [outer + 0x778] bound and the group array
  extent is the binary's own guard, not a proven invariant — the
  model therefore requires a consistent bound and array (see the
  model module's ValueError guard, which is model-only).
- The neighbouring function at 0x5f6ad70 ("proportional share",
  open PR #2224) is a different address and is not this ratio; no
  ground from it is re-claimed.

## Excerpt export commands

Run from the repository root:

```
objdump -d --start-address=0x5eed240 --stop-address=0x5eed329 work/hl-node-115.bin
objdump -d --start-address=0x5f6aed0 --stop-address=0x5f6af99 work/hl-node-115.bin
objdump -d --start-address=0x61d0df0 --stop-address=0x61d0e87 work/hl-node-115.bin
```

`export_excerpts.py` in this directory runs all three commands and
writes the three excerpt files; `verify.py` re-runs them and requires
a byte-for-byte match, plus the digest, manifest, frame, census,
sampled instruction-byte, and model-test checks.

## Environment limits, stated honestly

This VM has no cargo/rustc, no git-lfs, and no Ghidra/Java, so no Rust
reconstruction is attempted; the model is Python only, as in the
prior #115 items. `make doctor` fails on missing providers and
`make verify` / `make catalogue-check` fail on the LFS-pointer
artifact here (both pre-existing); this packet binds instead to the
materialized `work/hl-node-115.bin`, whose hash matches provenance
exactly. No pytest is installed, so the pytest-style test file runs
under plain python3 via its `__main__` runner.
