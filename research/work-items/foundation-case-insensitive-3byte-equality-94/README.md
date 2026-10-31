# Foundation work item: case-insensitive 3-byte equality (node #94)

## Question

Bind one small, previously unclaimed window in node #94 whose rule reads
directly from its own bytes: a fixed-length-3, ASCII case-insensitive byte
equality test. No stdlib type, source-level function, or caller purpose is
claimed.

## Target

- Binary: node #94, `artifacts/node/94/hl-node`
  (91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`).
- Window: `[0x151a4a0, 0x151a52f)`, 143 bytes
  (`.eh_frame+0x14a00`, CIE at offset 0, `zR` pcrel sdata4,
  GNU `--dwarf=frames` confirmed).
- Padding: 1 int3 byte to the next FDE at `0x151a530`
  (`[0x151a530, 0x151a7e9)`); 14 int3 bytes precede the window
  (previous FDE ends `0x151a492`). Stride is not the FDE extent; the
  checker locks body and padding separately.

## Scope

Included: the window's own bytes, its FDE record, the next FDE record,
the single caller FDE record, the two direct call sites, the
zero-relocation-slot result, and the decoded rule below.

Excluded: what the compared strings hold, what the caller does with the
result, any stdlib or private provenance (see Unknowns), and the peer
lane discussed under Distinctions.

## Reproduce

```sh
objdump -d --start-address=0x151a4a0 --stop-address=0x151a530 \
  artifacts/node/94/hl-node
objdump --dwarf=frames artifacts/node/94/hl-node   # FDE at .eh_frame+0x14a00
python3 tools/foundation_case_insensitive_3byte_equality.py \
  --check research/work-items/foundation-case-insensitive-3byte-equality-94/evidence.json
python3 -m unittest tests.test_foundation_case_insensitive_3byte_equality -v
```

## Observations (from the bytes)

- Entry: `cmp $0x3,%rsi; jne 0x151a52c` — the length gate. The window
  does NOT open with endbr64.
- For each of the 3 byte positions (offsets 0, 1, 2), each side is folded
  as: `lea byte-0x41; cmp $0x1a (unsigned); setb; shl $0x5; or`.
  That is: bytes in `A`..`Z` gain `0x20` (become lowercase); every other
  byte is unchanged, including bytes below `0x41` (whose wrapped
  difference exceeds `0x1a` unsigned, so `setb` clears).
- After each folded pair, `cmp` + `jne 0x151a52c` exits early on mismatch.
- Success path: `sete %al; ret`. Fail path: `xor %eax,%eax; ret`.
- Zero calls inside; zero unconditional jumps out. Two rets total.
- Incoming calls: the `.text` byte-pattern scan (70,370,352 bytes) finds
  exactly two direct `e8` sites, both inside the single caller FDE
  `[0x151b100, 0x151b6a3)`: `0x151b4f9` and `0x151b527`, each
  boundary-confirmed and independently resolved to the window start by
  objdump's caller disassembly. This is explicitly not a complete xref
  census.
- Data edge: zero `R_X86_64_RELATIVE` records in any `.rela.*` section
  name this window as addend (full-section scan: 80,022 `.rela.dyn` +
  278 `.rela.plt` entries) — reported as an absence, no meaning claimed.
- objdump prints a nearest-symbol label for this address, but the label
  sits ~0x3a8d960 bytes away from its anchor; that label is NOT used as
  an identification here and no provenance is inferred from it.

## Inferences

- Decoded rule: `rax = 1` iff `rsi == 3` and
  `fold([rdi+i]) == fold([rdx+i])` for `i = 0,1,2`, where
  `fold(b) = b | 0x20` if `'A' <= b <= 'Z'` else `b`; otherwise
  `rax = 0`. Case-folding is ASCII-only by construction.
- The label "case-insensitive 3-byte equality" is an inference from the
  observed rule, kept separate from the bytes above.

## Distinctions (stated head-on)

- Twin guard, verified by this builder (not taken on scout trust):
  full claimed-body byte-compare top match is only 8/127 vs
  `0x4ebf860` (round-15 UTF-8 encode, KNOWN) — NOT a twin.
  Byte-compare vs the avoid-list string compares `0x1a6af10` /
  `0x41d60c0` is 4/143 each — NOT twins: disassembled this round,
  those are byte-wise lexicographic compares with a `bswap` tail and
  no folding, a different rule.
- Fold-idiom disclosure: a whole-`.text` scan for the
  (`cmp` imm `0x1a` + `setb`) fold idiom finds 13 FDEs (size <= 400B)
  using case-folding somewhere, including this window (6 folds =
  3 positions x 2 strings) — e.g. `0x29a4970` (12 folds, 314B),
  `0x13d94c0` / `0x1635560` / `0x284b430` (4 folds each, 283B),
  `0x151aff0` (2 folds, 261B, immediately before the caller FDE).
  Those are larger functions that USE folding; none is a pure
  fixed-length-3 equality window, and none byte-matches this window.
  The idiom's recurrence elsewhere does not make this window a
  population member.
- Peer distinction: this window sits in the #1033 region scan
  (+-0x3000 around helper `0x151cba0`, ~0x2700 away), but its domain
  is unrelated to the peer's integer result projection (string
  equality vs integer math) — it is a neighbour by address only, not
  a sibling of the peer's claim. The peer lane is not claimed here.

## Unknowns

- What the two compared strings are, and what the caller does with the
  0/1 result.
- Whether this window corresponds to any stdlib routine or private
  helper — no claim either way. The compiler-intrinsic shape of the
  fold is not a provenance claim.
- Indirect callers, tail jumps, and PLT references are out of scope
  for the byte-pattern incoming scan.

## Limits

- No stdlib type, source-level function, field meaning, or caller
  purpose is claimed anywhere.
- The byte-pattern scan is not a complete xref census, and the
  zero-slot result does not identify the window's provenance.
- No progress gate is requested or claimed. Foundation's gates and
  generated progress files are unchanged.
- The reference tree was a search lead only; no inferred implementation
  was copied, and every claim is grounded in target bytes for node #94.

## Files

- `README.md` (this file), `evidence.json`, `window.objdump.txt`,
  `frames.txt`, `caller.objdump.txt`, `MANIFEST.sha256`.
- Checker: `tools/foundation_case_insensitive_3byte_equality.py`
  (stdlib only, `--check` compares regenerated evidence to retained JSON,
  with corruption controls).
- Test: `tests/test_foundation_case_insensitive_3byte_equality.py`.
