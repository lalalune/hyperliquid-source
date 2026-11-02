# RE-001: node #94 compaction-stats string line 0x514d770

Task RE-001, bounded question: what does the function at 0x514d770 in
node #94 print into its destination buffer, and which map entries feed
each field?

## Answer (see records.json for the full semantic record)

The function appends three lines to the destination buffer under a shared
2000-byte limit budget:

1. Header, via `__snprintf_chk` (limit 2000, flag 2, slen -1):
   `"\n** Compaction Stats [%s] **\n"`, with the name taken from window
   argument 2.
2. Data line, via a second `__snprintf_chk` at `dest +
   min(header_return, 2000)` with limit `2000 - min(header_return, 2000)`:
   21 `%s` fields in this order — the caller-provided string
   `*first_column_holder` (window argument 3 dereferenced), then the
   `value + 0x20` string of map keys 1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
   13, 14, 15, 16, 17, 18, 19, 20, 21. Key 2 is NOT read by this function:
   no `at(2)` call and no inlined search for key 2 exists in the window.
3. Dash line, via a third `__snprintf_chk` at `dest +
   min(header_return + data_return, 2000)`: a temporary string of exactly
   `data_return` (`-`, 0x2d) characters, built by `_M_construct` and
   disposed by `_M_dispose`, printed with `"%s\n"`.

Positions advance by the raw snprintf returns clamped to 2000, so the
visible buffer content is the ideal concatenation truncated to at most
1999 characters. The map is the global map anchored at 0x578bf20 (root at
+0x10, end sentinel at +0x8); every node has left +0x10, right +0x18,
int32 key +0x20, value at +0x28, and the string field at value +0x20
(node +0x48). All 20 lookups run in descending order
21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 1 —
13 through the `at()` helper at 0x514b1c0, 7 as inlined lower_bound
searches — and any missing key throws `std::out_of_range("map::at")`
before the output completes. The two direct callers (0x515611d and
0x5156afb, both in 0x51560b0..0x5157a19) pass the same triple shape:
destination buffer, `[[outer + 0x788] + 0x8]` name string, and a
first-column holder object. The enclosing function's wider semantics are
not claimed here.

This is a different function from the sibling numeric format line at
0x514d0c0 (a separate item): different format, different fields (string
fields here, numeric fields there). The RE-003 pr-integration packet
exports the raw bytes of this range as native material only; it does not
model this body, its lookups, its formats or its callers.

## Evidence format

Instruction-level detail lives ONLY in the verbatim objdump excerpts
below, kept whole-function. `records.json` holds semantic records, not a
per-instruction mnemonic list. Mnemonics such as `endbr64` in the
excerpts are genuine instructions present in the target binary, not
placeholders; `verify.py` regenerates every excerpt byte-for-byte from a
fresh objdump run on the real binary and re-checks the function SHAs,
the frames, the relocations and the recorded sites.

Excerpt commands (run from the repository root):

```
objdump -d --start-address=0x514d770 --stop-address=0x514dce0 work/hl-node-94.bin
objdump -d --start-address=0x514b1c0 --stop-address=0x514b220 work/hl-node-94.bin
objdump -d --start-address=0x51560b0 --stop-address=0x5157a19 work/hl-node-94.bin
```

or simply `python3 research/work-items/RE-001-compaction-string-line-94/export_excerpts.py`.

## Files

- `records.json` — semantic records only (formats, lookup order, slots,
  caller census, unknowns).
- `window.objdump.txt` — whole window function through the next FDE
  start (0x514dce0), including the 4 int3 padding bytes after the FDE end
  (0x514dcdc).
- `helper.objdump.txt` — whole `at()` helper 0x514b1c0..0x514b220.
- `callers.objdump.txt` — whole caller-enclosing function
  0x51560b0..0x5157a19.
- `plt.objdump.txt` — the five PLT stubs used by the window.
- `frames.txt` — the three FDE lines (window, helper, caller-enclosing).
- `relocations.txt` — the five PLT GOT entries.
- `verify.py`, `export_excerpts.py` — the packet's own runnable checks
  and excerpt generator.
- `MANIFEST.sha256` — digests of every packet file.

## Unknowns

- The value struct beyond its +0x20 string field, and what the other
  keys' values mean.
- The wider semantics of the caller-enclosing function and of the
  first-column holder object beyond its first qword.
- Behavior when a snprintf return is negative (not reachable for `%s`
  arguments in practice).
- Whether the destination buffer is exactly 2000 bytes or larger; only
  the 2000 limit budget is pinned by the code.

## Environment limits (honest)

This work was done without cargo/rustc, git-lfs or Ghidra/Java on this
machine, so the reconstruction is a Python model in
`tools/foundation_compaction_string_line.py` with tests in
`tests/test_foundation_compaction_string_line.py`, validated against the
digest-verified node #94 binary (`work/hl-node-94.bin`, SHA-256
3b7179cd…c0459f per `provenance/artifacts.json`). `make verify` /
`make test` / `make catalogue-check` were not run here: the repo's
binary-bound suites fail on this machine for pre-existing LFS-pointer
reasons unrelated to this change, and the packet's own `verify.py` plus
the new unit tests are the verification run for this item.
