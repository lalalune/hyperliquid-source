# RE-001: node #115 need-score predicate 0x5dbd6d0

## Bounded question

What does the 230-byte function at 0x5dbd6d0 decide, end to end?
It is the predicate reached only through a single function-pointer
slot (see Census below), and it calls the level gate at 0x5f6b720
that PR #2330 already pinned.

## Target and binding

- Binary: `work/hl-node-115.bin`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  bound in `provenance/artifacts.json` as `artifacts/node/115/hl-node`.
- The predicate window is 0x5dbd6d0..0x5dbd7b6 (230 bytes, FDE file
  offset 0xff4a68, length field 0x28). The gate window is
  0x5f6b720..0x5f6b736 (22 bytes, FDE file offset 0x1004c8c, length
  field 0x10). Both CIEs are at the `.eh_frame` start with
  augmentation "zR" and no LSDA field.

## Excerpts (verbatim raw disassembly)

Generated with exactly these commands from the clone root:

```
objdump -d --start-address=0x5dbd6d0 --stop-address=0x5dbd7b6 work/hl-node-115.bin
objdump -d --start-address=0x5f6b720 --stop-address=0x5f6b736 work/hl-node-115.bin
```

The outputs are kept whole-function in `excerpts/predicate.txt` and
`excerpts/helper.txt` and regenerate byte-for-byte (see `verify.py`).
Instruction-level detail lives only in those excerpt files; `records.json`
holds semantic records, not a per-instruction list.

Note on authenticity: `endbr64` at the head of each window is a genuine
instruction present in the target binary, not a placeholder. The verify
script checks sampled instructions byte-for-byte against a fresh objdump
run and against the raw binary bytes.

## Semantics, stated literally

The function takes the object in `rsi` (`rdi` is never read) and
returns 1 or 0.

1. Five "need" sums, in this order, each of the shape
   `((end - begin) >> 4 arithmetic on the wrapped 64-bit difference)
   + base` (wrapping at 64 bits), with the `jne` testing the wrapped
   sum against zero:
   - (0xc78, 0xc70, 0xbe0): nonzero returns 1 at once.
   - (0xd20, 0xd18, 0xc88): nonzero returns 1 at once.
   - (0xe70, 0xe68, 0xdd8): nonzero returns 1 at once.
   - (0xbd0, 0xbc8, 0xb38): nonzero returns 1 at once. This is the
     same shape as the #2326 formatter's need.
   - (0xf18, 0xf10, 0xe80): nonzero returns 1 at once; zero enters
     the score scan. The running index starts at 0 because this sum
     is the index register and it is 0 on entry to the scan.
2. Score scan: the gate at 0x5f6b720 is called (object in `rdi`) and
   returns 0 when the flag byte at obj+0xa90 is set, else
   signed32(obj+0x10) - 2 with 32-bit wrap. While the bound is >= the
   running index (signed 32-bit compare), the scan reads the double at
   [obj+0xf38] + index * 8, increments the index, and returns 1 as
   soon as a score is >= 1.0 (rodata double at 0x4592b0, verified
   1.0). A NaN score does not satisfy the compare (`comisd` + `jae`:
   unordered leaves CF set, so the branch is not taken) and the scan
   continues with a fresh gate call. When the bound falls below the
   index, the function returns 0.

## Census (whole-file scan, reproduced by `census.py`)

- Predicate 0x5dbd6d0: 0 direct calls, 0 tail jumps, and exactly
  one R_X86_64_RELATIVE record carrying it as addend (slot at vaddr
  0x64ca460) — a virtual-dispatch shape, reached only through that
  function-pointer slot. Its single whole-file qword hit (file offset
  0x106660) is the addend field of that same relocation entry, not a
  separate stored pointer.
- Gate 0x5f6b720: exactly 4 direct calls (this predicate's 0x5dbd78d,
  the #2330 pass's 0x5f6c859, plus 0x5f7e45e and 0x5f7e5a7, sites
  only), 0 tail jumps, 0 stored qwords, 0 RELATIVE addends.

## Model and tests

- `tools/need_score_predicate_115.py` is the literal model
  (`need_sum`, `level_gate`, `predicate`).
- `tests/test_need_score_predicate_115.py` covers every need position,
  the wrapped-to-zero need arm, arithmetic (not logical) shifting,
  the threshold boundary, the flag-set bound, negative bounds reading
  no score, NaN handling, the 32-bit gate wrap, missing-field guards,
  and the packet checks.

## Assumptions

- The caller guarantees the scores array holds an entry for every
  index the scan reaches; the native code reads scores[i] without a
  length check, so running past the end is a model guard error, not a
  native behavior.
- Nothing in this function mutates the object, so the gate bound
  recomputed each iteration is constant for a fixed object.
- The table owning the predicate's single function-pointer slot
  (vaddr 0x64ca460) is not identified in this item; the slot itself
  is the whole recorded consumer surface.

## Environment limits, stated honestly

This VM has no cargo/rustc, no git-lfs, and no Ghidra/Java, so no Rust
reconstruction is claimed. `make doctor` fails on missing providers and
`make verify` fails on the LFS-pointer artifact here (both pre-existing);
this packet binds to the materialized `work/hl-node-115.bin` instead.
pytest is not installed, so the pytest-style test file runs under plain
python3 via its `__main__` runner.
