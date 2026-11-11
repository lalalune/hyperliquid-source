# abci: reconstruct node #115 generic state save (format choice, error hand-back, parent directory, atomic write)

This packet makes it possible to re-implement, in a few dozen lines each, the generic "save a value to a path"
function of node #115 (two instantiations, 0x50DD9D0 and 0x50DEB30) and the two file helpers it calls through
relocated slots: the parent-directory preparation 0x15020F0 and the atomic writer 0x15024A0. After it, a
reconstruction can state exactly: which path skips everything ("/dev/null"), how the output format is chosen
from the last normalised path component (extension "rmp" in any ASCII case -> MessagePack, everything else ->
two-space pretty JSON), which buffer-capacity word is an error, in which order the parent directory is prepared
and the bytes are written, which callee error word is handed back to the caller (this variant never unwraps),
when each buffer is freed, how the atomic writer names, fills and renames its temporary sibling, and which
exact inputs make each of the 0x15020F0 / 0x15024A0 branches fire. Verified by running the real instruction bytes
against independent reconstructions on 29,618 cases with 92/92 negative controls detected.

- Component ID: abci (Block execution and state; source file `l1/src/abci/state.rs` and the file helpers below it)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository base of the working tree at the time of the run; the
  `references/can1357-hl` tree was not used for any value (names such as `parent`, `isdir`, `tmpname` are
  inferences from the bytes and are marked as such below)
- Claim status: observation for every byte-derived value (instruction flow, constants, relocated slot targets,
  callee argument registers) and for every match between the evaluator run and the reconstruction; inference for
  the role names of the stubbed callees, which this packet does not prove
- Scope included and excluded: bodies 0x50DD9D0, 0x50DEB30, 0x15020F0 and 0x15024A0 (every instruction of the
  first three and 127 of 148 of the fourth is reached by the cases; the unreached instructions are unwind landing
  pads), plus 0x159FCA0 (the ASCII case-insensitive comparison, scalar path) run for real. Excluded and replaced by
  logging stubs: the normaliser/component iterator 0x5CAB560, the serializers 0x5480950 / 0x5482640 (first
  instantiation) and 0x5481900 / 0x5481690 (second), the error converters 0x50DF4C0 / 0x50DF400 / 0x1500B90 /
  0x15026E0, the path-library slots 0x5C8E8C0, 0x16815E0, 0x1500A60, 0x5C8F4C0, the temporary-name builder
  0x1501360, the formatter 0x141E3A0, the joiner 0x1502F90, the file writer 0x5CA5110, the rename 0x1502DA0,
  malloc 0x6355830, free 0x635DE30 and the allocation-failure slot 0x141E264.

## Reproduce

Working directory: repository root; Python 3 standard library plus `tools/decimal_scaled_u64.py` (the shared
evaluator already in the repository). No binutils, no subprocess; the target is read and never executed.

```
python3 tools/abci_state_save_generic_115.py --out research/work-items/abci-state-save-generic-115
python3 -m unittest tests.test_abci_state_save_generic_115
```

`--out` writes `cases.tsv`, `mutants.tsv`, `calls.tsv`, `summary.json` and `measure.json`; they are byte-identical
across runs (checked with two output folders). The tool first checks the SHA-256 above and fails otherwise. Peak
resident memory measured at about 0.46 GiB because cases are generated, run, compared and only counted. Side
effects: none. The unit tests run 32 checks, no skips, no external programs.

## Evidence

All addresses are virtual addresses of the #115 image; file offsets are derived by the tool from the section table.
The GOT slots 0x64E0938 (normaliser), 0x64E0028 (parent preparation) and 0x64E09E8 (writer) carry RELATIVE
addends 0x5CAB560, 0x15020F0 and 0x15024A0 (`summary.json`, `slot_callees`).

- 0x50DD9D0 and 0x50DEB30 (FDE 0x50DD9D0..0x50DDCB4 and 0x50DEB30..0x50DEE14, 180 decoded instructions each, 164
  reached): arguments rdi = value to serialize, rsi/rdx = path pointer/length, rcx = a fourth word handed to the
  writer unchanged. Flow reconstructed from bytes, identical in both bodies:
  1. path length 9 and bytes `/dev/nul` + `l`: return 0 immediately (no log, no callee);
  2. otherwise build the 0x3C-byte normaliser request (pointer, length, tag byte 6, u16 0x0201 at +0x38, absolute
     flag at +0x3A = first byte is `/`) and call the slot target 0x5CAB560; output tag byte 9 means a component was
     found (pointer/length follow at +8/+0x10);
  3. extension: length 2 and `..`, a failed normalisation, no dot, or a dot at index 0 only -> default (JSON);
     else compare the text after the last dot with the 3 bytes `rmp` through 0x159FCA0;
  4. equal -> MessagePack route: empty buffer vector (cap 0, ptr 1, len 0), writer configuration word 0x01000400
     at +8 of the configuration, one serializer call; output tag 0x8000000000000004 is Ok; any other tag frees the
     buffer if its capacity is non-zero and returns `0x50DF400(path pair, error triple)`;
  5. otherwise JSON route: `malloc(0x80)` (null -> allocation-failure slot with size 0x80, align 1, never
     returns), indent literal `"  "` (2 bytes), one serializer call; a non-zero return frees the 0x80 buffer when
     its capacity word is non-zero and returns `0x50DF4C0(path pair, error)`; an Ok return whose capacity word is
     exactly 0x8000000000000000 returns `0x50DF4C0(path pair, buffer pointer)` without freeing; MessagePack
     accepts any capacity including that marker;
  6. common tail: call slot 0x15020F0 with the path; a non-zero result skips the write; otherwise call 0x15024A0
     with (buffer pointer, buffer length, path pointer, path length, fourth word); free the buffer when its
     capacity is non-zero; return the word that was in rax before the free (prep error, else write result).
- 0x15020F0 (FDE 0x15020F0..0x15021C2, 61 instructions, all reached): rdi/rsi = path. Builds the same normaliser
  request on the stack, calls 0x5CAB560 into a result at +0x40; if the result tag byte is 7, 8 or 9 it calls slot
  0x5C8E8C0 and, when that returns non-zero, slot 0x16815E0; when the dword at the request start is not 1 the
  path is replaced by the (pointer, length) the callee left at +8/+0x10. It then calls slot 0x1500A60 (only the low
  byte of the result is tested: 0x100 counts as "not a directory"); a directory returns 0. Otherwise it builds
  options (dword 0x1FF, byte 1 = recursive, mode 0777) and calls slot 0x5C8F4C0; zero returns 0, anything else is
  converted by 0x1500B90 and that word is returned.
- 0x15024A0 (FDE 0x15024A0..0x15026D1, 148 instructions, 127 reached): rdi/rsi = data, rdx/rcx = path. Order:
  temporary-name builder (slot 0x1501360) into a String at +0x20; formatter (0x141E3A0) with pieces 0x44B7F0 and
  the write function 0x14FCB40 into a String at +0x70; free of the first String if its capacity is non-zero; join
  (0x1502F90) into the sibling path at +8; free of the second String if its capacity is non-zero; open-and-write
  (0x5CA5110) of the data into the sibling path; a non-zero result is converted by 0x15026E0 together with the
  original path pair and **skips all directory work and the rename**. Otherwise the same normalise / parent /
  directory-check / create sequence as 0x15020F0 runs on the original path (errors converted by 0x1500B90 and
  returned without rename), and finally the rename slot 0x1502DA0 moves the sibling onto the **original** path
  (not the parent). The sibling path buffer is freed on every exit when its capacity word is non-zero, with the
  pending return word preserved.
- Per-body case counts, outcome counts, instruction coverage and a result digest are in `summary.json`; the callee
  call sites of the four bodies are in `calls.tsv`; every conditional jump of the four bodies is listed with its
  mutation verdict in `mutants.tsv`; a sample of the cases with their outcome class is in `cases.tsv`.

## Implementation and comparison

`tools/abci_state_save_generic_115.py` contains `model_save`, `model_prep`, `model_write` and `model_eq`, written
from the flows above and not from the evaluator. For each case the real bytes run in the shared evaluator with
every callee replaced by a stub that logs its arguments (stack addresses as offsets from the entry stack pointer,
memory words read through the argument pointers) and returns case-controlled values; the ordered log plus the
returned word must equal the reconstruction's. Rust: not yet implemented (this packet is the Python
reconstruction that a Rust port can be checked against).

- 0x50DD9D0 and 0x50DEB30: 10,432 cases each (8 paths including every `/dev/nul`-near spelling, 19 normalised
  names including `..`, `.rmp`, `a.`, `rmp`, `d/.rmp`, serializer failure, allocation failure, capacity 0 / 0x40 /
  the 0x8000000000000000 marker, buffer length 0 / 7, three prep error words, three write error words),
  21 outcome classes; the twins produce identical result digests (`save_twins_agree`: true).
- 0x15020F0: 3,240 cases (5 paths, 9 tag bytes including 0xF9 and 0xFF, parent present/absent, three dword kinds,
  four directory-check results, three create results), 9 outcome classes.
- 0x15024A0: 4,320 cases (5 paths, 9 tags, parent, dword kind, directory check, create, open-write and rename
  failures, all eight capacity combinations of the three Strings), 28 outcome classes.
- 0x159FCA0: 1,194 cases against `model_eq`, 185 equal results.
- Negative controls (92): 14 wrong save models per instantiation (28), 6 wrong preparation models, 4 wrong
  writer models, 2 wrong comparison models, and 52 single-bit flips of conditional jumps (all four bodies); every
  one is detected. 7 further jump sites are unwind landing pads that no case reaches and are reported as
  `unreached`, not counted.

## Results and limitations

Machine-readable metrics are in `measure.json`: cases 29,618, negative_controls 92, negative_detected 92;
`summary.json` records 0 mismatches, 52 jump mutants killed, 0 survived, 7 unreached.

Limitations: the stubbed callees are not reconstructed here, so the bytes behind each role name (normalised
component, parent, directory check, directory create, rename, serializer wrappers, error converters) are
inferences from argument shapes only; which concrete value type each of the two instantiations serializes is not
decided (the callers 0x4E4A960 / 0x4E4AC70 were reconstructed by an earlier abci packet); the SIMD arm of 0x159FCA0
(equal lengths of 16 or more) is not reached by the 3-byte literal and is not covered. No progress gate is
requested.

Next question: reconstruct the normaliser/component iterator at 0x5CAB560 (it is called from all four bodies and
carries the tag bytes 6..9 used above) together with its callee 0x5C8E790.
