# abci: reconstruct node #115 abci state save front ends (format choice, failure branches, timed log record)

This packet makes it possible to re-implement, in a few dozen lines, how node #115 saves the abci state to a
path: the "/dev/null" shortcut, the way the output format is chosen from the extension of the *normalised* path
("rmp" in any ASCII case selects MessagePack, everything else - including a hidden ".rmp", "..", a trailing dot,
a missing extension and a failed normalisation - selects two-space pretty JSON), the exact point where each
failure ends in `Result::unwrap()` or an allocation failure, and the timed log record that follows (elapsed
seconds as an f64 from whole seconds plus signed nanoseconds / 1e9, a UTC stamp in a fixed format, and the
`serialized abci state` message). It also reconstructs two plain twin bodies that run one serializer and the same
log record, and proves the shared ASCII case-insensitive comparison 0x159FCA0 against its own reconstruction.

- Component ID: abci (Block execution and state; source file `l1/src/abci/state.rs`)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository base 0781ce04826eeefd89fe336cb8ea073be0c1de30; the
  `references/can1357-hl` tree was not used for any value (names and meanings below are inferences from the bytes)
- Claim status: observation for every byte-derived value and every callee log; inference for the role names
  (`norm`, `prep`, `write`, ...) which are not proved by this packet
- Scope included and excluded: bodies 0x26A2C80 (full save), 0x4E4A960 and 0x4E4AC70 (plain twins) and the helper
  0x159FCA0, with every callee stubbed except 0x159FCA0 (run for real, scalar path). Excluded: the serializers
  0x22EBDC0, 0x22EBC70, 0x50DD9D0, 0x50DEB30, the normaliser 0x5CAB560, the file helpers 0x15020F0 / 0x15024A0,
  the clocks 0x5C842E0 / 0x5C84210 / 0x1629690 and the log sink 0x5C9B830 (their bytes are not reconstructed here),
  and the SIMD arm of 0x159FCA0 (only reachable for equal lengths of 16 or more, never with the 3-byte literal).

## Reproduce

Working directory: repository root; Python 3 standard library only plus `tools/decimal_scaled_u64.py` (the shared
evaluator already in the repository). No binutils, no subprocess, the target is read and never executed.

```
python3 tools/abci_state_save_timed_115.py --out research/work-items/abci-state-save-timed-115
python3 -m unittest tests.test_abci_state_save_timed_115
```

`--out` writes `cases.tsv`, `mutants.tsv`, `calls.tsv`, `summary.json` and `measure.json`; they are byte-identical
across runs (checked with two output folders, different hash seeds and time zones). The tool first checks the
SHA-256 above and fails otherwise. Peak memory is far below 1 GiB because cases are generated, run, compared and
only counted. Side effects: none.

## Evidence

All addresses are virtual addresses of the #115 image; file offsets are derived by the tool from the section table.

- 0x26A2C80 (FDE 0x26A2C80..0x26A326E, 316 decoded instructions, 269 reached by the cases): one argument, a pointer
  to a triple (state handle, path pointer, path length). Flow reconstructed from bytes:
  1. call clock 0x5C842E0 (seconds in rax, nanoseconds in edx), saved for the end of the function;
  2. path length 9 and bytes `/dev/nul` + `l` -> jump straight to the timing tail (no normalisation, no write);
  3. otherwise build a 0x3C-byte request (path pointer, length, tag byte 6, u16 0x0201 at +0x38, absolute flag at
     +0x3A = first byte is `/`) and call the slot target 0x5CAB560; tag byte 9 means Ok (pointer and length of the
     normalised path follow);
  4. extension: length 2 and `..` -> default; otherwise scan down from the last byte for `.`; none, or only at
     index 0 -> default; else call 0x159FCA0 with the text after the dot against the 3 bytes `rmp` (rodata
     0x4659E5);
  5. equal -> MessagePack route: empty buffer vector (cap 0, ptr 1, len 0), writer configuration word 0x01000400,
     call 0x22EBDC0; result tag 0x8000000000000004 is Ok, anything else frees the buffer if its capacity is
     non-zero and converts the error with 0x26A6BC0 before `unwrap`; MessagePack accepts any capacity,
     including the 0x8000000000000000 marker;
  6. otherwise JSON route: `malloc(0x80)` (a null result calls the allocation-failure slot 0x141E264 with
     size 0x80, align 1), the indent literal `"  "` (2 bytes, rodata 0x5F3CC0), call 0x22EBC70; a non-zero result frees the
     0x80 buffer and converts with 0x26A6AF0 before `unwrap`; an Ok result whose capacity word is the
     0x8000000000000000 marker is also routed through 0x26A6AF0 and `unwrap` (without a free);
  7. file stage: 0x15020F0(path, len) (non-zero -> release the buffer if cap != 0, `unwrap`), then
     0x15024A0(buf, len, path, len, location) and the buffer release (cap != 0), then `unwrap` on a non-zero result;
  8. tail: second clock read, 0x5C84210 (end, start) into a result whose tag 0 is Ok with seconds at +8 and
     signed 32-bit nanoseconds at +0x10; f64 = nanoseconds / 1e9 + seconds (the u64 -> f64 conversion is the
     usual two-halves constant trick, one rounding); an Err result and an exact zero both log +0.0; then
     0x1629690 fills a 12-byte UTC stamp whose words are re-ordered into the record (tag 1, qword at +4, dword at
     +0), the once-cell flag at 0x64F01A8 triggers 0x5C87D50 when non-zero, and the record
     (message pointer, 0x2B, f64, stamp, format literal `%Y-%m-%dT%H:%M:%S%.3fZ`, 0x16, 8, 0) is handed to the
     log sink 0x5C9B830 with the target string at 0x43DF63.
- 0x4E4A960 and 0x4E4AC70 (150 instructions each, 118 reached): clock, then one serializer call (0x50DD9D0 /
  0x50DEB30) on (state view, path, length, table 0x649D9C8); a non-zero result goes to `unwrap` (message at
  0x918865, 0x2B bytes) with the result as the error, otherwise the same timing tail with a different frame layout.
  The two twins have identical outcome digests for the same cases.
- 0x159FCA0 (78 instructions, FDE 0x159FCA0..0x159FDE1): unequal lengths -> 0; below 16 bytes a scalar loop folds
  `A`..`Z` (byte - 0x41 < 0x1A) by or-ing 0x20 on both sides; 16 bytes and more use a SIMD fold (not run here).
- `calls.tsv` lists every direct call and every GOT-slot call of the three bodies with relocated targets read from
  `.rela.dyn`; `cases.tsv` lists one representative of each distinct outcome signature; `mutants.tsv` lists every
  conditional jump with the result of flipping it; `summary.json` has digests, counts and the rodata literals.
- Analysis was complete for the three bodies; the stubs record call order and arguments (stack addresses are logged
  as offsets from the entry stack pointer).

## Implementation and comparison

`tools/abci_state_save_timed_115.py` runs the real instruction bytes of each body in the shared evaluator
(`tools/decimal_scaled_u64.py`) extended here with the scalar double instructions the timing code uses (`movsd`,
`cvtsi2sd`, `unpcklps`, `subpd`, `unpckhpd`, `addsd`, `divsd`, `ucomisd`). Every callee is a logging stub driven by
the case, and the ordered log of (callee, arguments) plus the result kind (return, `unwrap` panic, allocation
failure) is compared with `model_full` / `model_plain` / `model_eq`, independently written Python reconstructions
(the executable specification of the behaviour above). Case grid for the full body: 7 path shapes x 19
normalisation outcomes (failure plus 18 names) x every downstream route (MessagePack: serializer error with and
without capacity, three capacities x 2 lengths x prepare/write failures; JSON: allocation failure, serializer
error, three capacities x prepare/write failures) with 5 of 54 timing tails each (9 durations incl. an Err,
3 stamps, once-cell off/on), plus the 54 tails on "/dev/null". No Rust implementation is attempted in this packet.

Negative controls (all detected): 22 deliberately wrong reconstructions (16 for the full body, 4 for the twins,
2 for the comparison helper: device name prefix only, no device
shortcut, absolute flag always, case-sensitive extension, prefix-only extension, first dot instead of last,
hidden file accepted, `..` accepted, allocation failure ignored, marker capacity accepted, buffer freed when
empty, write before prepare, unsigned nanoseconds, nanoseconds dropped, truncated seconds, once-cell always
called, and two comparison folds), plus every conditional jump of the three bodies flipped in the
instruction bytes (34 killed, 0 survived; 8 jumps sit on exception landing pads or the dead release of a marker
and are reported as unreached, not counted as detected), plus the corruption tests in the unit tests (target
digest, mid-function start, `rmp` literal byte, 0x80 size immediate, unknown callee).

## Results and limitations

- Cases: 12,994 (full 11,464; twins 168 each; comparison helper 1,194 run for real); mismatches: 0.
- Negative controls: 56 of 56 detected (22 wrong reconstructions + 34 killed jump flips); 8 jumps unreached.
- Unit tests: 37 pass (about 90 s). `measure.json` holds the three counted numbers.
- Limits: the serializers, normaliser, file helpers, clocks and log sink are stubs - this packet proves how the
  three bodies call them, in what order and with what arguments, not what they do inside. The names of the
  stubbed roles are inferences. The SIMD arm of 0x159FCA0 and the landing pads are not exercised. The tool does
  not claim that these bodies are the only savers of abci state.
- No component gate is requested.
- Next question: the serializer behind the MessagePack route (0x22EBDC0, 228 bytes) and the two JSON-side
  helpers 0x22EBC70 / 0x26A6AF0, then the normaliser 0x5CAB560.
