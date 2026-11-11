# RE-009: node #115 state-export output router rebuilt from ten code copies

With this packet the output routine that every `state.rs` export in node #115 ends in can be re-created as an
executable model: `route_model` in `tools/state_export_route115.py` decides, for any output path and any callee
outcome, which of the thirteen reachable call roles happen, with which arguments, in which order, and what is returned —
and it agrees with the real bytes of all ten monomorphised copies on 25,000 generated cases (2,500 per copy),
while 37 of 37 deliberately wrong variants (20 wrong models, 13 corrupted code bytes, 4 out-of-range inputs) are caught.

- Component ID: RE-009 (storage / state roots), `state.rs` export tail
- Target release and full SHA-256: node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository 0781ce04826eeefd89fe336cb8ea073be0c1de30; no reference source was copied
- Claim status: observation (branch and call structure, proven by execution of the bytes against stubs); the meaning of
  the stubbed callees is inference and is listed under limits
- Scope included and excluded: the 0x2e4-byte generic body in ten copies (VA below); excluded are the callee bodies
  (component iterator `0x5cab560`, the two serialisers per copy, parent check `0x15020f0`, file writer `0x15024a0`) and
  the 0x342/0x348-byte sibling variants that dispatch on an enum through a jump table

## Reproduce

```
python3 tools/artifacts.py verify
python3 tools/state_export_route115.py --out research/work-items/RE-009-state-export-route-115
python3 -m unittest tests.test_state_export_route115
(cd research/work-items/RE-009-state-export-route-115 && sha256sum -c MANIFEST.sha256)
```

Pure standard library plus the repository's `tools/decimal_scaled_u64.py` image and x86 evaluator (it parses the
ELF sections, FDE table and relocated slots itself). The binary is never executed; the evaluator interprets
the copy bytes. The tool refuses to run unless the input digest matches. Runtime about 17 s, peak RSS about 250 MB.
Output is deterministic (no clocks, no randomness: a fixed 64-bit congruential generator picks stub answers).

## Evidence

All coordinates are virtual addresses of node #115. Each copy is exactly one FDE of `0x2e4` bytes, begins with the same
17-byte prologue (six pushes, `sub rsp,0x98`) and has the same fifteen call sites at the same offsets
(`roles.tsv`, 150 rows). Ten copies:

`0x422ed40` `0x422f030` `0x50dd6e0` `0x50dd9d0` `0x50de010` `0x50deb30` `0x50dee20` `0x50df110` `0x26a4e10` `0x26a55a0`

The shared callee at each call-site offset (checked for all ten copies by `check_role_table`):

| offset (copy 0x50dd9d0) | role | callee |
| --- | --- | --- |
| 0x87 | components | slot, target `0x5cab560` |
| 0xf4 | ext_eq | `0x159fca0` (ASCII case-insensitive slice equality) |
| 0x142 | rmp_serialize | per copy (`0x5480950` here) |
| 0x173 | alloc | slot, `0x6355830` |
| 0x1c8 | json_serialize | per copy (`0x5482640` here) |
| 0x1f1 | parent_check | slot, `0x15020f0` |
| 0x20b | file_write | slot, `0x15024a0` |
| 0x221, 0x24c, 0x27b | frees | slot, `0x635de30` |
| 0x25a, 0x29a | drop_json_err, drop_rmp_err | per group (`0x50df4c0`, `0x50df400` here) |
| 0x2ab | alloc_error | slot, `0x141e264` (does not return) |
| 0x2d6, 0x2df | unwind free and resume | slot `0x635de30`, `0x63f0a50` (landing pad only) |

Observed behaviour of the bytes (each line is a branch the model contains and the cases exercise):

1. A path that is exactly the nine bytes `/dev/null` returns 0 at once, before any call. The compare is a length check, one
   8-byte immediate and one byte; any other length or byte, including case, goes on.
2. A "root" flag is `path[0] == '/'` for a non-empty path (0 for the empty path); it is stored with the path pointer,
   length, state byte 6 and the bytes `01 02` into a 0x40-byte iterator struct at frame offset 0x38 and passed to the
   component call, which returns a tag byte at the output (tag 9 means a normal component with pointer and length).
3. Only for tag 9: a name of exactly `..` is skipped; otherwise the name is scanned backwards for the last `.`; no dot, or a
   dot at index 0, means no extension. Otherwise the text after that dot is compared with the three bytes `rmp`.
4. Equal: a `Vec` `(cap 0, ptr 1, len 0)` and a config `{vec address, 0x01000400, 0}` are built and the per-copy MessagePack
   serialiser is called as `(frame+0x38, value, frame+0x88)`; success is the result word `0x8000000000000004`. Any other word
   frees the vec if its capacity is non-zero and returns the per-copy error drop of the three result words.
5. Not equal, not normal, `..`, no extension: 0x80 bytes are allocated (a null result calls the allocation-error handler with
   `(1, 0x80)`), a `Vec` `(0x80, ptr, 0)` and a pretty formatter `{vec, two-space indent, 2, 0, 0}` are built and the per-copy JSON
   serialiser is called as `(value, frame+0x38)`. A non-zero result is an error: the vec is freed if its capacity is
   non-zero, then the JSON error drop is called with the result; its return value is returned. A capacity word of
   `0x8000000000000000` after success (negation overflows) skips the write and calls the same error drop with the vec pointer.
6. Common tail: `parent_check(path, len)`; a non-zero result is returned, a zero result calls
   `file_write(vec ptr, vec len, path, len, extra)` and returns its result. A non-zero capacity is freed afterwards
   without changing the returned value.

Generated files (all from `tools/state_export_route115.py --out`):

| file | content |
| --- | --- |
| `roles.tsv` | every call site of every copy: offset, index, role, kind, target |
| `sample_cases.tsv` | first 70 cases of each copy: path bytes, return, call list, branch labels |
| `coverage.tsv` | per-branch and per-callee counts, per-copy counts, per-copy trace digests and the digest of all traces |
| `controls.tsv` | all 37 negative controls and whether each was caught |
| `measure.json` | counts used by the packet measurer |

## Implementation and comparison

`route_model(path, rep)` returns the call list `(role, arguments...)`, the return value and branch labels. `rep` holds
the stub answers of one case (component outcome, serialiser outcome and register words, allocation result, parent
check, write and drop results). `StubMachine` runs the real bytes of a copy in the repository evaluator, answers every
`call` from the same `rep`, and records each call's arguments plus the memory the callee would read (iterator struct,
vec, config, formatter, name slices, indent bytes). Per case the two call lists and return values must be equal.

Paths come from 7 prefixes times 15 names plus `/dev/null`, all single-byte substitutions of it and boundary paths;
component outcomes are the tail segment, a random name, `..`, or a non-normal tag; each copy gets 2,500 cases.
All ten per-copy trace digests are in `coverage.tsv`. Every reachable branch appears (`devnull` 395 times, `jo` 1,892,
`alloc_fail` 1,519, `rmp_err` 1,501, `json_err` 7,668 in the committed run); only the unwind landing pads are never reached.

Negative controls (37, all caught, see `controls.tsv`): 20 model mutants (wrong path length or text, wrong root test,
dropped root flag, first instead of last dot, case-sensitive compare, wrong extension text, skipped `..` rule, wrong tag,
wrong vec or config constant, wrong indent, wrong alloc size, swapped free/drop order, missing overflow branch, inverted write
test, unconditional free, lost return value); 13 one-byte corruptions of copy `0x50dd9d0` (compare length, `/dev/null`
immediate, root byte, `..` word, dot byte, extension length, config word, alloc size, `neg` operand, component slot argument,
ok-tag word, `sete`, vec init) each making the evaluator disagree or fail; and four range controls (non-FDE start, neighbouring
function, over-long path, damaged prologue).

## Results and limitations

- 25,000 / 25,000 cases agree; 37 / 37 negative controls detected (`measure.json`). No Rust implementation is claimed.
- The five-register call arguments are checked only where the callee reads them; callee results are free stub values, so
  the packet proves the router, not the serialisers.
- Stub meaning is inference: `0x5cab560` is treated as the path component iterator (tag 9 = normal component) and
  `0x159fca0` as ASCII case-insensitive equality (the evaluator stub uses `lower()` on bytes; the SSE body was not run).
  Path semantics of the real component iterator are therefore not part of the agreement.
- Pointers and lengths past what the router passes on are symbolic; frame offsets are compared relative to the entry stack.
- No component gate is requested.

Next question: the 0x342/0x348-byte siblings (`0x422f320`, `0x50ddcc0`, `0x4773b90`) that switch on an enum tag through a
jump table before the same tail, and the parent-directory check `0x15020f0` and file writer `0x15024a0` this tail ends in.
