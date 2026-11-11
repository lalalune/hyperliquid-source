# transport: reconstruct node #115 AlertConfig pretty-JSON writer 0x4783f20 and its byte-sink helpers

This packet makes it possible to reimplement, byte for byte, how node #115 writes the rate-limiter alert configuration
(`ip_rate_limiter_alert_config`, struct `AlertConfig` with the single u64 member `bucket_limit_mult_threshold`) as pretty-printed JSON,
including the exact `Vec<u8>` growth schedule (capacities and allocator calls), the string escape classes, the u64 decimal formatter and
the panic/allocation-failure exits. The five bodies run as real x86-64 code in a small evaluator and are checked against an independently
written rule list on 15,034 cases, with 32 negative controls (all detected) and 261 byte edits (229 change an outcome).

- Component ID: transport (Network transport; rate limits). Task: first transport task, error handling without network traffic.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit: repository checkout used for this run (origin/main at the time); no reference source was copied.
- Claim status: observation (bytes, evaluator results) plus inference (names of roles; labelled below).
- Scope included: functions 0x4783f20, 0x4777cc0, 0x4779320, 0x4787e90, 0x4787da0 (link-time ELF VAs, FDE-exact bounds).
  Excluded: the other users of the shared helpers, the AlertConfig reader (0x4784750 area), the enclosing config writer, LZ4 statistics.

## Reproduce

From the repository root with the pinned artifact present (the binary is only read, never executed):

```sh
python3 tools/transport_alert_json_115.py --out work/alert-json
python3 -m unittest tests.test_transport_alert_json_115 -v
(cd research/work-items/transport-alert-config-json-115 && sha256sum -c MANIFEST.sha256)
```

The tool checks the SHA-256 first, parses ELF sections, `.rela.dyn` and the FDE table through `tools/elf_index.py` and
`tools/fde_extents.py`, and runs the evaluator from `tools/funding_rate115.py` (decoder and memory model). It
needs no binutils, writes no times or paths, and takes about three minutes with a small memory footprint (cases are generated, run and
compared one at a time). Output is byte-identical across runs.

## Evidence

Observed from bytes (all addresses are link-time VAs):

| Body | FDE extent | Role (inference from the verified behaviour) |
| --- | --- | --- |
| 0x4783f20 | 518 bytes | `AlertConfig` object writer: `{`, one member, closing newline/indent, `}` |
| 0x4777cc0 | 1241 bytes | pretty member writer: separator, indent, escaped key, `": "`, decimal value |
| 0x4779320 | 322 bytes | u64 to decimal text in a 20-byte scratch buffer (4-digit lookup) |
| 0x4787e90 | 142 bytes | `Vec<u8>` amortised growth (reserve for push) |
| 0x4787da0 | 233 bytes | allocation front end: layout check, malloc / realloc / aligned variants |

- The key text `bucket_limit_mult_threshold` (27 = 0x1b bytes) is passed by 0x4783f20 to 0x4777cc0; the string appears next to
  `struct AlertConfig with 1 element` and `ip_rate_limiter_alert_config` in `.rodata`.
- GOT slots reached (`pointer-slots.tsv`, relocation types read from `.rela.dyn`): memcpy 0x64df508, raw-vec error 0x64df498,
  unreachable-panic 0x64df730 (message `internal error: entered unreachable code`, 40 bytes), add/sub overflow panics 0x64df520 and
  0x64df848, malloc 0x64df480, realloc 0x64df588, aligned realloc 0x64df580, aligned malloc 0x64df590; data slots 0x64e13d8
  (escape class table, 256 bytes) and 0x64e13e0 (hex digits). Slot roles are inferred from argument shapes and checked by stubs.
- `escape-table.tsv`: the 34 non-zero classes of the table in the image (`u` for control bytes, `b t n f r`, `"`, `\`) equal the rule list.
- `direct-callers.tsv`: direct call/jmp sites of the five bodies; `function-rows.tsv`: every decoded instruction with the number of cases
  reaching it.

Rules reproduced (all confirmed by 15,034 cases):

1. Object writer: depth is incremented (depth = 2^64-1 panics with the add-overflow slot before any write), `has_value` cleared, `{`
   written, one member with state (ok, first), then `\n`, `depth` copies of the indent string (only when depth is non-zero), `}`.
2. Member writer: state byte 1 panics (`unreachable`); first member writes `\n`, later members `,\n`; then `depth` indent copies; key
   run-copied with escapes (`\u00XY` lower-case hex for class `u`, otherwise backslash plus class byte; bytes >= 0x80 and DEL are raw);
   `": "`; decimal value; `has_value = 1`; state byte 1 becomes 2.
3. Every write of n bytes grows the buffer first when `cap - len < n`: new capacity = max(2*cap, len+n, 8) for byte vectors
   (minimum is 8 for size 1, 4 for sizes up to 1024, else 1); the log of `malloc` (cap 0) / `realloc` requests is predicted exactly.
4. Allocation front end: size = elem*newcap, error when it overflows u64 or exceeds 2^63 - align; zero size returns the dangling
   pointer `align`; plain allocator when `align < 17 and align <= size` or `ctz(align) == 0`, else the aligned variants with `ctz(align)`;
   a null result becomes the `(align, size)` error; an add overflow or element size 0 becomes the capacity-overflow error.

## Implementation and comparison

`tools/transport_alert_json_115.py` holds (a) the rule list (`spec_*`), written from the bytes and not from the evaluator, and (b) the
harness: heap images for the serializer, `Vec`, key, indent and scratch, recording stubs for the GOT slots, failure injection for the k-th
allocation, and a comparison of result bytes, capacity, whether the buffer moved, depth, `has_value`, state bytes, the allocator call log
and panic kind. Not implemented here: a Rust port, the AlertConfig reader, and the enclosing config writer. The evaluator and decoder are
reused from `tools/funding_rate115.py`; the stubs, rule list and case generators are new.

Controls: 14 wrong readings of the rule list (comma first, indent omitted, upper-case hex, DEL escaped, newline as `\u000a`, backslash
raw, tight colon, zero-padded decimal, closing brace without indent, exact-need growth, no minimum of 8, minimum 4, limit off by one,
aligned allocator unused) are each refused; 18 structural controls (wrong digest, mid-function addresses of all five bodies, NOBITS
offset, short decoder windows, truncated section table, missing memcpy model, callees not real, int3 entry bytes, shifted table pointers,
step budget, tampered rule table) are all detected. Byte edits of every reached conditional jump, immediate and structure displacement
(`edits.tsv`): 261 edits, 229 change an observable outcome on the 400-case subset; the 32 survivors were not
distinguished by the sampled cases (cause not analysed) and are listed with `killed = 0`; they are not counted as negative controls.

## Results and limitations

- `measure.json`: cases 15,034, mismatches 0, negative controls 32, detected 32; edits 261, killed 229.
- Limits: roles of the GOT slots and body names are inferences from argument shapes; the allocator is modelled, not run; floating
  formatting is not involved (the member is a u64). Only depth values below 6, indent strings up to 8 bytes and keys up to 40 bytes are
  generated; the AlertConfig reader at 0x4784750 and the enclosing config object are not covered. No progress gate is requested.
- Next question: the AlertConfig reader (deserialize path, `struct AlertConfig with 1 element`) and the parent writer that emits
  `ip_rate_limiter_alert_config`, `tcp_lz4_stats` and `traffic_logger`.
