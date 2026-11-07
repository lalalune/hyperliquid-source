# risk: rmp-serde newtype(BTreeSet<OutcomeRecord>) serializers, the five-field record writer and the 0x98-byte-key B-tree Iter::next (node #115)

This packet makes it possible to rebuild, as one executable Python model, the MessagePack writer of the ordered set of
five-field records (`outcome`, `settleFraction`, `details`, `nameAndDescription`, `sideNames`) in the 0x226/0x419/0x52f
serializer copy families: the set body's reserved-name reject, u32 length test, array header and counted-compound path,
the record writer's field order, key tests and marker byte, the two-string helpers, and the B-tree `Iter::next` over
0x98-byte keys. The model was checked against the real bytes of 3 set bodies, 3 record writers (one of which tests
a different flag value than its siblings), 3 `Iter::next` copies and 20 dependency functions on 17,400 cases with
0 mismatches, and 107 of 107 negative controls were detected.

- Component ID: `risk` (field names `outcome` / `settleFraction` / `sideNames` mark an outcome record; the component
  is an inference from those names, the bytes only fix the layout and the writer calls)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: lalalune/hyperliquid-source main `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`; no reference source
  used (references/can1357-hl was not consulted for these bodies)
- Claim status: observation (bytes, call pattern, executed behaviour of the original instructions) + inference
  (the rmp-serde / `std::collections::BTreeSet` names and the outcome-record reading of the field names)
- Scope included: the three 727-byte set bodies 0x226c320, 0x41a70c0, 0x52f0c10 (serializer-first layout "a"), their
  record writers 0x28ff740 / 0x44b83e0 / 0x50c01d0, the three 536-byte `Iter::next` copies 0x238a340 / 0x37cc740 /
  0x5133fb0; header, uint, string, two-string helpers, tuple end and `Compound::end` run for real as dependencies
  (see `coverage.tsv`). Excluded: the layout-"b" siblings 0x2271480 / 0x41a5a00 / 0x52fc050 and their direct record
  writers 0x28ffab0 / 0x44b81c0 / 0x50c0580, the 3,545-byte callers of the record writers, `finish_grow`, strings of
  65,536 bytes or more. No progress gate is requested.

## Reproduce

From the repository root (Python 3 standard library only; binutils not needed; the binary is never executed):

```
python3 tools/risk_outcome_set_115.py --out research/work-items/risk-outcome-record-set-115
python3 -m unittest tests.test_risk_outcome_set_115
```

- The tool checks the input SHA-256 first and stops on any other binary.
- It writes `bodies.tsv`, `records.tsv`, `iter-next.tsv`, `cases-sample.tsv`, `next-cases-sample.tsv`,
  `controls.tsv`, `undetected-flips.tsv`, `coverage.tsv`, `summary.json` and `measure.json`.
- Two runs with different `PYTHONHASHSEED` and `TZ` give byte-identical files.
- The generator retains cases and their evaluated outputs while computing coverage and negative controls.
  `--per-body N` (default 1500), `--per-rec N` (default 3000) and `--per-next N` (default 1300) change the case counts.
- Case generation is a SHA-512 counter stream keyed by unit; `cases-sample.tsv` holds every 5th set case and every 6th
  record case, `summary.json` carries a SHA-256 over the output bytes, results and call lists of all cases.

## Evidence

Coordinates are virtual addresses in node #115; sections are mapped through `tools/elf_index.py`, FDE extents come from
`tools/fde_extents.py`. Every number in the tables is read from ELF bytes by the tool.

### Set body (0x226c320, family 0x226)

Human-readable excerpt (`objdump -d -M intel`, not used by the tool):

```
226c341: cmp    rcx,0xa                       ; name length, "_ExtStruct" test follows -> (9223372036854775810, 'expected tuple', 14)
226c368: mov    rax,[r8] ; mov rcx,[r8+8]     ; set record {root, height, length}
226c3d8: jne    226c402                       ; length >= 2^32 (shr by 0x20) -> malloc(0x80) compound
226c3e2: call   25e7c10                       ; array header (low 32 bits of the length)
226c4ad: call   238a340                       ; Iter::next -> *record or NULL
226c49b: call   28ff740                       ; record writer, serializer in direct mode
226c4cb: call   28ff740                       ; record writer, compound in buffered mode (counter at +0x20, panic at 0xffffffff)
226c56c: call   227e1b0                       ; Compound::end
```

### Record writer (0x28ff740, family 0x226)

```
28ff757: movzx  ebp,byte [rdx+0x1b] ; xor bpl,1 ; shl bpl,4 ; or bpl,0x85     ; marker = ((flag ^ 1) << 4 | 0x85) & 0xff
28ff783: cmp    byte [r15+0x1b],1                                             ; key "outcome" only when the flag is exactly 1
28ff7e0: call   25e9f10 (rdx = [r14+0x90])                                    ; outcome u64
28ff84b: call   25e8bf0 ([r14+8],[r14+0x10])                                  ; settleFraction string (key 0xae + 14 bytes before it)
28ff8af: call   25e8bf0 ([r14+0x20],[r14+0x28])                               ; details string
28ff8df: call   25e8bf0 ("nameAndDescription", 0x12) ; 28ff8f8: call 22e6f10   ; value: 0x92 + two strings at +0x30 / +0x48
28ff91e: call   25e8bf0 ("sideNames", 9)    ; 28ff942: call 22771c0 ("SideMap", 7) ; value: two strings at +0x60 / +0x78
```

The three copies run the same field sequence. `records.tsv` lists the `cmp byte [ser+0x1b], imm` immediates in code
order: 1,1,1,1,1 in the 0x226 and 0x419 copies and 1,1,1,0,1 in the 0x52f copy, whose `nameAndDescription` key is
therefore written for every non-zero flag value (a test over the generated cases, not an assumption).

### Iter::next over 0x98-byte keys (0x238a340)

Node layout read from displacements: parent at +0, key i at `8 + 0x98 * i` (11 keys), parent index u16 at +0x690, length
u16 at +0x692, edge i at `0x698 + 8 * i`; a leaf is 0x698 bytes. The control flow is the one of the u32 version
(lazy first-edge descent, parent walk, right-edge descent, remaining length at `+0x40`, two unwrap panics) with these
offsets; `iter-next.tsv` lists the panic Locations decoded from the rip-relative `lea` operands.

## Implementation and comparison

`tools/risk_outcome_set_115.py` is a single standard-library module: an x86-64 subset evaluator (decoder raises on
unknown forms) plus the reconstruction.

- `record_model` writes the record in the order above, with `write_uint` / `write_str` / `write_array_len` models
  (smallest form; marker byte before payload; one `reserve` call per marker, length and payload write); every writer call
  is an event and a fault point, so fault `k` makes the `k`-th writer call fail without running it, and the three
  result conventions (header/uint in memory with Ok = 2, helpers in memory with Ok = `0x8000000000000004`, string
  writer in registers) are all exercised.
- `body_model` adds the reserved-name reject, the set record, the u32 length test, the direct array header and the
  buffered compound (counter, config word masked with `0xff0101`, free on error, panic at the end of the tree).
- `next_model` is the iterator. `reference_bytes` is an independent MessagePack encoding of the record list used as an
  oracle for every valid direct case (length equal to the record count, below 16).
- The two-string newtype `0x22771c0` ends with the tuple end `0x22999e0`; its capacity word is the direct mark
  `0x8000000000000000`, `neg` overflows, and it returns Ok without writing: the model has no trailing bytes there.
- Cases: 17,400 in total (alloc_error 147, buffered_fault 188, buffered_panic 427, direct_fault 448, direct_ok 545, direct_ok_oracle 929, direct_panic 495, empty_set 757, ext_error 564, next_bad_tag 280, next_empty 354, next_lazy 180, next_mid 3086, record_array 1198, record_fault 4493, record_flag_other 2401, record_named 908).
- Mismatches: 0. Coverage: 3131 of 3880 instructions of the 29 functions in `coverage.tsv`.
- Negative controls: 107 of 107 detected (bytes 77, model 23, range 7); 17 byte flips of reached
  instructions had no witness in the generated cases (`undetected-flips.tsv`, not counted as controls).

Rust path, Cargo.lock and build flags: not yet implemented; this packet is a Python reconstruction checked against the
original bytes, no Rust comparison is claimed.

## Results and limitations

- 17,400 cases, 0 mismatches, 107/107 controls detected
  (`measure.json`).
- The fixed `reserve` / `finish_grow` contract (capacity becomes length plus the request; growth must not be reached),
  `malloc`, `free` and `memcpy` are stubs; the cases keep room for the direct path.
- Strings of 65,536 bytes and more (the `0xdb` form) are not generated; the str32 arm is run only as far as the
  generated lengths reach.
- The component and the record meaning come from field names; the bytes do not name an owner type.
- No progress gate is requested; this does not cover the whole `risk` or `constants` component.

Next question: the layout-"b" siblings 0x2271480 / 0x41a5a00 / 0x52fc050 with the direct record writers 0x28ffab0 /
0x44b81c0 / 0x50c0580 (map/array header pair 0x25e7670 / 0x25e7940, inlined growth), and the 3,545-byte callers
0x2901c80 / 0x44ba320 / 0x50c7b10 of the record writers.
