# RE-004: per-asset mark quantity pass 0x2c4fe30 on node #115, rebuilt as a model and proven against the bytes

The 2,225-byte function at `0x2c4fe30` is now a written-down rule list: for one dex entry it walks the asset slots `10000 * id + i`, resolves each slot's
oracle index through a ring of pairs or an ordered map, reads the index's mark integer from a hashed table, scales it by the book scale `(s - 1.0) + 1.0`
(or exactly `1.0` for the first dex's `HYPE` and `PURR` rows), rounds half away from zero, saturates to u64 (never below 1), divides by `10**(6 - size decimals)`,
converts the f64 to a 96-bit decimal with the already proven converter `0x5c43c60` (both flags 1) and inserts it into a local map before handing the map to
`0x2c509b0`; a Python model of this agrees with the original bytes, run in an x86-64 interpreter, on 10,000 generated cases (400 of them also run the real converter bytes),
which lets a Rust rewrite take the pass as a pure function of the dex entry, the book scale and the mark table.

- Component ID: RE-004 (hl-quantities; sources named by the assignment: `l1/asset/pdi.rs`, `l1/dex_registry/clearinghouses.rs`, `l1/perp_meta.rs`, `l1/spot_meta.rs`, `l1/books.rs`, `base/l1_map/entry.rs`)
- Target release and full SHA-256: node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit: a8616af94 (origin/main at the start of the run); no #94 material and no reference-repository label was used
- Claim status: observation for the rule list agreeing with the instruction bytes on the generated cases, for the field table and the constants; inference for the
  names of fields and for what the stubbed callees compute; unresolved items are under Results and limitations
- Scope included and excluded: included is the root FDE `0x2c4fe30..0x2c506e1` (433 decoded instructions, 27 call edges). Run as real bytes: everything in the root and, in 400 cases,
  the converter `0x5c43c60`. Stubbed at the call edge and checked for their arguments: drop guard `0x44e0810`, ordered-map search `0x35bd660`, ring search `0x45547e0`, mark table
  probe (slot `0x64e78b0`), round leaf (slot `0x64e1890`), map insert `0x2dc25d0`, sink `0x2c509b0`, drop and drain helpers, the allocator free slot and the panic slots.
  The bodies of `0x2c509b0` (4,344 bytes) and `0x2dc25d0` (1,154 bytes) are not reconstructed here; only their call contract is.

## Reproduce

From the repository root on Linux with Python 3 and the pinned binary in place:

```
python3 tools/artifacts.py verify
python3 tools/quantity_mark_pass_115.py --out research/work-items/RE-004-quantity-mark-pass-115
python3 -m unittest tests.test_quantity_mark_pass_115
(cd research/work-items/RE-004-quantity-mark-pass-115 && sha256sum -c MANIFEST.sha256)
```

The tool checks the input SHA-256 first, never runs the binary, calls no external program and reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`
(via the copied interpreter `tools/quantity_pass_x86_115.py`). It reuses the converter specification `spec_kernel` of `tools/decimal_from_f64_115.py`. One run takes well under a minute.
Cases are built, run and compared one at a time; only counters and one signature line per case are kept. `--cases N` changes the corpus size (default 10000; `cases.tsv` keeps the rows of odd seeds, 5,000 lines).

## Evidence

Coordinates are virtual addresses of the #115 image.

### Rule list read from the instructions (constants are read from the bytes, `constants.tsv`)

Arguments: rdi output (u16 result word), rsi book, rdx an object of which only 21 bytes are copied, rcx dex index, r8 a 32-byte value moved to the sink. Field offsets are in `fields.tsv`.

1. `0x2c4fe44`: `rcx >= book[+0x7d0]` panics through slot `0x64df6a0` (location record at `0x648c5f8`). The entry is `book[+0x7c8] + rcx * 0x510`. The drop guard `0x44e0810` runs twice on a stack tag `0x156`.
2. `0x2c4fee7..0x2c4ff11`: entry `+0x378 == 0x8000000000000000` or entry `+0x408 == 0x8000000000000001` writes `0x19e`; otherwise entry `+0x58 != 0` writes `0x101`. Either early exit
   then consumes the r8 value: first word `0x8000000000000000` drains it with `0x2447830`; any other first word is a capacity and a nonzero one frees `capacity * 24` bytes at the pointer in word 1 (slot `0x64df4a0`).
3. Otherwise, with `n = entry[+0x10]` slots and book scale `s = book[+0x7a0]`, `scale0 = (s + (-1.0)) + 1.0` (constants `0x458dc8`, `0x4592b0`), for `i < n`:
   key `= 10000 * entry[+0x50] + i`, a multiply overflow panics (slot `0x64df870`), an add carry panics (slot `0x64df520`).
4. The key is looked up in the entry's ring (`+0x428` capacity, `+0x430` buffer, `+0x438` head, `+0x440` length, 16-byte pairs key, value; position `head + index` wrapped once) or, when `+0x428` is
   `0x8000000000000000`, in the ordered map rooted at `+0x430` with height `+0x438` (value at node `+0x60 + 8 * idx`). A miss skips the slot. The value `v` is an oracle index.
5. The mark is the table probe in the **first** entry (`book[+0x7c8] + 0x148`, hasher words `book[+0x60]` and `book[+0x68]`); a zero or missing mark skips the slot.
6. If the first entry's id is 0, `v <= 0x270f`, `v` is below the first entry's row count (`+0x10`), the row's name length (`+0x10` of the 32-byte row at `+0x8`) is 4 and its first four name bytes are `HYPE` (`0x459f10`) or `PURR`
   (`0x45a1e8`), the scale is `1.0`; otherwise it is `scale0`.
7. `count = max(1, saturating_u64(max(0, round_half_away(f64(mark) * scale))))`. Infinity becomes 0 before the cast, the value is clamped at `2**64`, anything above `0x1.fffffffffffffp+63` saturates to u64::MAX
   (constants `0x459090`, `0x459360`, `0x458d58`), and a result of 0 becomes 1. The rounding is the leaf behind slot `0x64e1890` (add-copysign-truncate, proven equal to round half away in `spot_scale_roundup_fc0_115`).
8. `v / 10000` must equal the first entry's id and `v % 10000` must be below its row count, otherwise the panic at `0x64768a8` (slot `0x64df830`). The row byte at `+0x1d` is the size decimals; `>= 7` panics (slot `0x64df848`).
   The quantity is `f64(count) / 10**(6 - decimals)` (table `0x5ed748`).
9. The f64 is split (implicit bit `0x100000`, exponent bias 1075, or 1074 for exponent 0) and passed to `0x5c43c60` with both flags 1. A refusal or a non-finite value skips the slot (`0x2c94f00`). A success calls the drop helper
   `0x42320d0` and inserts the 16-byte decimal at the key through `0x2dc25d0` (the call passes `rcx = rsp+0x114`, the decimal itself).
10. After the loop the sink `0x2c509b0` receives (out, book, 0, the 32-byte r8 copy, a 22-byte block with a leading 1 and the first 21 bytes of rdx, the local map, and the entry pointer on the stack).
    On every non-early path the result word is therefore written by the sink; the harness gives it a marker.

### Static tables

`callees.tsv` lists every call edge of the three members decoded from the FDE bytes (root 27 calls, sink 47, insert 11) and the three FDE sizes (2,225, 4,344 and 1,154 bytes). `constants.tsv` lists the nine constants with their bytes.
The relation to the funding premium body (`RE-014-funding-premium-115`) is consistent: the same entry layout (`+0x08` row pointer, `+0x10` count, `+0x50` id, 32-byte rows with decimals at `+0x1d`) appears there.

### Instruction excerpt (objdump, intel syntax)

```
2c500b1: mov eax,0x2710 ; 2c500b6: mul QWORD PTR [rbp+0x50] ; jo -> 64df870          key = 10000 * id + i, both overflows panic
2c502a3: movabs rdx,0x346dc5d63886594b ; 2c502b0: shr rdx,0xb ; cmp rdx,r14 ; jne      v / 10000 == first entry id
2c50298: cmp rcx,0x1 ; 2c5029c: adc rcx,0x0                                            count 0 becomes 1
2c502de: movzx eax,BYTE PTR [rax+r12*1+0x1d] ; cmp rax,0x7 ; jae                       size decimals < 7
2c50436: mov r8d,0x1 ; 2c5043c: mov r9d,0x1 ; call 5c43c60                             converter flags
```

## Implementation and comparison

`model(case)` returns the event list and result for a case. `Harness` loads the case into the interpreter heap (book, entries at stride `0x510`, rings, a stub ordered-map node, metadata rows, the r8 value), runs `0x2c4fe30` and records
every hook call. A case passes when the machine's event list and result equal the model's; panics are compared by slot and by the events before them. Case generation is seeded and deterministic: oracle indices, marks of every magnitude up to u64::MAX,
scales including 0, negative, NaN, infinity and 1e300, both lookup forms, both early exits, bad dex index, decimal 7 and 9, an id mismatch, and two kinds of key overflow. Seeds congruent 7 mod 300 build a first entry with 10,000 rows so the
`v <= 0x270f` boundary is reachable at index 9,999.

## Results and limitations

| Item | Value |
|---|---|
| Cases compared (machine equals model) | 10,000 (`cases.tsv` keeps the 5,000 odd-seed signature lines); 400 also run the real converter bytes |
| Outcomes | sink 4,252; result `0x19e` 1,461; result `0x101` 1,614; panics: oracle id 1,314, size decimals 973, dex index 293, key add 48, key mul 45 (`outcome-kinds.tsv`) |
| Negative controls | 46 (32 one-byte patches of the pass, 14 model variants); 45 detected, 1 equivalent (`controls.tsv`, `equivalent-mutants.tsv`) |
| Equivalent control | `0x2c50406` (zero-mantissa test): the exponent-0 branch is unreachable because `count >= 1` and the divisor is at most `10**6`; the corpus counts 0 reaches of it (`dead_branch_reaches` in `measure.json`) |

Limits and unresolved items:

- The bodies of `0x2c509b0` and `0x2dc25d0` are not rebuilt. Observed only: the insert callee receives the map (`{0, 8, 0, 0}` initially, length at `+0x18`), the key and a 16-byte value, and its first instructions test a `0x8000000000000000` tag and a length against `0x20` and `0x40`
  (small-vector to ordered-map upgrade is an inference, not shown). The sink's role (what it does with the map) is unresolved.
- The two callers of the root were not resolved; the meaning of the `rdx` object (only 21 bytes copied) and of the `r8` value is unresolved. Names such as "dex entry" and "mark" are inferences from the field use.
- The exponent-0 and zero paths of the decimal split are modelled as in the bytes but cannot be reached by the corpus (see the equivalent control); the non-finite skip after the division is likewise unreachable with the table values.
- The ordered-map and ring searches are stubbed by exact-key lookup; their search order is not part of this claim. The converter is run as real bytes only in 400 cases and is otherwise the specification of the earlier converter packet.
- This does not raise any gate in `docs/PROGRESS.md`.

## Next question

Rebuild `0x2dc25d0` (insert into the local map: small form, conversion at the length thresholds, ordered-map insert) with its callees `0x2348e20`, `0x24c7070`, `0x23a54e0` and `0x24bdde0`, then the sink `0x2c509b0`.
