# fees: conversion and accumulation path at 0x37153f0 (node #94)

- Component ID: fees (path rule `l1/fees/*`, first task "maker/taker fee formulas")
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository
  `1f8c67c63ca4794c9689235471c60297f8a5c985`; reference lead
  `references/can1357-hl/l1/fees/compute.rs` (used as a seed and compared below, nothing
  copied)
- Claim status: observation for the decoded bytes, constants, panic records, the exact division
  and the evaluated outcomes; inference for names and roles; unresolved items at the end
- Scope included and excluded: included - the whole function: asset split, multiplier, three
  float-to-integer conversions, two clamps, two divisions, six checked additions, five checked
  multiplications by 100, the three B-tree searches, the side branch and the two set calls.
  Excluded - the bodies of the callees (stubbed), the meaning of the record fields, the sibling at
  `0x372faa0`, the fee validator, node #115.

## Reproduce

Working directory: repository root. Platform used: Linux x86-64, Python 3.12 (standard library
only). The tool runs no external program, so its output does not depend on a binutils version. The
node is only read as a file and is never executed; the evaluator below interprets its bytes in
Python.

```
python3 tools/artifacts.py verify
python3 tools/fees_unit_conversion.py --out research/work-items/fees-unit-conversion-94
python3 -m unittest tests.test_fees_unit_conversion
sha256sum -c research/work-items/fees-unit-conversion-94/MANIFEST.sha256
# optional, for a human reader only; no evidence file uses this
objdump -d -M intel --start-address=0x37153f0 --stop-address=0x3715e8b artifacts/node/94/hl-node
```

The tool refuses to run if the input SHA-256 differs. It prints
`{"hook_calls": 6, "instructions": 576, "instructions_not_executed": 3, "mismatches": 0,
"mul_100_branches": 5, "vectors": 3436}` and writes:

- `evidence.json`: extents, constants, sites, panic records, callers, coverage.
- `instructions.tsv`: every instruction with its size, bytes and decoded form, from the tool's own
  decoder.
- `vectors.tsv`: 3436 evaluated inputs and outcomes.
- `reference-diff.tsv`: ten inputs run on the binary bytes and on the reference formula.

## Evidence

Coordinates are ELF virtual addresses. The function is `0x37153f0..0x3715e8b` (FDE `0xe4c1a8`, 2715
bytes; `.eh_frame_hdr` has 121299 entries). It has no direct call site: pointer slot `0x5774560`
names it through a RELATIVE relocation, and `call [rip+d]` byte patterns through that slot occur at
`0x24fc475`, `0x4329c95` and `0x432a525`.

Method. A table decoder reads the bytes from the FDE start and must land exactly on the FDE end; any
encoding outside its table is an error. It yields 576 instructions. An evaluator then interprets
those instructions from the function entry to `ret` or a panic:

- General registers, flags and SSE scalar operations are modelled; doubles use Python's IEEE binary64.
- Input records are strict: reading a byte the scenario did not set is an error, so no evaluated path
  depends on a field the scenario left out.
- Every call is a stub. A stub keeps the callee-saved registers and overwrites the rest with junk, so
  the function cannot pass by relying on a value that a real callee may destroy.
- The B-tree stubs read back the entry handle the search built and check it against the key and the
  expected slot, so the search loops are tested too.

Each outcome is compared with `model()` in the tool, a separate closed form. The steps below are what
that model states, with `rdi = state`, `rsi = record`, `edx = side`, `rcx = runtime`:

1. Inputs. `asset = [record+0x208]`, `ntli = [record+0x218]`, `day = [record+0x228]` (32 bits),
   `tag = [record+0x234]` (byte). The per-side block is at `record + side*0x100`. Its user id is 20
   bytes at `+0xd8`.
2. Admission. `asset / 10000` must equal `[state+0x30]` and `asset % 10000` must be below
   `[state+0x10]`. Both failures reach one panic at `l1/src/perp_meta.rs:194:38`. `ntli < 0` panics
   through `Result::unwrap` with location `l1/src/qtys/mod.rs:843:1`. Asset records have a 48-byte
   stride.
3. Multiplier. `m = [runtime+0xa0]` when byte `[state+0x58]` is set, otherwise 1.0 (`0x20a730`). When
   the asset byte `+0x29` is zero, `m *= 0.1` (`0x20a880`).
4. Conversion. `to_i64(x)`: NaN and both infinities give 0, `x <= -2^63` gives `i64::MIN`,
   `x >= 2^63` gives `i64::MAX`, otherwise truncation toward zero. There are three copies.
5. Rate step, two copies, `rate = [state+0x2a0]`, `LIMIT = 0x28f5c28f5c28f5c`,
   `CLAMP = 0x147ae147ae147ae`:

   ```
   s        = to_i64(m * f64(ntli))
   scaled   = (s > LIMIT    ? max(s, 0) : step(max(s, 0))) / 10000
   unscaled = (ntli > LIMIT ? ntli      : step(ntli))      / 10000
   step(v)  = x = to_i64(f64(v) * rate); panic if x == i64::MIN;
              max(min(max(x, -CLAMP), CLAMP), 0)
   ```

   The panic is at `library/core/src/num/mod.rs:320:5`. `LIMIT` equals `u64::MAX / 100`, `CLAMP`
   equals `i64::MAX / 100`, and `0xfeb851eb851eb852` is `-CLAMP`. The tool asserts these relations.
   Above `LIMIT` the rate is not applied at all. Both `/ 10000` are exact floors for every u64 by the
   round-up reciprocal test (`magic == ceil(2^75 / 10000)` and `0 < magic*10000 - 2^75 <= 2^11`).
6. Optional split, when the qword at `side block + 0x58` is not 2. `scaled` is added to the entry that
   `0x3596da0` returns for the user, under the 64-bit key `[state+0x50]`. Five amounts at `+0xa8`,
   `+0xb0`, `+0x60` (when bit 0 of the qword is set), `+0x88` (when `+0x80` is 1) and `+0xb8` are
   multiplied by 100, and any overflow panics at `l1/src/fees/compute.rs:50:42`. They then go to
   `0x3745a60` with the two optional 20-byte recipients.
7. Accumulation. Six additions call the hook at slot `0x5773190` with location
   `l1/src/qtys/impl_ntl.rs:664:1` on carry, then store `u64::MAX` and go on: the split entry above,
   `[user+0x40] += scaled`, `[user+0x48] += unscaled`, `[day entry + 8*(tag == side)] += scaled`, and,
   only for nonzero `side`, `[total entry] += scaled` and `[total entry + 8] += unscaled`.
8. Keys. The day maps compare `day` with `setl`/`setg`, so the key is a signed 32-bit value; a stored
   key of -3 sorts below 20 in the vectors. The other map compares a 64-bit key unsigned.
9. Set calls. The word `[user+0x20]` is read before and after the day-map call. `0x339b590` runs only
   on a change from 0 to nonzero and `0x33acfe0` only on a change from nonzero to 0.

`l1/src/fees/compute.rs` appears once in `.rodata`, and exactly one RELATIVE relocation points at that
string, so `0x570b510` is the only panic record that names the file.

Analysis was complete for this function's own instructions; callee bodies were not analysed.

## Implementation and comparison

Not yet implemented. No Rust component is added and no differential execution was run, so there is
no build comparison and no normalization mask.

Comparison with the reference lead, which is not a target comparison. Rows marked
`reference-diff.tsv` are computed; the others come from reading the reference source:

| item | `l1/fees/compute.rs` | binary |
|---|---|---|
| post-rate clamp (`reference-diff.tsv`) | `0x0014_7ae1_47ae_147a` (line 20) | `0x0147_ae14_7ae1_47ae`; the reference value is this one shifted right by 4 bits, and line 198 of that file has this value in a comment |
| pre-rate limit | `0x028f_5c28_f5c2_8f5c` | same value |
| product of `i64::MIN` (`reference-diff.tsv`) | gives 0 | panic |
| scale by 100 overflow | returns `Err(ComponentScaleOverflow)` | panic |
| dex mismatch, asset bound | returns `Err` | panic |
| negative notional | returns `Err(NegativeNotional)` | `Result::unwrap` panic |
| day key | `DayBucket = u32` | signed 32-bit compare |
| active set | sets or removes on every call from a bool | one call, only when the 64-bit word changes |

With rate 1.0 the binary and the reference first differ at notional 5764607523040000 (576460752304
against 576460752303 units). At `LIMIT` the binary gives 9223372036854 and the reference
576460752303. They agree again above `LIMIT`, where the rate is skipped.

## Results and limitations

- Decoding: 576/576 instructions from the FDE start to the FDE end, using no external program. As a
  one-off authoring check, not part of the evidence, GNU objdump 2.42 listed the same 576 addresses and
  the same operation names.
- Evaluation: 3436/3436 vectors match the model, 0 mismatches: 3300 rate, 12 admission, 28 saturation,
  48 split, 40 tree and 8 set-call. Outcomes: 3347 ok, 16 at `compute.rs:50:42`, 67 at the abs panic, 4
  at `perp_meta.rs:194:38`, 2 at the unwrap. The 3300 rate vectors are a product of boundary values,
  which is a sample, not a proof over all inputs.
- Coverage: 573/576 instructions executed. The other 3 are padding nops (`0x371579c`, `0x3715ace`,
  `0x3715d1e`).
- Sites: 6 hook calls, 5 multiplication panic branches, and 8 64-bit immediate loads of 6 distinct values
  (`immediates_64` in `evidence.json`).
- Whole-domain proof: only the floor division.
- Boundary note: the branch on `s` is `jg` at `0x3715555`, but `s` comes from a double and `LIMIT` has no
  exact double (nearest values `0x28f5c28f5c28f40` and `0x28f5c28f5c28f60`), so `s == LIMIT` cannot
  occur. A test changes `jg` to `jge` and shows no vector moves. The unsigned branch on `ntli` at
  `0x3715611` is an integer boundary, and changing it does move a vector.
- Unit tests: `tests/test_fees_unit_conversion.py`, 47 tests. Negative controls: wrong digest; a wrong
  file through the CLI; addresses outside the image; truncated and over-wide ULEB128; an unlisted opcode;
  an FDE overrun; changed 64-bit immediates; changed float constants; a wrong pointer slot; magic +/- 1, a
  wrong shift and a wrong divisor; and byte mutations of the rate field, the unsigned branch, the tag
  compare, the division shift, two multipliers of 100, the panic and hook locations, the side branch and
  the signedness of the day compare.
- Inferences, not proven:
  - `scaled` and `unscaled` are a scaled and a raw quantity. The reference calls them fee units, while
    its `l1/raw_vlm.rs` comment calls value offsets `+0x40` and `+0x48` scaled and raw volume. The hook
    location is in `impl_ntl.rs`, so the binary does not settle the name.
  - `0x339b590` inserts into and `0x33acfe0` removes from a set; that reading comes from their calling
    pattern only, and the stubs do not establish it.
  - `LIMIT` and `CLAMP` look like an inlined guard for a later multiplication by 100.
  - `0.1` and `[runtime+0xa0]` are fee multipliers, as the reference suggests.
  - This is the perp path. `0x37153f0` panics in `perp_meta.rs`, and a comment in
    `references/can1357-hl/l1/exchange/handlers/34_twap_cancel.rs` labels its caller `0x24fb610` as the
    perp persist path. That comment is a lead, not evidence.
- Unresolved: what `[state+0x2a0]` is; which record type `rsi` is; whether a real callee can change
  `[user+0x20]` during the day-map call, because the evaluator only flips it through a stub; which values
  the rate takes in practice; the three callers; node #115.
- No progress gate is requested.

Next question: `0x372faa0` sits in the pointer slot after this one and reuses the same helpers with
different constants (`/ 5`, `/ 1000000`, a threshold of 999999). What are its branches and rounding?
