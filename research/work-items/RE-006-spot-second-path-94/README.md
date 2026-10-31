# RE-006: second spot order path: reserve step, order run, two health reads, shortfall set insert, three copies

- Component ID: RE-006 (book state transitions)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is used as a list of labels to check.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included, whole and with mutants, are the three bodies `0x4d2f4a0`, `0x4d2e9e0`, `0x2726ce0`, the snapshots `0x46f2be0`, `0x46f2960`, the reserve steps `0x46f09e0`, `0x46f08a0` and the post checks `0x46f26f0`, `0x46f2480`, `0x2739b00`. Stubbed at the edge, with arguments compared: ratio report `0x373d8e0`, health report, map clone and drop, reserve and apply helpers, order runner, settle, set insert, balance lookup, free, memcpy, memcmp and the lazy init call. Excluded: the bodies of all those helpers, and the other callers of the snapshot and post check.

## Reproduce

From the repository root:

```
python3 tools/spot_second_path.py --out research/work-items/RE-006-spot-second-path-94
python3 -m unittest tests.test_spot_second_path
```

The tool takes about 20 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `call_sites.tsv`, `cases.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs (`functions` in `evidence.json`).

### What the reference leaves open

`l1/spot_clearinghouse/cl_trait.rs:338` declares `replace_order_after_existing_lookup_main_book` and `_alt_book` with no body. The four spot adapters call `0x4d2f4a0` or `0x4d2e9e0` at that point (`call_sites.tsv`). `0x26d0e50` and `0x26d16b0` call the third body `0x2726ce0`.

### The path

Arguments: `rdi` result, `rsi` state, `rdx` order block. All three bodies follow the same steps. The first two have the snapshot, reserve step and post check outlined. The third has the first two inlined.

| # | Step | On a stop |
| --- | --- | --- |
| 1 | Find the user (`+0xb0`, 20 bytes) in the map at state `+0x598`, or take the default row | |
| 2 | Ratio report `0x373d8e0` of that row. Save word `+0x18` / word `+8` as doubles when `+8` is not 0 | word `0x187`, report code, vector freed |
| 3 | Snapshot: find the row again, clone its map, health report (`r8` 0) | word `0x187`, report code, map dropped, vector freed |
| 4 | Both health words must be non-negative as `i64`. Save `margin = +0x10 - +8` | panic `l1/src/qtys/mod.rs:843:1` |
| 5 | Row `u32` at `+8` must not be 0 | word `0x187`, row byte `+0`, vector freed |
| 6 | Reserve step when last (`+0xa8`) is not 0, mode 3 on the base token (`+0x98`) | see below |
| 7 | Run the order: first `0x48` bytes and next `0x50` bytes of the block, runner flag 0 | |
| 8 | Settle the quote token (`+0xa0`), then the base token, flag 0 | |
| 9 | Second ratio report | result becomes word `0x187`, report code; order result dropped |
| 10 | When both denominators are nonzero and the first ratio is strictly above the second: balance lookup `0x371b3a0` on state `+0x80` | |
| 11 | Post check, always, also after a stop in 6 or 9 | |
| 12 | Result out | |

Result rules at step 12: a post check stop gives word `0x187` with its code, and the order result is dropped unless it was already `0x187`. Run word `0x188` turns into word `0x187` with the byte at result `+2`. Any other word goes out whole, `0x60` bytes.

The vector at `+0x70`, `+0x78` has rows of `0x48` bytes. It is freed here only on a stop before the runner, only when tag `+0x48` is below 2 and capacity is not 0. Otherwise the runner takes it.

### Reserve step

The step is skipped when last is 0. Otherwise the helper gets the account block (state `+0x498`), user, base token, mode 3, flag 1, last, the 12 bytes at state `+0x60` and state `+0x80`.

| Helper result tag | Effect |
| --- | --- |
| 3 | stop with byte `+8`. Byte `0x11` is success, so the order runs with no apply |
| 2 | go on with no apply |
| other | amount `+0x100` must equal last and byte `+0x108` must be 0, then apply (mode 3). Else stop with code `0xc` |

On a stop the runner and settles do not run, and the post check still does.

### Post check and the set

The post check finds the row a third time and reads the health report again. With `now = +0x10 - +8`, words non-negative as above:

```
if report stops: return its code
if now < 0 and now < margin and user != 0xbb * 20: insert user into the set
return 0x11
```

The insert does not change the returned byte, so it never changes the result. `now == margin` does not insert, and a surplus of 0 does not insert. The first and third copies insert at state `+0x8b8`, the second at state `+0x1338`. That offset is the only byte difference between `0x46f26f0` and `0x46f2480` (`twins` in `evidence.json`).

The excluded address is two `.rodata` constants, `0x204560` (16 bytes) and `0x208160` (4 bytes). `exempt_address` shows the same 20 bytes at `0x5994d8`, `0x5994e8`, read by the sweep below.

### Default row

The row at `0x5786350` is a lazy value: the word in `.data` is a relocation to builder `0x3790910`, with the Once word at `0x5786380`. The builder sets word 0, the map root and the map length to 0, and `+8` to the result of a date call on `0xaf93b` (`host_bytes`). So a user with no row goes the whole path with an empty map. Value `+8` nonzero is what makes step 5 pass. The evaluator uses a stand-in word for that date.

### Differences between copies

`twins` compares instructions with call targets as absolute addresses. `0x4d2f4a0` and `0x4d2e9e0` differ only in five call targets. `0x46f2be0`, `0x46f2960` are equal. `0x46f09e0`, `0x46f08a0` differ in one call target. `0x2739b00` differs from `0x46f26f0` in three call targets. The same specification ran on all three bodies, with one set offset per copy.

### Layouts

`fields` in `evidence.json` lists every offset. User map node: values at `+0x00` (stride `0x30`), keys at `+0x218` (stride 20), length at `+0x2f6`, edges at `+0x2f8`.

## Inferences

- Word `0x187` is the failure word of the adapter, which writes 0 to state `+0x5b3` on it (the spot preprocess packet). Not modelled here.
- The set is the input of a sweep. `0x2765600` takes the address of state `+0x8b8`, gates on user byte `+0x3c >= 4`, and compares report word `+8` with words `+0x28`, `+0x20`, `+0x18`, then tests the same `0xbb` address. So report word `+8` looks like a value and `+0x18` like the lowest of three thresholds, which would make the saved ratio threshold over value. I did not trace the set into that sweep's row list.
- `+0x8b8` and `+0x1338` differ by `0xa80`. An earlier packet saw the same stride between per-domain state fields, so the two sets likely belong to two domains.
- Step 10 looks like leftover work: no instruction reads the lookup result before the next call overwrites `rax`, and a stub value does not change any output. The lookup body is not modelled, so a side effect in it stays unresolved.
- The name `replace` in the reference does not fit. These bodies have no book lookup, cancel or insert of their own. The order runner is stubbed here, so this is about these bodies only.

## Implementation and comparison

Not yet implemented in Rust. The comparison here is byte evaluator against a written specification. The specification was written from a full instruction read and kept apart from the evaluator. The first runs showed two gaps in that read: the default row is a lazy value, not its file bytes, and the second copy has its own set offset. Both are now stated above. The mutation pass then found harness gaps (unused key slots, the panic and Once arguments, map length against height), which were closed with more cases.

Mutants flip each branch, `set`, `cmov`, immediate and field offset, one at a time, over the cases that reach it.

| Metric | Value |
| --- | --- |
| Cases | 336 |
| Mismatches | 0 |
| Instructions stepped | 183,241 |
| Stepped / total: second path, first copy | 474 / 521 |
| Stepped / total: second path, second copy | 474 / 521 |
| Stepped / total: second path, third copy | 654 / 707 |
| Stepped / total: snapshot, first copy | 140 / 148 |
| Stepped / total: snapshot, second copy | 140 / 148 |
| Stepped / total: reserve step, first copy | 82 / 82 |
| Stepped / total: reserve step, second copy | 82 / 82 |
| Stepped / total: post check, first copy | 135 / 144 |
| Stepped / total: post check, second copy | 135 / 144 |
| Stepped / total: post check, third copy | 135 / 144 |
| Mutants killed / survived / unreached | 677 / 2 / 43 |

## Results and limitations

- The result is exact only for the stubbed edges. Helpers are stubbed, so their own rules are not claimed.
- Report words are unnamed in the observations. Only their use is pinned.
- Unwind landing pads are not run. They account for all unreached rows.
- The two surviving rows are one immediate of a memcpy that writes bytes back over themselves (`mutations.tsv`). The third copy kills the same immediate.
- Every surviving or unreached mutant has a stated reason in `mutations.tsv`.
- Open #246 shows `0x4d2f4a0`, `0x4d2e9e0` only as call targets in instruction transcripts of the adapters, and it recovers no behavior. It is a different question. `0x373d8e0` is a row in open #234, so it is stubbed here with no mutants.
- No progress gate is requested.

Next question: which code reads the set at state `+0x8b8`, and what does the sweep `0x2765600` do to a user in it?
