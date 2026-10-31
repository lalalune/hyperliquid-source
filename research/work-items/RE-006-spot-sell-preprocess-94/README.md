# RE-006: spot sell preprocess for portfolio margin users: gates, health class, rewritten order, three copies

- Component ID: RE-006 (book state transitions)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is used as a list of labels to check.
- Claim status: observation for everything in Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences and unresolved items are marked.
- Scope included and excluded: included are three whole preprocess functions `0x4c21720`, `0x4c21230`, `0x26d2070` and two whole health class functions `0x48cfb30`, `0x28db4e0`, all with mutants. Four callers `0x445e270`, `0x445e630`, `0x445e9f0`, `0x445edb0` run as context with no mutants (see Overlap). Stubbed at the edge, with arguments compared: user row lookups, account lookup, health report, room, balance lookups, amount, quote and notional helpers. Excluded: the bodies of those helpers, the direct and second paths, and the callers `0x26d0e50`, `0x26d16b0`, which are longer and only have a few bytes pinned here.

## Reproduce

From the repository root:

```
python3 tools/spot_sell_preprocess.py --out research/work-items/RE-006-spot-sell-preprocess-94
python3 -m unittest tests.test_spot_sell_preprocess
```

The tool takes about 20 s. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `call_sites.tsv`, `cases.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs (`functions` in `evidence.json`). The order fields below are read from the same request layout that the two order builders use: `+0x08` size, `+0x10` tif byte, `+0x19` byte k, `+0x20` price, `+0x28` spot, `+0x30` side, `+0x31` reduce only, `+0x32` cloid.

### What the reference leaves open

`l1/spot_clearinghouse/cl_trait.rs` has the adapter, and `preprocess_main_spot_order` and `preprocess_perp_dex_order` only as trait methods with no body.

### The gates, in order

Arguments: `rdi` result, `rsi` order, `rdx` user, `rcx` state. The first test that fails decides the result. `direct` means result word 2 with a byte: the caller sends the order to the direct path. `stop` means result word 3 with a code.

| # | Test | When it fails |
| --- | --- | --- |
| 1 | state `+0x5b3` is exactly 1 | direct 0 |
| 2 | bit 0 of state `+0x5b4` is clear | direct 0 |
| 3 | spot < spot count (`+0x200`) | bounds panic, `l1/src/spot_meta.rs:565:25` |
| 4 | size tag nonzero, side nonzero, reduce only zero, k is 2 | direct 0 |
| 5 | base and quote of the spot row (stride `0x20`, words 0 and 1) are keys of the map at state `+0x568`, `+0x570` | direct 0 |
| 6 | user row byte `+0x3c` >= 4 | direct 0 |
| 7 | bit 0 of state `+0x5b0` is clear | direct 0 |
| 8 | health report has no error | stop, code of the report |
| 9 | health class >= 2 | direct 0 |
| 10 | room helper has no error | stop, its code |
| 11 | `free + room < amount / 2` (below) | direct 0 |
| 12 | quote helper does not stop | stop, its code |
| 13 | quote tag is not 2, and `room < last` | direct 0 |
| 14 | `price * size` fits u64 and is <= `0x7ffffffffffffffe` | direct 0 |
| 15 | notional helper on that product >= 1e9 | direct 0 |
| 16 | tif byte mod 32 is not 0, 2 or 4 | direct 1 |
| 17 | `max(low, price) <= high` | direct 1 |

Test 4 checks the fields separately, so side 2 passes. Test 5 uses plain B-tree nodes: keys at `+0x798`, length at `+0x7f2`, edges at `+0x7f8`, value stride `0xb0`.

### Test 11

```
free = total - held, 0 if held > total (recorder call)
left = free + room, u64::MAX if it wraps (recorder call)
amount = helper 0x37606b0(meta, base, size)
go on only if the helper says ok and left < amount >> 1
```

`total` and `held` are words 0 and 1 of the balance row of the base token. The recorder is `l1/src/qtys/impl_wei.rs:6:1`. The size helper is the one from `RE-004-spot-wei-scale-family-94`, so `amount` is size times a power of ten in the token's wei scale.

### Result word 1

If every test passes, the function returns a rewritten order for the second path:

| Offset | Value |
| --- | --- |
| `+0x00` | 1 |
| `+0x08` | size rule below |
| `+0x10..+0x18` | tif and the next 8 bytes of the order |
| `+0x19` | 2 |
| `+0x1a` | 6 bytes of the order |
| `+0x20` | `max(low, price)` |
| `+0x28` | spot |
| `+0x30`, `+0x31` | 1, 0 |
| `+0x32` | 17 cloid bytes |
| `+0x48`, `+0x50` | base, quote |
| `+0x58` | last |

```
n = min(x, size) if quote tag bit 0 is set, else size
if n < size: n = n + 1
```

So a clipped size is one above `x`, and never above the order's size. With size 1000, price 2000000, `x` 700, low 1900000, high 2100000, last 900, the result has size 701 and price 2000000 (`worked_example`). Test 13 reads the room word, not `x`: `x` may be above `last` (`test_room_not_x_is_compared_with_last`).

### Health class

`0x48cfb30` and `0x28db4e0` call the report (`0x48cfb90`, `0x28db540`) with `r8 = 0`:

```
report byte 0 is 1: return flag 1, code in dl
value = report +8, low = +0x18, middle = +0x20, high = +0x28
class 0 if value > high, 1 if value > middle, 2 if value > low, else 3
```

Only the class word is returned to a caller. The preprocess sees it through `class >= 2`, so `value <= middle` goes on. These two functions have one or two callers each (`call_sites.tsv`).

### The three copies

`0x4c21720` and `0x4c21230` are equal instruction for instruction but for one call target, `0x46f2fe0` against `0x46f2e60` (`twins`). Those lookups read row tables at `+0x740` and `+0x11c0` (`host_bytes`). `0x26d2070` is a separate compile: it passes the user pointer directly, leaves `rax` unset, has its own lookup `0x2755400`, report `0x28db540`, room `0x28d8b10` and panic Location record, and uses other stack slots. The same specification and the same case list match all three, apart from the entry and these stubs.

### Callers, as context

The callers run with stubs on both paths. All four have the same 184 instructions apart from call targets and frame words:

| Caller | Preprocess | Direct path | Second path | Direct result starts at |
| --- | --- | --- | --- | --- |
| `0x445e270` | `0x4c21720` | `0x4d3ddb0` | `0x4d2f4a0` | +8 |
| `0x445e630` | `0x4c21230` | `0x4d3be40` | `0x4d2e9e0` | +0 |
| `0x445e9f0` | `0x4c21230` | `0x4d3c640` | `0x4d2e9e0` | +8 |
| `0x445edb0` | `0x4c21720` | `0x4d3e860` | `0x4d2f4a0` | +0 |

- Context word 0 (u32) above 1 skips the preprocess, with flag 0.
- Result word 3 goes to the direct path with flag 0, so its code is dropped. Result word 2 passes its byte as the flag.
- The direct path gets the book word `side ^ 1` of the spot row, value 1 in `ecx`, a stack block with the order and context, and the Location `l1/src/spot_clearinghouse/cl_trait.rs:621:28`.
- Other result words go to the second path. Word `0x187` writes 0 to state `+0x5b3` and returns `0xe1`, byte `0xa`.

### Who writes the guard

`guard_writers` is a byte scan of `.text` for byte writes with displacement `0x5b3`: 21 rows. 18 write 0: the four callers, `0x26d0e50`, `0x26d16b0`, and six other functions. One of those, `0x222caf0`, clears it when `0x2739d70` or `0x2765600` returns a word other than `0x11`. 3 write a register (`0x2359431`, `0x4cadd31`, `0x4cb66c1`). At `0x235942d` the byte is `value & 1` in an arm of table `0x3dd340`, entry 0. So a register write sets it, and a failed second path or a failed check clears it.

### Mode byte

`0x46f2fe0` and `0x46f2e60` return a row whose byte `+0x3c` is compared with 4. The name table at `0x570d358` (`variant_name_rows`) ends with `portfolioMargin`, then `variant index 0 <= i < 5`.

### Results

| Measure | Value |
| --- | --- |
| Cases | 548 |
| Mismatches | 0 |
| Instructions stepped | 93,691 |
| Stepped / total: preprocess, first copy | 290 / 290 |
| Stepped / total: preprocess, second copy | 290 / 290 |
| Stepped / total: preprocess, third copy | 288 / 288 |
| Stepped / total: health class | 27 / 27 |
| Stepped / total: health class, third copy | 27 / 27 |
| Stepped / total: caller A, run with no mutants | 178 / 184 |
| Stepped / total: caller B, run with no mutants | 178 / 184 |
| Stepped / total: caller C, run with no mutants | 178 / 184 |
| Stepped / total: caller D, run with no mutants | 178 / 184 |
| Mutants killed / survived / unreached | 447 / 3 / 0 |

Unstepped instructions are unwind landing pads in the callers.

### Comparison with the reference

`reference_claims` has one row per claim. Words 391, 225 and code 10, the opposite book, the `ctx.tag > 1` test and the pairing of preprocess and replace bodies all agree with `cl_trait.rs`. The reference has no body for the preprocess, and the rest of this packet is new against it.

### Overlap

Open #246 lists the four callers' FDEs in a Location census with instruction transcripts, and states it recovers no behavior. For that reason they have no mutants here and appear only as context. #234 has rows for the report functions, #438 uses `0x46f2fe0`, `0x46f2e60` and `0x2755400` as lookups, #403 has a row for `0x37344a0`, and merged #46 has a recorder row in this area. None of them reads the preprocess.

### Inferences

These are readings of the observations above, not observations.

- Byte `+0x3c` holds the abstraction mode, and 4 is `portfolioMargin`: the enum has five variants and that name is last in the table. Test 6 then means portfolio margin users only.
- Side 1 is sell, as in `RE-006-hyperliquidity-refresh-94`, so this path handles spot sells that are too large for the user's free balance plus room.
- The map at state `+0x568` is token state, keyed by token, and the room helper gives what the user can still borrow. Its value stride `0xb0` and the text `borrows_allowed` in the binary suggest this; nothing here proves it.
- State `+0x5b3` is the guard the reference calls `direct_execute_guard`, from the writers in the callers.

## Implementation and comparison

Not yet implemented in Rust. The comparison is real bytes against a specification written from an instruction read. Every stub argument, the stack arguments of the room and quote helpers, and all `0x60` result bytes are compared. Unused map key slots hold a tempting key, filler bytes are a non-periodic ramp, and untouched result bytes must keep the fill mark. The evaluator's first run found two wrong readings in the specification: test 13 compares the room word and not `x`, and the callers turn the cloid flag into 0 or 1.

## Results and limitations

- Every surviving or unreached mutant has a stated reason in `mutations.tsv`.
- The three survivors are one `mov rbp, -1`, once per copy: the saturated word is only compared with a half of a u64, so any word from 2^63 up acts the same.
- `0x37344a0` is stubbed, so the meaning of `x`, `low`, `high` and `last` is not stated. Names here are the order in which words are read.
- The second path `0x4d2f4a0`, `0x4d2e9e0` is not read. The reference calls it replace, which is unverified.
- Stubs give results a caller could not get from a real helper (tag 0 with any word, for example).
- `0x26d0e50`, `0x26d16b0` are not modelled: only the `0x187` compare and the guard writes are pinned.
- Which of `0x4c21720` and `0x4c21230` is the reference's main or perp dex body is open. The table offsets do not settle it.
- The action word that reaches `0x235942d` is not named.
- Fixtures hold map trees of height 0 and 1.

Next question: what do `x`, `low`, `high` and `last` of `0x37344a0` mean, and what does the second path do with the rewritten order?
