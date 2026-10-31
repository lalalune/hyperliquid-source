# RE-004: L1 to EVM transfer fee: EIP-1559 next base fee, 1e8 floor, ceil divide by 1e10, cap

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference has no code for these functions and no text for the fee rule (search for `calc_next`, `0x30d40`, `unable to compute fee`). Its only related line is a handler note, `fee_cap >= 100_000_000 wei`, in `l1/exchange/handlers/08_evm_raw_tx.rs`, about another check.
- Claim status: observation for everything in Evidence, which comes from ELF bytes, an evaluator of those bytes, and a symbolic walk of the same rows. Inferences and unresolved items are marked.
- Scope included and excluded: included are the whole functions `0x1359660`, `0x342a1b0` and `0x37325d0`, their three GOT slots and every `call` through those slots, and the argument rows just before the three fee calls. Excluded: what the callers do with the fee, and the rest of the three callers. They are big functions with rows in other packets, so this packet gives only site addresses inside them. The four other callers of `0x1359660` are named by site only.

## Reproduce

From the repository root:

```
python3 tools/l1_evm_transfer_fee.py --out research/work-items/RE-004-l1-evm-transfer-fee-94
python3 -m unittest tests.test_l1_evm_transfer_fee
```

The tool takes 10 s to 2 min, depending on server load. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It does not start objdump or readelf, so the binutils version cannot change the output. The binary is never executed. It only reads bytes.

Generated files: `evidence.json`, `functions.tsv`, `leaves.tsv`, `panic-locations.tsv`, `slots.tsv`, `constants.tsv`, `base-fee-sites.tsv`, `fee-sites.tsv`, `examples.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are virtual addresses in the ELF. Function ends come from FDEs (`functions.tsv`). Slot targets come from `.rela.dyn` RELATIVE rows (`slots.tsv`). Constants are read at the listed rows (`constants.tsv`).

### `0x1359660`: next base fee

The eight panic Location records this function passes all name one file, `alloy-eips-0.9.2/src/eip1559/helpers.rs`, at lines 33, 43, 47, 48, 56 and 57 (`panic-locations.tsv`). The file text is in the binary. The source is not.

Inputs by register: `used` rdi, `limit` rsi, `base` rdx, denominator rcx:r8 as `u128`, and elasticity `e` as the stack word above the return address. Only the low word of the `e` pair is read.

```
if e == 0: panic 33:22
T = limit / e
used == T: base
used >  T: D = T * denominator    (past 128 bits: panic 48:27; zero: panic 47:21)
           q = (used - T) * base / D        (u128)
           step = q if q >= 2^64 (low word only), else max(1, q)
           base + step                      (past 64 bits: panic 43:13)
used <  T: D as above             (past 128 bits: panic 57:23; zero: panic 56:17)
           q = (T - used) * base / D        (u128)
           max(base - low word of q, 0)
```

So a rise has a floor of 1 and a fall has none. A quotient of exactly `2^64` gives a step of 0, not 1, because the cut to 64 bits comes after the `max`. The rows are `0x1359705..0x135971c`. The test is `used 5, limit 2, base 2^62, denominator 1, e 2`, which returns `2^62`.

The walker finds no path to the records at lines `47:40` and `56:37`, the two `sub` panics, because the three way compare has already fixed the order.

### `0x342a1b0`: price

`header` is rdi. `+0` is a tag, `+8` the base fee, `+0x218` the limit, `+0x220` the used word.

- Tag 1: calls `0x1359660(used, limit, base, 8, 2)`, then `max(result, 1e8)`. `1e8` is `cmp $0x5f5e101` plus `cmovb`.
- Tag 0: `1e8`, with no call.

Each caller tests the tag against 2 first and uses `1e8` without calling (`fee-sites.tsv` rows, `cmpl $2`). So every path gives a price of at least `1e8`.

For a tag past 2 with a nonzero low byte the function returns `max(rax on entry, 1e8)`. rax is not set on that path. This is in the table for completeness. Those tags are not values the callers are shown to hold.

### `0x37325d0`: fee

Result pointer rdi, price rsi, flag bit 0 of cl, gas r8. rdx is overwritten unread.

```
g = flag bit 0 ? gas : 200000
p = g * price                  (u128)
v = ceil(p / 10^10)            (u128)
v <= 0x0ccccccccccccccb: word 0 = 0x186 (Ok), word 1 = v
otherwise:               word 0 = 0x14d, word 1 untouched
```

Tag `0x14d` reads `L1 to EVM transfer unable to compute fee` through the Display table. The ceiling is the row pair `or %r14,%r15; setne %al`, after a call to the 128 bit divide helper `0x565f5a0` (`__udivti3` by shape) and a multiply back. The bound is `i64::MAX / 10 - 1`, compared as 128 bits, so a quotient past `2^64` with a small low word is refused. The function also builds the `0x14d` error at entry and calls `0x3762510` with a pointer to it, then builds the same tag again at the end. That callee is stubbed here (see limits).

### Sites

`base-fee-sites.tsv` lists the 6 `call *0x576e198(%rip)` in `.text`, found by a byte scan. Four pass immediates 8 and 2 and floor at `1e8` after the call: the function above and three inline copies at `0x27bb587`, `0x27c35a7`, `0x37dc226`. Two read the parameters at run time and have no floor there: `0x27b7cab`, `0x4e4b0b1`.

`fee-sites.tsv` lists the three fee calls, each 39 bytes after its price call, in the three copies of the caller. Rows before each pair, matched by byte pattern:

- `0x14c` (`L1 to EVM transfer queue too long`) when a state word (`+0x3128`, or `+0x3ba8` in the second copy) is above 9.
- Price `1e8` when the state tag (`+0x2a30`, or `+0x34b0`) is 2.
- flag = frame word `+0x3e0` is nonzero, gas = frame word `+0x420`.

`examples.tsv` joins the real bytes of the price and fee functions. A plain send at the floor costs 2000. With a 30000000 limit, which is a fixture value and not read from any chain, a full block gives 2250. At 1 gwei the same send costs 20000, and gas 1 still costs 1.

## Implementation and comparison

Rust implementation: not yet implemented. There is no compiled comparison. The comparison here is between real instruction bytes and closed forms kept apart from the evaluator.

Three independent checks:

1. Evaluator. 1590 cases for `0x1359660`, 514 for `0x342a1b0` and 538 for `0x37325d0` run the real rows, with the real `__udivti3` and the real next base fee callee, against the closed forms. Stubs check callee arguments. All match.
2. Path walker. A symbolic reader follows the same rows over all inputs: each compare forks only where facts do not settle it, 128 bit products stay as exact expressions, and any shape it cannot follow stops the run. This gives `leaves.tsv`, with 16, 6 and 6 leaves. The result sets are literals in the tool, and any other set fails the run. So the table covers every input, not only the vectors.
3. Partition. Every vector matches exactly one leaf, and that leaf's expression evaluates to the closed form's value, so the walker and the integer model are tied together. Every result text in the fee and next base fee tables is hit, and so are the 3 results for the price table.

Mutation: 55 edits over every reached conditional, immediate and field offset. 54 killed. 1 of those is killed only by the walker: `0x342a1e2`, where `cmp $1e8` in place of `cmp $1e8+1` gives the same value on every input, so that edit changes the table text and not the behaviour. 1 survived: `0x1359713`, `mov $1,%edx`, is equivalent because the two `cmov` rows after it always replace rdx. An unedited image runs first under the same step limit, so a kill cannot come from that limit.

Tests: 48 pass, with negative controls for hash, a changed byte, a NOBITS address, a non-FDE start, edited floor, gas, branch and immediate, a changed result set, unpaired sites, a changed slot, wrong constants and a wrong Location file. Test numbers are literals.

## Results and limitations

- Whole domain: the leaf tables hold for every input to the three functions, given two lemmas the walker assumes: `__udivti3` divides, and the 128 bit `P - Q * k` rows give the remainder. The walker checks the operand shape of the second one. The first is checked only by the real helper running on the vectors.
- `0x3762510` is stubbed in both the evaluator and the walker. The stub checks that it receives the `0x14d` word, and the result is taken not to depend on it. The rows after it reload nothing from it, but the callee itself is not read here.
- Function names, `base`, `limit`, `used` and `alloy` signature order are inferences from the Location file and argument use. The file text proves the crate and file, not the function name. That the state word at `+0x2a30` is an EVM block header is an inference from the fields used.
- Inference: the unit of the result is `1e-8` of the native token, because `10^10 = 10^(18 - 8)` and the caller tests the native token just before. This packet does not read the debit.
- Inference: flag means a call with data and `gas` a user limit, and 200000 is the default for a plain send. The binary shows the flag test only.
- The caller side is limited to rows by byte pattern. The later handling of a nonzero status and of the fee word is not read.
- The two run time parameter sites and their source of parameters are not read.

Progress gate: none requested.

Next question: where the two variable sites read their base fee parameters, and whether a chain configuration can give them other values than 8 and 2.
