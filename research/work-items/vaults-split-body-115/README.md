# vaults: reconstruct node #115 vault share-split body 0x44af2f0 with its key-set walk, per-depositor lookup and overflow rules

- Component ID: vaults (vault deposits, shares and leader credit; upstream label `l1/vault*`)
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: repository commit `0781ce04826eeefd89fe336cb8ea073be0c1de30` (origin/main when the tool was written); the reference tree under `references/can1357-hl` was only used for naming hints and nothing was copied from it
- Claim status: observation for every table, inference only where a sentence says so; the rule list is a reconstruction that the bytes confirm on the cases listed below
- Scope included: the whole body at VA 0x44af2f0..0x44b04b6 (954 instructions, one FDE), the deque binary search 0x45578e0 that it calls twice (run as real code, 136 instructions), the shape of the four direct callees, six runtime slots and the `memcmp` call it uses (recording stubs, not reconstructed here); scope excluded: the bodies of the stubs, the sibling caller 0x44a97b0, any gate raise

This packet makes the share-split step of a vault reconstructible as a runnable rule list. Given a vault state object, a depositor key, two signed limits, a ledger context and a rate, the rule list in `tools/vault_split_body115.py` (`spec`) predicts the 0xe0 byte result, the final ledger counter and per-depositor slots, and the exact ordered list of callee calls and overflow events that the original bytes make. The original bytes are run in a small x86-64 evaluator on 10,030 generated cases plus 30 named ones, and the rule list matches on every one (0 mismatches). 385 deliberate corruptions (28 wrong readings, 10 structural controls, 347 byte edits of reached instructions) were tried: 364 are refused and 21 are proved equivalent edit by edit (`equivalent-mutants.tsv`).

What a reader can decide from this packet: the amount of a share split is `total - (total - cast(rate * total))` with a saturating cast that sends NaN and infinities to 0, not to the Rust saturation values; the value passed to the apply callee is `-cast(g * total)` where `g` is the *adjusted* ratio (not the input rate), because the spill slot that held the rate is overwritten by `g` in the middle of the body; the sum over the key set stops after the stored count, not after the tree is exhausted; an overflow in the running sum or any signed subtraction saturates and fires one event per overflow site (15 sites, three source positions), but the `remainder + gap` accumulation wraps and only fires an event; and the depositor key is read again after the apply callee, so a callee that rewrites the key buffer changes which map entry is debited.

## Reproduce

Run from the repository root with the target binary linked at `artifacts/node/115/hl-node` (the tool checks its SHA-256 first and fails otherwise; it never executes the binary and calls no external program):

```
python3 tools/vault_split_body115.py --out research/work-items/vaults-split-body-115
python3 -m unittest tests.test_vault_split_body115
```

The tool imports the evaluator of `tools/funding_rate115.py` (decoder, evaluator memory, x86 machine) and extends it in the tool itself by three vector forms the funding body never used: `unpcklpd` (decoded as `punpcklqdq`, identical bit result), the `movhpd` store, and the `cmppd` predicates 0 and 3. ELF sections, relocations and FDEs come from the shared parsers `tools/elf_index.py` and `tools/fde_extents.py` through that module.

Measured here (single process, Python 3 standard library): one `--out` run takes about 140 s alone and about 180 s while two other jobs ran; maximum resident set 300 MB; the test file takes about 25 s for 86 tests. Two runs into different directories, the second with `PYTHONHASHSEED=7 TZ=Asia/Tokyo`, were compared with `diff -r` and are identical. `MANIFEST.sha256` lists every file of the folder except itself.

Generated files (all produced by the one command above; nothing here is written by hand except this README):

| file | rows | content |
| --- | ---: | --- |
| `measure.json` | 12 | counts read by the verifier: cases, negative controls, detected, equivalent |
| `instructions.tsv` | 1,090 | every decoded instruction of both subject bodies with bytes, operands, branch targets and execution counts |
| `blocks.tsv` | 181 | basic blocks of both bodies with their terminator and entry counts |
| `branches.tsv` | 99 | every conditional jump with taken / not-taken counts over all cases |
| `coverage.tsv` | 2 | instruction coverage of the two bodies |
| `callees.tsv` | 34 | every call site: direct target or GOT slot, slot relocation addend, role |
| `event-sites.tsv` | 15 | the 15 overflow event sites and the Location record each one passes |
| `layout.tsv` | 34 | state, tree node, deque entry, ledger and result field offsets with the first access |
| `constants.tsv` | 13 | the 13 constant pools the body reads, as bytes and values |
| `cases.tsv` | 1,697 | every 6th case with its outcome and digest, plus all named cases |
| `outcomes.tsv` | 6 | outcome counts over all cases |
| `wrong-readings.tsv` | 28 | how many cases refuse each named wrong reading |
| `mutants.tsv` | 347 | every byte edit with status and the first refusing case |
| `equivalent-mutants.tsv` | 21 | the edits that cannot change a result, with the reason |
| `structural-controls.tsv` | 10 | corrupt-input controls |

## Evidence

Coordinates are virtual addresses of the ELF image. File offsets come from the section table (`SHT_NOBITS` sections are never used to resolve an address). Boundaries: `0x44af2f0` is an FDE start and the FDE ends at `0x44b04b6`; the 954 instructions decode linearly to exactly that end (a window one byte short is refused). `0x45578e0` is an FDE start of 0x1ec bytes (136 instructions); a second, near-identical function starts right behind it at `0x4557ad0` and is not used here. Analysis of both bodies is complete; nothing was limited to a range.

### Arguments and frame

| register | meaning (inferred from use, each with the first reading instruction) |
| --- | --- |
| rdi | result pointer, 0xe0 bytes; saved to a spill slot at 0x44af37f |
| rsi | vault state object (fields below); saved at 0x44af37a |
| rdx | pointer to the 20 byte depositor key; kept at spill +0x30 |
| rcx | signed `limit` (saved at 0x44af309) |
| r8 | signed `other` (saved at 0x44af301); only forwarded to the apply callee |
| r9 | pointer to a three word ledger context; word 0 is the ledger pointer whose +0x4a8 is a running counter |
| xmm0 | f64 `ratio` (saved at 0x44af311, later **overwritten** at 0x44afaa5 by the adjusted ratio `g`) |

The frame is 0x188 bytes plus six pushes. Callee-saved registers are restored on every exit that returns; the four panic exits never return.

### State object fields read by the body

The table below is `layout.tsv`; each offset is a displacement that the instruction listed in the last column uses.

| object | offset | type | meaning | first access |
| --- | --- | --- | --- | --- |
| state | 0x00 | u32 | tag; the key set is walked only when it is 2 | 0x44af376 |
| state | 0x08 | ptr | key set B-tree root | 0x44af392 |
| state | 0x10 | u64 | key set height | 0x44af3b1 |
| state | 0x18 | u64 | key set length (count of members visited) | 0x44af396 |
| state | 0x50 | u64 | depositor map word: deque capacity, or 0x8000000000000000 for a B-tree | 0x44af6d7 |
| state | 0x58 | ptr | deque buffer, or B-tree root | 0x44af6f8 |
| state | 0x60 | u64 | deque head, or B-tree height | 0x44af705 |
| state | 0x68 | u64 | deque length | 0x44af7bd |
| state | 0x70 | f64 | rate for the leader credit | 0x44afe41 |
| state | 0x8c | [u8;20] | vault key | 0x44af35c |
| state | 0xa0 | [u8;20] | leader key | 0x44afec6 |
| set node | 0x08 + 20*i | [u8;20] | key i, eleven slots, parent at +0x00, index in parent at +0xe4, length at +0xe6, edges at +0xe8 + 8*i | 0x44af57e |
| map node | 0x30*i | value | f64, i64 units, i64 slot3; keys at +0x218 + 20*i, length at +0x2f6, edges at +0x2f8 + 8*i | 0x44af7ee |
| deque entry | 0x00 | [u8;20] | key (72 byte stride); value at +0x18 with the same three fields | 0x45579c1 |
| ledger | 0x4a8 | i64 | running counter debited and credited by the body | 0x44afbc3 |

The key set is a B-tree of 20 byte keys with eleven keys per node and a 0x148 byte internal node; the per-depositor map is either a sorted `VecDeque` of 72 byte entries or a B-tree whose value slots are 0x30 bytes. Both layouts were built by the harness from scratch and the body walked them with the real instructions, including wrapped deques (head anywhere in the capacity), trees of height 0..2 with different node splits, and synthetic complete trees of height 6, 8 and 9 (empty leaves) that reach the 8-way unrolled edge loops.

### Callees

`callees.tsv` lists 34 call sites. Eight are direct calls, 24 go through GOT slots whose `R_X86_64_RELATIVE` addend names the callee body, and two are the indirect `memcmp` calls (the register is loaded from the symbol-bound slot 0x64dfb50, which has no RELATIVE record).

| call | target | role | how modelled |
| --- | --- | --- | --- |
| 0x44a9430 (2 sites) | direct | amount of one key; first on the vault key, then once per member | recording stub with a table of amounts |
| 0x45578e0 (2 sites) | direct | binary search over the deque, returns (not-found flag, position) | **real bytes** |
| 0x44ad9e0 | direct | apply the split to the vault state | recording stub with four effects (see below) |
| 0x4472ea0 (2 sites) | direct | credit a key on the ledger | recording stub |
| 0x44e0810 | direct | build the 0x34 error value | recording stub |
| slot 0x64e4ea8 (15 sites) | body 0x4524e40 | overflow event, rsi is a Location record | recording stub, location checked |
| slot 0x64e5078 (2 sites) | body 0x446bdd0 | ledger balance of a key | stub returning a case table |
| slot 0x64e7170 | body 0x447db40 | ledger debit of a key | recording stub |
| slot 0x64df9f0 (2 sites) | body 0x5c87d50 | one-time initialisation guarded by the word at 0x64f01d8 | recording stub, arguments checked |
| slot 0x64df830 (3 sites) | body 0x1680c10 | panic with a message record | raises |
| slot 0x64df6a0 | body 0x1680c30 | panic on a failed integer conversion | raises, length argument checked |
| register (2 sites) | memcmp | 20 byte key compare | stub returning the first byte difference |

The four apply effects the harness can inject, because the body re-reads the map after the callee returns: `none`; `drop` (the container is emptied); `rewrite` (the callee stores new units and slot3 into the entry); `rekey` (the callee writes another key into the depositor key buffer). Without these the second lookup could not be told from a cached read.

### Overflow event sites

`event-sites.tsv` gives, for each of the 15 call sites of slot 0x64e4ea8, the Location record that the preceding `lea rsi` loads and the source position stored in that record (read from the record bytes: path pointer through the RELATIVE relocation, then length, line and column):

| position | sites |
| --- | --- |
| `l1/src/qtys/mod.rs` 834:1 (checked add) | acc 0x44af602, round 0x44b020c, credit_depositor 0x44b0369, credit_leader 0x44b0468 |
| `l1/src/qtys/impl_ntl.rs` 70:1 (checked sub) | cut 0x44b0118, rest 0x44b0153, diff 0x44b0189, diff_again 0x44b01c2, debit 0x44b02cd, after 0x44b0307, keep 0x44b033d, slot3 0x44b03a2, gap 0x44b03eb, gap2 0x44b0434 |
| `l1/src/qtys/impl_ntl.rs` 26:1 (unsigned sub) | units 0x44afe13 |

13 of the 15 sites are hit by at least one case (the event stub records the call site address and the Location pointer, and the rule list predicts both). The other two are never reached and cannot be by arithmetic: `rest` (0x44b0153) is the second subtraction `total - rest` after `rest = sat(total - cut)`; when the first subtraction does not overflow the second is exactly `cut`, when it overflows upward `rest` is i64::MAX and `total - MAX` stays in range for `total >= 0`, and when it overflows downward `rest` is i64::MIN and `total - MIN = total + 2^63` stays in range for `total < 0`, so the jump at 0x44af6be was taken 0 times in 9,579 runs; `credit_depositor` (0x44b0369) adds `max(keep, 0)` where `keep = held - max(raw, 0)`, so the two credits never exceed `held`, which the debit before them already removed from the counter, and the jump at 0x44aff7f was taken 0 times in 3,389 runs. These two arguments are reading of the bytes, not proofs by test; a ledger counter that starts above i64::MAX cannot exist.

### Constants

`constants.tsv` reads thirteen constants from the bytes: the cast floor -2^63 (0x459808) and ceiling 2^63 (0x459360), the cast guard 0x43dfffffffffffff (0x458e50), the pair 1e6 (0x450e80 and the scalar 0x4599a0), infinity (0x455810, 0x459010), the tiny threshold 1e-15 and its negation (0x459ba0, 0x458fa0), and the unsigned-to-double magic pairs (0x454dc0, 0x452030, 0x452040) with the low mask (0x456790).

### Coverage

954 body instructions: 917 were reached by the generated cases and 37 were not: five alignment nops, two `ud2` that follow panic calls, the two dead event blocks above (0x44b012b..0x44b0159 and 0x44b0348..0x44b037a, eleven instructions each), the panic arm for an invalid iterator state (0x44b0298..0x44b02a4, a built tree cannot reach it), the clamp tail of the `q * n` cast (0x44afaef..0x44afafb, `q <= 1` and `n < 2^63` keep the product in range) and two instructions after the 8-way unrolled loops. Of the 136 instructions of the deque search 135 were reached (the missing one is a jump after a branch that is always taken). `branches.tsv` shows 99 conditional jumps; 79 were taken and not taken, and 20 were one-sided in the cases: the unrolled-loop back edges (a second turn needs a 16 level climb), the guards that the earlier checks make redundant (non-finite quotient, negative units, lane tests, position at or past the length after a found flag, the second cast clamp), the two dead overflow jumps above, and the `test cl` iterator guard. Every decision of the decision table is two-sided in the cases except the ones whose row says that the value cannot occur.

## Implementation and comparison

### The rule list

The independent implementation is `spec(case, flags)` in `tools/vault_split_body115.py` (about 120 lines of plain Python, written from the bytes, not translated from the instructions). In words, with `sat` meaning "on overflow fire the event for that site and clamp":

1. Call the amount callee on the vault key; `total` is its result.
2. If the state tag is 2, the key set root is non-null and the count is non-zero, walk the set in key order for exactly `count` members: ask the amount callee for each member and do `total = sat(total + amount)` at event site `acc`. If `count` exceeds the number of members the walk climbs past the root and panics at 0x44b01a5.
3. `cut = cast(ratio * float(total))` where `cast` returns 0 when the product is infinite or NaN, clamps to [-2^63, 2^63] and converts with the saturating rule (anything above 0x43dfffffffffffff becomes i64::MAX).
4. `rest = sat(total - cut)` at `cut`; `base = sat(total - rest)` at `rest`.
5. Look up the depositor key. A deque is searched with the real binary search and the position is checked against the stored length; a B-tree is scanned node by node with `memcmp`, going to edge `i` when the key is smaller than key `i` and stopping at an equal key. A missing key returns the empty variant (tag 0x8000000000000019, nothing else written).
6. Call the balance slot for the vault key, `balance`. `exact = base - balance` with `diff = sat(exact)` at `diff`; `gap = max(diff, 0)`.
7. If `exact <= 0`: `held = base`, `g = ratio`; if `g > v` (v is the f64 stored in the entry) return the empty variant. Otherwise `low = float_u64(base)/1e6`, `high = float_u64(balance)/1e6` (unsigned conversions, so a negative balance becomes a huge value); if `1e-15 > low` return empty; `quotient = high / low`; if `exact` overflowed upward fire `diff_again`; if `rest + wrap(exact)` overflows fire `round` (the sum wraps and only the event fires); `g = ratio * quotient`; with the lazy word non-zero the one-time initialisation slot is called once (0x44af98d); if `g > v` return empty; `held = balance`.
8. A negative stored unit count panics at 0x44b04a1. A non-finite `g` or `v` returns empty. For `g < 0`: `g <= -1e-15` returns empty, a tiny negative `g` with `v >= 1e-15` is treated as exactly 0.0; for `g >= 0` a `v < 1e-15` returns empty. `q = g / v` (an infinite quotient returns empty).
9. `units = cast(q * float(n))` where `n` is the stored unit count; with the lazy word set the initialisation slot is called again (0x44b027e).
10. Call the balance slot again; if `held > balance_again` write tag 0x8000000000000019, call the 0x34 error builder and return.
11. `spend = max(held, 0)`; call the debit slot with the vault key and `spend`; `counter = sat(counter - spend)` at `debit`.
12. Call the apply callee with (state, depositor key copy, `-cast(g * total)` with MIN mapped to MAX, `total`, `other`, the context).
13. Search the depositor key again (the key buffer is read again). A missing entry panics at 0x44b04ae. `entry.units`: if `entry.units < units` (unsigned) fire `units` and store 0, else subtract.
14. `left = sat(held - units)` at `after`; `raw = cast(float(left) * state.rate)`; when `raw > 0` credit the leader key with `raw` and `counter = sat(counter + raw)` at `credit_leader`.
15. `keep = sat(held - max(raw, 0))` at `keep`; credit the depositor key with `max(keep, 0)`, `counter = sat(counter + ...)` at `credit_depositor`; `entry.slot3 = sat(entry.slot3 - keep)` at `slot3`.
16. `gap_a = sat(limit - held)` at `gap`, `gap_b = sat(gap_a - gap)` at `gap2`. Write the result: tag 0x8000000000000005; `limit/1e6` and `max(raw,0)/1e6` at +0x08; `gap_b/1e6` and `units/1e6` at +0x18; `keep/1e6` at +0x28; vault key at +0x30; depositor key at +0x44; `keep` at +0xb0; the leader option tag at +0xb8 (0x8000000000000007 when `raw > 0`, else 0x8000000000000019); `max(raw,0)/1e6` at +0xc0; the leader key at +0xc8 only when present.

### The rule list as Rust-shaped pseudocode

This is a reading aid for a future Rust reconstruction, not code from the repository; names are descriptive and every operator is the one the bytes use. `Q` is a signed 64 bit quantity whose `+` and `-` report an overflow event (site given in the comment) and saturate, `cast` is the saturating float to integer rule above.

```
fn split(state: &mut Vault, key: &Key20, limit: i64, other: i64, ctx: &Ctx, ratio: f64) -> Option<Split> {
    // 1-2: total of the vault base and of the first `count` set members, in key order
    let mut total = amount(ctx, &state.vault_key);
    if state.tag == 2 && state.set.root.is_some() && state.set.len != 0 {
        for member in state.set.iter().take_exactly(state.set.len) {      // panics at 0x44b01a5 when the tree ends first
            total = total + amount(ctx, member);                           // event `acc`
        }
    }
    // 3-4
    let cut = cast(ratio * total as f64);
    let rest = total - cut;                                                // event `cut`
    let base = total - rest;                                               // event `rest` (unreachable)
    // 5: depositor entry (deque or tree), absent -> None
    let entry = state.map.find(key)?;
    let v = entry.value;                                                   // f64
    // 6
    let balance = ledger_balance(ctx.ledger, &state.vault_key);
    let exact = base - balance;                                            // event `diff`
    let gap = max(exact, 0);
    // 7
    let (held, g) = if exact <= 0 {
        (base, ratio)
    } else {
        let low = (base as u64 as f64) / 1e6;
        let high = (balance as u64 as f64) / 1e6;
        if 1e-15 > low { return None; }
        let quotient = high / low;
        // event `diff_again` when `exact` overflowed upward; event `round` when rest + wrap(exact) overflows
        if lazy_word != 0 { once_init(); }                                 // first lazy call, only on this path
        (balance, ratio * quotient)
    };
    if g > v { return None; }
    // 8
    assert!(entry.units >= 0);                                             // panic 0x44b04a1
    if !g.is_finite() || !v.is_finite() { return None; }
    let q = if g < 0.0 {
        if g <= -1e-15 || v < 1e-15 { return None; }
        0.0 / v
    } else {
        if v < 1e-15 { return None; }
        g / v
    };
    if !q.is_finite() { return None; }
    // 9
    let units = cast(q * entry.units as f64);
    if lazy_word != 0 { once_init(); }
    // 10
    if held > ledger_balance(ctx.ledger, &state.vault_key) { return None_with_error(0x34); }
    // 11
    let spend = max(held, 0);
    ledger_debit(ctx.ledger, &state.vault_key, spend);
    ctx.ledger.counter = ctx.ledger.counter - spend;                       // event `debit`
    // 12: the callee may rewrite the entry or the key buffer
    apply(state, key, -cast(g * total as f64), total, other, ctx);          // MIN maps to MAX
    // 13
    let entry = state.map.find(key).expect("0x44b04ae");                    // key buffer read again
    entry.units = if entry.units as u64 < units as u64 { fire(`units`); 0 } else { entry.units - units };
    // 14
    let left = held - units;                                                // event `after`
    let raw = cast(left as f64 * state.rate);
    if raw > 0 {
        ledger_credit(ctx.ledger, &state.leader_key, raw);
        ctx.ledger.counter = ctx.ledger.counter + raw;                      // event `credit_leader`
    }
    // 15
    let keep = held - max(raw, 0);                                          // event `keep`
    ledger_credit(ctx.ledger, key, max(keep, 0));
    ctx.ledger.counter = ctx.ledger.counter + max(keep, 0);                 // event `credit_depositor` (unreachable)
    entry.slot3 = entry.slot3 - keep;                                       // event `slot3`
    // 16
    let gap_a = limit - held;                                               // event `gap`
    let gap_b = gap_a - gap;                                                // event `gap2`
    Some(Split { limit_m: limit as f64 / 1e6, leader_m: max(raw, 0) as f64 / 1e6, gap_m: gap_b as f64 / 1e6,
                 units_m: units as f64 / 1e6, keep_m: keep as f64 / 1e6, vault_key: state.vault_key, key: key /* buffer read again */,
                 keep, leader: (raw > 0).then(|| state.leader_key) })
}
```

Three details a straight translation would get wrong: the first lazy call exists only on the `exact > 0` path of step 7 while the second one follows the cast of step 9 on every path; the quantity that is debited, credited and subtracted from step 11 on is `held` (the balance, or `base` on the non-positive path), not `total` and not the balance read a second time; and the key in the result and in the depositor credit is the buffer content *after* the apply callee, because the body loads the key pointer again.

### Decision table (each row is one decision the bytes make)

| step | address | decision | outcome |
| --- | --- | --- | --- |
| 2 | 0x44af376 | state tag == 2 | other tags skip the set walk |
| 2 | 0x44af39a | root != 0 and count != 0 | else skip |
| 2 | 0x44af4b6 | parent link null while members remain | panic 0x44b01a5 |
| 3 | 0x44af64c | product bits above the largest finite | cast is 0 |
| 3 | 0x44af65a | product below -2^63 | clamp (redundant, equivalent edit) |
| 3 | 0x44af681 | clamped value above 0x43dfffffffffffff | i64::MAX |
| 4 | 0x44af6a5 | `total - cut` overflows | event `cut`, saturate |
| 5 | 0x44af6e7 | map word == 0x8000000000000000 | B-tree, else deque |
| 5 | 0x44af7b5 | deque search returns not found | empty variant |
| 5 | 0x44af7c1 | position >= stored length | empty variant |
| 6 | 0x44af843 | `base - balance` overflows | event `diff`, saturate |
| 6 | 0x44af862 | `base - balance <= 0` | take the non-positive branch (no lane math) |
| 7 | 0x44af8da | `1e-15 > low` | empty variant |
| 7 | 0x44af8fc | quotient equals infinity | empty (cannot happen) |
| 7 | 0x44af902 | exact overflowed | second event `diff_again` |
| 7 | 0x44af925 | `rest + exact` overflows | event `round`, wrapped value kept |
| 7 | 0x44af935 | lazy word non-zero | initialisation slot called |
| 7 | 0x44af9dc | `g > v` | empty variant |
| 8 | 0x44afa02 | stored units negative | panic 0x44b04a1 |
| 8 | 0x44afa30 / 0x44afa34 | `v` or `g` non-finite | empty variant |
| 8 | 0x44afa3a / 0x44afa40 | `g < 0` and `g > -1e-15` | tiny negative path, quotient 0.0 |
| 8 | 0x44afa62 / 0x44afa6e | `1e-15 > v` | empty variant |
| 8 | 0x44afa78 | `g < 0` (at or below -1e-15) | empty variant |
| 8 | 0x44afa9f | quotient bits above the largest finite | empty variant |
| 9 | 0x44afb22 | lazy word non-zero (second use) | initialisation slot called |
| 9 | 0x44afb2b | `units < 0` | empty variant (cannot happen: q >= 0, n >= 0) |
| 10 | 0x44afb81 | `held > balance_again` | error 0x34, tag 0x8000000000000019 |
| 11 | 0x44afbd0 | `counter - spend` overflows | event `debit` |
| 13 | 0x44afcec | map word == niche (second lookup) | B-tree, else deque |
| 13 | 0x44afdb3 / 0x44afdc0 | second lookup misses | panic 0x44b04ae |
| 13 | 0x44afe06 | `entry.units < units` (unsigned) | event `units`, store 0 |
| 14 | 0x44afeb6 | cast of `left * rate` is positive | credit the leader |
| 14 | 0x44aff08 | counter + credit overflows | event `credit_leader` |
| 15 | 0x44aff7f | counter + credit overflows | event `credit_depositor` |
| 15 | 0x44affa1 | `slot3 - keep` overflows | event `slot3` |
| 16 | 0x44affe5 / 0x44afffa | the two gap subtractions overflow | events `gap`, `gap2` |
| 16 | 0x44b0047 | leader option present | tag 0x8000000000000007 and key copy |

### Evaluation

The harness builds the vault state, the key set tree, the per-depositor map (a ring or a tree, with random fill bytes in the unused parts of nodes and ring slots so a read past a length cannot hide), the ledger and the key buffers in an evaluator heap, runs the real instructions, and compares the tuple (outcome, ordered call log, final ledger counter and every entry's units and slot3) with the rule list. The ordered call log includes amount, balance, debit, credit, apply and error calls with their arguments, every overflow event with its call site and Location pointer, and both lazy-initialisation calls with their five arguments and closure environment checked. Result bytes outside the documented fields must keep the fill value.

Case generation is deterministic (a linear congruential stream, fixed seeds): 55% "typical" draws (balanced ratios and amounts) and 45% adversarial draws (NaN, infinities, ±i64 extremes, near-overflow amounts and balances, tiny ratios, empty sets, counts past the set, trees of different heights, deques with every head, applied effects). The 10,030 cases split as follows (outcomes.tsv):

| outcome | cases |
| --- | ---: |
| ok (split performed) | 3,388 |
| none (empty variant) | 5,227 |
| error 0x34 | 416 |
| panic 0x44b01a5 (set walk past the end) | 452 |
| panic 0x44b04ae (second lookup missed) | 328 |
| panic 0x44b04a1 (negative stored units) | 219 |

### Wrong readings (28)

Each is a variant of the rule list with one plausible deviation; the bytes must refuse it on at least one case, and `wrong-readings.tsv` shows how many of the cases refuse each. All 28 are refused. They are: cast rounds to nearest; cast saturates an infinity; unit borrow compared as signed; set walk skipped; sum wraps instead of saturating; only the set summed; ratio quotient inverted; gap not clamped at zero; gap taken from the base; leader rate applied to `held` instead of `left`; tiny-value guard dropped; tiny negative `g` divided instead of zeroed; tag not checked; count ignored; second lookup cached; leader credit always made; depositor credit uses the leader amount; slot3 uses the clamped keep; second balance check ignored; debit not clamped; scale missing; lazy calls ignored; unit borrow wraps without event; remaining gap not subtracted; apply sign flipped; missing key panics; cap check dropped; round event dropped.

### Byte edits (347)

For every conditional jump, every 1- or 4-byte immediate and every unique structure displacement of a reached instruction in both bodies one bit is flipped (conditions: low bit of the opcode; immediates: low bit; displacements: bit 3), the edited image is run on the kill suite (30 named cases plus 1,200 generated ones) and must differ from the rule list on some case. 326 are refused. 21 survive and each is justified in `equivalent-mutants.tsv`:

- eight edits in the four saturating-cast sequences (0x44af65a, 0x44af664, 0x44afadd, 0x44afae7, 0x44afc49, 0x44afc53, 0x44afe6e, 0x44afe78): the clamp is redundant with `cvttsd2si` returning 0x8000000000000000 for an out-of-range input and the later `cmova` on the guard; the edit only changes which redundant test runs;
- two edits of unrolled-loop thresholds (0x44af438, 0x44af51b): the compare with 8 is on a path that exists only when the low three bits are not zero, so the value 8 cannot occur;
- one edit of the unrolled loop's second `lea` (0x44af557): it feeds a second iteration that needs a climb of 16 levels, which no tree of 20 byte keys with at least five keys per node can have in memory;
- one stale-copy edit (0x44afb4e) and one zero-sized panic argument (0x44b049b);
- eight edits in the deque search (0x455794e, 0x4557984, 0x4557997, 0x4557a03, 0x4557a32, 0x4557aa3, 0x4557aa9, 0x4557ab0): the changed values are either the position of a not-found result (which the body never reads) or an extra pure `memcmp` call.

The tool exits non-zero if any survivor is missing from that table, and the test `test_equivalent_table_names_real_edit_addresses` checks that every table entry names a real edit.

### Structural controls (10)

Wrong digest; mid-function address is not an FDE start; an address in a `SHT_NOBITS` section; a decoder window that ends inside the body; a truncated section table; the deque search not run as real code; the amount callee without a model; the entry byte replaced by `int3`; an endless loop cut by the step limit; a tampered event location. All ten are detected.

### Overflow arithmetic per site

The rule list names each saturating or wrapping operation by the event site it reports through.

| site | call address | source position | operation |
| --- | --- | --- | --- |
| acc | 0x44af602 | mod.rs 834 | `total + amount` while summing the vault base and the set members |
| cut | 0x44b0118 | impl_ntl.rs 70 | `total - cut` |
| rest | 0x44b0153 | impl_ntl.rs 70 | `total - rest`; never reached, see above |
| diff | 0x44b0189 | impl_ntl.rs 70 | `base - balance` |
| diff_again | 0x44b01c2 | impl_ntl.rs 70 | second report of the same overflow when the lane path is taken |
| round | 0x44b020c | mod.rs 834 | `rest + wrap(exact)` accumulation (wraps, does not saturate) |
| units | 0x44afe13 | impl_ntl.rs 26 | `entry.units - units` as an unsigned subtraction, stores 0 |
| debit | 0x44b02cd | impl_ntl.rs 70 | `counter - spend` |
| after | 0x44b0307 | impl_ntl.rs 70 | `held - units` |
| keep | 0x44b033d | impl_ntl.rs 70 | `held - max(raw, 0)` |
| credit_leader | 0x44b0468 | mod.rs 834 | `counter + leader credit` |
| credit_depositor | 0x44b0369 | mod.rs 834 | `counter + depositor credit`; never reached, see above |
| slot3 | 0x44b03a2 | impl_ntl.rs 70 | `entry.slot3 - keep` |
| gap | 0x44b03eb | impl_ntl.rs 70 | `limit - held` |
| gap2 | 0x44b0434 | impl_ntl.rs 70 | `(limit - held) - gap` |

Saturation direction: every saturating operation clamps to i64::MAX when the exact result is above the range and to i64::MIN when it is below. The bytes derive the direction from the sign of the wrapped result (`setns`/`sar` then `cmovo`), which is equivalent to clamping the exact value; the rule list clamps the exact value directly and agrees on every case.

### Worked example: the clean case, step by step

The named case `clean-ring` has a vault amount of 4,000,000 and two set members of 3,000,000 and 1,000,000, a ratio of 0.25, a stored value of 0.9, 5,000 stored units, slot3 4,000, a ledger balance of 1,000,000, a leader rate of 0.1, a limit of 100,000,000, a starting counter of 1,000,000,000 and the depositor in a two-slot ring with head 1.

| step | quantity | value |
| --- | --- | ---: |
| 1-2 | `total` | 8,000,000 |
| 3 | `cut = cast(0.25 * 8,000,000)` | 2,000,000 |
| 4 | `rest = total - cut` | 6,000,000 |
| 4 | `base = total - rest` | 2,000,000 |
| 6 | `balance` | 1,000,000 |
| 6 | `exact = base - balance`, `gap` | 1,000,000 |
| 7 | `low = 2,000,000 / 1e6`, `high = 1,000,000 / 1e6` | 2.0, 1.0 |
| 7 | `quotient` | 0.5 |
| 7 | `g = 0.25 * 0.5` | 0.125 |
| 8 | `q = 0.125 / 0.9` | 0.13888... |
| 9 | `units = cast(q * 5,000)` | 694 |
| 11 | debit of `held = balance` | 1,000,000 |
| 12 | apply argument `-cast(g * total)` | -1,000,000 |
| 13 | stored units after | 4,306 |
| 14 | `left = held - units` | 999,306 |
| 14 | `raw = cast(999,306 * 0.1)` | 99,930 |
| 15 | `keep = held - raw` | 900,070 |
| 15 | stored slot3 after | -896,070 |
| 15 | counter after the debit and two credits | 1,000,000,000 |
| 16 | result doubles | 100.0, 0.09993, 98.0, 0.000694, 0.90007 |

The test `test_clean_case_intermediate_values` checks the stored units, slot3 and the five result doubles against these literals, and `test_apply_receives_the_adjusted_ratio` checks the apply argument.

### The 28 wrong readings, one line each

| reading | what it changes | refusing cases |
| --- | --- | ---: |
| cast_rounds_to_nearest | rounds a cast instead of truncating | 914 |
| cast_inf_saturates | turns an infinite product into i64::MAX | 517 |
| units_signed_compare | compares stored units and `units` as signed | 22 |
| sum_skips_set | ignores the key set | 7124 |
| sum_wraps | wraps the running sum | 1327 |
| sum_only_set | drops the vault base amount | 4543 |
| ratio_inverted | divides low by high | 1967 |
| diff_not_clamped | keeps a negative gap | 1173 |
| gap_uses_base | uses `base` as the gap | 1650 |
| rate_on_held | applies the leader rate to `held` | 565 |
| tiny_guard_dropped | lets a stored value below 1e-15 through | 22 |
| tiny_negative_divides | divides a tiny negative `g` instead of using 0.0 | 26 |
| tag_not_checked | walks the set for any tag | 1269 |
| count_ignored | walks the whole tree, not `count` members | 878 |
| relookup_cached | keeps the units read before the apply callee | 421 |
| leader_credit_always | credits the leader even when `raw <= 0` | 2293 |
| depositor_credit_uses_leader | credits the depositor with the leader amount | 1683 |
| slot3_uses_clamped | subtracts `max(keep,0)` from slot3 | 646 |
| second_balance_ignored | skips the second balance comparison | 416 |
| debit_unclamped | debits a negative `held` | 288 |
| scale_missing | leaves the result doubles unscaled | 3289 |
| lazy_ignored | omits the two initialisation calls | 1211 |
| units_borrow_wraps | wraps instead of zeroing on a unit borrow | 71 |
| gap_not_subtracted | omits the second gap subtraction | 1457 |
| apply_sign_flipped | passes `+cast(g * total)` | 2188 |
| missing_is_panic | panics on a missing first lookup | 105 |
| cap_check_dropped | omits the 0x34 error path | 416 |
| round_event_dropped | omits the `round` event | 105 |

### The 21 equivalent edits, grouped

| group | edit addresses | argument |
| --- | --- | --- |
| redundant clamp of the saturating cast | 0x44af65a 0x44af664 0x44afadd 0x44afae7 0x44afc49 0x44afc53 0x44afe6e 0x44afe78 | the clamp bounds repeat what `cvttsd2si` and the `cmova` guard already do |
| unrolled-loop thresholds | 0x44af438 0x44af51b | the compared value 8 cannot reach this path |
| second turn of an unrolled loop | 0x44af557 | needs a climb of 16 levels |
| stale copy | 0x44afb4e | the slot already holds the same bytes |
| zero-sized panic argument | 0x44b049b | never read |
| deque search, not-found position | 0x4557984 0x4557a03 0x4557a32 0x4557aa3 0x4557aa9 | the position of a not-found result is never read |
| deque search, extra pure compare | 0x455794e 0x4557997 | one more `memcmp` call, same result |
| deque search, flag low byte | 0x4557ab0 | `setne` overwrites it |

### How the 347 edits split

| kind | edits | refused | equivalent |
| --- | ---: | ---: | ---: |
| condition | 99 | 90 | 9 |
| immediate | 61 | 52 | 9 |
| displacement | 187 | 184 | 3 |


### Stub argument contracts

Each recording stub checks the register contract it relies on (a failed check halts the case, so a body that changed an argument register would be refused):

| stub | registers read | what the stub records or checks |
| --- | --- | --- |
| amount 0x44a9430 | rdi = pointer to three context words, rsi = pointer to a 20 byte key | logs (context words, key); returns the case amount of that key |
| balance slot 0x64e5078 | rdi = ledger pointer, rsi = pointer to a 20 byte key | logs (ledger pointer, key); returns the first or second case balance |
| debit slot 0x64e7170 | rdi = ledger pointer, rsi = key pointer, rdx = amount | logs the four values |
| credit 0x4472ea0 | rdi = ledger pointer, rsi = key pointer, rdx = amount | logs the four values |
| apply 0x44ad9e0 | rsi = key copy, rdx = signed cut, rcx = total, r8 = other, r9 = context pointer | logs the values, then applies the injected effect to the evaluator heap |
| error builder 0x44e0810 | rdi = pointer to a u16 | logs the u16 (always 0x34) |
| event slot 0x64e4ea8 | rsi = Location record | logs (call site, record address) |
| initialisation slot 0x64df9f0 | rdi = 0x64f01d8, esi = 1, rdx = closure environment, rcx = 0x63fe250, r8 = 0x63fe278 | checks all five and that the environment points at 0x64f01c0; logs the call site |
| panic slots 0x64df830 and 0x64df6a0 | rsi (length for the conversion panic) | the conversion panic must pass length 0x2b; both raise at the call site |
| memcmp (register call) | rdi, rsi = two key pointers, rdx = 20 | returns the first differing byte difference as a 32 bit value, 0 for equal keys |

The extreme-input sweep in `TestEventSitesReached.test_dead_sites_never_fire_on_extreme_inputs` runs 540 crafted cases (six amounts including both i64 extremes, six ratios including -1.0, 1.5 and 1e300, five balances, three counters including both extremes) and checks that the two event sites called dead above never fire; the generated cases and the sweep agree with the arithmetic argument.

### Output file hashes

The SHA-256 of each generated evidence file of this packet (the same values as in `MANIFEST.sha256`; repeated here so the README can be checked on its own):

| file | SHA-256 |
| --- | --- |
| `blocks.tsv` | `3ac650437ec778eb8ab7de6772276a9cdf542e566717dee6cebc6d30d6a4aac0` |
| `branches.tsv` | `a7c64a4b189cb72f7ca4a43c3a3dc3fe09d38f6e06dff9b19f3a23d95317e918` |
| `callees.tsv` | `70fbf143d4dacdb659dbcd04d824a787e3fc93371c8e4f7f6ed6e0ca249d0fe0` |
| `cases.tsv` | `0a2cfc8d471193e273a2ce3775abbc6ea567eefd072fe277c125b6f416e3b197` |
| `constants.tsv` | `4b621bd5d22f774edf197d30000a5bcfe0057370d3c1635afa16401f41d721b3` |
| `coverage.tsv` | `cec47d24b342d0da73a3dafb32d177db05fe8eefccaaff69442ec040cb5b885f` |
| `equivalent-mutants.tsv` | `1efce5d5227717b883bbc33455139f6e5f3b8cb737dbce72e83689cedd367a90` |
| `event-sites.tsv` | `aa7fe249e17179ddf27f70404c3b97e5525661c22df5d982687749c726cd27de` |
| `instructions.tsv` | `099be4afa4953c276da7eea3013062393ba9791659f9e84f757f1bcedee2104a` |
| `layout.tsv` | `6c1d2d56fe14ea3ebbccd8d2dd0320092ed86085e418571b0fcdc192effe431f` |
| `measure.json` | `433c5185d855f412a0c4e9c5f08e7be1b24f93e0569935354b21ab1109ff8418` |
| `mutants.tsv` | `d729f4828044d464e8a7b32f35cd12b70e99e1d97ec506380e4e749f3141f5df` |
| `outcomes.tsv` | `a5633d5669140ab72a64be1ec772b5fc727fe1043e6e0acfa502c891383effbf` |
| `structural-controls.tsv` | `25ecc1dcbe8b790109304431aff863615b1a4f7fe591929716160acdfde918aa` |
| `wrong-readings.tsv` | `c90bd2b00f0bc6a46bf469bab52d11ee280f2fc462b33c3805034d5558ec2f17` |


## Results and limitations

Metrics (denominators in parentheses, from `measure.json`):

| metric | value |
| --- | --- |
| comparison cases | 10,030 |
| mismatches between bytes and rule list | 0 (of 10,030) |
| negative controls | 385 |
| negative controls refused | 364 |
| negative controls proved equivalent | 21 |
| negative controls neither | 0 |
| body instructions reached | 917 (of 954) |
| deque search instructions reached | 135 (of 136) |
| event sites hit | 13 (of 15); the other two are arithmetically dead |

Limits, stated plainly:

- The four direct callees, the six runtime slots and `memcmp` are recording stubs. Their results are inputs of the cases (amounts, balances) and their effects are limited to the four injected ones; this packet says nothing about what they compute. The amount callee 0x44a9430 is covered by the separate packet `vaults-amount-helper-115`; the others are the next questions.
- The evaluator is a small interpreter written for these two bodies; it is not a general x86 emulator and it halts on any form it does not model.
- Heights above 9 and trees with more than 511 keys were not built. Two edits whose only reachable difference needs such inputs are listed as equivalent with the argument above rather than tested.
- The key set and map layouts are inferred from the displacements the body uses; the packet does not prove that the real allocator produces trees with these shapes, only that the body treats exactly these shapes this way.
- This packet requests no component gate. It covers one function and its helper, not the whole vaults component.

Next question: the sibling caller at 0x44a97b0 (5.5 KB, same state object and the same amount callee) and the apply callee 0x44ad9e0 that this body hands the split to, which is the first function that mutates the vault state and is therefore the next place where the stub effects used here can be replaced by real bytes.
