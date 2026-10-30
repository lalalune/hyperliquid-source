# RE-006: one resting-order match step on node #94

- Component ID: `orderbook` (task RE-006, book transitions)
- Target release and full SHA-256: node #94, `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (labels used as leads only, nothing copied)
- Claim status: observation for every offset, branch and constant below; inference where the section says so; unresolved items are listed at the end
- Scope included and excluded: included are the three FDEs that match a taker record against one resting slot, the fill-mask wrapper they call, and their two call sites each. Excluded are the loop around them (including the insert bodies that contain inlined copies), the size cap, the margin record and the leg logic behind `0x3bfcdc0`. No function pinned by open PR #47 is a target here; #47 excludes matching.

## Reproduce

Run from the repository root. The tool starts no external program and never runs the binary.
Author environment: Python 3.12.3, Linux x86-64. It reads only `artifacts/node/94/hl-node`.

```sh
python3 tools/artifacts.py verify
python3 tools/match_resting_order.py --out work/match-check
diff -r work/match-check research/work-items/RE-006-match-resting-order-94 -x README.md -x MANIFEST.sha256
python3 -m unittest tests.test_match_resting_order
```

Generated files: `functions.tsv`, `callers.tsv`, `callees.tsv`, `exits.tsv`, `mutations.tsv`, `evidence.json`.
Every number there comes from `struct` reads of the ELF or from the evaluator in the tool.
The one disassembly excerpt below is for reading only and is not an input to anything.

## Evidence

Coordinates are virtual addresses; offsets marked `+` are from each copy's start. Analysis was complete for the
three bodies: every instruction was decoded to the exact FDE end, and 506 of 515 ran.

### The three copies

| Copy | FDE | Context offsets (entries ptr, len, table, flag) | Leg builder | Panic Location slot |
| --- | --- | --- | --- | --- |
| a | `0x431c530..0x431d01d` | `+0x1040, +0x1048, +0x1050, +0x1372` | `0x49e3d20` | `0x571ca38` |
| b | `0x431d020..0x431db0d` | `+0x5c0, +0x5c8, +0x5d0, +0x8f2` | `0x49e4450` | `0x571ca38` |
| c | `0x26eff10..0x26f09fd` | `+0x5c0, +0x5c8, +0x5d0, +0x8f2` | `0x232d590` | `0x56bd8a0` |

All three are 2,797 bytes and 515 instructions. With rel32 fields, rip-relative displacements and the four context
displacements zeroed they hash to one value, `0c499708...df104` in `evidence.json`. The Location records decode to
`l1/src/book/book/impl_insert_order.rs:768:85`. Each copy has two direct callers (`callers.tsv`).

### Entry and result

| Register | Observed use |
| --- | --- |
| `rdi` | result record |
| `rsi` | u64 asset key; `key / 10000` indexes a 0x2f0-stride table at the context |
| `rdx` | record S: `+0x68` 40 bytes, `+0xb0` flag byte, `+0xc8` size, `+0xe0` 20-byte user |
| `rcx` | context: table above, flag byte, `+0x60` u64 and `+0x68` u32 copied to the fill record |
| `r8` | record T: `+0x00` 16 bytes, `+0x10` 40 bytes, `+0x38`, `+0x40` price, `+0x48`, `+0x50` 20-byte user, `+0x64` side, `+0x65` 17 bytes, `+0x76` byte |
| `r9` | u64 budget |

Result record: `+0x00` tag (2 means no fill), `+0x00..+0x235` fill record on a fill, `+0x238` status word,
`+0x250` budget, `+0x258` reason byte. `0x8000000000000018` is the none word.

Fill record (`0x235` defined bytes): two 0x100-byte legs, `+0x200` price, `+0x208` asset, `+0x210` size,
`+0x218` notional, `+0x220` zero, `+0x228` context u64, `+0x230` context u32, `+0x234` T side.

### Order of operations

1. `key / 10000` must be below the table length. Otherwise `Result::unwrap` fails with Location
   `l1/src/dex_registry/clearinghouses.rs:11:29`. The error word `0x141` is built on every call and dropped when the
   index is in range.
2. Budget 0 returns no fill, none word, budget 0, reason 3.
3. Equal 20-byte users, or the predicate `0x37e4fb0` holding for T's user and then S's user, return no fill, none
   word, the budget, reason 2. No flag is read before this predicate.
4. If S `+0xb0` is set, S's user selects an entry through `0x36f57f0` on the table entry `+0xf8`, and the code walks
   a B-tree keyed by the asset: keys at node `+0x2c8`, length at `+0x322`, edges at `+0x328`, values of stride
   `0x40` at node `+0x10`, compared as u64. Absent, zero, or wrong sign (T side 0 needs a positive value, T side 1 a
   negative one) returns no fill, none word, the budget, reason 1. Otherwise the usable size is
   `min(S size, |value|)`, and when `|value| < S size` the reason is 3 if the usable size reaches the budget, else 1.
5. Usable size 0 returns no fill, none word, the budget, and the reason so far.
6. Amount is `min(usable, budget)`. The margin record `0x37130b0` is called for S's user with S `+0x68`, and its
   u64 at result `+0x50` divided by `1e9` as a double goes to the cap `0x370afd0`. A first cap of 0 returns no fill,
   none word, the budget, reason 0. A smaller first cap sets the amount and sets reason 0.
7. The same two calls run for T's user with T `+0x10`, and the cap gets a tagged option holding T `+0x76` and the
   budget. The cap returns two values. If the first is below the amount the status word becomes `...03` when the
   second is also below the amount, else `...04`. A first value of 0 returns no fill with that word, budget 0 and
   the reason so far. Otherwise the amount and **the budget field** both become that value, and the fill continues.
8. Both legs are built, with the bid-side user first: T's user when T side is 0, S's user otherwise.
9. `price * amount` is checked. A leg tag of 2, a 64-bit overflow, or a product above `0x7ffffffffffffffe` panics at
   line 768. The value `0x7ffffffffffffffe` itself passes. All three leg builders write tag 1 only, so the tag arm
   is not reachable through them.
10. `0x3711ba0` returns a mask. Both bits set returns the fill with the status word, budget and reason so far.
    If the leg bit of S's side is clear (bit 8 when T side is 0, bit 0 when T side is 1) it returns no fill with the
    status word so far, the budget so far, and reason 0. If only T's bit is clear it returns no fill, word `...03`,
    budget 0 and the reason so far.

`exits.tsv` gives the reason-store offset and case count of each exit.

### Fill mask wrapper, `0x3711ba0..0x3711cf1`

It reads `+0x200`, `+0x208` and `+0x210`, takes `asset % 10000` as an index below `+0x70` of the table entry (panic
Location `l1/src/clearinghouse/oracle/oracle.rs:197:18`), loads `+0x20` of a 0x60-stride row at `+0x68`, and calls
`0x3bfcdc0` for leg 0 then leg 1. The mask is bit 0 of the first result, plus bit 0 of the second shifted to bit 8.

### Status words

The status table already pinned by open PR #36 is read here for two entries only. Its 24 entries end before the
none word's index, and arm offsets give:

| Word | Arm | Text |
| --- | --- | --- |
| `0x8000000000000003` | `0x3a00a49` | `Insufficient margin to place order.` |
| `0x8000000000000004` | `0x3a00984` | `Order would exceed maximum position size for current leverage. ...` |

The cap's tail at `0x370befb` keeps one value in `rdx` and returns in `rax` its min with another value when a stack
flag bit is set, and those two returns are what step 7 compares. Reading excerpt from copy a:

```text
431ca48: jae  431ca66
431ca4a: cmp  rdx,rdi
431ca4d: sbb  r14,0x0
431ca51: add  r14,0xffffffffffffffec
431ca55: test rax,rax
431ca58: je   431cec0
```

`r14` starts at the none word, so this gives `...03` or `...04`.

### Budget returned to the caller

Before each call `r9` is loaded from a stack slot, and after the first call of each pair result `+0x250` is stored
back in the same slot (`callers.tsv`: slot `0x168`, or `0x198` in copy c, stored at `0x43121a0`, `0x4315e00`,
`0x26ed03b`). In copy a's caller, `0x43122dc..0x43122e4` then subtracts the fill size. So the field is the budget
before this fill, not after it.

### Inferences

- T is the taker and S the resting maker. The first call site of each caller reaches `rdx` through a stride 0xf8
  index into a slab with a vacant check, and `r8` is a stack record. The second site reuses the saved slot pointer.
- The `+0xb0` flag is reduce-only and the keyed value is a signed position size: the sign test lets the maker fill only
  when the fill reduces its position, and the amount is clamped to the absolute value.
- The 0x2f0-stride entry is one clearinghouse and `key / 10000` a dex index, from the Location path.
- The first cap return is the size after the maximum-position limit and the second the margin size, from the two
  status texts.
- Status words are niche values of an error enum over a string capacity, because the caller frees `+0x240` for a
  positive `+0x238`.

## Implementation and comparison

Rust implementation: not yet implemented.

The comparison here is the original bytes against a specification written from the claim above. `spec()` predicts the
result fields, the fill record bytes and the arguments of every callee. Stubs replace `0x3379490`, `0x36f57f0`,
the leg builder, the GOT calls and memcpy. They poison volatile registers and all xmm registers on return, and
callee-saved registers are checked on exit. B-tree nodes are real memory with stale keys past the live count.

Corruption and mutation controls: all 2,904 cases were reused against copy a with one change at a time. Each
branch, `setcc` and `cmov` condition was inverted, and bit 0 of each immediate was flipped, in both the match
step and the wrapper.

The reference file `l1/book/book/impl_insert_order.rs` differs from the bytes as follows:

| Point | Reference lead | Bytes |
| --- | --- | --- |
| Which cap runs first | taker | resting user |
| Cap of 0 for the taker | success word, budget kept | word `...03` or `...04`, budget 0 |
| Cap of 0 for the resting user | word `...12`, budget 0 | none word, budget kept, reason 0 |
| Partial taker cap | no status | fill plus word `...03` or `...04`, budget becomes the cap |
| Budget field on a fill | requested minus matched | budget before the fill |
| Mask, maker bit clear | error word, budget 0 | word so far, budget kept, reason 0 |
| Self-cross predicate | gated by a context flag | no flag read |
| Reduce-only source | incoming order and user | slot `+0xb0`, slot user, slot size |
| Word 3 name | queue mask | `Insufficient margin to place order.` |

## Results and limitations

| Metric | Value |
| --- | --- |
| Cases per copy | 2,904 (1,404 structured, 1,500 generated) |
| Mismatches, all three copies | 0 |
| Instructions stepped | 1,932,663 |
| Wrapper cases | 41, 0 mismatches |
| Mutants killed / survived / unreached | 110 / 7 / 1 |

The seven survivors and the unreached mutant have a written reason in `mutations.tsv`. Six change a copy length
whose extra byte is overwritten or unused, and one re-tests a bit already known to be clear. The nine instructions
never executed are that dead pair, the `ud2`, and the unwind cleanup.

No progress gate is requested. Limits:

- Stubs are contracts, not evidence of what the callees compute. Only the cap tail is read in `0x370afd0`.
- Stale bytes on no-fill exits and the last three bytes of the fill record are not compared.
- The check at 0x577ab98 in the reason 1 exit has no visible effect here and its purpose is unknown.
- What `0x3bfcdc0` tests, what the predicate `0x37e4fb0` tests and what `0x46efb70` does before the second call of
  each caller are unresolved.
- Whether every path keeps the amount inside the notional ceiling before step 9 is not established.

Next question: what does the caller's jump table at `0x6eec9c`, indexed by the reason byte, do for reasons 0 to 3
when the tag is 2, and which of those paths removes the resting order?
