# fees: node #94 deployer fee scale setter and its action arm

- Component ID: fees
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: 1f8c67c63ca4794c9689235471c60297f8a5c985 / references/can1357-hl 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for byte-derived rules below, inference where marked, unresolved items listed under Results and limitations
- Scope included and excluded: included are the rule that sets a perp dex fee scale, the 12-byte time add and the dex lookup it depends on, and the action arm that calls it, in all 3 copies. Excluded are the authority checks that run before the arm, the decimal text parser itself, the chrono helpers as mutation subjects, and the fee arithmetic that consumes the scale.

## Reproduce

Run from the repository root:

```
python3 tools/fees_fee_scale.py --out research/work-items/fees-fee-scale-94
cd research/work-items/fees-fee-scale-94 && sha256sum -c MANIFEST.sha256
python3 -m unittest tests.test_fees_fee_scale
```

Python 3 standard library only. The tool refuses any binary whose SHA-256 differs from the value above, never runs the binary, and calls no external program. Sections and FDE data come from `tools/elf_index.py` and `tools/fde_extents.py`. A full run takes about 110 s on 3 workers. Two full runs gave identical `vectors.tsv`, `mutations.tsv`, `instructions.tsv` and `reference-diff.tsv`.

## Evidence

Coordinates are virtual addresses in the ELF above. The objdump lines below are a reading aid from a human session. They are not part of the generated files, which come from bytes alone.

### Boundaries

- 0x3718e30: FDE 0xe4c3c0, end 0x3719023, 121 instructions decoded, 121 executed. The setter.
- 0x1459ca0: FDE 0xceca78, end 0x1459df7, 77 decoded, 77 executed. Time plus f64 seconds.
- 0x3332380: FDE 0x116b480, end 0x3332481, 67 decoded, 59 executed. Dex lookup. The 8 others are one `ud2` and the unwind tail, and are listed in `evidence.json`.
- 0x15206e0: FDE 0xcf67f0, end 0x1520842, 87 decoded, 53 executed. Real chrono time add, run but not mutated.
- 0x151f870: FDE 0xcf65ac, end 0x151fa9c, 145 decoded, 132 executed. Real chrono date add, run but not mutated.
- Arm 0x273f6ee in 0x273e080: 151 instructions, all executed.
- Arm 0x4d51822 in 0x4d50130: 147 instructions, all executed.
- Arm 0x4d57242 in 0x4d55b50: 147 instructions, all executed.

An arm has no FDE of its own. The tool walks both ways of each branch from the arm entry and ends a path at the drop of the action (`movzx eax, byte [rbp+0]`) or just after the byte store of success tag 0xd.

`evidence.json` shows one relocated slot holding the setter (0x5774bd0), three calls through it (0x27411bc, 0x4d53355, 0x4d58d75) and no direct call. The third copy keeps the mode byte at exchange +0x1372 and the dex table at +0x1038, the first two at +0x8f2 and +0x5b8. All three read the time at exchange +0x60.

### The setter

```
3718e3b: xorpd   xmm1,xmm1
3718e3f: ucomisd xmm1,xmm0
3718e43: ja      3718e5f                      ; tag 0xe5
3718e45: ucomisd xmm0,[20aab8]                ; 3.0
3718e4d: ja      3718e5f
3718e4f: cmp     byte [rsi+0x230],3
3718e56: jne     3718e81
3718e58: mov     word [rdi],0xe3
3718e8a: xor     eax,eax
3718e8c: cmp     dl,3
3718e8f: sete    al
3718e92: lea     rdx,[208d90]
3718e99: movsd   xmm0,[rdx+rax*8]             ; 60.0, then 2592000.0
```

Rules, in order, each checked against the model on every vector:

1. `0 > scale` or `scale > 3`: tag 0xe5 with f64 3.0 at result +8. NaN passes both tests.
2. Row byte +0x230 == 3: tag 0xe3.
3. `next = last + wait`, where `last` is at meta +0x68 and `meta` is the box at row +0x208. `wait` is 2592000 s when dl == 3 and 60 s for any other byte. Only dl is read.
4. `next > now`, comparing a signed date word, then seconds, then fraction: tag 0xe0 with a String at +8. `next == now` passes.
5. `scale > 1`: walk the rows at row +8, length row +0x10, stride 0x30. A zero byte +0x29 gives tag 0xe6. Dex index (row +0x30) x 10000 and that base + i are checked: overflow panics at `l1/src/asset/pdi.rs:30:14`. The multiply panic needs at least one row.
6. `old != scale` (NaN counts as different): store the scale at meta +0x60 and `now` at meta +0x68. Then tag 0x186. An equal value changes nothing, so it does not restart the wait, and +0.0 and -0.0 count as equal.

Rejected calls write nothing to the row, the meta box or the assets. For tag 0xe0, result +2..+8 holds the low 6 bytes of 0x20a1a0, left over from the stack.

### Time add

0x1459ca0 multiplies by 1e9, sends NaN and infinities to 0, saturates to i64, then floor-splits into seconds and nanoseconds. It has no failure result: a date past the chrono range panics with `` `NaiveDateTime + TimeDelta` overflowed `` at chrono-0.4.38 `src/naive/datetime/mod.rs:1631:38`. So a `last` within the wait of the final date panics the setter. The 12 bytes are `date, seconds, fraction`, the same packed chrono date as `fees-start-trial-94` (open).

### Lookup

0x3332380 with an empty name returns row 0 with no status test, and panics by `unwrap` (0x333245e) when the table is empty. With a name it returns the first row whose byte +0x230 != 3 and whose name (meta +8, +0x10) is equal, otherwise tag 0x141. So rule 2 of the setter is reachable only through the empty name.

### Action arm

Order in all 3 copies, with the action at rbp:

1. Text String at action +0x20: length >= 101 gives tag 0x143.
2. Parser 0x374fe60 (through slot 0x5773328), result tag or f64.
3. Name String at action +8: length >= 101 gives tag 0x143.
4. Lookup through slot 0x5773eb8 in the dex table.
5. Setter through slot 0x5774bd0, dl = mode byte, rcx = copy of the time.

Failures set outer byte 0xe and put the 0x60-byte status at result +8. Success sets outer byte 0xd only. For the text failure, result +0x10 holds a stack address; for the name failure, result +0x20 holds the length. The text failure frees text then name, and so does a parser failure. The name failure, lookup failure, setter failure and success free name then text.

### Status text

- 0xe3 `Invalid perp deployer`
- 0xe5 parts `Fee scale cannot be negative or greater than `, value, `.`
- 0xe6 `Growth mode cannot be set when deployer fee scale is more than 1`
- 0xe0 parts `Error deploying perp: `, value; the value is built from `can only change fee scale once every `, f64 30.0 at 0x20a1a0, ` days`
- 0x141 `Invalid perp DEX`
- 0x143 `Invalid input length`
- 0xab `Error converting decimal to float`

### Other readers of the stored scale

A byte search for a load of row +0x208 followed by a load of +0x60 gave 4 sites, pinned in `evidence.json`. It is not a census.

- 0x37130de in 0x37130b0, the perp trade fee producer of `fees-trade-fee-94` (open): the scale counts as 0.0 when row byte +0x230 == 3.
- 0x273b79c, 0x4d4b30c and 0x4d4bbfc, in 3 copies of one function: each load is followed by a compare with 1.0.

### Inferences (not proved by these bytes)

- Mode byte 3 means mainnet. `fees-start-trial-94` shows byte 3 rejected with `Action only allowed on testnet`, and the 30-day text fits. So mainnet waits 30 days and other chains 60 s.
- Row byte +0x230 == 3 means a deleted dex: lookup hides such a row and the fee producer treats its scale as 0.
- Scale is the deployer fee scale: `deployerFeeScale` and `lastDeployerFeeScaleChangeTime` are in .rodata and the two meta fields fit them, but no serializer was traced.
- The two values in messages print as `30` and `3`: 0x1571d50 passes minimum precision 0 (`xor edx,edx` at 0x1571d6b), which is the f64 Display path. The formatter body was not run.
- NaN cannot reach the setter through the action: 0x374fe60 converts a decimal to f64, per tag 0xab. The decimal parser it calls was not read here.

### Reference comparison

`reference-diff.tsv` has 14 rows: 10 differ, 3 agree and 1 is unverified. The largest difference is the wait: `references/can1357-hl/l1/asset/pdi.rs` gives 60 s for mode 3 and 30 days otherwise, and the bytes do the reverse. The reference also has a None branch where the bytes panic, other message text, a status filter on the empty name, and an `f64` action field where the bytes hold text.

## Implementation and comparison

No Rust implementation: not yet implemented. The comparison here is byte evaluator against a separate closed-form Python model.

- Vectors: 3613, mismatches 0. Groups: range 1200, cooldown 620, growth 258, write 24, time 240, lookup 200, lengths 216, setter 855.
- By subject: 2102 direct setter vectors, 240 time add, 92 direct lookup, and 393 through each of the 3 arms (1179, in groups lengths, lookup and setter).
- Caller-saved registers are spoiled by stubs, unset bytes in strict arenas fault, and state arenas hold a position-dependent pattern.
- Outcomes are listed per group in `evidence.json` and per vector in `vectors.tsv`.
- Stubs check their arguments: parser (string words), format (pieces, value pointer, formatter), free (pointer, capacity), panics (location, or message and length), byte compare length.

Mutation survey over the setter, time add, lookup and 3 arms: 470 mutants (321 field offsets, 74 immediates, 68 condition flips, 7 read constants), 461 killed, 9 equivalent with a reason each in `evidence.json`. All 9 are in the time add: 5 where clamp and `cvttsd2si` give the same value, 2 at a gate no f64 input can reach, 1 lower reciprocal that the chrono carry repairs, 1 sign shift. One real gap showed up in the first survey (the largest-finite test), and a vector whose product is exactly the largest f64 closed it.

## Results and limitations

- Passed: 3613/3613 vectors, 461/470 mutants killed plus 9 equivalent, 121/121 setter instructions, 77/77 time add instructions, 445/445 arm instructions.
- The equivalence of the 9 survivors is an argument plus no tested input telling them apart, not a proof. The reciprocal case relies on a fraction below 1e9.
- Time fractions of 1e9 and above (leap seconds) were not tested. 34 instructions of 0x15206e0 and 13 of 0x151f870 did not run; those two are unmutated helpers.
- The arm starts from a built frame. Dispatch to the arm and the authority check before it are not covered. The third copy's shape is observed, not named.
- The text parser is a stub, so which texts become which f64 is not covered here.
- Byte +0x29 of an asset row has no established name. Tag 0xe6 speaks of setting growth mode, which suggests zero means growth mode is on, while the reference calls the field `growth_mode_allowed`.
- No progress gate is requested.

Next question: at 0x273b79c and its 2 copies, what action reads the scale, and does its compare with 1.0 give tag 0xe6, fixing the meaning of asset byte +0x29?
