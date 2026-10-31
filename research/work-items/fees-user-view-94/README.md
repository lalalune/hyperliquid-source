# fees: node #94 userFees view builder 0x27d7fe0

- Component ID: fees
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: 1f8c67c63ca4794c9689235471c60297f8a5c985 / references/can1357-hl 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for byte-derived rules below, inference where marked, unresolved items listed under Results and limitations
- Scope included and excluded: included is the whole function 0x27d7fe0, plus the field map of its serializer 0x2a3c4e0. Excluded are the bodies of every callee (rate row 0x3743df0, discount 0x3743020, schedule copy 0x2a3bb60, daily list 0x25806a0, the clock, the lock slow paths), the caller 0x2586ae0 beyond its call, and the text form of the floats.

## Reproduce

Run from the repository root:

```
python3 tools/fees_user_view.py --out research/work-items/fees-user-view-94
cd research/work-items/fees-user-view-94 && sha256sum -c MANIFEST.sha256
python3 -m unittest tests.test_fees_user_view
```

Python 3 standard library only. The tool refuses any binary whose SHA-256 differs from the value above, never runs the binary, and calls no external program. Sections and FDE data come from `tools/elf_index.py` and `tools/fde_extents.py`. A full run takes about 150 to 600 s on 3 workers.

## Evidence

Coordinates are virtual addresses in the ELF above. Every generated number comes from bytes.

### Boundaries

| Address | FDE end | Role | Decoded / executed |
|---|---|---|---|
| 0x27d7fe0 | 0x27d8ada | userFees view builder | 565 / 506 |
| 0x2a3c4e0 | 0x2a3c784 | its serializer, field map only | not run |

The builder has one direct caller, 0x2586ae0 at 0x2586b2f. The serializer has one, 0x2a30590 at 0x2a30597. The instructions not executed are listed under `unexecuted` in `evidence.json`: the unwind blocks from 0x27d89f2 to the FDE end, and the jump after a panic call that does not return.

### Result layout

The result is 0x130 bytes. The JSON keys and offsets are read by the tool from the serializer's own instructions (`serializer_fields`). The sources are from the evaluated code (`result_fields`).

| Result | Key | Source |
|---|---|---|
| +0 tag, +8..+0x27 body, +0x28 end | `trial` | tag 1 when the rate row dword +0x68 is non-zero; body is rate row +0x28..+0x47; end is that dword as Unix ms |
| +0x30 tag, +0x38 value | `nextTrialAvailableTimestamp` | value dword +0xb0 plus 90 days, as Unix ms, only when the dword is non-zero |
| +0x40 | `dailyUserVlm` | 0x25806a0, called with the date, the user and the range word (0, 14) |
| +0x58..+0xc7 | `feeSchedule` | 0x70 bytes from slot 0x5774ef0, which holds 0x2a3bb60 |
| +0xc8, +0xd0, +0xd8, +0xe0 | `userCrossRate`, `userAddRate`, `userSpotCrossRate`, `userSpotAddRate` | rate row +0, +8, +0x10, +0x18 |
| +0xe8 | `activeReferralDiscount` | xmm0 from slot 0x5774ef8, which holds 0x3743020 |
| +0xf0 | `feeTrialEscrow` | below |
| +0xf8, +0x100 | `activeStakingDiscount` | rate row +0x20, then the ladder pick below |
| +0x108..+0x11c | `stakingLink` | tag byte and 20 address bytes |
| +0x120, +0x128 | none | 2 Durations as f64 seconds, below |

### Order of the function

Arguments: rdi result, rdx outer state, rcx user address, first stack dword a flag byte. rsi is not read. The caller passes byte outer +0x4b90 as the flag.

1. Clock read. Read lock on outer +0x568: the fast path adds 0x10 by compare-exchange when bit 3 is clear and the word is below 0xfffffffffffffff0, otherwise slot 0x576f5e8 takes it with arguments (lock, 0, 1000000000).
2. Clock read. The wait is the first result +0x120.
3. Daily list from the date dword outer +0x5d0, with the exchange at outer +0x570.
4. A 0xe8-byte hash table at outer +0x1680 (mask +0x1688, count +0x1698, hasher +0x16a0) is probed by 20-byte user key. A count of 0 skips the hash. The value is the key address + 0x18. This table is tracker +0xc0 with the tracker at outer +0x15c0, the `user_states` map of `fees-fill-ledger-94`.
5. Rate row, schedule copy, staking link tree, discount.
6. Trial end, escrow, next trial, ladder.
7. Lock release: subtract 0x10, and slot 0x576f5f8 is called when the old word masked by 0xfffffffffffffff2 is 0x12.
8. Clock read, the second Duration goes to +0x128.
9. When the flag is non-zero, slot 0x576e8f8 (0x13c9e20) is called with 50, after the result is complete and before it is copied out.

The whole read sits inside one read lock, and the lock is held across steps 3 to 6.

### Escrow

With a value row, the tree at value +0x98 (height +0xa0) is searched for u64 key 0. Keys sit at node +0x218, count at +0x272, children at +0x278, 0x30-byte values at node +0. A hit takes value word +0x28, the sixth word, `T` in `fees-fill-ledger-94`.

`feeTrialEscrow = f64(T) / table[d]`, where `d` is byte +0x49 of the first row of the list at outer +0x780 and `table` is the f64 powers of ten at 0x584b08. An empty list panics with Location `l1/src/spot_meta.rs:113:33`. A hit on key 0 is what reaches that panic: no key 0, no list read.

The field has no tag. With no value row or no key 0 it is 0.0.

### Dates

Rate row +0x68 and value +0xb0 are packed chrono dates: year in bits 13 and up, ordinal in bits 4..12. Both copies of the conversion compute the day number from year 1 with 400-year cycles added for years up to 0, subtract 719163 and multiply by 86400000, floored at 0. Value +0xb0 first goes through slot 0x576e8b0 with 90, and a result of 0 panics with ``NaiveDate + TimeDelta overflowed`` at `chrono-0.4.38/src/naive/date/mod.rs:1909:38`.

### Stake ladder

The list is at outer +0x15f8, length +0x1600, 16-byte rows (cutoff f64, discount f64). `s` is rate row +0x20.

- Empty list, or first cutoff above `s`: 0.0.
- Otherwise the discount of the row before the first later cutoff above `s`, or of the last row. A cutoff equal to `s` counts as reached.
- `ucomisd` then `ja` and `jbe`: a NaN cutoff is treated as reached, and a NaN `s` reaches every row.

### Staking link

Tree at outer +0x4a08, height +0x4a10. Keys are 20 bytes at node +8, compared by memcmp, count at +0xe6, values at +0xe8 (21 bytes: tag, address), children at +0x1d0. A hit copies the tag and the address. No hit gives tag 3 and leaves the 20 address bytes as stale stack.

### Durations

Each is `nanos / 1e9 + secs as f64`, with 0.0 when 0x4ee3730 returns its error tag. The first spans the lock wait, the second the time under the lock. The caller reads both words at once, at its +0x130 and +0x138, and adds them.

## Implementation and comparison

not yet implemented. `reference-diff.tsv` has 6 rows against `info_server/abci_state_info_handler.rs` and `l1/fees/compute.rs`. The reference's Option fields for referral discount, escrow and staking discount have no tag word in the result. The reference has `staking_link` as an address, and the bytes have a tag byte beside it.

## Results and limitations

- 252 vectors, 0 mismatches against a separate closed-form model. Every stub checks its arguments, and every run checks the order of the calls, that the lock is held during the state reads, the callee-saved registers, the final lock word and all compared result bytes.
- 318 mutants: 298 killed, 20 equivalent, each with a reason in `mutations.tsv`. The first survey found 4 real vector gaps: table hits with no escrow gave the same result as a miss, and no date had a year - 1 divisible by 100. Both were fixed.
- Regenerating with the tool gives byte-identical files, compared over full runs.

Inferences, not observations:

- `T` is the escrow of a fee trial. This now rests on the serializer key at +0xf0 and on the load of value word +0x28, which is stronger than the letter used in `fees-fill-ledger-94`.
- Key 0 of the token tree is USDC and `d` is its wei decimals. Byte +0x49 of the first token row is read, and the `spot_meta.rs` panic Location points at a token list. No text names key 0.
- Value +0xb0 is the last trial end date: the 90 days are added here and the rollover family stores it. `fees-start-trial-94` reads the same word as the cooldown base.
- Rate row +0x20 is the stake share in bps of max supply. `bpsOfMaxSupply` sits in `.rodata` beside these keys, and the discount rows have 2 words. The inner serializer 0x29fed30 was not read.
- The stakingLink tag names the link state. `requested`, `stakingUser` and `tradingUser` follow in `.rodata`, 3 names for 3 tags. The order of the tags is not established.
- The Durations are lock wait and lock hold timings used for a metric or log in the caller.
- The call with 50 is a sleep of 50 ms. 0x13c9e20 reads thread-local state and was not traced. The flag byte's meaning is unknown.

Unresolved:

- How 0x2a01350 prints the rate and escrow floats, and how a 0.0 escrow or discount appears in the JSON.
- What 0x25806a0 returns for the 14-day list, and the field names of `dailyUserVlm`.
- Whether the rate row call here sees the same trial row as a fill. The stub writes a pattern outside the fields the builder reads.
- All state is synthetic. No value here was read from a real state.
- Each vector is one call. The equivalence of the survivors is an argument, not a proof.

Next question: what does the 14-day list 0x25806a0 return, and does its `userCross`/`userAdd` pair confirm which day tree word is the maker side?
