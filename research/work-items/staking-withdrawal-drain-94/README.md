# staking: pending withdrawal drain in node #94

This packet shows how node #94 finishes a staking withdrawal, so a reconstruction can write the block step from bytes: rows with an unlock key strictly below block time leave the time keyed queue, each one lowers `user_to_total_withdrawal` first and the balance in `user_states` second, and only rows that pass the balance test reach the spot credit and the `isDeposit = false` ledger row.

- Component ID: staking (Staking and validator lifecycle)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. `l1/staking.rs` of the reference has a type `BTreeMap<Address, Vec<WithdrawalRequest>>` with `unlock_epoch` and no drain code. The bytes hold a different shape, see below.
- Claim status: observation for everything under Evidence, from ELF bytes and an evaluator of those bytes. Names not found in rodata are marked inference. Unresolved items are under limitations.
- Scope included and excluded: included are the whole functions `0x26fdaf0`, `0x4ce6090`, `0x4ce5be0` (the step in three copies), `0x3c13400`, `0x3bae220`, `0x3babc50`, `0x33aedb0`, `0x3bbb120`, `0x33082c0`, `0x2fb2ce0`, `0x2fb1c70`, `0x2fb2930`, `0x33bac00`, `0x33aa1b0` and `0x39935d0`. `0x26fdaf0`, `0x4ce6090` and `0x4ce5be0` appear only as inventory rows in #650 and #907, and `0x33bac00` is a bound helper of the enqueue packet #599, which does not run the drain. This packet answers the next question of #599. Excluded, and stubs here: the credit `0x371d120`, `0x371cf40`, the name builder `0x3c0d6e0`, the sinks `0x3576710`, `0x4855a50`, `0x4856e20`, the leaf insert `0x2f90ca0`, the removal `0x2fd8ea0`, and the stake sum `0x3c0f050`. The queue insert side is #599.

## Reproduce

From the repository root:

```
python3 tools/staking_withdrawal_drain.py --out research/work-items/staking-withdrawal-drain-94
python3 -m unittest tests.test_staking_withdrawal_drain
```

The tool takes about 7 minutes with 4 worker processes. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It starts no objdump or readelf. The binary is never executed: an interpreter inside the tool evaluates its bytes.

Generated files: `evidence.json`, `function-rows.tsv`, `callers.tsv`, `constants.tsv`, `field-names.tsv`, `kind-sites.tsv`, `copy-compare.tsv`, `outcomes.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

Virtual addresses. Function bounds are FDE bounds. Slots come from `.rela.dyn`. `E` is the Exchange state pointer in `rdi`, and `S = E + 0x8f8` is the staking state. `S+0x1f8` is `user_states` and `S+0x210` is `pending_withdrawals`, bound in `field-names.tsv`. Its two parts read `queue` and `user_to_total_withdrawal` in the serializer `0x3c13910`, and `0x3c13400` steps from one to the other with `add r14,0x18`.

### Path

```
block step list: 0x222a12a in 0x22297c0, 0x470f2be in 0x470e9a0, 0x4716d18 in 0x47162d0
0x26fdaf0(E)                                  word E+0x80 low 32 bits == 1, else return
  0x3c0d6e0  token name of id E+0x88
  0x371cf40  balance handle of the same token
  0x3c13400(out, S+0x210, block time at E+0x60)
    0x2fb2ce0 + 0x2fb1c70 + 0x2fb2930         split the time map at block time
    0x3bae220 + 0x3babc50 + 0x33aedb0         walk due keys, row by row
      0x33bac00, 0x358dcd0, 0x33aa1b0         lower one row of S+0x228
  0x33082c0                                   in place filter over S+0x1f8
  for each kept row:
    0x371d120  credit
    0x3576710  ledger row (kind word 0x8000000000000016)
```

### Time split

The queue is a B-tree map from a 12 byte time key `(i32 date word, u32 seconds, u32 nanos)` to a `Vec` of 32 byte rows `(u64 amount, 20 byte user, 4 unused)`. Node sizes `0x198` and `0x1f8`, values at `+8`, keys at `+0x110`, length at `+0x196`, edges at `+0x198`. The date word compares as signed, the other two as unsigned.

A key strictly below block time is due. A key equal to block time stays until a later block. That edge is case `key_equal_now` and a byte control in the test file. Rows run in key order, then in list order. A map root of null with length 0 skips the split. A null root with a non-zero length panics at `0x3c134ec`.

The kept side becomes the new queue, so the root pointer, height and length are replaced on every block with a non-empty queue, even when nothing is due.

### Pending totals, before any balance test

`S+0x228` maps user to `(P, N)`. For every due row, in order, before the filter runs:

| Input | Effect |
| --- | --- |
| `P >= x` | `P -= x` |
| `P < x` | recorder `0x358dcd0` with site `0x56dfd90`, `P = 0`, the run goes on |
| old `N > 1` | `N -= 1`, row stays |
| old `N <= 1` | row removed through `0x33aa1b0`, even with `P` left over |
| no row for the user | `0x33bac00` inserts `(0, 0)`, then the two rules above apply: a recorder hit if `x > 0`, and the new row is removed at once |

`N` never wraps: the `cmovae` at `0x3babefc` keeps 0.

### Balance filter

`0x33082c0` compacts the row buffer in place. For each row in order:

- No `user_states` row: dropped.
- First word of the row below `x`: dropped, word unchanged.
- Otherwise the word falls by `x` and the row stays. The other 16 bytes of the row are not touched. Equal amounts pass and leave 0.

A dropped row gets no credit and no ledger row, and its `P` and `N` were already lowered. A later smaller row of the same user can still pass (case `short_row_then_small_row`).

### Credit and ledger row

For each kept row, in order: `0x371d120(E+0x80, user, token, 0, x, handle)`, then a 20 byte user list and a copy of the token name, then the test `token < word E+0x218`. A token past the table panics after the first credit has run. With no kept row there is no panic.

The record is the kind word `0x8000000000000016`, the name, the f64 of `x` over `10^d` and a byte 0. `d` is byte `+0x49` of the `0xe8` byte token row, and `0x584b08` is a table of 23 doubles `1e0` to `1e22`. `x` above 2^53 rounds to nearest, as the two word sum `0x26fdd71..0x26fdd8e` does.

`kind-sites.tsv` lists the six writers of that kind word. The three drain copies store byte 0 and the three copies of the deposit `0x2734840` (#514) store byte 1 at the same record slot, which fits the rodata word `cStakingTransfer` and the serde key `isDeposit`. The variant name is an inference: no lea ties it to the number 0x16 here.

### Three copies

`copy-compare.tsv`: `0x4ce6090` has 223 rows, all equal to `0x26fdaf0` once inside branch targets are made relative. `0x4ce5be0` has 242 rows, the two state fields shifted by `0xa80`, the handle argument `E+0x3e00`, the ledger sink `0x4855a50` on `E+0x5b8` with a zero stack hash, and one more event `0x4856e20` after each row with `(x, token, E, E+0x90, user, byte E+0x1372, 1)`. All three copies run in every named case.

### Who reads P

`0x39935d0(S, user, flag)` returns `Some(U + D - P)` floored at 0, with `U` the `user_states` word and `D` from `0x3c0f050`. Flag low byte non-zero skips `P`. A wrap of `U + D` gives `None`. A missing user row counts as 0. Callers are in `callers.tsv`; `0x2751f5b` passes flag 0 and tests `Some` and `result >= rbp`. So `P` lowers the amount that caller sees until the drain runs, and that is the only effect of `P` read here.

### Controls

- 802 named and 300 generated cases: 0 mismatches between the real bytes and a rule list that shares no code with the tree walks. Compared: event order and arguments, recorder hits, freed sizes, final queue, totals and user rows, and every other byte of the state range.
- Trees of height 0, 1 and 2 at many cut points. Every result tree is walked and its parent links, slots and length word checked. Two runs in a row prove the kept tree works as next block input.
- 831 byte edits on reached rows: 737 killed, 94 survived. An unedited image must pass under the same step limit. Survivors by class; the open class was not analysed and is not a claim either way:

  - 71: open: no named case tells this edit apart and it was not analysed further
  - 12: dangling name pointer, or size and align arguments of an allocation failure stub: the stub compares neither
  - 9: size hint words of the row buffer and the iterator copy length: same rows in every case
  - 2: fresh node allocation size: the fixture arena does not check the size

## Implementation and comparison

not yet implemented

## Results and limitations

`python3 -m unittest tests.test_staking_withdrawal_drain`: 60 tests, all pass.

- Unreached rows, listed per function in `evidence.json`: 448 of 2786 rows. They are unwind cleanup, allocator and assert panics, tree arms of height 3 or more, the root pop in `0x33aa1b0`, and the back iterator of `0x3babc50`, which no caller here fills.
- The credit, handle, name, sinks and stake sum are stubs, so what they compute is not claimed. `0x371d120` is held by many open packets.
- `0x2fd8ea0` and `0x2f90ca0` are stubs that keep the tree logically right, so tree rebalance after a total row removal is not evaluated.
- Whether a due row can meet a short balance in a real chain is not shown. Only the rule is. The enqueue side does not lower the word, and delegate paths were not read for this.
- The block step list around the three call sites is unconditional at the site, but why the list runs was not read.
- `cStakingTransfer` for kind 0x16 is an inference, see above.

Next question: which paths lower the `user_states` word between enqueue and drain, and do they all respect `0x39935d0`?
