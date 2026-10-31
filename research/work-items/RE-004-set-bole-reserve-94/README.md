# RE-004: node #94 SetBole vote, reserve config apply and side gate

New in this packet: the shape of `SetBole::Reserve` is settled from bytes, so a reconstruction can write the reserve row, its validity rule, its caps and the side gate from one table; the reference's unit `Reserve` and its low tag selector names cannot be used.

- Component ID: `l1`, task `RE-004`
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit: `1f8c67c63ca4794c9689235471c60297f8a5c985`
- Claim status: partial. Words 0, 1, 2, 6, 8 (gate only), 9 to 15 of the vote, the Reserve apply, the check and the side gate are pinned. Words 4, 5, 7, 16, 17 are listed and not modelled.
- Scope: the vote's inner dispatch at selector entry `0x4e`, `reserve_apply 0x37417b0`, `reserve_check 0x3740300`, `reserve_side_gate 0x3734e00`. No execution of the binary.

## Reproduce

```
python3 tools/set_bole_reserve.py --out research/work-items/RE-004-set-bole-reserve-94
python3 -m unittest tests.test_set_bole_reserve
```

The tool checks the binary's SHA-256 first, uses only the standard library plus `tools/fde_extents.py`, and writes every generated file here byte for byte. It takes about 90 s on this server, the byte edit sweep included.

## Evidence

Files: `function-rows.tsv` (bytes of the three subject functions, 892 rows, 4123 bytes), `arm-rows.tsv` (1665 reached rows of the three dispatcher copies), `word-table.tsv`, `validity.tsv` (all 128 inputs of the rule), `texts.tsv`, `serde.tsv`, `slots.tsv`, `reference.tsv`, `outcomes.tsv`, `mutations.tsv`, `evidence.json`.

### Observed: inner words

The dispatcher maps a word below `0x12` to entry `0x4e` (`mov $0x4e,%ecx; cmovae`). That arm then maps word `w` to sub table index `w-2`, or index 1 for `w < 2`. Sub tables: `0x3dd340` and one per copy (`word-table.tsv`). The serde text has six struct variants for `SetBole`, and these words sit in their niche.

| word | index | effect, all bytes at state offsets |
|---|---|---|
| 0, 1 | 1 | Reserve; the word's bit 0 is the first option flag |
| 2 | 0 | byte `+0x5b3` = value bit 0 |
| 6 | 4 | byte `+0x5b2` = value bit 0 |
| 9 | 7 | byte `+0x5b0` = value bit 0 |
| 10 | 8 | byte `+0x5b1` = value bit 0 |
| 11 | 9 | `+0x550` = v if v < `0x0ccc...cc`, else tag `0x13f` with v |
| 12 | 10 | `+0x558`, same gate |
| 13 | 11 | `+0x548`, same gate |
| 15 | 13 | `+0x590`, same gate |
| 14 | 12 | seven optional words `+0x4f0, +0x500, +0x4f8, +0x510, +0x508, +0x520, +0x518`, in that order |
| 8 | 6 | tag `0x8d` on chain byte 3 (`+0x8f2`, `+0x1372` in copy c); the rest is not modelled |
| 4, 5, 7, 16, 17 | 2, 3, 5, 14, 15 | listed only |

Word 14 writes as it goes: a refused field leaves the fields before it stored. Fields three, five and seven use zero as absent; the others have a flag word.

### Observed: Reserve arm

Order of refusal, from the arm's rows:

1. token >= `+0x218`: tag `0xea`, token in word 1.
2. Optional LTV text: over 100 bytes tag `0x143`; the text parser's error; LTV gate result 2 gives tag `0xe1` inner `0xa`.
3. Optional curve: the curve parser's error.
4. Caps against `0x0ccc...cc`, in the order action `+0x18`, `+0x08`, `+0x38`, `+0x28`: tag `0x13f`. The `+0x08` refusal stores 1 in word 1, not the value; the other three store nothing there.
5. Two price texts: the parser's error.
6. Seed word from slot `0x5773ea8`, stamp from state `+0x60`, `+0x68`, then `reserve_apply(state+0x560, token, state+0x90, config)`.

`reserve_apply` returns `0x11` or 4, and the arm turns anything but `0x11` into tag `0xe1` inner `0xa`.

### Observed: reserve row, `0xb0` bytes

| offset | word | source |
|---|---|---|
| `+0x00`, `+0x08` | LTV option | config tag 2 sets, tag 1 clears the flag and keeps the value |
| `+0x10` | seed word | new row only |
| `+0x18`, `+0x20`, `+0x28` | balance, two more words | zero on a new row |
| `+0x30`, `+0x38` | min, max oracle price | tag 1 stores 0, tag 2 stores the value |
| `+0x40`, `+0x48`, `+0x50`, `+0x58` | borrowed, `borrow_state.mint_cap`, `user_mint_cap`, index | index `1e14` on a new row |
| `+0x60`, `+0x68`, `+0x70`, `+0x78` | supplied, `supply_state.mint_cap`, `user_mint_cap`, index | index `1e14` on a new row |
| `+0x80` to `+0xa0` | curve | four words |
| `+0xa0`, `+0xa8` | stamp | 8 and 4 bytes, new row only |

The cap names come from the three warning texts in `texts.tsv`, and the offsets from the compares that format them. Existing row: fields are patched on a working copy, the copy is checked, and only a clean copy is written. New row: LTV tag, both price tags, the curve and all four caps must be given, and LTV Some needs the min price tag 1. With LTV absent, word `+0x08` of a new row holds the min price tag.

### Observed: `reserve_check`

Inputs: token, whether the token is in the tree at state `+0x2e0`, and the patched row. `validity.tsv` holds all 128 inputs. A row is valid in exactly three shapes, 38 of the 128 inputs:

- not quote, has LTV, both borrow caps zero, no min price, has max price
- no LTV and token 0
- quote, no LTV, has min price, no max price

Separately, `borrow_cap > supply_cap` and `user_borrow_cap > user_supply_cap` each add a warning; equal passes. Warnings are built with `format` and then freed unread by `reserve_apply`: only the count being nonzero matters, and no text leaves this path.

### Observed: `reserve_side_gate`

`gate(new, old, amount, token, side, keep, record)` is called through slot `0x5775108` from 7 sites. `side` picks the index and the row field: 1 is `+0x58` with the value's second word, rounded up; 0 is `+0x78` with the fourth word, rounded down, both over `1e14` in 128 bits.

- A scaled value past 64 bits gives status 3.
- `keep` 1 needs old >= new, `keep` 0 needs old <= new; a miss gives `0x10`.
- Room comes from `0x37407b0`, run real here: `B=ceil(borrowed*index/1e14)`, `S=floor(supplied*index/1e14)`, `L=balance+B`, `R=+0x28+S`, status `0x10` if `L<R`, else room `(+0x20 + +0x28) + (L-R)`. Each add saturates and calls the recorder.
- `amount > room` gives `0x10`; otherwise `0x11`.

## Implementation and comparison

Not yet implemented in Rust. A rule list in the tool, written apart from the machine, predicts status, nested byte, tree rows, warnings in order with their arguments, every state byte and every freed block. 1115 named cases (each dispatcher case on all three copies) and 600 generated vectors match on real rows. Trees are real node layouts walked afterwards, with stale keys in unused slots; a full leaf split runs real code.

Hooks replace the text parser, the LTV gate `0x3b47c50`, the curve parser, the price parser `0x3978100`, the seed reader and `format`, and each hook checks what it receives. These are edges here, not claims.

| check | result |
|---|---|
| byte edits on reached rows | 983 |
| killed | 954 |
| survived | 29 |

Survivors, all classified in `mutations.tsv`:

- 12: drop flag of the arm: every case frees every string either way
- 10: the check reads none of these row words, so the working copy may hold anything there
- 3: the warning text length is never read: the list is freed by capacity and pointer
- 1: a larger node length: sorted keys stop the search first
- 1: any status but 0x11 gives the same 0xe1 with inner 0xa at the dispatcher
- 1: empty list pointer: not read before the first push
- 1: entry height word: this path reaches a leaf, the insert did not read it

## Results and limitations

- 58 rows of the subject functions are unreached: landing pads, a warning list free that a clean check cannot reach (the list has no capacity), and status 2 in the gate, whose test needs a zero value with a nonzero product.
- Field names outside the three warning texts are readings. `balance` follows earlier packets; the words at `+0x20`, `+0x28` have no name here.
- The serde key run `lybubusMpmp` fits nine fields but keys are not tied to action offsets here.
- Callers of the gate were read only at two sites, so what `new` and `old` mean per caller is open.
- Copy c keeps the chain byte at another offset; other shifts in that copy were reached only through these paths.

Next question: what do words 4, 5, 7, 16 and 17 do, starting with the side effects in word 16 (`0x373cc50`)?
