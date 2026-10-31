# fees: node #94 staking link and the stake share behind the fee discount

- Component ID: fees
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: 1f8c67c63ca4794c9689235471c60297f8a5c985 / references/can1357-hl 999556f6e0a474b8312db96ec3149e1c44e97c23
- Claim status: observation for byte-derived rules below, inference where marked, unresolved items listed under Results and limitations
- Scope included and excluded: included are the 2 link actions in all 3 copies, the request gate, both map writers, one tree search, and one range of each of the 3 fee row builders, from the link lookup to the 4 discounted rates. Excluded are the rest of the row builders, the bodies of the B-tree insert, set insert, stake lookup and requirement list (stubs), the dispatch before the actions, and any sequence of several actions: each vector is one call.

## Reproduce

Run from the repository root:

```
python3 tools/fees_staking_link.py --out research/work-items/fees-staking-link-94
cd research/work-items/fees-staking-link-94 && sha256sum -c MANIFEST.sha256
python3 -m unittest tests.test_fees_staking_link
```

Python 3 standard library only. The tool refuses any binary whose SHA-256 differs from the value above, never runs the binary, and calls no external program. Sections and FDE data come from `tools/elf_index.py` and `tools/fde_extents.py`. A full run takes about 90 s on 3 workers. Two full runs gave identical generated files.

## Evidence

Coordinates are virtual addresses in the ELF above. Every generated number comes from bytes. Field names on this page are mine unless a row says where they come from.

### Boundaries

| Address | FDE end | Role | Decoded / executed |
|---|---|---|---|
| 0x1e60770 | 0x1e60844 | linkStakingUser, copy A, called at 0x275985b in 0x2759240 | 54 / 54 |
| 0x46ba6c0 | 0x46ba8b0 | copy B, gate inline, called at 0x4d8478b | 108 / 108 |
| 0x46ba4d0 | 0x46ba6c0 | copy C, +0xa80 offsets, called at 0x4d8366b | 108 / 108 |
| 0x2769ff0 | 0x276a144 | request gate of copy A, one caller | 84 / 83 |
| 0x2fdcad0 | 0x2fdcbc3 | tree search in the inline gates | 70 / 69 |
| 0x3b45f40 | 0x3b462a0 | request writer, slot 0x5774df0 | 196 / 195 |
| 0x3b462a0 | 0x3b464dd | finalize writer, slot 0x5773150 | 136 / 135 |
| 0x1e648c0 | 0x1e64aba | action of discriminant 202, copy A, called at 0x2759eaf | 120 / 119 |
| 0x46bd7a0 | 0x46bd99a | copy B, called at 0x4d84dbd | 120 / 119 |
| 0x46bd5a0 | 0x46bd79a | copy C, called at 0x4d83c9d | 120 / 119 |
| 0x26fbab0 | 0x26fd364 | row builder, range only, called at 0x251cc9c | 336 / 333 |
| 0x4ce19c0 | 0x4ce3354 | row builder, range only, called at 0x476bb71 | 367 / 364 |
| 0x4ce3360 | 0x4ce4cf4 | row builder, range only, called at 0x47679c1 | 367 / 364 |

Range pieces of the 3 builders are in `evidence.json` under `functions`. A builder range ends at the first instruction after the rates are stored, which is the stop of the run and is not executed. Every other non-padding instruction decoded was executed by some vector, so `unexecuted` is empty.

`evidence.json` compares copies by decoded instruction with code addresses taken out. 0x46ba4d0 differs from 0x46ba6c0 by 4 rows, 0x46bd5a0 from 0x1e648c0 by 3, and 0x4ce3360 from 0x4ce19c0 by 8 rows in the range. All of those rows are exchange offsets moved by +0xa80 (+0x3a18 to +0x4498, +0xaf0 to +0x1570, +0x8b8 to +0x1338, +0x8f2 to +0x1372, +0xa60 to +0x14e0, +0x608 to +0x1088). 0x46bd7a0 has no differing row. 0x1e60770 keeps the gate in 0x2769ff0, the other 2 copies inline it through 0x2fdcad0. 0x26fbab0 has a different stack frame from 0x4ce19c0, so the tool holds a frame map for it and runs it on the same vectors.

Action discriminants 127 and 202 and their call sites 0x275985b and 0x2759eaf are already in `research/work-items/RE-010-exchange-handlers/exchange-dispatch.json`; this packet takes the bodies, not the dispatch.

### Link map

State +0x3a18 holds root and height of a B-tree from 20-byte address to 21-byte row. In a node: keys at +8, parent index +0xe4, count +0xe6, rows at +0xe8 with stride 21, children at +0x1d0. Byte 0 of a row is a tag, the next 20 bytes an address.

The decoder 0x3b464e0 names the 3 tags from .rodata (`names` in `evidence.json`):

| Tag | Name | Field |
|---|---|---|
| 0 | `Requested` | `staking_user` |
| 1 | `TradingUser` | `staking_user` |
| other | `StakingUser` | `trading_user` |

### linkStakingUser

Wrapper registers: rdi result, rsi action, rdx signer, rcx exchange. Action +0x28 is the 20-byte payload address. Action byte +0x3d selects the path: 0 is request, any other value is finalize.

Request, in this order, with signer = trading user and payload = staking user:

1. Payload has no key in the map at state +0xaf0: `Staking user has no staked HYPE`. Key presence is the whole test. A row whose 3 value words are 0 passes.
2. Both addresses equal: `Cannot link a staking user to itself`.
3. Row of the trading user has a non-zero tag: `Trading user already has a link established`.
4. Row of the staking user has a non-zero tag: `Staking user already has a link established`.
5. Write row of the trading user = tag 0 + staking user. An older pending row of that key is replaced.

Finalize, with signer = staking user and payload = trading user:

1. Row of the trading user is absent, has a non-zero tag, or names another address: `Trading user must request before staking user`.
2. Write row of the trading user = tag 1 + staking user.
3. Write row of the staking user = tag 2 + trading user.

Finalize reads no row of the staking user and does not repeat the stake test. Every failure is status 0x159 with the text in a new allocation of its exact size. The result byte is 0xd for success, 0xe for failure, and bytes +8..+0x68 of a failure are the inner result as it stood.

### Action 0x1e648c0

Same registers. Row of action +0x28 must have tag 1 and name the signer, else status 0x159 with `Trading user is not linked to this user.` On success the payload goes into the address set at state +0x8b8 through 0x284f810. The link row stays as it was: this body writes nothing to the link map.

### Stake share in the fee row builders

The builders 0x26fbab0, 0x4ce19c0 and 0x4ce3360 return a list of 0x98-byte rows, and each has one direct caller. Inputs of the range: user address, an option pair (tag in r9, value in the first stack word), the mode byte at state +0x8f2, 4 rates.

```
row = link row of user
if row tag > 1:                  share = 0
elif option is none:             share = 0
else:
    owner  = row address if row tag == 1 else user
    supply = 10^17 if mode byte == 2 else option value
    S = stake lookup of owner    (slot 0x5774900, state +0xa60)
    if S == 0:                   share = 0
    else:
        L = list call of owner   (bytes 4 and 1 in the closure)
        if L failed:             share = 0
        else:
            sum = saturating sum of L, each overflow calls the hook at slot 0x5773190
            credit = word 0 of the row of owner in the map at state +0xaf0, or 0
            excess = max(sum - credit, 0)
            share = 0 if S < excess or supply == 0
            share = f64(S - excess) / f64(supply) * 10000.0
```

So tag 1 counts the stake of the linked address, tag 0 counts the user's own stake, and a user whose row is the staking side counts nothing. The staking side's stake counts for the trading user instead.

The ladder is at state +0x608 (pointer) and +0x610 (count), 16-byte rows of 2 f64, limit then discount. The discount is 0 for an empty ladder or a first limit above the share. Otherwise the walk stops at the first later row whose limit is above the share and takes the row before it. An equal limit counts as reached. A NaN limit never stops the walk, and the ladder is not assumed sorted.

Each of the 4 rates r becomes r x (1 - discount) when 0 < r, and stays as it is otherwise, so a rebate and a NaN are unchanged. The share is stored at row +0x28 (byte pin at 0x4ce3174 and 0x4ce4b14).

### Other readers

`link-readers.tsv` lists 41 byte-scan sites of offset +0x3a18 or +0x4498 in .text with the function around each. Load sites are the 3 builders, the 3 copies of 0x1e648c0, the deployer gate 0x2751b30 with its copies 0x4d76ac0 and 0x4d77030, and one in 0x4d78460 that passes the root and height to 0x49989f0. The remaining sites take the address of the field beside others in serializer-shaped functions. A byte scan can hit inside another instruction, so this is a list of leads, not a proof.

The deployer gate is pinned only: a link row with a non-zero tag stores status 0x109 `Deployer cannot have staking link`, and a value from 0x258b4e0 above 100000000 stores 0x10a `Deployer cannot have more than $1M volume traded`. Tag 0 passes that gate.

## Implementation and comparison

not yet implemented. Comparison here is between decoded ELF bytes and a separate closed-form Python model, not a Rust build.

`reference-diff.tsv` has 9 rows against `references/can1357-hl`. Its handler `11_link_staking_user.rs` matches the order of both paths. It differs on the tag names and on the staking index, which is a map, not a set. It has no text for action 0x1e648c0 and no stake share or ladder.

## Results and limitations

- Vectors: 2520 over 6 action entry points and 3 builder ranges, 0 mismatches. A vector is one call. Strict arenas fault on any read of a byte the vector did not set. Stubs check their arguments, including the slot for the old row of each map insert and all 0x60 bytes of a list error.
- Mutants: 689 on 8 subjects, 679 killed, 10 equivalent with a reason each in `evidence.json`. They are 3 result words the only caller never reads, 2 dead spills, 1 store of a dword already there, and 4 write-backs of bytes the slot already holds.
- The first survey left 33 survivors. 21 were test gaps: addresses of near-repeated bytes hid shifted reads, the stubs did not check insert slots or the whole error payload, and no vector passed every key of a tall node. All 21 were closed. Of the others, 10 are the equivalents above, 1 was the stop instruction, now out of the sites, and 1 was the low byte of 10^17, which the f64 conversion loses, so that mutant now changes a higher byte and is killed.
- Copies 0x46ba4d0, 0x46bd7a0, 0x46bd5a0, 0x26fbab0 and 0x4ce3360 are run on all their vectors but not mutated.
- Inferences. The share is in basis points, from the factor 10000. The ladder is the staking discount, from the fields `staking_link` and `active_staking_discount` in the reference info response and from positive rates alone being scaled. With 8 decimals, 10^17 is 10^9 tokens, so mode byte 2 fixes the supply; which network that is, and where the option value comes from, are not traced. The list is the stake requirement and word 0 the delegated amount, from `exchange/stake_requirement.rs`, and the deployer gate reading the same helper 0x2512770; both are stubs here.
- Unresolved. The action name of discriminant 202. What the set at +0x8b8 does to a marked trading user, and whether a link row is ever removed. Whether a fill reads row +0x28. The rates at row +8..+0x27 by name.
- No progress gate is requested.

Next question: which code reads the set at state +0x8b8 for an address marked by 0x1e648c0, and does a link row leave the map there?
