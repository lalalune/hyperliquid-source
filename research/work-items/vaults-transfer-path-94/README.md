# vaults: node #94 vaultTransfer path: wrapper, user class router and host body

This packet shows that vaultTransfer stores its 300 ms time gate before any other test, refuses every
caller that is a normal or child vault, and writes the two account sums asymmetrically after the events,
so the host of a vault deposit or withdrawal can now be written from the bytes, with the
real order of its gates, events and sums, around the deposit and withdraw bodies held by other packets.

- Component ID: vaults
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository 1f8c67c; reference `references/can1357-hl` used as a label source only
- Claim status: observation for pins, layouts and evaluated results; inference where marked; unresolved items are listed at the end
- Scope included: 0x1e5fb20, 0x27312c0, 0x27362b0, 0x2755400, 0x26f6050, 0x25a7f50, 0x370c1e0, 0x2712a00
- Scope excluded: deposit 0x395b3a0 (our open PR #873), withdraw validation 0x39582c0 (open PR #630), withdraw body 0x395bdd0 (open PR #632), 0x26f7ef0 (open PR #864), settlement steps 0x272d000, 0x272fe00, 0x272f880, post step 0x26f7280

## Reproduce

From the repository root, Python 3 standard library only, no external programs:

```sh
python3 tools/vault_transfer_path.py --out research/work-items/vaults-transfer-path-94
python3 -m unittest tests.test_vault_transfer_path
```

The tool checks the binary SHA-256, reads ELF bytes, and imports `tools/elf_index.py` and
`tools/fde_extents.py` for sections and FDEs. It never runs the binary. It writes evidence.json,
functions.tsv, stubs.tsv, callers.tsv, pins.tsv, layout.tsv, locations.tsv, cases.tsv and outcomes.tsv.
All contents are deterministic.

## Evidence

Addresses are ELF virtual addresses. Function extents are FDE ranges (`functions.tsv`), 8 functions and
6,712 bytes in all. Instruction text in `pins.tsv` comes from the small decoder inside the tool, not
from objdump, and each of the 64 rows is compared with a frozen expected string. Unknown encodings
raise an error. `layout.tsv` gives 25 field offsets, each tied to one decoded access.

### Wrapper and router

The wrapper 0x1e5fb20 is called only from the dispatcher (index 43). It calls 0x27312c0 with flag 0, key 0
and a list count of 0, and the action and user on the stack. Code 390 maps to tag 13 and any other code to
tag 14. `callers.tsv` shows that the router's only caller is this wrapper.

The router reads the class byte, user row +0x3c through 0x2755400.

| Class | Test | Route |
| --- | --- | --- |
| 4 and up | bit 0 of exchange +0x5b0 set | direct |
| 4 and up | bit clear | slow |
| below 4 | bit 0 of exchange +0x5b1 set | direct |
| 0, 1 | any | direct |
| 3 | bit clear | slow |
| 2 | bit clear, count below 2, or exchange +0x3acb off, or flag set, or key 0 | direct |
| 2 | otherwise | settlement before and after the body |

From the wrapper, count and key are always 0, so class 2 is always direct. The class 2 settlement route
was evaluated by calling the router directly with other arguments.

The slow route opens a row with 0x1f84640 on exchange +0x770 and runs two window tests. Both false gives
code 368 with no body call. Otherwise the row counter +0x30 and exchange +0x7d0 go up, saturating, the
entry step 0x272fe00 runs and the body runs. Class 4 then calls 0x272f880, and class 3 calls 0x272d000.

A failed settlement step does not change the result. The router drops that code through 0x277eba0 and
returns the code from the body.

### Body 0x27362b0

Action: usd +0x00, vault +0x08, is_deposit +0x1c. Exchange +0x58 goes up on entry and down on exit, both saturating.

| Step | Test | Result |
| --- | --- | --- |
| 1 | now < stored time + 300,000,000 ns, compared as date, seconds, nanoseconds | code 31, stored time kept |
| 2 | always | stored time = now, before all later tests |
| 3 | usd >= 0x0ccccccccccccccc | code 319 with usd |
| 4 | caller is a vault key: tag < 2, or vault not in its child set | code 25 with the caller |
| 5 | vault key missing | code 7 with the vault |
| 6 | is_closed +0xac | code 8 |
| 7 | no clearinghouse | panic, unwrap of Err(321), clearinghouses.rs:17:33 |
| 8 | deposit and usd < 5,000,000 | code 41 |

The stored time at exchange +0x3ab0 is one exchange field with no user key. Steps 3 to 8 run after the store.

Deposit calls 0x395b3a0 through its slot. The first result word 0x8000000000000019 means failure and the
code follows. Otherwise the event goes out with users [caller, vault] and amount = -usd.

Withdraw first looks for a special vault:

```text
chain byte below 2: no compare
chain byte 2:       a15099a30bbf2e68942d6f4c43d70d04faeab0a0
chain byte above 2: dfc24b077bc1425ad1dea75bcb6f8158e10df303
if the vault matches and exchange +0xbb0 != 0:
    cap = trunc_sat(exchange +0xbb8 as i64 as f64 * (1.0 - exchange +0x39c8))
```

Then, in this order: validation 0x39582c0 with usd != 0, usd and the optional cap; 0x26f7ef0 with the amount;
if the validation flag is set, 0x26f7280 with its f64; a second vault lookup through 0x25a7f50, where a miss
panics; withdraw body 0x395bdd0 with the amount and a second f64.

| Withdraw body result | Effect |
| --- | --- |
| first word 0x8000000000000019 | code 390, no event, no sum |
| second word not that value | leader event first, users [leader] |
| always otherwise | event with users [caller, vault], amount = returned amount |

Both paths end in the same sum step:

```text
r = trunc_sat(amount as f64 * clearinghouse[0]+0x2a0)   non-finite gives 0
r == i64::MIN                                           panic, core num mod.rs:320, after the event
r = clamp(r, -0x147ae147ae147ae, 0x147ae147ae147ae)
vault:  +0x10 += trunc(-r / 10000), +0x18 += trunc(-r / 10000)
caller: +0x18 += trunc(r / 10000), +0x10 unchanged
```

Adds saturate and call the recorder with Location impl_ntl.rs:665:1. On withdraw the vault side goes down
and the caller's +0x18 goes up. `cases.tsv` shows both directions.

### Evaluation

The tool runs each body in Python over the real instruction bytes and compares the result with a plain
model: 512 body, 384 router and 64 wrapper vectors, 960 in all, with 33 distinct outcomes in
`outcomes.tsv` and 0 disagreements. `cases.tsv` has 21 named scenarios.

`stubs.tsv` lists the 25 replaced calls with their FDE extents. Fixtures build real B-tree nodes for the
vault map and child set and one SwissTable group for the user table. Caller-saved registers are overwritten
after each stub. The time stubs model chrono with plain integers: date + days and a 86400 s day.

### Reference comparison

| Reference text | Bytes |
| --- | --- |
| only parent or child kinds are tested, and either direction of the relation passes | every caller vault is tested; tag below 2 is refused, a parent passes only for a stored child |
| both sums change for both addresses | the caller's +0x10 does not change |
| `apply_scaled_ntl` clamps raw to i64 | scale at clearinghouse +0x2a0, clamp to 0x147ae147ae147ae, then / 10000 |
| failed post check returns Rejected(post) | the code is dropped and the body result returned |
| privilege and settlement order with `consume_required_key` | two window tests, code 368, then a counter on both row and exchange |
| withdraw computes equity and commission in the host | these live in validation and withdraw bodies; the host only forwards amounts |
| leader commission event after the transfer event | leader event first |
| no special vault | cap for two fixed addresses behind the chain byte |

## Implementation and comparison

not yet implemented. No Rust was written. The formulas above are readings of the bytes, checked over the
listed vectors. They are not a claim of binary equivalence.

## Results and limitations

Passed: 64 pins, 25 layout rows, 8 functions, 25 stubs, 4 Location records, 960 vectors with 0
disagreements and 21 named scenarios. `tests/test_vault_transfer_path.py` runs 49 tests: 9 positive,
8 negative controls (wrong binary hash, address outside file-backed sections, changed pin byte, changed layout
operand, unknown encoding, unmodelled call, non-FDE start, generated file drift) and 32 one-edit binary
mutants, each of which the models or fixed expectations catch.

Limits:

- Stubs are assumptions about interfaces. The result buffers of the deposit, validation and withdraw stubs carry
  only the words this host reads, and the fields inside each event are copied bytes.
- chrono is stubbed. Leap second values and the panic arms of date overflow were not evaluated.
- B-trees stay at height 0 or 1, and the user table holds one row in the router vectors.
- Inferred: chain byte 3 is Mainnet, from the bridge packet.
- Inferred: the address for chain byte above 2 is the HLP vault. The bytes are observed, the name is not in the binary path read here.
- Unresolved: what the two windows at exchange +0x4e8 and +0x4f8 measure, what the fields +0xbb0, +0xbb8 and +0x39c8
  mean, why the second f64 of validation goes to the withdraw body, and what the depth counter guards.

Next question: what do the window tests 0x37d9ef0 count, and which user classes reach them on mainnet?
