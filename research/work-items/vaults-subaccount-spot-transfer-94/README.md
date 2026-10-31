# vaults: node #94 subAccountSpotTransfer path and the shared spot transfer core

This packet shows the whole path a spot transfer takes from the `subAccountSpotTransfer` action to the receiver: a vault can never receive spot (status 28), a sub-account map miss and a wrong master are one status (218), the core has its own 11 ordered gates, a system address send takes a different route, and a receiver of a system address send can pay a gas fee in the token, so a reconstruction can now write the shared transfer core behind `subAccountSpotTransfer` and `spotSend` with its gate order and fee rule from the bytes.

- Component ID: vaults
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository 1f8c67c; reference `references/can1357-hl` used as a label source only
- Claim status: observation for pins, layouts, status text and evaluated results; inference where marked; unresolved items are listed at the end
- Scope included: handler 0x1e64420 (arm 148), map check 0x2717a70, parse step 0x2714570, core 0x2712ce0, spotSend handler 0x1f66070 (arm 144), credit side 0x2716f90, and the helpers 0x375fc30, 0x37e5110, 0x371b8a0, 0x3724e80, 0x371b140, 0x371fcc0, 0x2712af0
- Scope excluded: gas quote 0x27101a0 (open PR #438), gas step 0x2711a80, follow-up 0x270f6f0, recipient step 0x2711440, system send 0x2715320 (open PR #29 holds its gates), ledger update 0x371d120, post-credit step 0x2716bc0, the other four callers of the core, the two same-size copies of 0x2716f90

## Reproduce

From the repository root, Python 3 standard library only, no external programs:

```sh
python3 tools/vault_subaccount_spot.py --out research/work-items/vaults-subaccount-spot-transfer-94
python3 -m unittest tests.test_vault_subaccount_spot
```

The tool checks the binary SHA-256, reads ELF bytes, and imports `tools/elf_index.py` and `tools/fde_extents.py` for sections and FDEs. It never runs the binary. It writes evidence.json, functions.tsv, stubs.tsv, callers.tsv, pins.tsv, layout.tsv, gate-order.tsv, status-text.tsv, same-size-fdes.tsv, locations.tsv, cases.tsv and outcomes.tsv. All contents are deterministic.

## Evidence

Addresses are ELF virtual addresses. Extents are FDE ranges (`functions.tsv`): 13 functions, 12,514 bytes. Instruction text in `pins.tsv` comes from the small decoder inside the tool. Each of the 258 rows is compared with a frozen expected string, and an unknown encoding raises an error. `layout.tsv` ties 27 fields to one decoded access each. `gate-order.tsv` lists 26 gates in run order. `status-text.tsv` reads each status's Display arm from the jump table at 0x59a8d0.

Callers (`callers.tsv`, a byte census of direct and slot calls): the handler has one call, 0x2759e1d in the dispatcher. 0x2714570 has two, from 0x2717a70 and spotSend. The core has six:

| Caller | Record +0x10 kind | Other |
| --- | --- | --- |
| 0x2714570 | 3 | Option word 0 or 1 |
| 0x1e5fcf0 | 3 | +0xb0 byte 0 |
| 0x2355f40 | 3 | +0xb0 byte 0 |
| 0x2750e60 | 3 | +0xb0 byte 1 and 20 bytes at +0xb1: the only caller that skips the block set |
| 0x272bd60 | 4 | +0xb0 byte 0 |
| 0x27196e0 | 0, 1 or 2 by its first argument, with +0x18 from rdx | +0xb0 byte 0 |

### Handler and sub-account step

| Order | Status | Text | Condition |
| --- | --- | --- | --- |
| 1 | 249 | Spot disabled | exchange +0x3ac8 nonzero, before any lookup |
| 2 | 367 | Action disabled when unified account is active | signer class byte 3 with +0x5b1 clear, or above 3 with +0x5b0 clear |
| 3 | 367 | same | same test on the sub-account |
| 4 | 218 | Invalid sub-account transfer from {} to {} | table empty, no row, or row master differs from the signer |
| 5 | 323 | Invalid input length | token text of 101 bytes or more |
| 6 | 323 | same | amount text of 101 bytes or more |
| 7 | 249 | Spot disabled | same flag, read again |
| 8 | 248 | Unknown token {} | no token of that name; the text is cloned into the error |
| 9, 10 | passed through | | status of the text parse, then of the Decimal scale |

`is_deposit` at action +0x44 picks the direction: nonzero moves signer to sub-account, zero moves sub-account to signer. The 218 payload holds both addresses in that order. Table rows are 0x28 bytes: key at +0, master at +0x14. The table sits at exchange +0x3810 with its count at +0x3828.

The step builds a transfer record: +0 and +8 Option word and value, +0x10 kind 3, +0x20 token, +0x28 amount, +0x30 payload word 0, +0x88 from, +0x9c to, +0xb0 byte 0. spotSend writes Option 1 with its time, and the sub-account path writes Option 0. That is the only record difference between them.

The token branch of status 323 stores a pointer word and the amount branch does not. The Display arm of 323 is plain text and reads no payload.

### Core 0x2712ce0: gates in order

| Order | Status | Text | Condition |
| --- | --- | --- | --- |
| 1 | 249 | Spot disabled | third read of the flag |
| 2 | 222 | Cannot self-transfer. | from equals to |
| 3 | 28 | Vault cannot receive spot. | `to` is a key of the vault tree at exchange +0x8d0, or is twenty 0xff bytes |
| 4 | 344 | User actions frozen for token | record +0xb0 bit 0 clear, and `from` in the token's set (row +0x10 tag 1, root +0x18, height +0x20) |
| 5 | 344 | same | same bit clear, and `to` in that set, by 0x375fc30 |
| 6 | 347 | Invalid send | kinds 3 and 4 only: token class word nonzero |
| 7 | 330 | EVM transfer not configured | `to` is not this token's system address but is in the system range |
| 8 | 347 | Invalid send | `to` is a user address and record +0x30 is nonzero |
| 9 | 38 | Error transferring to EVM. Use Arbitrum bridge instead. | token 0 into its system address: carry, total above exchange +0x3a48, or +0x31a2 set |
| 10 | 247 | Insufficient balance for token transfer | second word plus amount carries or exceeds first word |
| 11 | 356 | Can only transfer up to 1000 USDC to HyperCore per mainnet user | map value short, see below |

A sender that is a vault is not refused here. Only the destination is tested.

The system address of token n is 0x20, then 11 zero bytes, then n as 8 big-endian bytes. When state +0x80 holds tag 1 and n equals state +0x88, it is twenty 0x22 bytes. The range test 0x37e5110 is true for twenty 0x22 bytes and for 0x20 00..00 through 0x20 00..27 0f, so it covers 10,000 token numbers.

### Routes

| Route byte | Case | Then |
| --- | --- | --- |
| 0 | `to` is a user, `from` is not the system address | gas quote 0x27101a0, gas step 0x2711a80, follow-up 0x270f6f0 when the class byte is 2 or more, recipient step 0x2711440 |
| 1 | `to` is this token's system address | system send 0x2715320 |
| 2 | `from` is this token's system address | gas quote only; its result goes to the credit side |

In route 2 the core also hashes `to` and probes the table at state +0x740, but the hit, the miss and the empty test all branch to the same label, 0x27134bd, so the result is not used.

Token 0 only, when chain byte +0x8f2 is not 3 and token row 0 has tag +0xbc = 1. Call the 20 bytes at +0xbd the EVM word, and the map at state +0x3a50 the USDC map:

- Route 1 adds the amount to the sender's map value, saturating at u64 max, with a recorder call at `l1/src/qtys/impl_wei.rs:6`.
- Route 0 with `from` equal to the EVM word, and route 2 with `to` not equal to the EVM word, subtract from the receiver's map value. A missing key or a short value gives status 356 with payload word 0.
- The new value is written only after the route steps succeed.

### Debit and tally

After the route: raise the second word of the sender's token row (0x371b140), read the USDC price of the token, compute the USDC value, then call the ledger update with ecx 1. The cost word is 0 for kind 0, record +0x18 for kind 2, and the price otherwise.

USDC value 0x371fcc0: token 0 gives amount / 100. Any other token gives 0 at price 0, else the product-divide result, or 0 if its flag is clear. That value is capped at 1e16 unless the token is index 1 or is named `HYPE`. A value with bit 63 set takes the unwrap path at 0x2714469.

Kinds 3 and 4 add the negative value to the sender's tally through 0x2712a00.

### Credit side 0x2716f90

Route 0 and 1 go straight to the credit. In route 2:

1. Bit 0 of the gas flag sets byte +0x3d of the receiver's row at state +0x740.
2. With a gas quote of 0, go to the credit.
3. The price comes from the gas tree at state +0x2e0 (u64 keys at +8, length +0x62, flag bytes at +0x64, edges +0x70). A flag byte other than 1 reads the price through slot 0x5774548. A byte of 1 or a missing key needs the special token: none gives 251 `Native token does not exist`, another token gives 234 `Invalid token`, price 0 gives 352 `Price missing`, otherwise the transfer price is used.
4. A quote above 0x68db8bac710cb gives 319 `Invalid input number`. Otherwise quote x 100 goes to 0x333e310. A clear flag also gives 319.
5. Each of those statuses goes to the drop helper 0x277eba0, the transfer still returns 390, and the amount goes to slot 0x5774a48 and not to the receiver. A fee at or above the amount goes to the same sink with no status.
6. A smaller fee is kept. The credit runs with ecx 0, then the receiver's row +0x10 gets value / 10000, then 0x2716bc0.
7. With a fee: raise the receiver's second word, debit the fee with ecx 1, subtract the fee's USDC value / 10000 from the row, write a one-address event with tag 0x8000000000000012, and add the fee to the per-token total at state +0x420. The fee over 10^decimals is returned in xmm0.

The merge 0x2712af0 then forms the (name, first, second) result that the core returns. A first part above zero keeps its label. A nonzero second part takes the token's name. Equal names add. The name `HYPE` keeps the parts apart.

Kind 3 writes the ledger event: tag 0x800000000000000f, the two addresses, the optional word (or state +0x50 when state +0x78 is set), the token name, the amount over 10^decimals and the value over 1e6. Other kinds write none.

### Inferences

- Class 3 and up are unified or abstraction accounts. Basis: the text of status 367. The class byte itself is read from a stub.
- The first two words of a token row are total and hold, and 0x371b140 reserves. Basis: 0x371b8a0 tests hold + amount <= total, and the third word is read with them. The word names come from outside this packet.
- The USDC map counts what a user has moved to the EVM side and caps the way back. Basis: route 1 adds, the other routes subtract, and the status 356 text. The map is not reached from any other reader in this packet.
- The token set behind status 344 is a freeze list. Basis: the status text.

### Reference comparison

The reference is a clue, not a source. These points differ from the bytes.

- `l1/exchange/handlers/32_sub_account_spot_transfer.rs` gives 220 for an unregistered sub-account and 222 for master equal to sub in the map step. In 0x2717a70 both misses give 218, status 220 is not written, and 222 comes only from the core.
- `l1/exchange/handlers/28_spot_send.rs` keeps two blocked sets. The bytes have one set per token.
- That file has no vault gate, no system address route, no USDC map and no receiver fee, and it applies a plain checked debit where the bytes test hold plus amount.

## Implementation and comparison

Rust: not yet implemented.

The tool evaluates all 13 bodies from the file bytes and compares them with a plain Python model written from the reading. The compare object is the status, the result words, the error payload for stub statuses and the whole ordered stub log, including every argument the stubs read. 43 calls and slots are named stubs (`stubs.tsv`).

- 1,000 deterministic vectors: 400 on the core, 400 through the sub-account handler, 200 through spotSend. 0 disagreements, 51 outcome classes (`outcomes.tsv`).
- 57 named scenarios in `cases.tsv`, all equal to the model.
- Controls in the test file: wrong binary hash, read outside mapped bytes, unknown encoding, changed pin, changed function hash, wrong model, shortened log, broken status arm, and 33 one-edit binary mutants, each detected.

Reached code: 0x1e64420, 0x1f66070 and 0x37e5110 in full. In the core, what is left is unwinding pads, panic stubs, the group-probe continuation of the unused lookup, and the second status 247 at 0x2714011. The fixtures cannot reach that branch because 0x371b8a0 already passed on the same row. Not reached elsewhere: the token-bound, row-miss and vacant-row arms of 0x371b140, the clone of an empty unknown token name and the allocation failure in 0x2714570, the free at 0x2712bed in 0x2712af0, the overflow arm at 0x27176c0 in 0x2716f90, and the second-group probes of the swiss tables.

## Results and limitations

- All 13 bodies match the model on every vector. This does not establish that the model is the full behaviour of the real ledger: 43 calls are stubs.
- The ledger update is a stub, so the fixture balance does not change between the credit and the receiver's reserve. The receiver's reserve here sees the balance from before the credit.
- Gas quote, gas step, recipient step, system send and the sink are not read. The sink 0x371cc10 is named only by what reaches it. A hand reading, with no pin: it walks an address tree at its first argument +0x3d0 and then a u64-keyed tree in that value, so it looks like a per-address, per-token store of the amount.
- `same-size-fdes.tsv` lists 0x4d0dff0 and 0x4d0e820 with the same size as 0x2716f90. Their bytes are not compared here.
- The meaning of chain byte 3 and of the token class word 0x3728670 (open PR #475) is unresolved. What the five other callers are for is not read, only the record words below.
- The USDC limit at +0x3a48 is read as a stored word. Its source is not traced.

No progress gate is requested.

Next question: what does the sink 0x371cc10 do with an amount that is not credited, and what is the extra address that 0x2750e60 writes at record +0xb1?
