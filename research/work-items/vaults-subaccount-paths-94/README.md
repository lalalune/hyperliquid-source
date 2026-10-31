# vaults: node #94 sub-account paths: subAccountTransfer, create and modify wrappers, address preimage

This packet shows that a new sub-account address is derived from a 160-byte ABI encoding of
`("createSubAccount", master, count)` rather than the 44-byte concatenation in the reference, and it
pins the full subAccountTransfer path and the create and modify wrappers, so these three actions can
be written from the bytes, including which user table blocks a create and how the two transfer sums round.
It also settles the word rules of the encoder 0x1592160, the next question left open by the bridge packet.

- Component ID: vaults
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository 1f8c67c; reference `references/can1357-hl` used as a label source only
- Claim status: observation for pins, layouts and evaluated results; inference where marked; unresolved items are listed at the end
- Scope included: 0x1e60d00, 0x27148e0, 0x22cdfb0, 0x27e3140, 0x2755400, 0x3c97900, and the ethabi encoder 0x1592160 with its 7 helpers
- Scope excluded: 0x36f3610, 0x36f3c20, 0x36f40d0, 0x36f43c0 (open PR #615, stubs here), the equity read 0x275fee0, the settings read 0x3743df0, the balance helpers 0x36f7560, 0x370a3d0, 0x36ff4f0

## Reproduce

From the repository root, Python 3 standard library only, no external programs:

```sh
python3 tools/subaccount_paths.py --out research/work-items/vaults-subaccount-paths-94
python3 -m unittest tests.test_subaccount_paths
```

The tool checks the binary SHA-256, reads ELF bytes, and imports `tools/elf_index.py` and
`tools/fde_extents.py` for sections and FDEs. It never runs the binary. It writes evidence.json,
functions.tsv, stubs.tsv, callers.tsv, status_sites.tsv, link_readers.tsv, pins.tsv, layout.tsv,
locations.tsv, cases.tsv and outcomes.tsv. All contents are deterministic.

## Evidence

Addresses are ELF virtual addresses. Function extents are FDE ranges (`functions.tsv`), 14 functions
and 8,098 bytes in all. Instruction text in `pins.tsv` comes from the small decoder inside the tool,
not from objdump, and each of the 62 rows is compared with a frozen expected string. Unknown
encodings raise an error. `layout.tsv` gives 43 field offsets, each tied to one decoded access.

### Entry points

`callers.tsv` is a byte census of `e8` and `ff 15/25` sites. The three wrappers are called only from the
dispatcher 0x2759240, at the indexes RE-010 mapped (6, 30, 31). The transfer body has one caller. The
token list 0x3c97900 has one caller, 0x36f3d76. The census also lists the callers of the five sub-account
helpers held by #615, including second copies of create at 0x46ba9f0 and 0x46bb000 and of modify at
0x4897480 and 0x48975a0.

### subAccountTransfer

The action is usd at +0x00, the address at +0x08 and is_deposit at +0x1c. A wrapper gate comes first.
The class byte is user row +0x3c through 0x2755400. An address with no row reads a shared default row.

| Step | Test | Result |
| --- | --- | --- |
| 1 | master class above 3 and exchange +0x5b0 == 0, or class 3 and +0x5b1 == 0 | tag 14, code 367 |
| 2 | same test for the sub-account address | tag 14, code 367 |
| 3 | usd >= 0x0ccccccccccccccc | code 319 with usd |
| 4 | usd == 0 | code 49 |
| 5 | link table empty, address missing, or stored master != caller | code 218 with both legs at +0x02 |
| 6 | no clearinghouse | panic, unwrap of Err(321), clearinghouses.rs:17:33 |
| 7 | available(sender) < usd on clearinghouse 0 | code 51, no payload |

Then, on clearinghouse 0:

```text
sender, receiver = is_deposit ? (master, sub) : (sub, master)
debit(sender, usd); credit(receiver, usd)
event tag 0x800000000000000e, amount usd as f64 / 1e6, sender, receiver
event users [master, sub], in that order for both directions
hash: exchange +0 == 1 runs 0x3987cb0, otherwise 32 zero bytes
step = usd / 10000, truncating
sender row:   +0x10 -= step, +0x18 -= step
receiver row: +0x10 += step, +0x18 += step
```

The rows come from 0x1f849b0 on the user table at exchange +0x740. Each add saturates and calls the
recorder 0x358dcd0 with Location impl_ntl.rs:665:1, and the action still returns 390. The event is
pushed before the rows change. A usd below 10000 moves both balances and neither sum (`cases.tsv`).

No master == sub test exists in this path. `status_sites.tsv` has no code 222 in 0x27148e0, and a
fixture linking an address to itself runs to 390.

### createSubAccount wrapper

| Step | Action | Result |
| --- | --- | --- |
| 1 | call derive 0x36f3c20 through its slot | another code is copied out; #615 holds the body |
| 2 | look the derived address up in the user table at exchange +0x740 | found: tag 14, code 216, address at +0x0a |
| 3 | equity read 0x275fee0 for the master | passed to step 4 |
| 4 | clone the name, call create 0x36f3610 through its slot | another code is copied out with its payload |
| 5 | read 15 words through 0x3743df0 for master and sub-account | compare below |
| 6 | words differ | row from 0x1f84840 on exchange +0x690: first word 1, then the master's 0x78 bytes |
| 7 | 0x1f849b0 for the sub-account, then 0x1f84b30 on exchange +0x318 | tag 6, address at +0x01 |

Step 2 tests the user table, so any address with a user row blocks the create, also when it is not a
sub-account. The compare in step 5 uses f64 `==` for words +0x70 and +0x00 to +0x20. The u32 at +0x68
then decides: both zero stops as equal, one zero means different, and both non-zero compares words
+0x28 to +0x60 as well. A NaN word compares unequal, so the copy runs for identical NaN bytes.

### subAccountModify wrapper

The action is an `Option<String>` at +0x00 and the address at +0x18. The None test is `0 - word`
overflowing, true only for i64::MIN. The wrapper calls 0x36f40d0 through its slot for both cases: None
passes i64::MIN on and Some passes a fresh clone with capacity equal to the length. Code 390 maps to
tag 13 and any other code to tag 14 with 0x60 bytes copied. The wrapper itself has no None shortcut.

### Address preimage

0x3c97900 builds three 0x28-byte tokens: tag 6 with the domain String, tag 0 with the 20-byte master,
tag 4 with the count as the low limb and three zero limbs. It then calls 0x1592160 through slot 0x576ed20.
The tags match the order of the `ethabi` `Token` enum (Address 0, Uint 4, String 6). That name is
inferred, but the result is not: the real encoder bytes ran for 96 vectors and always gave

```text
word 0  0x60
word 1  master, left padded
word 2  count, big-endian
word 3  domain length
word 4+ domain, right padded to 32 bytes
```

The literal at 0x2035a0 is `createSubAccount`, so the input is 160 bytes. `evidence.json` holds a sample.

`research/work-items/bridge` named 0x1592160 as a finisher and left its per-tag word rules as its next
question. This packet runs the same function directly over 128 token lists, one in six in the withdrawal
shape string, address, address, uint, uint. The result equals standard ABI encoding for all seven scalar tags:

| Tag | Inferred name | Head | Tail |
| --- | --- | --- | --- |
| 0 | Address | 20 bytes at +0x01, 12 zero bytes first | none |
| 1 | FixedBytes | Vec at +0x08, right padded, (len + 31) / 32 words, no length word | none |
| 2 | Bytes | byte offset word | length word, then right-padded bytes |
| 3 | Int | 32 big-endian bytes from four limbs at +0x08 | none |
| 4 | Uint | 32 big-endian bytes from four limbs at +0x08 | none |
| 5 | Bool | byte at +0x01, 31 zero bytes first | none |
| 6 | String | byte offset word | length word, then right-padded bytes |

Tails follow in token order. Offsets count from the first head word. Tags 7 to 9 go through 0x1590d00 and
0x1590c60 and were not run.

### Restriction map

`status_sites.tsv` lists every word store of codes 214 to 222 in FDE-covered code, found by a byte
pattern and kept only when the decoder agrees: 27 sites. The code names come from the reference.

- 218 appears in 0x27148e0, 0x2717a70 and 4 functions at 0x4d09470 to 0x4d0f840.
- 219 appears in 6 functions, among them startFeeTrial 0x21e00b0.
- 222 appears only in 0x2710530 and two functions at 0x4d01240 and 0x4d01b40.

`link_readers.tsv` lists 25 inlined reads of sub_account_to_master (`cmp [reg+0x3828], 0`) in
22 functions. Together with the is_sub and lookup slots in `callers.tsv` this is the list of
places that a transfer-restriction reader must open next.

### Evaluation

The tool runs each body in Python over the real instruction bytes and compares the result with a
plain model: 512 transfer, 512 create, 64 modify, 96 address input and 128 token list vectors, 1312 in all, with 30
distinct outcomes in `outcomes.tsv` and 0 disagreements. `cases.tsv` has 28 named scenarios.

`stubs.tsv` lists the 22 replaced calls with their FDE extents. Fixtures build real SwissTable groups for
the link table and user table. The hash stubs return one fixed value per table, so the row compare picks
the key, and one case with 20 links reaches the second probe group. Caller-saved registers are
overwritten after each stub.

### Reference comparison

| Reference text | Bytes |
| --- | --- |
| preimage is label, master and count concatenated (44 bytes) | ABI encoding, 160 bytes |
| derived address checked against `sub_account_to_master` first | wrapper checks the user table at +0x740 |
| wrapper updates clearinghouse state for both addresses | it reads two settings records and may copy one row |
| `execute_sub_account_transfer` moves the two sums, then emits the event | the event is pushed first, then the sums move |
| `InsufficientWithdrawable { from, requested_usd }` | code 51 stores no payload |
| unknown link and wrong master split into 220 and 218 in `sub_account.rs` | both are 218 in this path |
| `master == sub_account_user` gives SelfTransfer | no such test in this path |
| `apply_sub_account_modify` for 0x22cdfb0 returns at once on None | the wrapper calls the helper with None |

## Implementation and comparison

not yet implemented. No Rust was written. The formulas above are readings of the bytes, checked over
the listed vectors. They are not a claim of binary equivalence.

## Results and limitations

Passed: 62 pins, 43 layout rows, 14 functions, 22 stubs, 2 Location records, 1312 vectors with
0 disagreements and 28 named scenarios. `tests/test_subaccount_paths.py` runs 53 tests: 11 positive,
8 negative controls (wrong binary hash, address outside file-backed sections, changed pin byte,
changed layout operand, unknown encoding, unmodelled call, non-FDE start, generated file drift) and
34 one-edit binary mutants, each of which the models or fixed expectations catch.

Limits:

- Stubs are assumptions about interfaces. The balance helpers and the settings read were not evaluated here.
- The address itself is not computed here. The hash step lives in 0x36f3c20, held by open PR #615. This
  packet covers its input bytes only. No address was compared with chain data.
- Token lists had 1 to 6 scalar tokens. Array and tuple tags were not run.
- The status census sees memory word stores only. A register move such as the 215 store at 0x36f45ec is outside it.
- Inferred: 0x3743df0 returns per-user fee settings. The fee tier code 0x26fbab0 and the userFees builder
  0x27d7fe0 also call it, but no field name was tied to the 15 words.
- Inferred: the encoder is the `ethabi` crate, from the tag order and the pad and head layout.
- Unresolved: what account +0x10 and +0x18 mean, what the class bytes 3 and 4 mean, what the second map
  at exchange +0x318 holds, and what the default row at 0x5786190 holds after its lazy init.

Next question: which action reaches 0x1e8db10, where the is_sub and lookup slots sit next to codes 219 and 220?
