# RE-004: spot UserGenesis staging: caps, blacklist gate and the three row writers

This packet shows that node #94 stages a spot token's genesis balances in three maps, not in lists. The caps of 10000 users and 2 anchor tokens are counted over the stored and new rows together, a repeated user replaces the stored amount, and adding a user to the blacklist deletes that user's stored balance. A reconstruction of `SpotDeployAction::UserGenesis` can now be written against these rules, and the reference's list form can be dropped.

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is used as a list of labels to check. Nothing is copied from it.
- Claim status: observation for everything under Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences are marked and listed apart.
- Scope included: five whole functions, `0x371f250`, `0x371fda0`, `0x371f030`, `0x3721160`, `0x37215b0`, and the B-tree helpers they call, which run as real bytes. Scope excluded: the host action handler and its parse of the amount text, the holder scan for an existing token, and the later finish step. Those are read elsewhere or left open.

## Reproduce

From the repository root:

```
python3 tools/spot_genesis_staging.py --out research/work-items/RE-004-spot-genesis-staging-94
python3 -m unittest tests.test_spot_genesis_staging
```

The tool takes about 90 s on a loaded machine. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It starts no external program, so the binutils version cannot change the output. The binary is never executed: an evaluator reads its instruction bytes.

Generated files: `evidence.json`, `function-rows.tsv`, `texts.tsv`, `serde.tsv`, `constants.tsv`, `slots.tsv`, `outcomes.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are ELF virtual addresses. Function ends come from FDEs. Rows and byte counts are in `function-rows.tsv`: 5 functions, 787 instructions, 3579 bytes. Each function has one RELATIVE slot and three `ff 15` call sites, found by byte scan (`slots.tsv`).

| Function | Slot | Name used here | Arguments |
| --- | --- | --- | --- |
| `0x371f250` | `0x5774c98` | cap gate | `rdi` result, `rsi` S, `rdx` token, `rcx`/`r8` user rows, `r9`/stack existing-token rows |
| `0x371fda0` | `0x5774ca0` | blacklist gate | `rdi` result, `rsi` S, `rdx` token, `rcx`/`r8` user rows, stack: token row count, optional list |
| `0x371f030` | `0x5774cb0` | user row writer | `rdi` S, `rsi` token, `rdx`/`rcx` rows of 0x20 bytes |
| `0x3721160` | `0x5774cb8` | token row writer | `rdi` S, `rsi` token, `rdx`/`rcx` rows of 0x10 bytes |
| `0x37215b0` | `0x5774cc0` | blacklist writer | `rdi` S, `rsi` token, `rdx` list head |

### The map

`S+0x370` holds a B-tree map from token (u64) to a 0x48-byte record, with root, height and length words. The node keeps its values at `+0x60`, its length at `+0x37a` and its edges at `+0x380`. The record holds three trees of three words each, read here by offset:

| Record offset | Key | Value | Node facts |
| --- | --- | --- | --- |
| `+0x00` | 20-byte address | u64 amount | values `+0x08`, keys `+0x60`, length `+0x13e`, edges `+0x140` |
| `+0x18` | u64 token | u64 amount | keys `+0x08`, values `+0x60`, length `+0xba`, edges `+0xc0` |
| `+0x30` | 20-byte address | none | keys `+0x08`, length `+0xe6`, edges `+0xe8` |

`S+0x198` is the token count. `serde.tsv` holds the text `struct TokenGenesis with 3 elements` and the field run `user_balances`, `existing_token_balances`, `blacklist_users`.

### Cap gate `0x371f250`

The result is `0x186` with a flag byte at `+2`, or tag `0xea`. Flag 0 is the refusal; this function writes no text.

1. `n >= 0x2711` or `m >= 3` gives flag 0, before any row is read.
2. If the token has a record, copy the keys of its first two trees into two sets. Otherwise both sets start empty.
3. Insert the 20 address bytes of every user row, in order.
4. Remove the address at `0x599044`, twenty `0xff` bytes (`constants.tsv`).
5. More than `0x2710` left in the set gives flag 0.
6. For each existing-token row in order: a token at or above `S+0x198` gives tag `0xea`, else insert the token.
7. More than 2 tokens in the set gives flag 0. Otherwise flag 1.

So 10000 is a cap on distinct stored and new addresses, and the all-ones address is outside it. Step 5 comes before step 6, so a user overflow hides a bad token. A third token before a bad one does not hide it, since step 7 is last.

### Blacklist gate `0x371fda0`

With a list: more than `0x3e8` rows gives tag `0xdf` with "blacklist users to update exceeds 1000". Then any user row or token row in the same action gives tag `0xdf` with "cannot update blacklist users when either user_and_wei or existing_token_and_wei is non-empty". Otherwise it passes. Stored balances do not block it, and it does not look at the stored blacklist.

Without a list: a clone of the token's blacklist is searched for every user row. A hit gives tag `0xdf` with the 162-byte text in `texts.tsv`, which starts "cannot update token genesis balance for blacklisted user(s)". Token rows are not looked at. A missing record or an empty set passes.

### Row writers

`0x371f030` and `0x3721160` find or create the record, then insert into the first or second tree, once per row. An equal key is replaced, so the last amount wins and amounts never add. No rows means no record. On a replace with a different amount, both read the word at `0x577ab98`; a non-zero word calls the `Once` slot `0x576e8b8`, then the loop goes on. The stored result is the same either way.

`0x37215b0` creates the record first, so an empty list on a new token still leaves an empty record. Each list row is 21 bytes: address, then a byte at `+0x14`. A zero byte removes the address from the blacklist tree. Any other byte first removes the address from the user balance tree, then inserts it in the blacklist tree. The second tree is never touched. Rows apply in order.

### Reference comparison

`references/can1357-hl/l1/exchange/impl_spot_deploy.rs`, `apply_user_genesis` and neighbours:

| Reference | Bytes |
| --- | --- |
| `genesis_users: Vec`, `extend(users)` | map, repeat replaces |
| `users.len() > 10_000` per call | per call and over the stored and new distinct set, all-ones address left out |
| `entries.len() > 2` per call | per call and over the distinct stored and new tokens, with a token bound |
| blacklist refused if any stored `genesis_users` or tokens | refused only for rows in the same action |
| `blacklist_users.extend(users)` of `Vec<Address>` | rows with a byte, add or remove; add deletes the balance row |
| one check order per list | fixed order in the two gates above |

## Implementation and comparison

not yet implemented. There is no Rust code in this packet. The Python rule list in the tool is a test oracle, not a port.

Every run starts from real B-tree nodes in a fake heap. The target and all helpers it reaches by direct call run as real instructions, including the sort behind slot `0x5774f60` and the node split and merge paths. Allocation, free, memcpy, memmove and memcmp are hooks. After each run the harness walks the trees through parent links and checks key order, then compares the maps, the result bytes and every other fixture byte with the rule list. A gate must also free all that it allocates.

Cases near the 10000 limit use a stated model of the set helpers (`model=True`), since a real 10000-key tree does not fit the fixture. The model checks all nine iterator words given to the key collector and the removed key. Smaller cases run the same gate with the real helpers.

Results: 129 named cases and 300 generated vectors match. 19 rows stay unreached in total, all listed per function in `evidence.json`: landing pads and panic rows.

Mutants: every reached conditional row, immediate and base-register displacement in the five functions is edited once. 250 of 260 are killed. An unedited image passes under the same step limit first. The 10 survivors are in `mutations.tsv`, each with a reason. All are `same:` cases: back cursor words of a drop iterator, dead words on the path without a record, a branch whose edges join at a zero test, and the height word of a vacant entry handle.

Tests: `tests/test_spot_genesis_staging.py`, 56 tests, no skips. Negative controls cover a wrong digest, a NOBITS address, an address inside a function, a corrupt serde name, a corrupt kept address, a wrong slot, a tree with bad key order, and edits of the limits and of the blacklist branch.

## Results and limitations

Inferences, not observations:

- `S` is `state+0x80`, the spot struct named in earlier packets. The bytes here only show offsets from the argument.
- The all-ones address is the Hyperliquidity allocation row. Packet `RE-006-token-genesis-book-word-94` (#449) reads the balance of the same 20 bytes at the finish step, next to the text "Hyperliquidity balance should be 0". That would explain why the row sits outside the holder cap. These five functions only show the removal.
- The list byte is a blacklist or unblacklist choice. The serde shape of that row was not read.
- The word at `0x577ab98` guards a lazy init. Only its test and the call are observed. #614 lists these two readers in a census of that word.
- The order in which the host calls the five slots was read by eye: cap gate (when the signer address is not zero), blacklist gate, row checks, user writer, token writer, then the blacklist writer when a list is present. The host is outside this packet.

Limits:

- The amount text parse is in the host and is not covered, so nothing here shows the unit or range of the stored words beyond "a whole u64 is kept".
- Near the limit the set helpers are a model. Only the small real cases tie the model to the bytes.
- Fixture trees have at most two levels, and writers grow them by a few nodes. Deeper trees use the same helpers but were not run.
- The panic rows for a zero root beside a non-zero length need an invalid tree and stayed unreached.
- Whether a replace or a blacklist delete can run after the token's finish step is not traced here.
