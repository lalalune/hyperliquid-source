# bridge: the voteL1Hash path of arm 87 and the quorum row list in node #94

This packet maps arm 87, the last action variant and one with no reference handler, from the wire through the signed bytes to the state it changes, so a reconstruction can build `VoteL1HashAction` and the state field `lhvt` (`L1HashSignatureTracker`) from the bytes: the signature covers a BLAKE3 digest of the MessagePack pair `[height, "0x...hash"]`, a sender may vote as a validator, as a linked listed address, or as both, and a quorum result pushes one `HardQuorumL1Hash` row, raises `highest_quorum_height` to a maximum, and removes tracker heights below the vote height minus 50,000, with the floor kept.

- Component ID: `bridge` for signature aggregation over the same voter context and listed set as the deposit path (state `+0x3840`, `+0x36a0`). Arm 87 of RE-010 has no file in the path rules `l1/bridge2.rs`, `l1/bridge_request.rs`, and nothing here claims it lives in them.
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`, `references/can1357-hl` at `999556f6e0a474b8312db96ec3149e1c44e97c23` (searched for leads only, it has no handler for this arm, nothing copied)
- Claim status: observation for bytes, branch order, constants, signed bytes up to the digest call, status text, serde keys, node layouts and call sites; inference for what the digest function is, for `0x2761b20` being a block step, for the meaning of the key `lhvt`, and for what `hard` and `hot` mean; unresolved items are under limits
- Scope included and excluded: included are 28 functions run as real bytes (`path.tsv`): the wrapper `0x1e5f010`, the core `0x394ac70`, the signed bytes path from `0x37e5620` through `0x32478a0` to the MessagePack writers, the height scan `0x3b45c80`, the signature map collect from `0x3315a60`, the prune from `0x3942c90`, and the list filter `0x3bc3150`. Excluded, and stubs here: the tracker `0x39438e0` (bound by #871, so its result is chosen per scenario and its arguments are checked), recovery `0x14c6f50`, the three digest functions at slots `0x57700c0`, `0x57700c8`, `0x57700d0`, `0x33690c0` (#133, #425), `0x3369500` (#879), the removed row reader `0x3941930`, and drops. The digest stub is SHA-256 of the same bytes, used only so a wrong input to recovery fails a stub check; no digest value is claimed. Shared generic code is run but not claimed for this path: the MessagePack writers, `0x2fb4520`, `0x2fc0390` and the iterators, so their unreached rows are expected. `tools/l1_hash_vote_path.py` holds no parser of its own for sections or unwind tables.

## Reproduce

```
python3 tools/l1_hash_vote_path.py --out research/work-items/bridge-l1-hash-votes-94
python3 -m unittest tests.test_l1_hash_vote_path
```

Run from the repository root with Python 3 and the standard library. No external program is used, no objdump or readelf output is parsed, and the binary is not executed: `tools/elf_index.py` and `tools/fde_extents.py` read the ELF, a Python decoder walks the bytes of each function, and `MANIFEST.sha256` holds the output hashes. The tool checks the binary SHA-256 first. A run takes about 1 minute under load.

## Evidence

Addresses are virtual addresses. Instruction rows are in `function-rows.tsv`; every function ends exactly at its FDE end. Rows quoted below are bound in `key-rows.tsv`, so a moved row fails the run.

### The path

```
dispatch table 0x3ede28 entry 87 -> arm 0x275a259 -> call 0x275a27c -> wrapper 0x1e5f010
wrapper 0x1e5f010   height limit, digest 0x37e5620, recovery, recovered == sender, then the core
core 0x394ac70      height limit, link scan, set test, voter lookup, height scan, tracker 0x39438e0
  on a result: maximum of highest_quorum_height, collect 0x3315a60, push one row, prune 0x3942c90
0x2761b20           takes the whole list and resets it; filter 0x3bc3150 keeps rows with hot users
```

Entry 87 and the wrapper call are in `dispatch.tsv`. The last name of the action variant list is `VoteL1Hash`, followed by `variant index 0 <= i < 88`, and the action text is `height`, `l1Hash`, `signature`, then `struct VoteL1HashAction with 3 elements` (`fields.tsv`). The hash is the 32 bytes at action `+0`, height the word at `+0x20`, the signature at `+0x28`.

The core has two more callers through slot `0x5773128`, the similar bodies `0x4676c20` and `0x4676dd0` (`slots.tsv`, `call-sites.tsv`). They are not run here.

### The signed bytes

`0x37e5620` loads the eight words at `0x20c020`, which equal the BLAKE3 start words, zeroes the rest of the state, then encodes and feeds one buffer. The bytes reaching the digest call are observed for every height form in `signed-bytes.tsv`:

```
92                      array of two
<uint>                  height in the smallest MessagePack form
d9 42                   str8 of length 66
30 78 <64 hex chars>    "0x" and lower-case hex of the hash
```

So the hash is signed as text, not as bytes. All of these bytes come from run code, including the hex helper `0x29ed380` and its digit table at `0x208620`.

### Status order in the wrapper

| Order | Test | Status | Text (`status-text.tsv`) |
| --- | --- | --- | --- |
| 1 | height above `0x0ccccccccccccccb` | `0x13f` | Invalid input number |
| 2 | recovery fails | `0x7a` | Unable to recover signer. |
| 3 | recovered address differs from the sender | `0x11f` | Signer does not match expected user |
| 4 | no voter key and no listed link | `0x91` | Unknown validator |

The core has its own limit test at `0xccccccccccccccc`, one above the wrapper's, so it is unreachable through the wrapper; `core_limit` runs it directly. On status `0x11f` the word at result `+0x10` is the leftover `pmovmskb` mask of the address compare (`equal_mask` in the tool), not an address. A success is outcome `9` with the result byte at `+1`: `1` when a row was pushed, else `0`.

### Who may vote

The core reads two things about the sender before the tracker:

1. It scans the map at state `+0x8f8 + 0x150` in key order, compares the 20 bytes at key `+0x38` with the sender, and stops at the first hit. The 20-byte value is tested against the set at state `+0x36a0`. A second link of the same sender is never looked at: `core_two_links_second_listed_only` gives no listed vote.
2. It calls `0x33690c0` for a voter key at the epoch word of state `+0x3840 + 0x48`.

A failed lookup is dropped if a listed link exists, so a listed address alone can vote (`core_link_only`, `arm_87_hard_only`). The vote record at `rsp+0xea` carries both, and a validator with a listed link hands the tracker both in one call (`core_validator_and_link`). The scan is linear over the whole map, on every vote.

### What is scanned and thrown away

`0x3b45c80` reads the tracker height map at `+0x28`. It returns none when the height is absent or holds only this hash, and otherwise all hashes at this height in key order. The rows between that call and the tracker contain one call, a free of that result (`notes.tsv`), so nothing depends on it in this build. `scan_` scenarios run it directly.

### The quorum row

Names come from the serializers `0x394a9c0` and `0x394a440` (`fields.tsv`). The state key is `lhvt`, by the writer `0x37922f0`:

| Field | At |
| --- | --- |
| `tracker` | `+0x0`, height map at `+0x28` |
| `quorum_l1_hashes` | `+0x40` capacity, `+0x48` pointer, `+0x50` length |
| `highest_quorum_height` | `+0x58` |

A list row is `0x58` bytes: height, then `HardQuorumL1Hash`: `l1_hash` at row `+0x8`, `hot_user_to_signature` at `+0x28`, `hard_voter_to_signature` at `+0x40`. The hash in the row is the one in the tracker result, not the action field (`core_quorum_winner_hash_differs`).

`hot_user_to_signature` is rebuilt. The result map is keyed by the 32-byte voter key; `0x3bd7af0` drains it and calls slot `0x5775c88` (`0x3369500`, named in #879) per entry to get a 20-byte `hot_user` at the current epoch. A voter with no answer is skipped with no status (`hot_voter_without_user_dropped`). Rows of `0x60` bytes are sorted by address, by insertion below 21 rows and slot `0x57758e0` above, then built into a map whose node layout is in `node-layouts.tsv`. Two voters that map to one hot user leave one entry, the later voter key (`hot_two_voters_same_user`). `hard_voter_to_signature` is copied from the result as it is.

### The prune

After a push, `0x3942c90` splits the height map at `max(vote height - 50000, 0)`. Heights at or above the floor stay and lower ones go to `0x3941930` one by one. It is the vote height, not `highest_quorum_height`: an old vote that reaches quorum prunes from its own height (`prune_uses_vote_height`). A vote with no result prunes nothing.

### Who takes the list

`0x2761b20`, reached once from `0x2209d40`, reads `0x35f0`, `0x3600` of the state, resets the list to empty at `0x276451d`, and calls the filter `0x3bc3150` at `0x2764546` on the taken list. The filter keeps rows whose word at row `+0x38`, the length of `hot_user_to_signature`, is not zero, in order (`filter_` scenarios). So a row whose voters all lack a hot user is dropped there. Reading `0x2761b20` as a block step, the list lives for one block; that is an inference. The filter has two more callers, `0x4d8fce0`, `0x4d92a10`, in `call-sites.tsv`.

## Implementation and comparison

Not yet implemented as Rust. `tools/l1_hash_vote_path.py` is a rule list written from the path above, compared with real bytes, not a reconstruction claim.

The tool decodes each function from ELF bytes and runs it in a small x86-64 model under stubs that record arguments. `Model` predicts each status, the signed bytes, tracker arguments, removed heights, the height map, `highest_quorum_height` and each row. The compare is exact.

| Check | Result |
| --- | --- |
| Named scenarios | 76, 91 operations |
| Generated scenarios | 200 |
| Mismatches | 0 |
| Byte edits on reached rows | 452: 340 killed, 112 survived |

`mutations.tsv` has every edit with the first scenario that killed it. Survivors have class labels only, and are rows this packet does not constrain: search steps for deeper trees, allocation sizes, free tests, tails of copied status records, stub arguments.

## Results and limitations

- The signed bytes are observed up to the digest call. BLAKE3 is an inference from the start words; `0x14f93e0` and `0x14fa010` are stubs, and no digest value or test vector is claimed.
- `0x39438e0` is a stub, so when a result appears, and how signatures enter the maps, belong to #871. `hard_voter_to_signature` is an opaque triple here.
- `0x3941930` is a stub. By reading, it writes only its locals and frees, using the f64 at tracker `+0x20`, so it looks like a dropped log value; this is not run.
- `0x14c6f50`, `0x33690c0`, `0x3369500` are stubs, so their results are fixture inputs.
- The key of the map at state `+0x8f8 + 0x150` is `0x58` bytes and only its bytes `+0x38..+0x4c` are read; who fills it is not established. Who is in the set at `+0x36a0` is not in the binary.
- `lhvt` as "L1 hash vote tracker", and `hot`, `hard` as voter classes, are readings of names.
- Fixture trees have height 0 or 1. 1751 of 4918 rows are not reached, mostly in shared writers and tree code (`unreached.tsv`).
- The consumer past the filter is not followed: the list stays in a local of `0x2761b20`.

Next question: arm 48 and its tracker `0x3946a80`, which has the same shape with `quorum_app_hashes`, and what other callers of `0x37e5620` (`0x44adfa0`, `0x4742f00`) sign with the same bytes.
