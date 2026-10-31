# fees: setReferrer path in node #94: gates, row made before the quota test, per-bucket count, log tree

- Component ID: `fees` (first task: maker/taker fee formulas and time-window rollover; this packet fixes how a user binds to a referrer, and the
  time-bucket quota on new referrals).
- Target release and full SHA-256: hl-node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` /
  can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23` (used as leads only, nothing copied).
- Claim status: observation for bytes, decoded instructions, evaluated outcomes and status texts; inference where marked; unresolved
  items are listed at the end.
- Scope included: in full, the wrapper `0x27de270`, the helper `0x37433c0`, the bucket step `0x394b7e0` and the log insert `0x33a2400`. Scope excluded, all stubs that
  check their arguments: the hash `0x399c7a0`, table growth `0x357d310`, the status drop `0x3999770`, the vacant B-tree insert `0x2f23c60`, and allocation. Also excluded: the readers of
  the row binding, the dispatch that reaches the wrapper, node #115.

## Reproduce

```sh
python3 tools/artifacts.py verify
python3 tools/fees_set_referrer.py --out research/work-items/fees-set-referrer-94
python3 -m unittest tests.test_fees_set_referrer
(cd research/work-items/fees-set-referrer-94 && sha256sum -c MANIFEST.sha256)
# optional, for a human reader only; no evidence file uses this
objdump -d -M intel --start-address=0x37433c0 --stop-address=0x374392d artifacts/node/94/hl-node
```

Run from the repository root on Linux x86-64 with Python 3 and no third-party package. The tool checks the input SHA-256 first and
fails on any other file. It starts no external program, so no binutils version can change its output. Sections and FDEs come from
`tools/elf_index.py` and `tools/fde_extents.py`. It does not run the node or visor: decoded instructions are interpreted in
Python, on memory built by the tool. A run took about 70 s on 3 workers.

Outputs: `evidence.json`, `vectors.tsv`, `mutations.tsv`, `instructions.tsv`, `reference-diff.tsv`.

## Evidence

Coordinates are ELF virtual addresses. All four ranges are `.eh_frame` FDEs, and the table decoder must land on each end.

Range | Role | Instructions | Executed
--- | --- | --- | ---
`0x27de270..0x27de313` | wrapper | 44 | 44
`0x37433c0..0x374392d` | helper | 306 | 305
`0x394b7e0..0x394b936` | bucket step | 99 | 99
`0x33a2400..0x33a2687` | log insert | 146 | 141

Not executed: `0x33a266e..0x33a2687` (panic of a full node: the node was allocated just above with length 0, so the cmp 0xb never passes), and 2 padding instructions. The tool fails on any other unexecuted instruction.

### Callers

The helper is reached through slot `0x5774f38` only, from three wrappers of 44 instructions, each called once:

Call site | Wrapper | Called from | Tracker
--- | --- | --- | ---
`0x27de2b6` | `0x27de270` | `0x2759240` | exchange `+0x5d0`
`0x4676fc6` | `0x4676f80` | `0x4d83050` | exchange `+0x1050`
`0x4677076` | `0x4677030` | `0x4d84170` | exchange `+0x5d0`

`0x4677030` is the same as `0x27de270` instruction by instruction; `0x4676f80` differs only in the tracker offset at `0x4676fad`. All three read the time at exchange `+0x60`.
The bucket step has one caller, the helper. The log insert `0x33a2400` has 5 direct callers, so four other sites use the same node shape; they are not examined here.

### Order of the path

The helper takes (out, tracker, user, code pointer, code length, time pointer). The wrapper passes the 12 time bytes from the exchange on its stack.

1. Wrapper: a code of 101 bytes or more gives `0x143` "Invalid input length", with the action pointer as word. The helper has no length test of its own.
2. The code tree at tracker `+0x120` is searched (key String at node `+8`, value at `+0x110`, stride 20). A miss gives `0xa2` "Referral code not registered".
3. The 20-byte value is the owner. An owner equal to the user gives `0x9e` "Cannot self-refer". All 20 bytes are compared.
4. The user's row is looked up in the table at tracker `+0xc0` (stride `0xe8`). **A missing row is inserted now**, before any later test.
5. Row `+0xcc` = 1 gives `0x9f` "Referrer already set".
6. The owner is looked up in the profile tree at tracker `+0x108`. A miss gives `0x186` with the flag left clear.
7. The bucket step runs. On `0xa1` "Referral code has no more referrals left until next referral refresh." the error is copied out and the flag stays clear.
8. On success row `+0xcc` becomes 1 and the 20 owner bytes go to row `+0xcd`.

So a first call that ends at step 6 or 7 still leaves a row: 1155 of the vectors end `0xa1` with a new row. Steps 1 to 3 leave none.

### New row

The insert follows the rules of the table in `free_slot`: first empty or deleted control byte on the probe sequence, re-read from group 0 when the first hit lands on a full slot through the mirror
(`0x3743916`, tables below 16 buckets), growth word reduced only for an empty byte, both control copies written. A growth word of 0 calls growth (`0x357d310`) even if a deleted slot is free,
then the table words are read again. Row bytes written: key `+0..+0x14`; zero at `+0x18`, `+0x98`, `+0xa8`, `+0xb0`, `+0xc0` (8 bytes each), `+0xc8` (4), `+0xcc` (1). `+0xa0` takes 8 unset stack bytes from `[rsp+0x80]`.
No other row byte is touched, and the tool compares the whole table.

### Bucket step `0x394b7e0`

Arguments: out, profile, user copy, time pointer, width. The width is tracker `+0x138`.

1. Width 0 gives `0xa1`, and the profile is not touched.
2. Time: signed milliseconds from the packed date, seconds and nanoseconds words (date >> 13 is the year, bits 4..12 the ordinal; year at or below 0 is shifted by whole 400-year cycles of 146097 days; days less 719163;
   times 86400, plus seconds, times 1000, plus nanoseconds / 1000000). The result is clamped at 0 (`0x394b8a0`).
3. Bucket = time / width, by a 32-bit divide when both words fit, else 64-bit. Both give the same value.
4. Bucket equal to profile `+0x38`: remaining is profile `+0x18`; 0 gives `0xa1`, with no write.
5. Bucket differs: `+0x38` takes the bucket, remaining becomes max(profile `+0x40`, 1000). This cannot be 0. A stored bucket of 0 with a later time counts as a change.
6. Remaining less 1 goes to `+0x18`, the prepared `0xa1` is dropped (`0x3999770`; case `0x399993e`, a plain return), and the log insert runs on profile `+0x20`.

So profile `+0x38` is the stored bucket and `+0x40` the refresh count.

### Log tree `0x33a2400`

A B-tree keyed by the 20-byte user, node: parent `+0`, keys `+8`, values `+0xe4` (12 bytes each), parent index `+0x168`, length `+0x16a`, edges `+0x170`, leaf `0x170`.
The value is the 12 raw time bytes, not milliseconds.

- Key present: the value is replaced and the old one returned; the length stays. **The remaining count has already dropped**, so a repeat uses quota and adds no entry.
- Null root: a leaf of `0x170` bytes is allocated with height 0.
- Otherwise the vacant insert `0x2f23c60` is called with the leaf and index. It is a stub here, which checks them against a walk of the node bytes.

## Implementation and comparison

Not yet implemented in Rust. The comparison is between the decoded bytes run in the evaluator and a separate closed-form model in the tool (`model`, `raw_millis`, `free_slot`).
Hook values are compared too: the signed time before the clamp at `0x394b89b`, and the result of the log insert at `0x394b91e`.

`reference-diff.tsv` compares `references/can1357-hl/l1/exchange/handlers/25_set_referrer.rs` with the bytes: 6 rows differ, 6 agree. The flow and constants agree. The largest gaps:

- `owner_tag` and `referrer_tag` do not exist. The value is 20 bytes, and the "trailing u32" is the end of the address.
- The reference's flow makes the row only on the missing profile branch, so a `0xa1` refusal would leave none; the bytes make it first.
- `referred_users` is a tree keyed by user holding raw time bytes, not a Vec of `(user, at_ms)`, so repeats replace.

## Results and limitations

- 6670 vectors, 0 mismatches. After each call the status, whole exchange block, table, code tree, profile tree, log trees, helper calls and live blocks are compared. Outcomes: 4468 `0x186`, 1163 `0xa1`, 636 `0xa2`, 236 `0x9e`, 143 `0x9f`, 22 `0x143`, 2 `panic allocation`.
- Groups: bucket 2018, clock 2590, length 138, log 305, order 388, sequence 560, table 131, tree 540.
- 326 mutants (conditionals, field offsets, immediates) of all four ranges: 318 killed, 8 equivalent, each with a reason in `mutations.tsv`.
  Three of them change the count of 400-year cycles, and `test_cycle_count_mutants_keep_days` checks them over every year from -262143 to 0, by a separate formula.
- The survey found real gaps, then closed: years below 1970 were hidden by the clamp (the signed time hook), the century divide needed a year after 1970 that is a multiple of 100 and not of 400,
  the 32-bit test needed a time past `2^32` ms, and the old value returned by the log insert was not read by any caller (the result hook).
- Two full runs gave identical bytes.

Inferences, not observations:

- The width word at tracker `+0x138` is `referral_bucket_millis`: the name comes from the FeeTracker serializer table in open #249 and the reference, not from this path.
- Row `+0xcc..+0xe1` is an `Option<address>` holding the user's referrer. The flag is only tested here against 1.
- `0x394b7e0`'s time words are the block time at exchange `+0x60`: this packet shows they are the words at that offset and that they are decoded as a chrono date and time, not what writes them.
- The row is shared with other per-user state, since the zeroed words sit between other fields. This packet does not name them.

Unresolved:

- Who reads row `+0xcc`, `+0xcd` at fill time, and who reads the log tree.
- `0x2f23c60` and table growth are stubs: rebalancing and rehash are not covered. The growth stub is this tool's own, so only the re-read of the table words is tested.
- The dispatch into `0x2759240`, `0x4d83050`, `0x4d84170` is not evaluated, so who may send the action is not shown here.
- The wrappers `0x4676f80` and `0x4677030` are matched by instruction compare, and not run.
