# fees: referral code registration and replacement in node #94

- Component ID: `fees` (first task: maker/taker fee formulas and time-window rollover; this packet fixes who may hold a referral code, the
  volume test behind it, and how the code and the per-bucket word of a referrer profile are written).
- Target release and full SHA-256: hl-node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` /
  can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23` (used as leads only, nothing copied).
- Claim status: observation for bytes, decoded instructions, evaluated outcomes and status texts; inference where marked; unresolved
  items are listed at the end.
- Scope included: the wrapper `0x27e30a0` and the helper `0x3744eb0` in full, in both modes of the stack flag; three linear pieces of the flag 1
  arm of `0x2355f40`. Scope excluded, all stubs that check their arguments: the hash `0x399c7a0`, the overflow recorder `0x358dcd0`, the
  B-tree entry helpers `0x33adba0`, `0x339a090`, `0x33c2c80`, `0x33bfa30`, and allocation. Also excluded: what selects the arm in `0x2355f40`,
  the readers of the profile, the writer of the volume tree, node #115.

## Reproduce

```sh
python3 tools/artifacts.py verify
python3 tools/fees_register_referrer.py --out research/work-items/fees-register-referrer-94
python3 -m unittest tests.test_fees_register_referrer
(cd research/work-items/fees-register-referrer-94 && sha256sum -c MANIFEST.sha256)
# optional, for a human reader only; no evidence file uses this
objdump -d -M intel --start-address=0x3744eb0 --stop-address=0x37459d3 artifacts/node/94/hl-node
```

Run from the repository root on Linux x86-64 with Python 3 and no third-party package. The tool checks the input SHA-256 first and
fails on any other file. It starts no external program, so no binutils version can change its output. Sections and FDEs come from
`tools/elf_index.py` and `tools/fde_extents.py`. It does not run the node or visor: decoded instructions are interpreted in
Python, on memory built by the tool. A run took about 135 s on 3 workers.

Outputs: `evidence.json`, `vectors.tsv`, `mutations.tsv`, `instructions.tsv`, `reference-diff.tsv`.

## Evidence

Coordinates are ELF virtual addresses. The first two ranges are `.eh_frame` FDEs, and the table decoder must land on each end. The three arm
pieces are linear ranges inside the FDE of `0x2355f40`, which is not decoded as a whole; the decoder must land on their ends too.

Range | Role | Instructions | Executed
--- | --- | --- | ---
`0x27e30a0..0x27e313b` | wrapper | 41 | 41
`0x3744eb0..0x37459d3` | helper | 624 | 604
`0x2356a11..0x2356a99` | arm: read action, length and limit tests | 24 | 24
`0x23599c7..0x23599de` | arm: length error | 5 | 5
`0x235a776..0x235a7b0` | arm: the call | 12 | 12

Unexecuted helper instructions are listed in `evidence.json` with reasons, and the tool fails on any other: `0x3745664..0x374566f` (capacity
overflow of a clone, the length is at most 100 there), `0x374597f..0x374598e` (a test of `dl`, which is 1 on every loop entry), `0x37459af..0x37459d3`
(trap and unwind landing pad), and 3 padding instructions.

### Six callers, two modes

The helper is reached through slot `0x5773e28` only. It takes (out, tracker, user, code pointer, code length, word) in registers and a flag byte on
the stack, tested at `0x3744ecc`.

Call site | Function | Flag | Tracker
--- | --- | --- | ---
`0x27e30de` | `0x27e30a0` | 0 | exchange `+0x5d0`
`0x46ba98e` | `0x46ba950` | 0 | exchange `+0x5d0`
`0x46ba8ee` | `0x46ba8b0` | 0 | exchange `+0x1050`
`0x235a799` | `0x2355f40` | 1 | exchange `+0x5d0`
`0x4caf0ba` | `0x4caa870` | 1 | exchange `+0x5d0`
`0x4cb7a4a` | `0x4cb3200` | 1 | exchange `+0x1050`

`0x46ba950` is the same as the wrapper instruction by instruction; `0x46ba8b0` differs only in the tracker offset at `0x46ba8ce`.

### Flag 0, the wrapper path

1. Wrapper: a code of 101 bytes or more gives `0x143` "Invalid input length", with the action pointer as word. The wrapper clears `r9`.
2. Tracker `+0xd8` = 0 gives `0xa5` "Cannot generate referral code until enough volume traded". So do a missing row in the table at tracker `+0xc0`
   (stride `0xe8`, all 20 key bytes compared), a null root at row `+0xb0`, and a length of 0 at row `+0xc0`.
3. The tree at row `+0xb0` is walked in key order. The first word of each `0x30`-byte value is added. On overflow the sum stops at `2^64 - 1`, and
   `0x358dcd0` is called with the Location at `0x56f2138` (`l1/src/qtys/impl_ntl.rs:664`). A later non-zero value overflows and calls it again.
   A sum below `1000000` gives `0xa5` (`0x37454e0`, `jae`). A tree holding fewer items than its length panics in
   `library/alloc/src/collections/btree/navigate.rs:534`.
4. More than 100 bytes gives `0xa0` "Referral code too long" (`0x374550f`). All three flag 0 callers are the same wrapper shape, which has already refused this, so no flag 0 caller reaches it.
5. An address already in the profile tree gives `0xa4` "Referral code already registered for this user".
6. A code already in the code tree gives `0xa3` "Referral code already registered by another user".
7. Otherwise the code is cloned twice, profile entry then code entry, and the status is `0x186`.

The new profile is written at `[rsp+0xd0]`: code String at `+0`, zero at `+0x18`, `+0x20`, `+0x30`, `+0x38`, the `r9` word at `+0x40`. `+0x28` is not written.

### Flag 1

1. More than 100 bytes gives `0xa0`, as the first test. There is no volume test, and the table is not read.
2. The address is looked up in the profile tree at tracker `+0x108`.
3. **Found**: the code tree at `+0x120` is searched. A code held by another address gives `0xa3`. A code held by this address, or a missing one, passes: the
   old code leaves the code tree (`0x33adba0`, key = the profile String), the new one enters it (`0x339a090`), the String is replaced and the old block freed,
   `+0x38` becomes 0 and `+0x40` becomes `r9`. `+0x18..+0x38` stay as they were.
4. **Not found**: the code tree is searched through the same path as flag 0. Any hit gives `0xa3`, including a code held by this same address. Otherwise
   profile and code entries are made as above.

### The arm supplies a non-zero word

The `xor r9d,r9d` before the call at `0x235a799` is on one branch only, so a scan of the bytes before the call is misleading:

- `0x2356a4c`: a code of more than 100 bytes jumps to `0x23599c7`, which gives `0x143`, word = the stack copy of the String at `[rsp+0x130]`.
- `0x2356a61`: the word at action `+8` = 0 goes to `0x235a776`, where `r9` is cleared. The value at `+0x10` is ignored.
- Otherwise `0x2356a74` compares the value at `+0x10` with `0x0ccccccccccccccc`. Below it, `jb` lands at `0x235a779`, **after** the `xor`, so `r9` keeps the value.
  At or above it gives `0x13f` "Invalid input number" with the value as word. Length is tested first.
- Action layout read here: `+8` word, `+0x10` value, `+0x18..+0x30` code String, `+0x30..+0x44` the 20-byte address.

The same `movabs`, `cmp r9,rax`, `jb` to just past a `xor r9d,r9d` is found in all three flag 1 callers: `0x2356a67`, `0x4cab3e1`, `0x4cb3d71` (`arm_copies`).

## Implementation and comparison

Not yet implemented in Rust. The comparison is between the decoded bytes run in the evaluator and a separate closed-form model in the tool (`model`). Nodes of the three B-tree
layouts are written by the tool:

Tree | Leaf size | Key | Value | Length word | Edges
--- | --- | --- | --- | --- | ---
volume | `0x278` | not read | `0x30` at `+0` | `+0x272` | `+0x278`
profile | `0x400` | 20 at `+0x320` | `0x48` at `+8` | `+0x3fe` | `+0x400`
code | `0x1f0` | String at `+8` | 20 at `+0x110` | `+0x1ee` | `+0x1f0`

`reference-diff.tsv` compares `references/can1357-hl/l1/exchange/handlers/15_register_referrer.rs` with the bytes: 7 rows differ, 4 agree. The largest gap is that the reference describes
only flag 0; `n_per_bucket = 0` holds for those callers and not for the arm.

## Results and limitations

- 2664 vectors, 0 mismatches. After each call the status, overflow count, entry helper calls, whole tracker, table, tree arenas and live blocks are compared. Outcomes:
  1515 `0x186`, 330 `0xa3`, 321 `0xa4`, 266 `0xa5`, 84 `0xa0`, 64 `0x143`, 64 `0x13f`, 12 allocation panics, 8 tree panics.
- 399 mutants (conditionals, field offsets, immediates) of all five ranges: 391 killed, 8 equivalent, each with a reason in `mutations.tsv`. One of the 8 is not proved
  by a run: `0x3745464` needs a tree of height 16 or more, which no vector has; its reason is an argument.
- The survey found real gaps, then closed: a success tag read as an error (status compare), scratch pointers to the entry helpers (argument checks), and the probe
  step at `0x3744fdc`, which needs a row at the third probe in a 128-slot table.
- Two full runs gave identical bytes.

Inferences, not observations:

- The arm is `VoteGlobalAction::ModifyReferrer`: only the reference's field names `code`, `n_per_bucket`, `enabled` suggest it. `+8` and `+0x10` look like an `Option<u64>`, while the
  reference writes `u128`. This packet does not prove which action reaches the arm.
- Profile `+0x40` is `n_per_bucket`: based on the same names. `+0x20..+0x30` looks like an empty B-tree (root null, height unset, length 0), which would explain why `+0x28` is
  not written.
- The first word of the volume value is volume in cents, so `1000000` reads as 10000 dollars. Open #249 reads the same word and also only infers the unit.
- The Location at `impl_ntl.rs:664` suggests the words are `Ntl` values.

Unresolved:

- Which selector reaches the arm in `0x2355f40`, and who may send that action.
- The arms in `0x4caa870` and `0x4cb3200` were matched by the limit test bytes, and not evaluated.
- Who reads profile `+0x40` and `+0x38`.
- The word `+8` of the arm action: any non-zero value takes the limit branch, and vectors only cover values chosen by the tool.
- The entry helpers are stubs: their tree rebalancing is not covered, and whether `0x33adba0` tolerates a missing key is not shown here.
