# fees: claimRewards path in node #94: fee ledger U to C, floor of one whole token, value capped at 1e16

- Component ID: `fees` (first task: maker/taker fee formulas and time-window rollover; this packet fixes how fee rewards recorded per user and token leave the ledger).
- Target release and full SHA-256: hl-node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` /
  can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23` (used as leads only, nothing copied).
- Claim status: observation for bytes, decoded instructions, evaluated outcomes and status texts; inference where marked; unresolved items are listed at the end.
- Scope included: in full, the handler `0x2710e30` and the ledger writer `0x3743930`, run with three real helpers `0x333e310`, `0x32815f0`, `0x375fb50`. Scope excluded, all stubs that check their arguments: the hash `0x399c7a0`, balance update `0x371d120`, mark lookup `0x371cf40`, account lookup `0x1f849b0`, block record `0x3987cb0`, token name `0x3c0d6e0`, event push `0x3576710`, overflow recorder `0x358dcd0`, vector growth `0x32d5a20`, allocation. Also excluded: the dispatch arm at `0x2759c55`, node #115.

## Reproduce

```sh
python3 tools/artifacts.py verify
python3 tools/fees_claim_rewards.py --out research/work-items/fees-claim-rewards-94
python3 -m unittest tests.test_fees_claim_rewards
(cd research/work-items/fees-claim-rewards-94 && sha256sum -c MANIFEST.sha256)
# optional, for a human reader only; no evidence file uses this
objdump -d -M intel --start-address=0x3743930 --stop-address=0x3743deb artifacts/node/94/hl-node
```

Run from the repository root on Linux x86-64 with Python 3 and no third-party package. The tool checks the input SHA-256 first and fails on any other file. It starts no external program, so no binutils version can change its output. Sections and FDEs come from `tools/elf_index.py` and `tools/fde_extents.py`. It does not run the node or visor: decoded instructions are interpreted in Python, on memory built by the tool. A run took about 360 s on 3 workers.

Outputs: `evidence.json`, `vectors.tsv`, `mutations.tsv`, `instructions.tsv`, `reference-diff.tsv`.

## Evidence

Coordinates are ELF virtual addresses. All five ranges are `.eh_frame` FDEs, and the table decoder must land on each end.

Range | Role | Instructions | Executed
--- | --- | --- | ---
`0x2710e30..0x2711434` | handler | 324 | 280
`0x32815f0..0x3281767` | value (real helper) | 103 | 86
`0x333e310..0x333e441` | floor (real helper) | 88 | 75
`0x3743930..0x3743deb` | ledger writer | 278 | 255
`0x375fb50..0x375fc29` | unit price (real helper) | 58 | 58

Unexecuted ranges of the two subjects, each with a reason in `evidence.json`:

- `0x2711065..0x271106a`: jump to the unwrap panic: 0x32815f0 reports success only below 0x28f5c28f5c28f5c, and failure leaves 0, so the sign test always passes.
- `0x271139f..0x2711434`: two token bound panics (the writer already passed the token through the same bound), the unwrap panic, unwind cleanup.
- `0x3743d0d..0x3743d12`: jump after cmp rax,8: rax is a non-zero multiple of 8 here, so the jae above always goes.
- `0x3743da2..0x3743db5`: free of an empty vector: capacity only grows just before a push, so length 0 means capacity 0.
- `0x3743dc2..0x3743deb`: ud2 after a panic call and unwind cleanup.

The tool fails on any other unexecuted instruction of the two subjects (12 padding instructions aside). The helpers are run, not surveyed.

### Callers

Slot `0x57749f0` holds the writer and has three call sites, one in each of three handlers:

Call site | Handler | Called from | Tracker
--- | --- | --- | ---
`0x2710e84` | `0x2710e30` | `0x2759240` | exchange `+0x5d0`
`0x4d02494` | `0x4d02440` | `0x4d83050` | exchange `+0x1050`
`0x4d02aa4` | `0x4d02a50` | `0x4d84170` | exchange `+0x5d0`

Instruction compare after rip targets are made absolute: `0x4d02440` has 324 instructions and differs from `0x2710e30` in 14 (`0x4d02457`, `0x4d024fd`, `0x4d02509`, `0x4d02510`, `0x4d02515`, `0x4d02519`, `0x4d0251e`, `0x4d02525`, `0x4d02717`, `0x4d027b7`, `0x4d028be`, `0x4d029cf`, `0x4d029d6`, `0x4d029dd`); `0x4d02a50` has 324 instructions and differs from `0x2710e30` in 10 (`0x4d02b19`, `0x4d02b20`, `0x4d02b25`, `0x4d02b29`, `0x4d02b2e`, `0x4d02b35`, `0x4d02d27`, `0x4d02fdf`, `0x4d02fe6`, `0x4d02fed`). The rows are exchange offsets of a second layout, a reordered spill of the same three addresses, panic data, the account function `0x47d7ca0` in place of `0x1f849b0`, and event slot `0x5776ad0`; no branch, constant or arithmetic differs. Listed in `evidence.json`.

### Writer `0x3743930`

Arguments: result, tracker, user, spot metadata.

1. Item count at tracker `+0xd8` of 0 gives status `0xa6`. So does a user with no row in the table at `+0xc0` (stride `0xe8`, 20-byte key compared in full), a row with root 0 at row `+0xb0`, or length 0 at row `+0xc0`.
2. The tree is walked in key order. Node layout: values `+0` (0x30 each), parent `+0x210`, u64 token keys `+0x218`, parent index `+0x270`, length `+0x272`, edges `+0x278`.
3. A token with value `+8` of 0 is skipped and does not set the seen flag.
4. Otherwise the floor is `0x333e310(100000000, token, unit price, 0, metadata)` and the seen flag is set before its result is read. The unit price from `0x375fb50` is `10^(w0 - s)`, with `w0` the wei decimals of token 0 and `s` the size decimals of this token. The floor is `floor(1e8 * 10^(w - s) / 10^(w0 - s))`. No mark, book or stored price enters it.
5. A quotient past 64 bits, or value `+8` below the floor, skips the token. Otherwise value `+8` becomes 0, value `+0x10` takes the saturating sum (recorder Location `l1/src/qtys/mod.rs:831`), and `(token, amount)` is pushed.
6. A non-empty vector gives `0x186`. An empty one gives `0xa6` or, if the seen flag is set, `0xa7`. Earlier claims in the same call stay applied, and a call returning `0xa7` changes nothing.

Status `0xa6` reads "No rewards to claim". The Display arm of `0xa7` at `0x3800161` loads f64 1.0 as its one argument for the format at `0x1f1184`: "Must have at least {} of a reward token to claim". The text and the formula agree when `w0` is 8.

Panics: a token at or past the token count, `s > w0` (subtract panic through `0x576e150`), `w < s`, an exponent of 20 or more (10^20 leaves 64 bits, the 5-bit ladder ends in the same panic path), and a tree length above its true item count (`0x3743db5`, Location `library/alloc/src/collections/btree/navigate.rs:560`).

### Handler `0x2710e30`

Any status other than `0x186` is returned with all `0x60` bytes copied from the callee result. On success the buffer is freed at the end, and for each `(token, amount)`, in order:

1. Price `px`: 0 for token 0; otherwise the value for that key in the tree at exchange `+0x250` (metadata `+0x1c0`; key `+8`, value `+0x60`, parent index `+0xb8`, length `+0xba`, edges `+0xc0`), else the unit price.
2. `0x371d120(exchange + 0x80, user, token, 0, amount, px)`.
3. Value `v`, token 0: `amount / 100`. Other tokens: mark from `0x371cf40(exchange + 0x80, token, exchange + 0x3380)`; a mark of 0 gives `v = 0` and skips step 4. Otherwise `v = 0x32815f0(amount, token, mark, 0, metadata)`, which is `floor(amount * mark / (10^(w - s) * 100))` and counts as 0 at or above `0x28f5c28f5c28f5c`.
4. Cap: `v = min(v, 1e16)`, except for token 1 and for a token whose name is exactly the 4 bytes `HYPE`. Token 0 is not capped.
5. `0x1f849b0(exchange + 0x740, user)` returns an account; its i64 at `+0x10` takes `v / 10000`, saturating (recorder Location `l1/src/qtys/impl_ntl.rs:665`).
6. One event through `0x3576710(exchange + 0x8f3, [user], time at +0x60, block, event)`: the block comes from `0x3987cb0` if the dword at exchange `+0` is 1, else zeros. The event is variant `0x8000000000000011`, a name string from `0x3c0d6e0`, and f64 `amount / 10^w` from the table at `0x584b08` (23 entries equal `10^i`, not bounds checked on `w`).

The sign test before the unwrap panic at `0x27113bf` cannot fail, since `0x32815f0` reports success only below `2^58`.

### Reference compare

`reference-diff.tsv` has 4 differing and 5 matching rows for `references/can1357-hl/l1/exchange/handlers/05_claim_rewards.rs`. Main difference: the reference calls these staking rewards, while the rows read here sit in FeeTracker `user_states`.

## Inferences

- Value `+8` is the unclaimed reward and `+0x10` the claimed total. Basis: this move, and the same tree carries the six-word value fed by the fill path (open #249).
- Tracker `+0xc0` is `user_states`, exchange `+0x5d0` is the FeeTracker: serializer table in open #249 and the exchange offset in open #345.
- `w0` is 8 on the live chain, so the floor is one whole token. Basis: the literal 1e8 and the 1.0 of the status text; the metadata is not in the binary.
- `v` is USD with 6 decimals, and account `+0x10` is a running signed count of whole USD. Basis: `amount / 100` on token 0 and the divide by 10000; the sibling at `0x2711440` subtracts with the same shape, and its purpose was not studied.
- Token 1 is HYPE on the live chain, because the two exempt tests sit together.

## Implementation and comparison

not yet implemented. The closed-form model in the tool is a test oracle and no Rust was written.

## Results and limitations

1554 vectors, 0 mismatches against a separate closed-form model. After each call the tool compares status, whole result bytes, ledger bytes outside U and C, table, scale tree, exchange block, account block, call order with arguments, overflow reports and live blocks. Outcomes: 0x186 1250, 0xa6 36, 0xa7 255, panic allocation 1, panic bound 11, panic subtract 1.

296 of 304 mutants of the two subjects killed, 8 equivalent with reasons in `evidence.json`.

Limits: the balance update, mark lookup, account lookup and event push are stubs, so what they do with their arguments is not covered. The copies are matched by instruction compare, and not run. The hash is a stub, so `0xe0` hasher state is not tested. Vector sizes are synthetic: metadata values come from vectors, not from the chain.

Unresolved: the name of event variant 0x11; what the tree at metadata `+0x1c0` holds and who writes it; which mark `0x371cf40` returns; who reads account `+0x10`; why the cap spares HYPE only.

Next question: which function credits value `+8` outside the fill ledger, and does the sibling `0x2711440` debit the same account word?
