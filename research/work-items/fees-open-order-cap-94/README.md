# fees: how node #94 bounds a user's open orders by volume

- Component ID: `fees` (path rules `l1/raw_vlm.rs`, `l1/scaled_vlm.rs`: the gate below reports overflow at
  `l1/src/scaled_vlm.rs:15:21` and `l1/src/raw_vlm.rs:17:21`, and it is the one place where the volume sum sets a limit).
- Target release and full SHA-256: hl-node #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` /
  can1357-hl `999556f6e0a474b8312db96ec3149e1c44e97c23` (used as leads only).
- Claim status: observation for bytes, decoded instructions and evaluated outcomes; inference where marked;
  unresolved items are listed at the end.
- Scope included: the gate at the start of six functions (`0x271b220`, `0x271bb40`, `0x4d19d40`, `0x4d1a670`,
  `0x4d1afa0`, `0x4d1b8b0`), from each function entry to the first instruction after the gate, plus the three count
  lookups, two volume lookups, the address predicate and the three lazy default constructors they use.
  Scope excluded: everything after the gate (order execution, notional, fills), the callers, the writers of the count
  and of the volume words, the hash function and fee rates.

## Reproduce

```sh
python3 tools/fees_open_order_cap.py --out research/work-items/fees-open-order-cap-94
python3 -m unittest tests.test_fees_open_order_cap
(cd research/work-items/fees-open-order-cap-94 && sha256sum -c MANIFEST.sha256)
```

Run from the repository root on Linux x86-64 with Python 3 and no third-party package. The tool checks the input
SHA-256 first and fails on any other file. It starts no external program, so no binutils version can change its
output. Sections and FDEs come from `tools/elf_index.py` and `tools/fde_extents.py`. It does not run the node or
visor: decoded instructions are interpreted in Python. A full run takes about one minute.

## Evidence

All addresses are ELF virtual addresses. Function ranges come from `.eh_frame`, and the decoder must land on each
FDE end (`copies.tsv`). At authoring time only, GNU objdump 2.42 gave the same instruction boundaries for the six gates
and six helpers (3265 instructions); that compare is not part of the evidence and the tool does not depend on it.

### Where the gate is

By byte pattern, `scaled_vlm.rs:15:21` has 20 LEA sites and `raw_vlm.rs:17:21` has 14 (`evidence.json`,
`location_lea_sites`). The pattern `REX.W 81 /7 imm32` with 4000 hits seven times in `.text` (`compares_with_4000`): the
six gates and `0x3261c40`, which tests an argument word at its entry and has no volume code near it. The six gates come
in three pairs, one pair per state layout:

| Copy | After the gate | Count lookup | Attempts word | Volume Vec | Observer |
|---|---|---|---|---|---|
| `0x271b220` | divides the asset by 10000 | `0x2755400` | `+0x888` | `+0x5c0` | `+0x3a88` |
| `0x271bb40` | no such divide | `0x2755400` | `+0x888` | `+0x5c0` | `+0x3a88` |
| `0x4d1a670` | divides the asset by 10000 | `0x46f2fe0` | `+0x888` | `+0x5c0` | `+0x3a88` |
| `0x4d1afa0` | no such divide | `0x46f2fe0` | `+0x888` | `+0x5c0` | `+0x3a88` |
| `0x4d19d40` | divides the asset by 10000 | `0x46f2e60` | `+0x1308` | `+0x1040` | `+0x4508` |
| `0x4d1b8b0` | no such divide | `0x46f2e60` | `+0x1308` | `+0x1040` | `+0x4508` |

Each has four direct call sites by byte pattern (`copies.tsv`, `call_sites`: the `e8 rel32` scan is a pattern match,
not a decoded caller). The three lookups share one body shape; `0x2755400` and `0x46f2fe0` read a map at `+0x740`,
`0x46f2e60` at `+0x11c0` (`evidence.json`, `count_lookup_offsets`).

### The rule

With `count` the word at `+0x20` of the value that the lookup returns for the user (bucket stride `0x58`, key 20
bytes, so `+0x38` from the bucket start), all six copies do this:

1. Add 1 to the attempts word, saturating at `u64::MAX`.
2. If `count < 1000`, leave the gate. No volume and no address is read.
3. If byte `+0x19` of the order is not 2, or bit 0 of byte `+0x31` is set, reject. No volume and no address is read.
4. If the user is one of the eight addresses in `addresses.tsv`, the bound is 10000, and no volume is read.
5. Otherwise add the `(scaled, raw)` pair of every per-dex entry (Vec of `0x2f0`-byte records, map at `+0xf8`, words at
   value `+0x40` and `+0x48`), then the pair of the map at state `+0x80` (words at value `+0` and `+8`). Both sums
   saturate. The bound is `1000 + min(scaled / 500000000, 4000)`.
6. If `count >= bound`, reject; otherwise leave the gate.

A reject writes tag `0xc3`. The Display table at `0x59a8d0` sends that tag to the arm at `0x380055b`, which prints
`Too many open orders` (text at `0x59d770`, 20 bytes). The reject route frees the 72-byte-element Vec passed in `r9`
when the first word behind the seventh argument is below 2 and the capacity is not zero, then calls the observer if one
is set. Three copies (`reject_writes_word_28` in `copies.tsv`) also store order word `+0x28` at result `+8`; the
Display arm does not read it.

Overflow never stops the gate. Per-dex adds report to `l1/src/qtys/impl_ntl.rs:664:1`, the base adds to
`l1/src/scaled_vlm.rs:15:21` and `l1/src/raw_vlm.rs:17:21`, through the recorder in slot `0x5773190`, and the sum
continues at `u64::MAX`. The raw sum is checked and then dropped: only the scaled sum reaches the bound.

The core at `0x271b7f2`, for reading only:

```
shr    r14,0x8
movabs rcx,0x44b82fa09b5a53
mov    rax,r14
mul    rcx
shr    rdx,0xb
cmp    rdx,0xfa0
mov    ecx,0xfa0
cmovb  rcx,rdx
add    rcx,0x3e8
```

`(x >> 8) * 0x44b82fa09b5a53 >> 75` equals `x / 500000000` for every u64. The proof is exact integer arithmetic in
`division_proof`: `0x44b82fa09b5a53 * 1953125 - 2^75 = 399807 > 0`, and `(2^56 - 1) * 399807 < 2^75`, so the error stays
below one step of `1 / 1953125` (`evidence.json`, `division_proof`). The bound reaches 5000 at a scaled total of
`2000000000000`.

### The address list

`0x37e4fb0` is reached through slot `0x5773228`. It has 66 instructions and no call: eight blocks that compare 16 bytes
and then 4 bytes of the user with `.rodata` constants, with a zero tail on the second constant. `addresses.tsv` lists
the eight addresses, read from those constants. The predicate reads the 20 user bytes and `.rodata`, nothing else, so
the list is fixed in the binary.

### Defaults

A user who is not in a map gets a lazy static: `0x5786190` for the count, `0x57862a0` for a per-dex entry and `0x5786308`
for the base entry. Their constructors `0x34d71a0`, `0x3790fc0` and `0x3791080` are run from bytes (the id allocator in
slot `0x576e890` is a stub) and give zero for each word the gate reads (`evidence.json`, `lazy_defaults`). So a user in
no map has count 0 and passes at step 2.

### How it was tested

Each copy is interpreted from its real entry. The two volume lookups, the count lookup and the address predicate run
from bytes over real swiss tables built by the tool: a direct hit, a decoy with the same control byte, a hit in the next
group, a missing key and an empty map, each in all three maps, with the lazy default ready or not. Stubs: the hash
function (it returns a chosen hash and checks the key it receives), the clock, the overflow recorder, the free call, the
Once call and the observer. State bytes are strict: a read of any byte the test did not set is a fault, so a read of any
other map would show.

- 1216 vectors on 6 copies, 7296 evaluations, 0 mismatches against the closed form `model()`, which was written from
  the rule above and shares no code with the evaluator. 342 vectors pass the gate and 874 are rejected.
- The compare covers outcome, attempts word, the ordered list of map lookups, recorder calls, free and observer calls,
  clock calls, and on the reject route the tag, the return value, the saved registers and the stack pointer.
- On every evaluation the watched memory (state, order, user, the two argument blocks, all tables, the observer) is
  byte identical before and after, apart from the attempts word. So the gate has no other write there.
- Gate instructions: 1613 of 1613 reachable executed over the six copies (`instructions.tsv`); the tool fails on any
  reachable instruction that no vector runs. Helpers: all instructions executed but one padding `nop` in each of the
  five map lookups; the predicate 66 of 66.
- Mutations: 235 of 235 killed, none equivalent (`mutations.tsv`). 187 in the gates: every conditional jump and every
  bound, cap, tag, multiplier, shift, field value, stride and map offset immediate, on all six copies. 48 in the
  helpers: every conditional jump. The compare `cmp rdx,0xfa0` is mutated to `0xfa2`, since `0xfa1` gives the same
  result through the `cmov` after it.

## Implementation and comparison

Not yet implemented in Rust. `reference-diff.tsv` compares the rule with `references/can1357-hl`; these rows differ:

| Reference | Says | Bytes say |
|---|---|---|
| `l1/exchange/impl_trading.rs:1033` | `is_vault_privileged`: `user[0] != 0 && user[19] == 0` | a byte compare with eight fixed addresses; none of the eight has that shape, and a user of that shape outside the list stays on the volume bound (vectors) |
| `l1/exchange/impl_trading.rs:741` | the check inserts `current + 1` into the count map | the gate writes the attempts word and nothing else that is watched |
| `l1/exchange/impl_trading.rs:762` | total adds base, main, alt and per-dex maps | the per-dex entries and one map at state `+0x80` |

The bounds, tag 195, the `order_kind == 2 && !reduce_only` test, the saturating attempts add and the per-dex-then-base
order in `l1/scaled_vlm.rs:277` agree with the bytes. `l1/scaled_vlm.rs:129` calls the bound an action cap; the Display
text for the tag says open orders.

## Results and limitations

Requested progress gate: none. Machine-readable results: `evidence.json`, and `copies.tsv`, `addresses.tsv`,
`instructions.tsv`, `mutations.tsv`, `vectors.tsv`, `reference-diff.tsv` beside it.

Inferences, not proved here:

- `count` is the user's open order count. The reject text says so, but no writer of that word is in this packet.
- Bytes `+0x19` and `+0x31` of the order are `order_kind` and `reduce_only`. Those names are reference labels.
- `+0x19 == 2` may mean "no trigger", as order `+0x10..+0x19` looks like an optional trigger; not tested.
- Copies with the divide by 10000 are perp order paths, and the others spot paths, as in
  `l1/exchange/impl_trading.rs:500` and `:520`. The three pairs would be three state layouts of one generic body.
- The eight addresses are not named by anything in the binary that this packet read.

Limits:

- The hash function is a stub, so which bucket a real key lands in is not tested; only probing from a given hash is.
- The stubbed recorder returns. That it always returns is not shown here.
- Non-empty lists of more than three dex records are not run: the loop has no per-index state beyond the two sums.
- The stack and the result block are not watched for writes: they are the gate's own memory.

Next question: who writes the word at `+0x38` of the `0x58`-byte count bucket, and does it move by exactly one on each
resting order insert and remove, so that `count` is proved to be the open order count?
