# RE-004: perp dex limit votes: MainOrHip3 row tag, raise-only global writes, transfer pair rule and max OI override

This packet shows what five VoteGlobal arms do to a perp dex row in node #94. A vote with no dex name stores a default for later dexes and only raises existing HIP-3 rows, while a named vote sets the exact word and can lower it. The byte at row `+0x230` is the `MainOrHip3` enum tag, and value 3 is the Main dex, so words such as `+0x1b8` and `+0x1d0` mean different things on each side. A reconstruction can now model the row as that enum, write the five vote arms and their number bounds, and stop using the reference's labels for these tags.

- Component ID: RE-004 (quantities and rounding)
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: `1f8c67c63ca4794c9689235471c60297f8a5c985` / `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`. The reference is used as a list of labels to check. Nothing is copied from it.
- Claim status: observation for everything under Evidence, which comes from ELF bytes and an evaluator of those bytes. Inferences are marked and listed apart.
- Scope included: 12 whole writer functions, the 2 insert and 2 remove functions of the override map with the tree helpers they reach, and the rows of words 71, 83, 84, 85 and 87 in all three copies of the VoteGlobal dispatcher, run from the dispatcher entry. Scope excluded: the rest of each dispatcher, vote tallying, the dex name lookup behind slot `0x5773eb8`, the asset lookup behind slot `0x5773318`, and the code that reads these limits at order or transfer time. Word 86 (`daily_px_range`) has its writer listed in earlier packets, so it is named here only as a field.

## Reproduce

From the repository root:

```
python3 tools/perp_dex_limit_votes.py --out research/work-items/RE-004-perp-dex-limit-votes-94
python3 -m unittest tests.test_perp_dex_limit_votes
```

The tool takes about 40 s on a loaded machine. It uses Python and the standard library, reads the ELF through `tools/elf_index.py` and `tools/fde_extents.py`, and checks the input SHA-256 first. It starts no external program, so the binutils version cannot change the output. The binary is never executed: an evaluator reads its instruction bytes.

Generated files: `evidence.json`, `function-rows.tsv`, `arm-rows.tsv`, `writers.tsv`, `arms.tsv`, `keys.tsv`, `texts.tsv`, `serde.tsv`, `outcomes.tsv`, `mutations.tsv`. `MANIFEST.sha256` covers them and this README.

## Evidence

All addresses are ELF virtual addresses. Function ends come from FDEs. `function-rows.tsv` holds 16 functions, 1985 instructions and 7999 bytes. `arm-rows.tsv` holds the 688 dispatcher rows the cases reach past the shared dispatch head.

### The enum at row `+0x1a8`

`S` is the state pointer given to the dispatcher in `rdx`. The dex table is a vector of rows of 0x2f0 bytes, with its pointer and count at `S+base+8` and `S+base+0x10`. Base is `0x5b8` in copies a and b, and `0x1038` in copy c.

Serializer `0x233ca40` tests `cmpb $3, 0x88(%rsi)` and then writes one of two variants. The table below lays its record over row `+0x1a8`: no direct caller was found, but `+0x88` then lands on the tag byte that the writers test at row `+0x230`, and the `limits` offsets land on the words they store. Key text, offsets and field rows are in `keys.tsv`, and the variant names `struct variant MainOrHip3::Main with 4 elements` and `MainOrHip3::Hip3 with 4 elements` are in `serde.tsv`.

| Record offset | Row offset | Main | Hip3 |
| --- | --- | --- | --- |
| `+0x00` | `+0x1a8` | `reset_recent_oi_bucket_guard` | `limits` (6 words, below) |
| `+0x10` | `+0x1b8` | `asset_to_recent_oi` | inside `limits` |
| `+0x28` | `+0x1d0` | `override_max_oi_per_second` | inside `limits` |
| `+0x30` | `+0x1d8` | inside the map above | `hip3_backstop_liquidator_state` |
| `+0x40` | `+0x1e8` | `assets_at_open_interest_cap` | inside the state above |
| `+0x60` | `+0x208` | unread here | `schema` |
| `+0x68` | `+0x210` | unread here | `state` |
| `+0x88` | `+0x230` | byte 3 | not 3 |

Serializer `0x233af80` gives the `limits` record:

| Limits offset | Row offset | Key | Default in copies a, b | Default in copy c |
| --- | --- | --- | --- | --- |
| `+0x00` | `+0x1a8` | `daily_px_range` | `S+0x3908` | `S+0x4388` |
| `+0x08` | `+0x1b0` | `total_oi_cap2` | `S+0x3910` | `S+0x4390` |
| `+0x10` | `+0x1b8` | `oi_sz_cap_per_perp` | `S+0x3918` | `S+0x4398` |
| `+0x18` | `+0x1c0` | `max_transfer_ntl2` | `S+0x3920` | `S+0x43a0` |
| `+0x20` | `+0x1c8` | `max_under_initial_margin_transfer_ntl2` | `S+0x3928` | `S+0x43a8` |
| `+0x28` | `+0x1d0` | `max_n_users_with_positions` | `S+0x3930` | `S+0x43b0` |

### Arms and writers

The dispatcher reads the action word at `+0`. Word `w >= 0x12` selects entry `w - 0x12` of a relative table (`0x3dd1b8`, `0x711064`, `0x711244`). `arms.tsv` lists every arm and `writers.tsv` every writer.

| Word | Copy a arm | Writer a, b, c | Number gate in the arm |
| --- | --- | --- | --- |
| 85 `0x55` | `0x2356c7a` | `0x235f110`, `0x4cbcf80`, `0x4cbc030` | `v >= 0x0ccccccccccccccc` tag `0x13f` with `v`; `v < 1000000` tag `0x13f` |
| 84 `0x54` | `0x2356429` | `0x235ea90`, `0x4cbc280`, `0x4cbcb50` | `v >= 0x0ccc..` tag `0x13f` with `v` |
| 87 `0x57` | `0x2356a99` | `0x235ece0`, `0x4cbbb90`, `0x4cbc4d0` | `v >= 0x0ccc..` tag `0x13f` with `v` |
| 83 `0x53` | `0x2358493` | `0x235ef30`, `0x4cbc970`, `0x4cbcda0` | below |
| 71 `0x47` | `0x2356851` | none, inline | below |

Word 83 carries `a` at `+0x20` and `b` at `+0x28`. In order: `a >= 0x0ccc..` gives tag `0x13f` with `a`, then `b >= 0x0ccc..` gives tag `0x13f` with `b`. Let `chain` be byte `S+0x8f2` (`S+0x1372` in copy c). The pair passes only if all three hold:

| | `chain == 2` | any other `chain` |
| --- | --- | --- |
| ratio | `2a <= b` | `5a <= b` |
| first floor | none | `a >= 100000000000` |
| second floor | none | `b >= 1000000000000` |

A failure gives tag `0x13f` with no payload word. The refused action's name is freed in every refusal. `a` is below `2^60`, so neither product can wrap.

All four writers share one shape, with arguments `rdi` result, `rsi` the name's (capacity, pointer, length), `rdx` S, and value or values in `rcx`, `r8`. A capacity of `2^63` means no name, tested by `neg; jno`.

No name:

1. Store the value in the default word.
2. For each row with tag not 3, store `max(row word, value)`. Main rows are skipped.
3. Return `0x186`.

So a vote with no name can raise a limit on existing HIP-3 dexes and can never lower one. `max` is unsigned, on `cmovbe`.

Name given:

1. Length above 100 frees the name and gives tag `0x143` with the capacity at `+8` and the length at `+0x18`.
2. Slot `0x5773eb8` (called with `S+base`) resolves the row. An error object comes back whole, all 0x60 bytes.
3. A row with tag 3 gives tag `0x141`, "Invalid perp DEX", so limits cannot be set by name on Main.
4. Otherwise the row word is set exactly, up or down, and the default is left alone.

### Word 71: the Main override map

The action holds an optional value (tag `+8`, value `+0x10`) and a name (`+0x18`, `+0x20`, `+0x28`). In order:

1. Slot `0x5773d80` gets `S+base` and dex 0, and returns a row.
2. Name length above 100 gives tag `0x143`.
3. Slot `0x5773318` resolves the name to an asset. An error object comes back whole.
4. Row tag not 3: nothing is stored, and the result is `0x186`.
5. No value: remove the asset from the map at row `+0x1d0` (`0x2866bf0`; `0x4945820` in copies b, c).
6. Value at or above `0x0ccc..`: tag `0x13f` with the value.
7. Value below 1000000: nothing is stored, and the result is `0x186`. This is a silent no-op, not a refusal.
8. Otherwise insert or replace (`0x285f5a0`; `0x4938ea0`).

The name is freed on every path. The map is a B-tree from u64 asset to u64 value. Its node keeps keys at `+0x08`, values at `+0x60`, the length at `+0xba` and edges at `+0xc0`.

### Reference comparison

`references/can1357-hl/l1/action/vote_global.rs` has `SetMaxOiPerSecond` at raw `0x49` and five labels at raw `0x55..=0x59`. The bytes put the same row order at words `0x47` and `0x53..=0x57`, 2 lower. The labels `SetPerpDexOpenInterestFundingCap`, `SetPerpDexOpenInterestLimit`, `SetPerpDexDailyInterestLimit` and `SetPerpDexMaxNotionalTransferredTotal` do not appear in the binary's serde variants. These words write `oi_sz_cap_per_perp`, `total_oi_cap2`, `daily_px_range` and `max_n_users_with_positions`. The reference also lists `SetPerpDexDailyPxRange` and `SetPerpDexMaxNUsersWithPositions` at raw `0x6c` and `0x6e`, while `serde.tsv` has one variant of each. `SetMaxOiPerSecond` in the reference has a required `RawPx`; the bytes take an optional u64 first, and None clears the row. A search for these names in the reference finds enum rows, structs, display names and one validator, and no writer.

## Inferences

These are readings of the observations above, not separate byte facts.

- Words 83, 84, 85, 87 and 71 are `SetPerpDexTransferLimits`, `SetPerpDexOpenInterestSzCapPerPerp`, `SetPerpDexOpenInterestCap`, `SetPerpDexMaxNUsersWithPositions` and `SetMaxOiPerSecond`. The link is field names and element counts: the field a word writes against the variant text. No table in the bytes joins the two.
- Slot `0x5773d80` with dex 0 returns the Main row, so word 71 normally reaches step 5. The harness tests the other side by giving it a non-Main row.
- Values 0, 1, 2 at `+0x230` are the `state` field of the Hip3 side, with 3 as the niche for Main. `state` is at `+0x210`, and the tag falls inside it.
- The `mode` byte at `+0x230` in earlier oracle packets is this same tag, which would make "mode 3 stores the raw price" a Main dex rule.
- Copies a and b are the older state layout and copy c a newer one, because the default block and chain byte move.
- `chain == 2` looks like a test network, by the relaxed floors. Other packets read byte 3 as Mainnet. This is not shown here.
- Units are not shown by these functions. `1000000` and `100000000000` read as 1 and 100000 dollars in 6-decimal notional, if these words share that unit.

## Implementation and comparison

Rust implementation: not yet implemented. Comparison is between the real instructions, run by the evaluator in `tools/perp_dex_limit_votes.py`, and a separately written rule list in the same tool (`spec_action`, `spec_writer`, `spec_override`, `spec_map`).

Each case starts at the dispatcher entry with the real jump table. Writers, map functions and tree helpers run as real bytes. The dex lookup, row lookup and asset lookup are stubs that check their arguments. For each case the tool compares the status, the listed payload words, the whole 32 KB state and row image, the map contents (walked through parent links, which are also checked) and whether the name was freed. Copy c runs with its own offsets.

1503 named cases and 1200 vectors match. Every named case's result is in `outcomes.tsv`.

Mutation test: every reached conditional row, immediate and field offset in the 16 functions and the reached dispatcher rows past the head is edited in turn. 1165 of 1198 edits are caught. The other 33 carry a reason in `mutations.tsv`:

- 9 `lea -0x2f0` displacement edits: the quotient used for the loop's parity step does not change.
- 2 replaced-value reads, 4 found flags and 4 handle words that no later row reads.
- 2 full-root bounds on a row where `rdx` is 0.
- 12 status test edits after a writer: the copy path writes the same `0x186` tag.

## Results and limitations

- 47 unit tests pass with no skips, including corrupt digest, corrupt key, corrupt field row, wrong tag text, bad parent link and out-of-FDE controls. `--out` run twice under another hash seed and time zone gives identical files.
- Unreached rows are listed per function in `evidence.json`: 134 rows, the unwind landing pads and panic rows of the writers and map functions. Tree helpers below the 16 functions run but are not mutated.
- The three stub lookups are not read here. Their real behaviour is an edge of this packet, so a wrong stub shape would show only as a mismatch against the real row use, not against the real callee.
- Trees in the cases have at most 2 levels.
- Word 71's `0x143` result holds a stack address at `+8`, where the writers hold the capacity. The tool checks only the tag there. No reader of that word was traced.
- Who reads the limits is not covered. A byte scan shows `0x3711d00` reading `+0x1b8`, `0x26caea0` comparing `+0x168` with `+0x1d0` before tag `0x161` "Perp DEX user positions limit reached", and `0x2729c30` reading `+0x1c0` and `+0x1c8`. Those functions have rows in other packets, so they are left out.
- The default block's reader was seen only as a site in `0x273d120`, and it is left out for the same reason.
