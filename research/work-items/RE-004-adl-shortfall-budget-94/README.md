# RE-004: what bounds the node #94 quantity at dex +0x248, and how does it move?

- Component ID: RE-004 (quantities/rounding)
- Target release and full SHA-256: node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c`; `references/can1357-hl` used for leads only, no code copied
- Claim status: observation for bytes, tables and evaluator results; inference where marked; unresolved items are listed
- Scope included and excluded: included are the name of the field, its initial value, the validator setter, the
  date bump, the compare that decides auto-deleveraging, and the one debit site. Excluded are the inputs of that
  compare and of the debit, and the rest of the liquidation path.

## Reproduce

From the repository root, on Linux with Python 3 and the pinned artifact linked at `artifacts/node/94/hl-node`:

```
python3 tools/adl_shortfall_budget.py --out research/work-items/RE-004-adl-shortfall-budget-94
python3 -m unittest tests.test_adl_shortfall_budget
sha256sum -c MANIFEST.sha256   # inside the folder
```

The tool uses only the standard library plus `tools/elf_index.py` and `tools/fde_extents.py`. It checks the target
hash first and fails on any difference. It calls no external program and never runs the target. Every number in the
generated files comes from ELF bytes. The objdump excerpts below are for reading only and feed no generated file.

## Evidence

Addresses are ELF virtual addresses of node #94. FDE extents come from `tools/fde_extents.py`.

### The binary names the field

- Six serializers read `+0x248` directly before a LEA of the serde key `adl_shortfall_remaining`. Three size passes do
  the same with a LEA of `+0x248`. Ten more key sites are in decoders (`field-sites.tsv`).
- `0x36f92eb` is the only LEA of this message, and its pieces are in `summary.json`:
  `Auto-deleveragings triggered [at][at] [total_shortfall: ] [at] [self.adl_shortfall_remaining: ] [at]
  [asset_and_side_to_adl_requirements: ]`. Evidence files write the at sign as `[at]`.
  Its second argument is the pointer spilled by `lea rdx,[rsi+0x248]` at `0x36f7ccd`.
- `0x36f936a` is the only LEA of `Not performing auto-deleveraging because shortfall is acceptable`.
- Error tag `0x3d` has the Display arm `0x3800ede`, which prints `Adl shortfall too large`. Tag `0x13f` has the arm
  `0x3800dd1`, which prints `Invalid input number`. Both are read through the jump table of `0x37ffd40`.

### Initial value

`0x370ac37` in FDE `0x370a640` stores 0 at `+0x248`, next to 1 at `+0x2ec` and 500000 at `+0x250`. The serializers
order those three fields as `perform_auto_deleveraging`, `adl_shortfall_remaining`, `bridge2_withdraw_fee`.

### Validator setter: raw tag 0x1e

Three dispatchers (`0x2355f40`, `0x4caa870`, `0x4cb3200`) select by `tag - 0x12`, and case `0xc` is the setter block
(`0x2357503`, `0x4cabdbd`, `0x4cb474d`). Each block takes dex 0 through `0x3332700`, which the evaluator runs, then
applies two guards. `setter-pieces.tsv` holds the result for all u64 x and all 256 chain bytes:

| chain byte | x | result |
| --- | --- | --- |
| 3 | 0..=1000000000000 | field = x |
| other | 0..=5000000000000 | field = x |
| any | above the cap, below 0x0ccccccccccccccc | tag `0x3d`, field unchanged |
| any | 0x0ccccccccccccccc and above | tag `0x13f` with x as payload, field unchanged |

An empty dex vector reaches the unwrap panic before either guard. The neighbour cases cross-check the key names:
case `0xa` stores a byte at `+0x2ec`, and case `0x10` stores at `+0x250` with the wire guard and no cap.

### Date bump

The immediate 5e10 has exactly three sites, one in each of `0x2702330`, `0x4ceea90` and `0x4ceeb80`. Each function has
one direct caller, which copies 12 bytes as the argument and repeats the same date compare after the call.

```
2702338: cmp eax, [rdi+0x60]            ; jge returns, date word compare is signed
2702371: movabs rcx, 0xfffffff45bc48c00 ; 2^64 - 5e10
270237e: jae 27023be                    ; recorder, then rax = u64::MAX
2702380: movabs rcx, 0xba43b7400
270238a: add rax, rcx
270238d: cmp bpl, 3
27023a5: cmove rdx, rcx                 ; rdx = chain byte == 3 ? 1e12 : 5e12
27023ac: cmovae rdx, rax                ; rdx = min(cap, sum)
```

`bump-pieces.tsv` gives the whole domain for each copy and all 256 chain bytes, with x the old value:

| x | new value | recorder |
| --- | --- | --- |
| 0..=cap-5e10 | x+5e10 | no |
| cap-5e10+1..=2^64-5e10-1 | cap | no |
| 2^64-5e10..=2^64-1 | cap | yes, Location `l1/src/qtys/impl_ntl.rs:26:1` |

The bump also lowers any value above the cap to the cap. `date-guard.tsv` covers all 2^32 argument words against 7
state words: the bump runs exactly when the argument word is below the state word as signed i32. An empty vector
panics. The third copy uses the larger layout, `+0x1038` and `+0x1372` in place of `+0x5b8` and `+0x8f2`.

### Decision compare

`0x36f86d9` loads the pointer and compares it with the running total: `cmp rax,[rcx]; jb 0x36f87c9`.
`gate-grid.tsv` holds 121 vectors, and the jump is taken exactly when total < budget. The block before it adds to the
total with saturation, recording Location `l1/src/qtys/mod.rs:829:1`, and the triggered log pairs that total slot with
`total_shortfall`.

### Debit

`0x3703874` in FDE `0x36fff10`:

```
mov rax,[rsp+0x338] ; test rax,rax ; jns skip
neg rax ; jo panic
mov rsi,[rsp+0x28] ; mov rcx,[rsi+0x248]
xor edx,edx ; sub rcx,rax ; cmovae rdx,rcx ; mov [rsi+0x248],rdx
```

`debit-grid.tsv` holds 121 vectors: x >= 0 leaves the field, x = i64::MIN panics, any other negative x gives
`max(field - |x|, 0)`. The slot at `[rsp+0x28]` has one register spill in the FDE, from the second argument. The value
at `[rsp+0x338]` is returned by slot `0x57746f0`, which relocates to `0x37d77e0`.

### Inferences, kept apart from the observations

- Unit: micro-USD, from the Location file and the reference scale. Then the bump is $50,000, and the caps are $1M and
  $5M. From 0 it takes 20 bumps to reach the cap at chain byte 3 and 100 otherwise.
- Chain byte 3 is Mainnet, from the variant order fixed in the merged `research/work-items/bridge` packet and the
  reference note on `+0x8f2`. This packet shows only the byte value and that the variant names are in `.rodata`.
- The argument and `+0x60` are the date word of a 12-byte date-time, so one bump happens per date advance, not per
  elapsed day. The callers were not traced.
- ADL requirements are collected only when total >= budget, because the fall-through at `0x36f86ea` builds the vector
  that the loop at `0x36f87c9` walks. So the budget is the shortfall the chain accepts without deleveraging.
- A negative x is an account deficit that spends the budget. The reference calls `0x37d77e0` a margin surplus helper.

### Reference comparison

The reference is a lead, and these labels disagree with the bytes:

| Reference | Binary |
| --- | --- |
| `clearinghouse/clearinghouse.rs:260` names `+0x248` `oi_cap_budget` | serde key and log say `adl_shortfall_remaining` |
| `action/vote_global.rs:31` puts 5e12 on mainnet and 1e12 on testnet | 1e12 is chain byte 3, 5e12 every other byte |
| `action/vote_global.rs:530` checks those caps on raw tag 0x14 | no 5e12 immediate in `.text` outside the six sites here |
| `action/vote_global.rs:80` has no check for `AdlShortfallRemaining` | two guards with their own error text |
| `qtys/impl_ntl.rs:226` plain saturating add, `AssetCapMode` names | same values, plus a recorder call, on this budget |

## Implementation and comparison

not yet implemented. No Rust path, no Cargo.lock and no build comparison. The closed forms above are the acceptance
fixtures for a later implementation: bump, setter guards, compare and debit.

## Results and limitations

- Whole-domain results: 3 bump copies × 256 chain bytes and 3 setter copies × 256 chain bytes, over all u64 inputs.
  18 + 18 merged pieces, 0 mismatches. A piece has one path and one output form for all its inputs.
- Date guard: all 2^32 argument words, but only 7 state words. 54 pieces.
- Compare and debit have two inputs, so interval cuts do not apply. They rest on exact bytes plus 121 vectors each.
- Single-bit sweep during development, 3 flips per byte, checking the evaluator results only: 44 of 480 survived in
  `0x2702336..0x27023d6` and 15 of 294 in the setter block. They are the dropped error temporary, REX-only changes,
  `ja` versus `jg` on values below 2^60, the Location LEA, the saturation value and the exit target. The last three
  are pinned by separate checks in `analyse`. This sweep is not a generated file.
- Other writers of the field are not excluded. A byte scan finds 64 64-bit register stores with displacement `0x248`
  across all types, and decoders fill the field from state. Only the sites in this packet are classified. Stores
  through a held pointer or as part of a wider SSE store would not show in that scan.
- The fake state holds only what the instructions read, and the evaluator stops on any other read.
- Text of `0x141`, the two `.rodata` hits of 5e12 and the other 1e12 sites were not followed.
- The setter blocks sit inside large dispatchers that open PRs #46 and #72 also list for other sites. This packet
  covers only cases `0xa`, `0xc` and `0x10`. The bump functions, compare and debit are in no other evidence.

No progress gate is requested.

Next question: does the path through `0x37d77e0` make x the account deficit in the same unit as `total_shortfall`?
