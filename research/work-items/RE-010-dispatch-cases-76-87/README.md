# RE-010 follow-up: dispatcher cases 76..87 and the shared tail (node #94)

The parent packet (`../RE-010-exchange-handlers/`) pins all 88 jump-table arms of the
exchange-action dispatcher at `0x2759240` and the 76 claimed cases. For cases 76..87 it
stops at "arm, first call". This packet adds four things for those 12 arms, all recomputed
from `artifacts/node/94/hl-node` (sha256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`):

1. **Names.** The binary has three identical serde variant-name tables (`0x56c46e0`,
   `0x56e8bd0`, `0x5733130`). Each is 88 RELATIVE `(ptr, len)` entries followed by the
   serde message `variant index 0 <= i < 88`. Index *i* is read as dispatcher case *i*.
   For cases 0..75 that reading agrees with the reconstruction's `wire_type`: 51 exact,
   13 differ only by an `Action` suffix, 6 only by first-letter case, 5 by both, and 1
   genuinely different (68: `Hip3Deploy` vs `perpDeploy`).
2. **Arm shape.** Each arm's entry gate (if any), first call, and the exact bytes after
   that call (pinned idioms).
3. **Callee anchors.** Every RIP-relative `lea` into `.rodata` inside the first-call FDE.
   A `Location` record is a lea whose target is a RELATIVE pointer to a path, followed by
   line and column.
4. **Shared tail.** The bytes `0x275a136..0x275a230`, what each entry does, and every
   branch inside the dispatcher that lands on an entry.

## Cases 76..87

| case | tag | serde name (index = case) | arm | first call → target [FDE end) | after call | reaches | callee leas |
|---|---|---|---|---|---|---|---|
| 76 | 0xc0 | `sendToEvmWithData` | 0x2759b60 | 0x2759b7e → 0x2729060 [..0x2729c29) | result_word_check | 0x275a182 (via 0x275a348) | 3 |
| 77 | 0xc1 | `userPortfolioMargin` | 0x275938d | 0x275939f → 0x1e611a0 [..0x1e61320) | join | 0x275a186 | 0 |
| 78 | 0xc2 | `userSetAbstraction` | 0x275a2cf | 0x275a2e1 → 0x1e60f90 [..0x1e6110a) | join | 0x275a186 | 0 |
| 79 | 0xc3 | `agentSetAbstraction` | 0x2759333 | 0x2759356 → 0x1e61110 [..0x1e61197) | join | 0x275a186 | 0 |
| 80 | 0xc4 | `userOutcome` | 0x275945c | 0x275946e → 0x204c4e0 [..0x204cd20) | join | 0x275a186 | 2 |
| 81 | 0xc5 | `gossipPriorityBid` | 0x2759865 | 0x2759888 → 0x1e60bb0 [..0x1e60cf2) | join | 0x275a186 | 0 |
| 82 | 0xc6 | `agentSendAsset` | 0x2759821 | 0x2759831 → 0x27288c0 [..0x2728e05) | result_word_check | 0x275a182 | 0 |
| 83 | 0xc7 | `hip3LiquidatorTransfer` | 0x2759306 | 0x2759329 → 0x1e641e0 [..0x1e642dd) | join | 0x275a186 | 0 |
| 84 | 0xc8 | `l1ValidatorVoteBridgeDeposit` | 0x27592ea | 0x27592fc → 0x1e646c0 [..0x1e6488f) | join | 0x275a186 | 0 |
| 85 | 0xc9 | `authorizeAqav2Role` | 0x2759e54 | 0x2759e77 → 0x27e3750 [..0x27e3902) | join | 0x275a186 | 0 |
| 86 | 0xca | `stakingLinkDisableTradingUser` | 0x2759e9d | 0x2759eaf → 0x1e648c0 [..0x1e64aba) | join | 0x275a186 | 0 |
| 87 | 0xcb | `voteL1Hash` | 0x275a259 | 0x275a27c → 0x1e5f010 [..0x1e5f1b4) | join | 0x275a186 | 0 |

- **join** (10 arms). The callee writes the result straight to `[rsp+0x68]`; the arm then
  does `jmp 0x275a186`.
- **result_word_check** (cases 76 and 82). The callee writes to `[rsp]`, then
  `cmp word [rsp],0x186`:
  - if the word is not 0x186, `jne 0x275a136`;
  - otherwise `al = 0xd` → `0x275a182`. Case 82 sets al inline; case 76 goes through the
    trampoline `0x275a348: mov al,0xd ; jmp 0x275a182`.
- **Case 76 entry gate.** `cmp byte [r15+0x3ac9],0 ; je 0x275a34f`, and `0x275a34f` writes
  `word [rsp+0x70] = 0x8e` then `jmp 0x275a180`. So when that byte is 0 the arm skips its
  callee. Case 63 has the same shape with code 0x8d (parent packet excerpt).
- **Callee anchors.**
  - Case 76's callee has one Location: `0x56be068`, rustc `library/alloc/src/string.rs:2918:14`.
    Its other leas are the literal `a Display implementation returned an error` and a
    mid-string pointer into a cargo-registry path. These come from the generic
    `to_string`/`Display` path and say nothing specific about the action.
  - Case 80's two leas both point at `0x3c4cec`, which holds non-ASCII data (it looks like
    a local jump table).
  - The other 10 callees have no `.rodata` lea at all.
  - So the names in this packet come from the serde table, not from Location records.

## Shared tail

| entry | bytes / behaviour | branch sources in the dispatcher |
|---|---|---|
| 0x275a136 | 6 `movups` copy `[rsp,+0x60)` → `[rsp+0x70,+0x60)` (callee result as payload), falls into 0x275a180 | 8 (1 jmp, 7 jcc) |
| 0x275a180 | `mov al,0xe` | 2 jmp (0x2759a90 case 63, 0x275a356 case 76 gate) + fall-through |
| 0x275a182 | `mov [rsp+0x68],al` (result tag byte) | 9 (7 jmp, 2 jcc) |
| 0x275a186 | `cmp ebp,0x3b9aca00`. If ebp is not 1e9 (the `Option<Instant>` None niche set by the prologue), it calls `0x4ee3800(edi=1)` (clock_gettime → Instant) at 0x275a193 and `0x4ee3730` (two-Instant subtract) at 0x275a1c9. Then it copies 0x68 bytes `[rsp+0x68..0xd0)` to `*rbx` and `ret`s at 0x275a22f. | 78 jmp |

The tail bytes `0x275a136..0x275a230` have sha256 `51b254e20ebec8b2c341feef9f1f902898b4fd6d54d48e788e75bf194f494122`
(`tail.bytes_sha256` in the JSON).

## Rerun

From the repo root, as the build user:

```
python3 -B tools/exchange_dispatch_tail.py | sha256sum      # 7a914e3ae82e149c8b78a29a12c5386a2e8dfe123ca988662de4cfdc6f502844 = dispatch-tail.json
python3 -I -B research/work-items/RE-010-dispatch-cases-76-87/verify.py
python3 -O -B research/work-items/RE-010-dispatch-cases-76-87/verify.py
python3 -I -B research/work-items/RE-010-dispatch-cases-76-87/independent_verify.py   # PASS / FAIL / INCONCLUSIVE
python3 -B tools/exchange_dispatch.py | sha256sum           # negative control: bf82df7744abc508bd73bc8337d5b21af0a17eab9c64b6849137a4f58dfa5cb1, unchanged
python3 -m unittest tests.test_exchange_dispatch_tail -v
```

`independent_verify.py` imports nothing from `tools/`. It has its own ELF and RELA reader
and re-derives the arms, names, first-call and continuation bytes, joins, tail hash and
branch counts. Tests marked `requires_gnu` compare against GNU objdump and readelf; when
those tools are absent or are LLVM's, the tests SKIP.

## What this does not claim

- **The names are an index match, not a code xref.** "Case *i* is serde variant *i*" rests
  on two facts: both lists have 88 entries, and 75 of the 76 claimed cases agree up to
  case or an `Action` suffix. No code path from the dispatcher to the name tables is shown.
- **It does not explain case 68's mismatch** (`Hip3Deploy` vs `perpDeploy`). The
  disagreement is recorded, not resolved.
- **It does not decode what the callees do.** Only their address, their FDE extent and
  their `.rodata` leas are pinned. No callee is named from its own code.
- **The meanings of tag 0xd/0xe, word 0x186 and error codes 0x8d/0x8e are inferred**
  ("ok, no payload" / "error with payload" / "callee Ok niche"). The bytes are pinned; the
  meanings are not proven.
- **The `0x4ee3800` and `0x4ee3730` roles are inferred** from clock_gettime, the `< 1e9`
  nanos check and the pairwise subtract. They are not symbol-backed.
- **Branch-source counts come from a byte-pattern scan of the dispatcher range.** The GNU
  test confirms every site is an objdump instruction start with that target. Sources
  outside the dispatcher are not counted.
- **Nothing here is dynamic**: no execution, no traces, no Ghidra.
