# RE-001: node #115 JsonRpcResult dispatch and local value-conversion paths

Task RE-001; `foundation` remains a tentative allocation. Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Input/reference source: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. New prose/readers are independently authored; captured evidence retains upstream rights. No equivalent parser, Rust reconstruction, recovered source type or component closure is claimed.

| Actual FDE range, ELF VA | Bytes | Native rows |
| --- | ---: | ---: |
| Constructor `[0x1751380,0x17514d6)` | 342 | 79 |
| Caller `[0x1707010,0x17077b2)` | 1,954 | 410 |
| Completion `[0x1700a10,0x1700ac3)` | 179 | 47 |
| First alternative `[0x16fdba0,0x16fdf82)` | 994 | 245 |
| Value helper `[0x16fd8b0,0x16fdb94)` | 740 | 185 |
| Text decoder `[0x167a9c0,0x167abfb)` | 571 | 143 |
| Sequence helper `[0x173fe30,0x173ff4e)` | 286 | 82 |
| Unique total | 5,066 | 1,191 |

## Findings

The constructor tries two alternatives; the first recognizes exact six-byte `result` and distinguishes missing/repeated recognized fields. The caller additionally requires local completion-helper success. The constructor copies 104 bytes, the first alternative's observed stores cover 40, and selected value helpers visibly store 33. Complete initialized ABI and whole-input grammar remain unproved.

Selected raw byte-record tags 14/15 require length 32. Text-like tags 12/13 request 32 decoder output bytes. The text decoder's local guards require 64 ASCII hex digits, optionally preceded by exact lowercase `0x` (66 total bytes). Digits accept either case. Odd original length reaches code 1 before prefix handling; wrong remaining length reaches code 2 before alphabet scanning. Invalid-byte reporting and feature/vector conversion are delegated. The caller's one-to-four-byte raw-tag-11 text cannot reach its code-3 copy arm. These are local guards and conditional scalar arithmetic, not full JSON mapping.

The new sequence helper resolves the raw-tag-20 delegation locally. It requires 32 successful element responses with first result byte zero and second byte exactly one, copying each returned byte. Early nonzero first bytes forward an error pointer with local status 1; short/non-one responses call a helper with the successful-response count. A 33rd probe accepts byte pair (0,0), reports argument 33 for (0,nonzero), and follows cleanup-like calls before local success for (nonzero,anything), conditional on normal returns and valid memory. The outer value helper still checks remaining cursor bytes afterward. Actual element grammar and cursor/count effects are opaque in 0x16fce10. This is not proof that any real malformed input is accepted.

See [observations](observations.md), [sequence data/relocation](sequence-helper/referenced-data.json), [text data](text-decoder/referenced-data.json) and [raw-value data](value-helper/referenced-data.json). Inferred helper roles are distinct from observed byte fields and complete source contracts.

## Reproduce

From repository root with the full pinned capture materialized:

```sh
python3 -I -B research/work-items/RE-001-node115-jsonrpc-result-dispatch/verify_packet.py --binary artifacts/node/115/hl-node
```

The standard-library reader authenticates the complete target, 135,313 ordered unwind starts, supported actual CIE/FDE records and all 1,191 unique native rows. It checks selected fields, branches, calls, tables, constants and actual relocations. The new stage binds 60 selected instructions, one FDE and one relocation, rejecting 62 new evidence corruptions; cumulative total 420. Earlier controls, including 1,530 field-name mutations, remain. The retained text arithmetic checks cover 4,096 byte/lane cases, 484 hex pairs and 14 policy examples. The new 76 response scenarios are abstract opaque-helper traces. None is captured-program execution, emulation or runtime equivalence.

## Native evidence and validation

All historical native exports, qualification and receipts remain unchanged. Latest native run [41574657184](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41574657184), execution `bf0438d5b3edb2d7d7f46b86ed864e177a8fd5b4`, fully authenticates the capture, decodes the new helper and renews its byte-identical caller. One job, attempt 1; GNU objdump 2.42 version query and two static decodes capped at 45 seconds each. The 17,245-byte archive SHA-256 is `5e6abed3cc8c3e1b2b8ee7537d8cd7bc4b34bfc45a06256f2185a1aef891d1b2`.

Native analysis qualifies rootless UID/GID, zero capabilities, no-new-privileges, an isolated loopback-only namespace and read-only/noexec input bindings. No captured program, emulator, compiler or VM ran. No repository/native code ran on the Mac.

This packet is frozen before its required validation. The exact candidate commit/tree and observed current check outcomes are recorded on [PR #2127](https://github.com/lalalune/hyperliquid-source/pull/2127), allowing publication of the exact tested bytes without a metadata-only followup. [Historical validation](validation/history.json) and older qualification/validation files apply only to their immutable snapshots. The prior six-range run 41572879425 passed all 10 checks (76 modules, 382 reported cases, four optional skips), and does not establish a pass for this new stage.

## Limits and next step

Element-reader acceptance/cursor/count behavior, raw JSON/null mapping, valid record/pointer domains, text feature/vector/error helpers, sequence error construction/cleanup/exception behavior, second alternative and initialized ABI remain unresolved. Source/type ownership and runtime equivalence remain unproved. No component gate, compiled-byte comparison, Points or payment is claimed. Next: recover element reader 0x16fce10 to connect local response handling to real sequence records and outer remainder validation.
