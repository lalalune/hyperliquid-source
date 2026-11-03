# RE-001: node #115 JsonRpcResult dispatch and result-value paths

Task RE-001; `foundation` remains a tentative research allocation. Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Captured-input/reference source remains `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. New prose/readers are independently authored; captured evidence retains upstream rights. Source/type identity, an equivalent parser, Rust implementation and component completion remain unproved.

| Actual FDE range, ELF VA | Bytes | Native rows |
| --- | ---: | ---: |
| Constructor `[0x1751380,0x17514d6)` | 342 | 79 |
| Caller `[0x1707010,0x17077b2)` | 1,954 | 410 |
| Completion `[0x1700a10,0x1700ac3)` | 179 | 47 |
| First alternative `[0x16fdba0,0x16fdf82)` | 994 | 245 |
| Value helper `[0x16fd8b0,0x16fdb94)` | 740 | 185 |
| Text decoder `[0x167a9c0,0x167abfb)` | 571 | 143 |
| Unique total | 4,780 | 1,109 |

The constructor tries two alternatives and copies 104 bytes on its ordinary arm. The caller additionally requires a local completion helper to return zero. Its whitespace/closing-brace path does not establish a whole-input trailing-data rule. The first alternative recognizes exact six-byte `result`, tracks presence and treats missing/repeated recognized fields separately.

The new helper narrows the result-value gap. Selected raw byte-record tags 14/15 require length 32 and visibly store 32 payload bytes plus zero status. Text-like tags 12/13 and scalar-to-text tag 11 request 32 output bytes from a shared decoder; returned code 3 selects their local copy arm. Tag 20 delegates sequence conversion and checks remaining records only after returned status 0. Sixteen other selected tags prepare diagnostic records and reach a local error result. These are raw-record observations; complete JSON/schema behavior and source-type identity remain open. See [observations](observations.md) and [selected data/relocations](value-helper/referenced-data.json).

## Reproduce as data

From repository root with the full pinned capture materialized:

```sh
python3 -I -B research/work-items/RE-001-node115-jsonrpc-result-dispatch/verify_packet.py --binary artifacts/node/115/hl-node
```

The standard-library reader authenticates the full image, all 135,313 ordered unwind starts, supported actual CIE/FDE records and all 1,109 unique native rows. It checks prior diagnostic/field/completion evidence, selected direct edges, instruction boundaries, 37 prior table entries and 22 new value-table entries, three new RELATIVE bindings and three unidentified descriptor spans.

New evidence controls mutate 74 selected helper instructions, 22 table entries, three relocation records, three descriptor records and one helper FDE extent: 103 new checks, alongside 158 historical-stage checks. The 1,530 field-name byte mutations remain. These are static evidence controls, not captured parser execution. Direct/text helper stores cover 33 bytes; first-alternative stores cover 40; the constructor later copies 104. Complete initialized layout is unproved.

## Observed native runs

- [41499013810](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41499013810): constructor/caller and diagnostic edges.
- [41532996012](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41532996012): completion/caller.
- [41543424275](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41543424275): first alternative/constructor.
- [41563843042](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41563843042), execution `f2dc73ffabe940c8103c463f10c56a1f7e31675d`: value helper and renewed first alternative. One job, attempt 1, three native invocations: a GNU objdump 2.42 version query and two static decodes capped at 45 seconds each. The 23,540-byte receipt archive matches GitHub SHA-256 `3917144395e29476a4d08bb3707cdbab79000d434a7b99742c188d25852fe34c`.

Native jobs authenticate the complete capture and qualify rootless execution, zero capabilities, no-new-privileges, an isolated loopback-only namespace and read-only/noexec inputs. Native bytes, command arguments, tool hashes, unchanged-input audits and qualified edges are retained. Renewed ranges count once. No captured program, emulator, compiler or VM ran; no repository/native code ran on the Mac.

## Repository validation and limits

The exact candidate commit and current observed required-check results are recorded in [PR #2127](https://github.com/lalalune/hyperliquid-source/pull/2127). This packet is frozen before that validation so publication can preserve the exact tested data. [Historical records](validation/history.json), `qualification/required-validation.json` and `validation/required-*.json` belong to earlier snapshots. They do not establish current passes. Original receipts and negative results remain preserved.

The latest historical four-range run, 41544793824, passed eight commands: 76 test files, 382 reported cases, four skips and zero failed files. Its immutable published packet is `01d91ad7058a586abd33bb280f2d3e4d7f2f2cd5`. It is not validation of the new helper reader.

The shared decoder’s invalid-byte, feature and vector helpers, sequence helper `0x173fe30`, raw JSON/null mapping, complete tag domain, source/type identity, second alternative, initialized ABI and exception semantics remain open. No component gate or compiled-comparison metric advances; no Points or payment is claimed.


## Fixed-size text findings

The new 571-byte / 143-row decoder resolves local text guards for the existing 32-byte request: 64 ASCII hex digits with optional exact lowercase `0x` prefix (66 total bytes). Hex digits accept either case. Odd original length produces code 1 before prefix handling; wrong remaining length produces code 2 before alphabet scanning. Other bytes delegate to an unresolved invalid-byte helper. The caller’s one-to-four-byte raw-tag-11 text cannot reach its local code-3 copy arm.

The new stage adds 87 selected instruction bindings and 97 evidence-corruption controls, bringing the cumulative total to 358. Five vector constants and the complete nibble table agree over 4,096 static byte/lane cases. Scalar nibble arithmetic agrees on 484 accepted character pairs. Fourteen static policy examples check local length/prefix/error precedence. These are data and arithmetic checks, not target execution. Runtime CPU-feature initialization and vector output remain delegated; code 3 after that call is conditional on its normal return. See the latest chapter of [observations](observations.md) and [bound data](text-decoder/referenced-data.json).

Native run [41571968425](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41571968425), execution `ecd4b9cef519055e13e7c843761e2b0a23388cdd`, authenticated the complete capture and renewed the byte-identical value helper. Its 20,254-byte archive SHA-256 is `05bb338d6c4b71e9d0e2652b402bc37c8d7fc8b025d95145eef35870edc15a3d`. All prior receipts remain unchanged. The six-range candidate is frozen before its required validation, whose exact commit/tree and actual outcomes are recorded on PR #2127. Historical validation does not assert a pass for this addition. Full-schema and component gates remain false.
