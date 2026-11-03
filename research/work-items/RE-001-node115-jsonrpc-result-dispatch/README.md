# RE-001: node #115 JsonRpcResult and local value/element paths

Task RE-001; `foundation` remains a tentative research allocation. Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source/input revision: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. New code/prose is independently authored; captured evidence retains upstream rights. This is partial static research, not a reconstructed parser, Rust implementation, source type or completed component.

| Actual FDE range, ELF VA | Bytes | Native rows |
| --- | ---: | ---: |
| Constructor `[0x1751380,0x17514d6)` | 342 | 79 |
| Caller `[0x1707010,0x17077b2)` | 1954 | 410 |
| Completion `[0x1700a10,0x1700ac3)` | 179 | 47 |
| First alternative `[0x16fdba0,0x16fdf82)` | 994 | 245 |
| Value helper `[0x16fd8b0,0x16fdb94)` | 740 | 185 |
| Text decoder `[0x167a9c0,0x167abfb)` | 571 | 143 |
| Sequence helper `[0x173fe30,0x173ff4e)` | 286 | 82 |
| Element reader `[0x16fce10,0x16fcf18)` | 264 | 73 |
| Unique total | 5330 | 1264 |

## Findings

The constructor tries two alternatives. The first recognizes exact six-byte `result`, tracks presence and distinguishes missing/repeated fields. The caller additionally requires local completion-helper success. Selected raw byte-record tags require exactly 32 bytes; text-like forms request 32 decoded bytes, with local guards for 64 hex digits and optional exact lowercase `0x`. Digit case is unrestricted locally. Odd original length and wrong remaining length have distinct raw codes. Text error/feature/vector helpers remain delegated. Raw-tag-11 one-to-four-byte text cannot satisfy the 32-byte output request.

The raw-tag-20 sequence path collects 32 successful element responses and probes a 33rd. Early errors are forwarded; the boundary error path follows cleanup-like calls before conditional local success. The caller then checks remaining cursor bytes. The new leaf reader establishes actual local record rules: empty returns an end marker without mutation; nonempty advances one 32-byte record, checks/increments a u64 counter, then selects eight numeric tags. Signed/unsigned 8/16/32/64-bit payloads return a byte only for values in 0..255. Other values/tags delegate to error helpers after consumption. Cursor advance precedes the overflow edge.

Normal element byte/end paths make no opaque calls. Their output stores fit result offsets 0..2 of the caller's 16-byte response area, and header stores touch only current/count fields. This closes ordinary local store framing under valid nonaliasing memory. Error/default/overflow and cleanup memory effects/returns remain unproved. Conditional raw-record traces connect the earlier boundary-response observation to cursor/count state, but do not establish serialized JSON/wire reachability, accepted malformed input or security impact.

See the latest chapter in [observations](observations.md) for the numeric-tag table, output/write offsets and remaining premises. [Element data](element-reader/referenced-data.json) pins all eight dispatch entries, two actual relocations and two unidentified descriptor spans. Role names are inferences, distinct from raw observations and source/type claims.

## Reproduce and controls

From repository root with the complete pinned capture:

```sh
python3 -I -B research/work-items/RE-001-node115-jsonrpc-result-dispatch/verify_packet.py --binary artifacts/node/115/hl-node
```

The standard-library reader reauthenticates the complete image, all 135,313 ordered unwind starts, supported actual CIE/FDE records and all 1,264 unique native rows. The new stage checks 48 selected instructions, one FDE, eight table entries, two relocation records and two descriptor spans: 61 new evidence corruptions, 481 cumulative. All earlier controls and 1,530 field-name mutations remain.

New static checks cover all 256 tag bytes, 131,584 8-/16-bit raw payload patterns, 48 selected wider boundaries, 23 cursor/frame cases and 41 conditional composed raw-record traces. Retained text arithmetic and response-only scenarios remain explicitly scoped. These are data/predicate models, not captured execution, instruction emulation, end-to-end parsing or runtime equivalence.

## Native evidence and required validation

All prior packet paths and receipts are preserved. Latest native run [41671774824](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41671774824), execution `a0dad085cec1e39de53c1c08ca69909b62ae5c73`, reauthenticates the full capture, decodes the new leaf and renews the byte-identical sequence helper. One job/attempt 1, a GNU objdump 2.42 version query and two static decodes capped at 45 seconds each. The 13,158-byte archive SHA-256 is `d2adf7d3865c7c3f54f05423fcc8f8ab29a73cb0bccb270ee74e304e7df465c6`.

Native analysis qualifies rootless UID/GID, zero capabilities, no-new-privileges, isolated-loopback networking and read-only/noexec inputs. No captured program/emulator, compiler or VM ran; no repository/native code ran on the Mac.

This packet is frozen before current required validation. Exact candidate commit/tree and actual current check outcomes are recorded on [PR #2127](https://github.com/lalalune/hyperliquid-source/pull/2127), preserving identical tested/published bytes without a metadata-only followup. [Historical validation](validation/history.json) applies only to its immutable snapshots; prior seven-range run 41575688334 passed 10 checks (76 modules, 382 reported cases, four optional skips), not this addition.

## Limits and next step

Serialized JSON/null mapping and valid raw/pointer domains, error/default/overflow helpers, cleanup and text feature/vector/error contracts, initialized ABI, second alternative, source/type ownership, exception closure and runtime equivalence remain unresolved. No component gate, compiled comparison, Points or payment is claimed. Next: resolve the remaining constructor alternative/initialized-result layout or the error-construction boundary with new bounded evidence after feedback/overlap checks.
