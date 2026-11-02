# RE-001: node #115 JsonRpcResult dispatch and local completion

Task RE-001; `foundation` is a tentative research allocation, not proven source/type ownership. This independently authored packet maps the diagnostic-associated constructor, one caller, and its local completion helper in node #115. All incomplete component gates remain false.

Target: 105,896,032-byte node #115, SHA256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Source `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.

## Result and bounds

| Actual FDE range, ELF VA | Bytes | Retained instruction rows |
| --- | ---: | ---: |
| Constructor `[0x1751380,0x17514d6)` | 342 | 79 |
| Caller `[0x1707010,0x17077b2)` | 1,954 | 410 |
| Completion helper `[0x1700a10,0x1700ac3)` | 179 | 47 |
| Unique retained total | 2,475 | 536 |

The constructor tries two opaque alternatives in order, associates their sentinel path with the exact JsonRpcResult diagnostic, and copies 104 local bytes on its ordinary arm. The completion helper consumes whitespace bytes 9,10,13,32 and a closing `}` before returning zero; EOF, comma and other-byte paths pass raw tags 3,21,22 to an opaque error helper. A zero-cursor guard reaches an unresolved indirect call. The closing-brace path itself checks no trailing-input exhaustion. The caller requires its staged value to be non-sentinel and the completion result to be zero before its 104-byte output stores. These are static local contracts, not recovered field schemas or whole-input acceptance.

[Detailed observations, inferences and unknowns](observations.md), [machine-readable evidence](evidence.json), [original FDE records](candidates.json), [completion FDE records](completion/candidates.json). The 410 caller rows were independently renewed without differences and count once. FDE bounds are not complete CFG/exception closure.

## Reproduce as data

From repository root with Python 3.12+ standard library and the authenticated full input:

```sh
python3 -I -B research/work-items/RE-001-node115-jsonrpc-result-dispatch/verify_packet.py --binary artifacts/node/115/hl-node
```

The reader authenticates the complete input, all 135,313 ordered unwind-header rows, supported actual CIE/FDE fields, all 536 unique native instruction rows and selected evidence-field corruptions. It independently resolves the helper call's rel32 displacement, checks every direct conditional-branch target in the helper, and enumerates all 256 values for the local whitespace mask. Controls mutate evidence fields and FDE extents; they are not runtime parser inputs. No subprocess, repository import, network request, native decoder or captured program is launched by this reader.

## Actual hosted evidence

[Original native run 41499013810](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41499013810) binds constructor/caller data and the diagnostic/incoming-call instruction boundaries. [Follow-up native run 41532996012](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41532996012), execution `07da73ed0221822dbeaa8f78f1b3c5ad9b0065de`, authenticates the complete capture, decodes helper/caller ranges and qualifies the helper call at `0x17073f9`. It passed as one job, attempt 1, in 37 seconds under a 12-minute ceiling. Each job uses one GNU objdump 2.42 version query and two exact static decodes with `-D -z -b binary -m i386:x86-64 -M intel --insn-width=16 --adjust-vma=<ELF-VA>`.

Both jobs qualified UID/GID 65534, empty supplementary groups, zero capabilities, no-new-privileges, distinct loopback-only network namespaces, sealed read-only/noexec inputs and EROFS write controls before native analysis; payload/capture hashes remained unchanged. Actual stdout/stderr and per-file audits remain in `receipts/`, `artifact-audit.json`, `completion/receipts/` and `completion/artifact-audit.json`. The follow-up 24,828-byte archive matches GitHub's SHA256 `2f43de45dbee1def7fcb2c58856d5c2918013ab6da56c678fd0258c7c7529ec7`. No captured executable, compiler or VM ran. New readers/prose are independently authored; captured evidence retains upstream rights.

The prior required-check run 41510269507 applies to the earlier two-range packet. Its records remain under `validation/baseline/` and `qualification/baseline-required-validation.json` as history. The extended packet was subsequently validated in the required-check run below; no earlier test result was transferred to the new reader.

## Required validation of the extension

All eight frozen commands passed. The unchanged runner completed **76 files**, reporting **382 cases** and **4 skips**, with **zero failed files**.

[Run 41533803927](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41533803927), execution `d5fbf0829bb5484d79c14f50a0a31fd593c80895`, checked immutable source `8fd8db680ec4bfef40996e5616bce3d5156d0b86` plus the frozen 48-file extended packet. One job, attempt 1, 25-minute ceiling; test command up to 15 minutes; no retry.

| Command | Exit | Timed out | Seconds |
| --- | ---: | --- | ---: |
| `catalogue-generate` | 0 | False | 0.967 |
| `packet-full-input` | 0 | False | 3.373 |
| `doctor` | 0 | False | 0.214 |
| `verify` | 0 | False | 0.615 |
| `catalogue-check` | 0 | False | 0.966 |
| `reproduce` | 0 | False | 6.979 |
| `test` | 0 | False | 833.664 |
| `verify-after-test` | 0 | False | 0.615 |

The packet reader reproduced all 536 unique rows and 61 evidence corruptions under Python 3.12.3, matching local data replay except Python version. The unchanged source tests ran rootless, capability-free and offline in a disposable writable copy; sealed original inputs remained read-only/noexec. Hard-link and executable-marker fixtures were allowed in disposable scratch. Compiler/emulator paths and captured-emulation opt-ins were absent. Both source/input snapshots and strict reference pins were checked afterward. Actual skip reasons, tool identities and per-module results remain in [the audit](validation/required-audit.json) and [qualification](qualification/required-validation.json).

GitHub's archive digest and every receipt hash/size matched. The final 55-file packet adds seven actual receipt data records and updates status/prose/evidence metadata after the frozen run. The checked reader, field bindings, core observations and native exports are unchanged. No completion gate or comparator metric changes. Ordinary upstream PR CI was suppressed with `[skip ci]` under this batch's two controlled-job budget and is not claimed as run.

## Remaining gaps

The alternative field schemas, fully qualified source ownership, error-helper semantics, indirect slot, outer trailing-data validation, all callers and exception paths remain unresolved. No initial depth budget from #94 is transferred. No Rust implementation, target equivalence, captured execution, completion-gate change, Points or payment is claimed. Next research question: establish one alternative's actual field requirements on #115 after maintainer review.
