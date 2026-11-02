# RE-001: node #115 JsonRpcResult dispatch, completion and first result field

Task RE-001; `foundation` remains a tentative research allocation. Target node #115, 105,896,032 bytes, SHA256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`; immutable source `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. No full source/type ownership, equivalent parser or component-gate completion is claimed.

## Bounded findings

| Actual FDE range, ELF VA | Bytes | Native rows |
| --- | ---: | ---: |
| Constructor `[0x1751380,0x17514d6)` |342|79|
| Caller `[0x1707010,0x17077b2)` |1,954|410|
| Completion `[0x1700a10,0x1700ac3)` |179|47|
| First alternative `[0x16fdba0,0x16fdf82)` |994|245|
| Unique total |3,469|781|

The constructor tries two alternatives and copies 104 bytes on its ordinary arm. The caller additionally requires its local completion helper to return zero. That helper consumes four whitespace bytes and a closing brace; its ordinary path does not establish an outer trailing-input rule.

The first alternative's map-like path recognizes exact six-byte `result`, tracks presence, and routes missing/repeated recognized fields separately. Four supported string-like key paths cross-check the same name; raw internal tags 1/4 also recognize zero-valued raw-key aliases. Nonmatching supported key names step to the next record; unsupported raw key types use an opaque helper. The required value is passed to opaque converter 0x16fd8b0, so null handling, complete value grammar and the second alternative remain unresolved. These internal record observations do not establish a whole JSON-RPC response schema.

[Native-grounded observations and explicit unknowns](observations.md), [evidence index](evidence.json), [first-variant tables/literals](first-variant/referenced-data.json). The new 994-byte range adds 245 unique rows. Renewed constructor/caller exports count once. The first variant visibly writes 40 ordinary output bytes; the constructor's 104-byte copy is not a fully initialized-layout proof.

## Reproduce as data

From repository root, with Python 3.12+ standard library and the authenticated full capture:

```sh
python3 -I -B research/work-items/RE-001-node115-jsonrpc-result-dispatch/verify_packet.py --binary artifacts/node/115/hl-node
```

The reader verifies the full input, all 135,313 ordered unwind starts, actual supported CIE/FDE fields and all 781 unique native rows. It cross-checks selected direct edges, the completion whitespace predicate, the first variant's 37 selected/bounded relative table entries and native boundaries, all 256 key-tag dispatch calculations and both exact six-byte comparison predicates. One baseline plus 1,530 distinct single-byte field-name mutations agree between the wide and bytewise predicates. Evidence corruption controls mutate selected instruction/table/literal/FDE records; they are not runtime parser cases. No repository import, subprocess, native decoder, network request or captured execution is launched by this reader.

## Actual native runs

- [41499013810](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41499013810): constructor/caller and original diagnostic edges.
- [41532996012](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41532996012): completion/caller and its direct call.
- [41543424275](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41543424275), execution `27e83067013d617b1f7c40073ed1689009baecfc`: first alternative/constructor and call at 0x175140e. One job, attempt 1. The 20,288-byte archive matches GitHub SHA256 `9cc6533c02b6769cda6e53f91735ae7d26c88e3a8bf716decc19c8ce4a196738`.

Every native run authenticates the complete capture and uses one GNU objdump 2.42 version query plus two 45-second static decodes under rootless/no-capability/no-new-privileges/offline/read-only-noexec input controls. Actual exports, command arguments, executable hashes and unchanged-input/per-file audits are retained in `receipts/`, `completion/` and `first-variant/`. The first variant's additional table/literal reader was added after native decode and was subsequently reproduced in the latest required-check run below. No captured executable, compiler or VM ran; no repository/native code ran on the Mac. New prose/readers are independently authored; captured evidence retains upstream rights.

Historical full-check records are indexed in [validation/history.json](validation/history.json), with immutable parent commits and the original local archives retained. They are historical results, not passes for the newly extended reader. Full required checks for this extension subsequently passed as recorded below. All incomplete gates remain false; no Points or payment is claimed.

## Latest required checks

All eight commands passed. The unchanged test runner completed **76 files**, reporting **382 cases**, **4 skips** and **zero failed files**.

[Run 41544793824](https://github.com/clutchpbcfo/hyperliquid-source/actions/runs/41544793824), execution `055c4cbcfb0643376a33cbab1d05aad137e4874a`, checked the immutable source plus the frozen 60-file packet. One job, attempt 1; 25-minute overall cap, 21-minute analysis deadline and 18-minute test sublimit, no retry. The previous unchanged suite took 833.664 seconds; only the owned driver's bounded time allowances changed, with all source tests, inputs and qualification requirements preserved.

| Command | Exit | Timed out | Seconds |
| --- | ---: | --- | ---: |
| `catalogue-generate` | 0 | False | 0.967 |
| `packet-full-input` | 0 | False | 4.976 |
| `doctor` | 0 | False | 0.265 |
| `verify` | 0 | False | 0.666 |
| `catalogue-check` | 0 | False | 0.966 |
| `reproduce` | 0 | False | 7.082 |
| `test` | 0 | False | 831.255 |
| `verify-after-test` | 0 | False | 0.615 |

The extended stdlib reader reproduced 781 unique native rows and 158 evidence-corruption cases under Python 3.12.3, matching the local reader output except Python version. UID/GID 65534, no supplementary groups/capabilities, no-new-privileges, a distinct loopback-only namespace, sealed read-only/noexec original inputs, writable disposable test copy and absent compiler/emulator opt-ins were qualified. Hard-link and executable-marker fixtures remained in disposable scratch. Input hashes and strict reference pins matched afterward. [Actual audit/skips](validation/required-audit.json), [qualification](qualification/required-validation.json).

GitHub's archive size/digest and all receipt files were independently checked. The final 67-file packet adds seven actual receipt records and updates status/prose/evidence metadata after the frozen run. Reader, field bindings, core observations, referenced data and native exports are unchanged. Earlier validation receipts are indexed in `validation/history.json` and preserved in immutable parent commits and local original archives. Normal PR CI was suppressed with skip-ci under the two-job batch budget and is not claimed as run. No component gate, source/import pin or comparison metric changed.

Next: close the opaque value-converter contract or second alternative after maintainer review. Complete value/schema, outer parser, ABI/initialization and exception behavior remain unproved.
