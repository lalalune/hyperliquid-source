# RE-001: node #115 RPC throttle expiry and diagnostic collection

- Component: consensus RPC throttle; preparatory static research under RE-001.
- Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
- Target: `artifacts/node/115/hl-node`, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Coordinates: ELF virtual addresses, interval ends exclusive.
- Evidence: owner `0x2e098e0..0x2e11140`, flat prune `0x24c1e90..0x24c26cc`, tree extraction `0x239be50..0x239c25a`, duration context `0x15ed960..0x15edb81`; 34,503 bytes across four complete FDEs. Most of the owner and generic duration helper remain context, not new reconstruction claims. Gates remain false.

## Finding

The throttle map at owner `+0x2e0` is pruned after an opaque cadence helper permits the pass. Both the flat and tree representations use the same policy: remove a row only when the supplied current triple is **strictly later** than its helper-derived deadline. The row is retained at exact equality. A separate raw flag controls inclusion in a diagnostic list, not whether the expired row is removed.

The deadline path passes binary64 `30.0` to the existing duration helper. Constant propagation through its positive integral route yields 30 seconds and zero nanoseconds. The native date-addition/reconstruction helpers then combine this with the stored timestamp. If their validity checks fail, the comparison uses the static triple `(0x7fffd6de, 86399, 999999999)`. This is the same date-helper family used in prior work; its general calendar arithmetic is not newly claimed.

The comparison is lexicographic. The first 32-bit word is **signed**; the second and third are **unsigned**. Removal therefore requires the first differing word to be greater under its respective comparison, or, when the first two words match, a strictly greater third word. It is not an inclusive deadline test.

| Row outcome | Retained in map | Added to diagnostic list |
| --- | --- | --- |
| Current triple before deadline | Yes | No |
| Exact deadline equality | Yes | No |
| Expired, raw flag 0 | No | No |
| Expired, raw flag 1 | No | Yes |

Flat rows have stride `0x60`, timestamp at `+0x40`, and flag at `+0x58`. Both the first-expired-row path and the remaining-row pass use identical predicates. Retained rows are compacted into their original order, the retained count is published at descriptor `+0x18`, and cleanup is requested for removed payloads. The diagnostic entry consists of the row's first 32 bytes plus its qword at `+0x20`, for a 40-byte output stride.

The tree uses 64-byte value slots. Timestamp and flag are at value `+0x20` and `+0x38`; the corresponding 32-byte key is in the separate key array at node `+0x2c0 + index*0x20`. For an expired value, flag exactly 1 appends the key and value qword `+0` to the same diagnostic list. The shared count is decremented before invoking the opaque removal/repair helper. A non-expired row advances traversal without decrement. End of traversal writes output byte `+0x58 = 2`; the caller consumes removed rows until that marker.

The caller exposes the collected list with the exact 27-byte label `Pruned rpc request throttle` and later frees its allocation. This packet does not rename the list as retries or notifications: no such downstream effect is established. The caller's representation down-conversion and generic tree repair are supporting context, not newly claimed container algorithms.

## Limits

Valid map structures, extents and boolean stored flags are assumed for full traversal. Raw flags 2..255 are used only to distinguish the local exact-equality diagnostic test; in particular the tree result's byte 2 is also its terminal marker, so those probes do not prove acceptance of malformed rows. Date helpers and fallback bounds are authenticated call/data bindings but are not a complete proof of calendar behavior. Opaque cadence duration, cleanup side effects, exceptions, concurrency and complete consensus behavior remain unresolved.

The relations cover 46,656 mixed-width comparisons, 1,280 local flag/deadline decisions and 256 ordered four-row collections. Actual instruction changes distinguish signed versus unsigned date ordering, equality retention versus equality expiry, and diagnostic flag 1 versus 2. No captured code is executed or emulated.

## Evidence and controls

`verify.py` checks the full target digest first, authenticates the FDE extent and body digest, and compares every decoded instruction byte and boundary in independently produced GNU and LLVM exports. It binds selected instruction obligations, RIP-relative constants, source Locations, RELATIVE data/call slots and applicable dynamic imports. Its incoming reference census qualifies E8 and RIP-relative FF15/FF25 instructions using complete FDE decoding; register and vtable dispatch remain outside that census.

`controls.json` records mutations tested after deliberately bypassing the whole-image, body-hash and saved-export guards. The deeper instruction, literal, relocation, import and unwind checks must reject them. Separate tests exercise the outer guards. `relations.py` reads actual instruction operands and checks independent algebraic statements for the selected policy. Three changed-operand counterfactuals must change a witness result. These relations are **not execution or emulation of captured instructions** and do not prove runtime equivalence.

## Reproduce

Materialize the repository's pinned artifacts, submodules and research LFS inputs first. The validation environment uses Python 3.14, Capstone 5.0.7, pytest 9.0.2, GNU binutils and LLVM; actual results and tool versions are retained in `validation.json` and logs.

```sh
python3 research/work-items/RE-001-node115-rpc-throttle-expiry/export_disassembly.py
python3 research/work-items/RE-001-node115-rpc-throttle-expiry/verify.py --controls
python3 research/work-items/RE-001-node115-rpc-throttle-expiry/relations.py
python3 -m unittest discover -s tests -p 'test_node115_rpc_throttle_expiry.py' -v
shasum -a 256 -c research/work-items/RE-001-node115-rpc-throttle-expiry/MANIFEST.sha256
make doctor verify test catalogue-check reproduce
```

The verifier and relation checker accept `--write` to regenerate their retained JSON. No captured binary was executed or emulated. No live-node calls, signing, chain actions, imported code changes or new Rust implementation are included.

## Scope and authorship

The scoped all-state audit and census are retained with the packet. [PR #951](https://github.com/lalalune/hyperliquid-source/pull/951) leaves throttle pruning and sent-flag lifetime unread. [PR #1647](https://github.com/lalalune/hyperliquid-source/pull/1647) covers registration/reason and inclusive send-deadline behavior while excluding pruning/reset. This packet closes the separate strict expiry and conditional diagnostic-collection policy. [PR #1176](https://github.com/lalalune/hyperliquid-source/pull/1176) already owns the surrounding heartbeat lag gate, which is only context here.

Date-helper context is credited to [#2117](https://github.com/lalalune/hyperliquid-source/pull/2117), [#2167](https://github.com/lalalune/hyperliquid-source/pull/2167) and [#2624](https://github.com/lalalune/hyperliquid-source/pull/2624). [PR #2890](https://github.com/lalalune/hyperliquid-source/pull/2890) uses the same fallback triple in a different stake-count deadline question. None is being re-claimed as a new conversion primitive.

GPT-6.1 Terra inspected open and closed PR metadata and available file evidence, including older-release analogues. Missing API patches, a capped historical file list and unavailable historical PRs limit the negative search. New analysis and relations are independently authored under MIT; ELF/export/corruption scaffolding adapts existing MIT research packets. No unlicensed inferred source is copied, no input rights are changed, and no full component, source-equivalence or hosted-CI success is claimed.

The final audit also retains 32 previously observed PRs that were absent from the refreshed listing (sampled direct requests returned HTTP 404). Historical citations may therefore be unavailable now; their earlier observed scope remains an overlap exclusion. No reason for the disappearance is inferred.
