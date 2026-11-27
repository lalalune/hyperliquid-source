# RE-010: crosswalk the node #115 Action decoder and router direct callers

This packet inventories direct `E8 rel32` references to four linked addresses around Action parsing and execution. It answers a narrower question than the runtime handoff: which FDEs directly call the Action decoder and the 92-arm router, and whether any one caller FDE contains direct calls to both. It does **not** establish that a decoded object reaches the router.

- Component: `action-dispatch` (RE-010).
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base commit: `ec87b0e812f363a43abaa26e6c9c4c808bf9a285`.
- Tooling: Python 3.14.3; GNU objdump 2.47.20260726 for manual inspection of the discovered sites.
- Claim status: exact direct-call byte and indexed FDE observations. Labels for types/call roles reuse prior packets and remain qualified as inferences.
- Captured binaries were not executed; no network, signing, or chain actions were performed.

## Reproduce

```sh
python3 tools/action_dispatch_callsite_graph_115.py
python3 -m unittest tests.test_action_dispatch_callsite_graph_115
(cd research/work-items/action-dispatch-callsite-graph-115 && shasum -a 256 -c MANIFEST.sha256)
```

The generator authenticates the full artifact digest, scans executable `.text` for `E8 rel32` call encodings to the four pinned targets, checks each displacement, verifies the call-site FDE against the unwind index, and compares the complete result with the inspected call-site list. It emits linked ELF virtual addresses and file offsets. The scan is deliberately limited to direct relative calls; it does not enumerate indirect calls, tail jumps, or dataflow through memory.

## Evidence

Targets are the `Action` decoder at `0x2b817d0`, 92-arm action router at `0x2bda7c0`, outer action-envelope parser at `0x20f00b0`, and nested parser at `0x2109050`. `call-sites.tsv` retains each five-byte instruction and the containing FDE.

The complete direct-call scan reports:

- Two calls to decoder `0x2b817d0`, at `0x20f06d3` and `0x20f0a29`, both inside FDE `0x20f00b0..0x20f128a`.
- Two calls to envelope parser `0x20f00b0`, at `0x2109697` and `0x2109e11`, both inside FDE `0x2109050..0x210a4bb`.
- Two calls to nested parser `0x2109050`, at `0x2b83af5` in FDE `0x2b817d0..0x2b84365`, and at `0x2bd5a97` in FDE `0x2bd34f0..0x2bd6066`.
- Five calls to router `0x2bda7c0`, at `0x2704c0c`, `0x2704c54`, `0x2c69574`, `0x2c69744`, and `0x2c719c3`. These occur in FDEs `0x27048a0..0x2704e4f`, `0x2c69220..0x2c69793`, and `0x2c71250..0x2c71ea5`.

No FDE in the enumerated direct-call census contains both a direct call to `0x2b817d0` and a direct call to `0x2bda7c0`. The recursive parser relationship is consistent with nested Action decoding; it does not connect a returned decoder object to a router argument. A separate packet records the `setDisplayName` decoder's selected tag and object layout, and the router packet records its tag dispatch; equal tags alone do not establish pointer identity or runtime transfer.

## Limits and next question

This evidence is a call-site/FDE crosswalk, not a proof that the parser and router are unrelated. An object may cross functions, queues, or serialization boundaries, and indirect transfers are outside this scan. The router's caller argument provenance is not closed for every site. The exact producer-to-consumer path remains **unverified**.

Next: trace one concrete caller's input object through any intervening storage or copy boundary into a router argument, retaining both producer and consumer bytes; if no bounded static path exists, preserve that negative result and the unresolved indirect edges without claiming runtime identity.
