# RE-008: first latency-EMA query wrapper argument handoff

- Component: consensus; bounded #115 static helper-closure question.
- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `a8616af9432b8d8517b2af677880e117b7c28ef3`; no reference source was consulted.
- Coordinates: linked ELF VAs, exclusive end; actual FDE `0xfc4c68` covers `[0x5a722f0,0x5a72356)` (102 bytes). Body SHA-256: `074771f3a83db1ec44b2d199db29ed86f92181397dc97acec510d27dd0da5d52`.
- Claim: observed registers, stack context and call targets only. No behavior of the callees is established.

## Gap and observation

The integrated `RE-001-node115-rpc-throttle-expiry` records call slot `0x64e8710` with target `0x5a722f0` but leaves that callee as owner context. Open PR #6782 binds the preceding conditional stack copy and notes this first call may change the input before the next query. This packet closes the wrapper's **direct argument handoff**; it neither repeats the prior copy nor credits the later query.

The target saves incoming RSI in RBX and incoming RDI in R14. It passes a temporary output pointer at its local `rsp+0x34` through relocated slot `0x64e0990` to `0x1629690`. The integrated `RE-012-time-producer-115` already studies that time producer; this packet credits its result and adds only this caller's output-pointer binding. The incoming RSI is still live at this first call, so no immutability claim follows. The wrapper then constructs a five-word context at its local `rsp+0x8`: temporary output pointer, original input pointer, and owner-relative pointers `+0x188`, `+0x148`, `+0x168`. It calls `0x4de2150` with RDI at owner `+0x108` and RSI pointing at that context. The selected body then returns without inspecting a result. All 102 body bytes, the FDE and the relocation are checked against the authenticated image; no normalization is used.

The names “owner” and “query” are contextual labels from the caller packets. The 102-byte wrapper proves argument construction, not the helper contracts, writes, return value, buffer preservation or runtime reachability. Callee-saved R14/RBX behavior follows the x86-64 calling convention; the helper bodies need separate validation.

## Reproduce

From the repository root with the pinned artifact present:

```sh
python3 research/work-items/RE-008-node115-ema-first-query-wrapper/verify.py
```

The standard-library verifier uses the repository ELF/FDE readers, authenticates the full digest before parsing, checks the actual FDE and 102/102 body bytes, decodes the selected indirect and direct calls, and verifies the RELATIVE slot. Five local byte mutations are rejected after bypassing the full-image digest guard. `result.json` records the output. Static discovery used GNU objdump/readelf 2.47.20260726. No captured binary is loaded, executed or emulated. Imported binary bytes retain upstream rights; new work follows the root MIT license.

Local results on macOS arm64 with Python 3.14.3: the verifier passed (102/102 bytes, 5/5 controls); `make doctor` passed with the installed GNU binutils exposed through an ignored `work/bin` PATH; `make verify` passed after materialising the pinned submodules (3,728 manifests, 29,756 entries); `make reproduce` and `make catalogue-check` passed. `make test` was stopped after 25 seconds at file 11/1397, so no full-suite pass is claimed. Hosted CI was not observed here.

## Limits and next question

No Rust implementation, complete `0x4de2150` semantics, source-built node, function-coverage denominator, progress gate, network behavior or target equivalence is claimed. Next: determine whether `0x4de2150` reads or writes through the input pointer in context word 1 on the selected container arm, and connect the already studied time output to this wrapper's context.
