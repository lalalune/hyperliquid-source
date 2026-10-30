# RE-001: HTTP factory result discrimination and timeout stores

- Component: foundation/network-client support. Bounded question: which raw
  builder-result word admits continuation, and what timeout state is then stored?
- Target: node #94 SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Baseline: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Reference pin: `999556f6e0a474b8312db96ec3149e1c44e97c23`;
  `base/http_client.rs:8-10` provides a seed and an unverified TLS-builder label.
  No inferred implementation is copied or treated as ground truth.
- Status: static observations; no production defect, Rust implementation,
  effective network timeout, full type recovery or progress gate claimed.

## Reproduce

From repository root, CPython 3.12.14 on Windows:

```sh
python tools/http_client_init_static.py --out work/http-client-factory-94.json
python -m unittest discover -s tests -p test_http_client_init_static.py -v
python research/work-items/RE-001-http-client-factory-94/export_disassembly.py
```

The verifier/tests use the standard library. Only the optional decoder export
requires Capstone 5.0.6 (x86-64, Intel syntax). The inspected Windows wheel was
`capstone-5.0.6-py3-none-win_amd64.whl`, SHA-256
`761c3deae00b22ac697081cdae1383bb90659dd0d79387a09cf5bdbb22b17064`.
The source identity is checked before structural analysis. No captured code,
network request or TLS connection is executed.

## Evidence

Coordinates are ELF VAs, not guessed runtime addresses. Parsed FDE range:
`[0x1439010,0x143940b)`; file offset `0x1438010`; 1,019 bytes. Body SHA-256:
`40e00039073ad06301362c8852215468d94fe1cf85a6497732b44b54020d96e0`.
`window.capstone.txt` retains the original FDE/CIE bytes and **all 180 instructions**,
consuming the complete range contiguously. The independent existing
`evm_amount_scale.Fdes.range_of` reader returned the same interval during
investigation. GNU binutils/Ghidra were not available for another export.

| Site | Established caller-side fact |
| --- | --- |
| `0x14390e9` | R14 is loaded with `0x8000000000000000`. |
| `0x143913a` | Direct call to `0x3cd75e0`, with output storage at stack `+0x10`. Its internal TLS/result semantics remain outside the claim. |
| `0x143913f`, `0x1439144` | Load that first output qword into R15 and add 6 to R14. |
| `0x1439152`, `0x1439155` | Compare R15/R14; JNE selects `0x1439331`. The ordinary continuation therefore requires the raw word `0x8000000000000006`, not an assumed 0/1 enum tag. |
| `0x1439275` | Direct call to `0x14ee540` before the final timeout stores; its construction behavior is not reimplemented here. |
| `0x143927a..0x1439292` | Store binary64 bits `0x4024000000000000` (10.0) to output `+0xb8`, and byte 1 to output `+0xc0`. This agrees with the reference's raw default fields. |
| `0x1439367..0x143938f` | The error arm prepares the 43-byte Result::unwrap diagnostic, source Location and formatter state, then calls slot `0x576e048` (RELATIVE target `0x157aa10`). A preceding drop helper must return to reach this call. |
| Location `0x566a150` | RELATIVE target `0x1eb91c`, path `/home/ubuntu/hl/code_Mainnet/base/src/http_client.rs`, line 24, column 67. |

The pointer supplied to the final constructor and the raw timeout fields do
not prove a complete `HttpClient` Rust layout. In particular, an f64 10.0 store
alone does not prove seconds or an effective request/body/connect deadline.
Those consumer paths need separate evidence. The source's TLS label remains
inference; no certificate validation policy is inferred from these bytes.

This is separate from #211's gossip RPC duration/retry records: those producers
and request futures are different functions. The default production context,
MCP pipe and host output-byte questions are also outside this packet.

## Controls and checks

`records.json` is regenerated from the real capture. `controls.txt` records six
passing test methods: original record; result-word/branch changes; timeout
value/offset/tag changes; actual message/FDE changes; source/panic RELATIVE
retargets; helper-call and whole-input identity rejection. These alter actual
captured bytes, not mocked parser responses or a new imagined network API.
No runtime comparison masks or target execution are used.

The Makefile's Python commands were invoked directly (GNU make unavailable):

- Full suite: 363 tests, 110.685 seconds, **7 failures, 16 errors, 21 skips**.
  All six new controls pass. This independent branch starts at unchanged main,
  so the output-byte fixes in the separate unmerged #227 are not included.
  Other failures include missing binutils, Windows path assertions and temporary
  directory cleanup. The full suite is not reported as passing.
- Doctor completes with `analysis_ready=false` and missing native prerequisites.
- All eight artifact size/SHA-256 checks pass, then GPG absence prevents signature
  verification. No signature pass is claimed.
- Imports verification fails on the Windows reference checkout (reserved
  `node/aux.rs`, plus hydrated LFS inputs kept unstaged). Pins/imports are unchanged.
- Catalogue check fails on native backslash paths. Reproduce was attempted and
  stops at artifact signature verification; it did not rewrite imported evidence.

No Rust build, hosted CI, Linux/macOS run, complete helper/caller closure, node
equivalence or completion gate is measured. Next question: trace the `+0xb8/+0xc0`
consumers to establish units and whether send/body waits share or restart a deadline.
