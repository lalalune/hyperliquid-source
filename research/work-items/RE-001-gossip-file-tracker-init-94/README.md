# RE-001: gossip configuration tracker initialization and failure propagation

Focused static verification and 32 actual-capture/export corruption controls pass. Exact-head mandatory repository results are reported with the PR; a focused pass does not establish an all-green repository check. No reconstruction, runtime or progress-gate completion is claimed.

- Task/component: RE-001 / node-runtime configuration integration.
- Target: Linux x86-64 node #94, SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, 91,774,280 bytes.
- Base: `e5c9b6436876b2a4a39daef813171f9879317699`.
- Question: does this specialized tracker initializer replace a failed gossip override with defaults, or propagate an error to its selected caller?
- Coordinates: linked ELF virtual addresses; FDE ends exclusive. No ASLR base assumption.

## Observed selected paths

The existing [gossip inventory](../gossip-config-inventory-94/README.md) and [local-Abci packet](../local-abci-gates-94/README.md) bind the caller at `0x4741dc0`, but leave its file tracker path unresolved. The [generic tracker initializer](../RE-001-file-tracker-init-94/README.md) at `0x13cc980` has a different value layout and an observed fallback; that fallback cannot be transferred to this specialization.

The selected caller saves its output address in R14. For the optional-vector sentinel `0x8000000000000000`, it constructs the 27-byte override filename and calls the regular-file predicate. Predicate zero branches to `0x474223b`, the previously documented compiled-root selection. Predicate nonzero calls `0x471e1e0` at `0x4741ea5`. The returned first word is compared with 2 at `0x4741eb2`; other values branch to `0x474268d`, while 2 enters the diagnostic/error route. Under ordinary helper returns that route writes `0x800000000000003c` to the caller output at `0x474218c`, then returns. It does not branch to compiled-root selection.

Initializer `0x471e1e0` calls metadata slot `0x576e9f0` at `0x471e20a`. DWORD tag 1 loads the error word and joins `0x471e247`, which writes payload at output+8 and tag 2 at output+0. Other metadata tags call `0x4721440` at `0x471e232`. That result's word 0 is compared with 2; equal takes the same output-tag-2 path. Non-2 copies the selected value and stores the owned path, binary64 bits `0x4014000000000000` (5.0), zero poll/error fields and the metadata-shaped words. No default payload is installed on the two shown error branches.

The load body `0x4721440` has both binary-extension and text paths. On the selected text path it calls read slot `0x576f648` at `0x47216f4`. NEG/JNO distinguishes the raw first word `0x8000000000000000` from other words. Its error route builds output tag 2. Other words reach the parser boundary `0x43a3aa0` at `0x4721842`; returned DWORD tag 2 reaches a separately wrapped output-tag-2 route at `0x47218dc..0x47218e0`. The parser grammar and all malformed-input cases remain unresolved.

These are conditional byte/dataflow observations. Allocation, diagnostics, drops, metadata/read effects, parser internals and unwind helpers are boundaries; their normal returns are assumptions, not execution results. No actual configuration file or network is used.

## Retained evidence and outstanding work

Three complete FDEs, 6,193 bytes / 1,200 instructions, were decoded independently with Capstone and GNU objdump and every instruction address/byte pair agreed. `records.json` binds the body hashes, address ranges and selected anchors. `disassembly.json.gz` retains the decoded transcripts. `gnu.objdump.txt.gz` retains the GNU exports; only the local capture pathname in its header is replaced by `<node94>`. Original unmodified exports remain in the local operator record. No instruction normalization or transplanted implementation is used.

Tooling: CPython 3.12.1, Capstone wrapper 5.0.7 / API 5.0, GNU objdump 2.47. Target not executed or emulated. No inferred unlicensed source copied.

The independent verifier checks full target identity, exact FDE/body/anchor/relocation bindings, pinned archive hashes and complete address/byte agreement of both exports. Controls bypass the image/body/export checks for local anchor and RELA obligations; export corruption and image identity have separate controls. These are structural checks, not execution of the target. Reproduce from the repository root with `python -B research/work-items/RE-001-gossip-file-tracker-init-94/verify.py --binary <authenticated-node94-path> --controls --out <new-output-file>`. Official commands are `make doctor`, `make verify test catalogue-check` and `make reproduce`. If the combined command stops, run the remaining independent targets and disclose each result. No generated catalogue is edited. New raw exports can be produced with `python -B research/work-items/RE-001-gossip-file-tracker-init-94/export.py --binary <authenticated-node94-path> --objdump <GNU-objdump-path> --capstone-dir <installed-Capstone-directory> --out <new-output-directory>`. This never changes the pinned archive expectations. The recorded toolchain reproduced both committed gzip files byte for byte; `export-report.json` records actual versions and hashes. Other tool versions may render different text; address/byte coverage is checked without operand normalization. No source build, Rust ABI, full gossip schema, polling/update behavior, target equivalence, #115/visor parity or component gate is requested.
