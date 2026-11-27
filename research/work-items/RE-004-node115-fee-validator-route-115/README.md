# RE-004: distinguish fee-schedule validation from trade-fee application

This bounded static packet advances the unresolved fee path in issue [#3913](https://github.com/lalalune/hyperliquid-source/issues/3913). It binds the known schedule validator to its caller and records the validator result's status handling. It does not claim to have found the live tier selector or to compose a maker/taker calculation through the ledger.

- Component: `fees` (`RE-004`).
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source revision: `4b51edee8718d5492f2cb0c04352547ce0bea0c5` (main at packet start).
- Coordinates: linked ELF virtual addresses; FDE ranges are unwind extents, not asserted source-level function boundaries.
- Method: pinned ELF section/RELA/FDE parsing, GNU Binutils `objdump` direct and slot-call xref scan, byte-anchored verifier. No captured binary execution or emulation.

## Observations

The schedule validator `0x36a1c20..0x36a31ff` has one direct call instruction in the full `objdump -d` scan: `0x3c190fb`, inside FDE `0x3c18a80..0x3c193c5`. Immediately before it, the caller supplies `&[rsp+0x60]` and byte count `0xb0` to an indirect helper, then passes `rbx` to the validator. This packet records those input-setup bytes without assigning a source type to the helper or object. The caller tests AL and stores status `0x1a2` on the true path or `0xa1` on the false path before returning. The exact setup, call, branch, and status bytes are checked by `verify.py`.

FDE `0x3c18a80..0x3c193c5` is also the relocated target of slot `0x64e6b88`. Three indirect call instructions reference that slot: `0x28d3a49`, `0x5392b0f`, and `0x539d92f`, in the unwind ranges recorded in `xrefs.objdump.txt` and `evidence.json`. The slot's `R_X86_64_RELATIVE` relocation resolves to `0x3c18a80`.

These bytes establish the selected validation call and its status result. They do not establish that `0x36a1c20` selects a tier for a live fill, that the three indirect callers are maker/taker paths, or that this validation result reaches fee credit distribution. The separate fee-handler packet covers call edges to `0x44896f0` and `0x3c10000`; no edge between those paths and this validator is asserted here. The issue's requested calculation from tier/window selection to ledger debit or rebate remains open.

## Reproduction

Run from the repository root with Python 3 and GNU Binutils:

```sh
python3 research/work-items/RE-004-node115-fee-validator-route-115/verify.py
objdump -d artifacts/node/115/hl-node | rg 'call.*(36a1c20|64e6b88)'
python3 -m unittest tests.test_fee_validator_route_115 -v
```

The verifier checks the target digest, exact FDE extents, direct-call instruction and raw xref candidate, result/status bytes, all three RIP-relative slot calls, and the slot relocation. Tests mutate the call displacement, relocation addend, status immediate, and target digest. These controls protect the retained facts; they are not a semantic test of a fee calculation or a whole-component acceptance gate.

## Limits and next step

No maker/taker labels or financial units are recovered. No gate in `research/progress.json` changes. Continue by identifying the actual fill-time tier/window selection and tracing one target-grounded result into the existing fee credit path; retain its ledger effect and a boundary case before claiming an integrated calculation.
