# RE-004: bind node #115 fee-credit dispatch callers

This bounded static packet connects the existing fee-credit reconstruction at
`0x3c10000` to the machine-code callsites that dispatch to it. It records the
registration relocation, the full set of three RIP-relative indirect calls in
`.text`, each caller's unwind extent, and the four argument-register setup
bytes immediately before each call. It advances the still-open Fees and volume
investigation in [issue #3913](https://github.com/lalalune/hyperliquid-source/issues/3913).

- Component: `fees` (`RE-004`).
- Target: Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source revision: `60af0e3449827115182c822d72cc40d68dc5dd7f` (main at packet start).
- Coordinates: linked ELF virtual addresses; FDE ranges are unwind extents,
  not asserted source-level function boundaries.
- Method: pinned ELF section/RELA/FDE parsing, raw `.text` slot-reference scan,
  and GNU Binutils `objdump` disassembly of all matching callsites. The
  captured node is read as bytes only and is not executed or emulated.

## Observations

The `.rela.dyn` relative relocation at slot `0x64e5b60` resolves to the start
of the existing fee-credit caller FDE, `0x3c10000..0x3c1128e`. The raw scan
finds three `call *disp32(%rip)` instructions in `.text` whose effective
address is this slot: `0x241abca`, `0x593c633`, and `0x593d2c3`. GNU `objdump`
decodes the same three instructions; the full-image filtered output is
retained in `xrefs.objdump.txt`.

Each callsite belongs to its own FDE unwind extent, recorded in `evidence.json`.
Immediately before each call, the bytes load a first argument into RDI, form a
stack-relative pointer in RSI, load the third argument into EDX, and load a
fourth argument into RCX. The first callsite sources EDX from R15D; the other
two source it from EBX. The exact setup bytes are retained and tested. The
existing `fees-credit-caller-115` packet reconstructs the callee's register
contract as four arguments, but these callers' source-level types, meanings,
higher-level transaction identity and the relation between the three caller
FDEs are not established here.

This proves a dispatch route into the existing fee-credit/ledger routine. It
does not prove that any caller performs maker/taker selection, identify a fee
tier or rolling window, establish financial units, or compose the selected
amount through the final debit/rebate. The integrated calculation requested by
issue #3913 remains open.

## Reproduction

Run from the repository root with Python 3 and GNU Binutils:

```sh
python3 research/work-items/RE-004-node115-fee-credit-dispatch-115/fee_credit_dispatch_verify.py
/opt/homebrew/opt/binutils/bin/objdump -d artifacts/node/115/hl-node | rg -i 'call.*64e5b60'
python3 -m unittest tests.test_fee_credit_dispatch_115 -v
```

The verifier checks the target digest, the callee FDE, all three caller FDEs,
the exact indirect-call bytes and their effective slot addresses, the relative
relocation, and the four argument-setup instruction sequences. Tests corrupt
the call displacement, relocation addend, argument setup and image digest.
These checks protect the recorded dispatch facts; they do not interpret the
callers' source-level business roles or establish an integrated fee model.
