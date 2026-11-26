# RE-004: node #115 indirect fee-handler dispatch

This packet binds two indirect calls from adjacent unwind ranges in the
authenticated node #115 image to two fee-related handler addresses. It records
the exact call instruction, the RIP-relative slot, its `R_X86_64_RELATIVE`
relocation and the register/stack setup immediately before the call.

- Component: fees (`RE-004`), partial caller-path evidence for issue [#3913](https://github.com/lalalune/hyperliquid-source/issues/3913).
- Target: Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Evidence coordinate system: ELF virtual addresses.
- Captured target execution or emulation: none; this packet reads bytes, FDE
  metadata and relocation records only.

## Observations

| Caller unwind range | Callsite | Indirect slot | Relocated target | Argument setup |
| --- | --- | --- | --- | --- |
| `0x2419810..0x241a3c0` | `0x2419ee5` | `0x64e5b40` | `0x44896f0` | `rdi=r13`; `rsi=&[rsp+0xf0]`; `edx=[rsp+4]`; `rcx=[rsp+0x78]` |
| `0x241a3c0..0x241b097` | `0x241abca` | `0x64e5b60` | `0x3c10000` | `rdi=[rsp+0x28]`; `rsi=&[rsp+0x260]`; `edx=r15d`; `rcx=[rsp+0x68]` |

The ranges above are `.eh_frame` unwind extents. They are not asserted to be
complete source-level function boundaries. Each call instruction is an
indirect `call [rip+disp32]`; resolving its displacement identifies the stated
slot. The slot's relative relocation addend supplies the destination.

## Relation to existing fee evidence

The existing `RE-004-node115-fee-scaling` packet documents a caller at
`0x44896f0`, including a call to scaler `0x46a6860` followed by a call to fee
credit distribution `0x3c1ae50`. The existing `fees-credit-caller-115` packet
models the separate handler `0x3c10000`; its output also reaches
`0x3c1ae50`. The distribution behavior is documented in the evidence for
[PR #4527](https://github.com/lalalune/hyperliquid-source/pull/4527).
This packet adds the two upstream indirect dispatch edges and the arguments
visible at those boundaries.

## Limits

The bytes do not establish that these two handlers correspond to “maker” and
“taker”, nor do the observed arguments recover their source types or units.
This packet does not connect tier or rolling-window selection to either
handler, and it does not prove that one trade's selected point reaches a
particular ledger debit or rebate. The fee component gates remain false. Those
questions remain required before the first integrated calculation described
by issue #3913 can be claimed.

## Reproduction

From the repository root:

```sh
python3 research/work-items/RE-004-node115-fee-handler-dispatch-115/verify.py
python3 -m unittest tests.test_fee_handler_dispatch_115 -v
```

The verifier authenticates the full target digest, checks both unwind extents,
the eight argument-setup instruction anchors, both indirect call instructions,
their RIP-relative destinations and the matching relative relocations. Focused
tests reject changed argument bytes, a changed relocation addend and a wrong
target digest. These checks validate the retained static evidence, not native
runtime behavior or fee semantics.

Recorded verifier output: [`evidence.json`](evidence.json). File hashes:
[`MANIFEST.sha256`](MANIFEST.sha256).
