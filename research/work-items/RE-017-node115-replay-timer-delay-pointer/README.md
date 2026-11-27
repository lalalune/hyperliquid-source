# RE-017: node #115 replay timer delay pointer flow

- Component ID: `abci` / `storage`; advances the open timer-delay provenance question in `RE-009-node115-expected-root-provenance`.
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source commit: `e1528748a34c6ef79736ba16002caadbdff163a4`.
- Claim status: exact selected-path pointer-flow observation; the value, its initializer, units, runtime reachability and complete timer eligibility remain unresolved.
- Scope: four exact FDE windows and two relocation slots; no captured binary execution, emulation, gate change or claim of full component recovery.

## Question

Does the selected replay flat-map timer callback consume the address `tracker + 0x88` as its f64 input?

## Finding

Yes, along the selected no-overflow path, the address flows as callback context word `+0x18` and is dereferenced once as an 8-byte floating-point value:

1. At `0x5afa06a`, the drain path forms `tracker + 0x88`; at `0x5afa07f` it stores that address in the callback context at `[rsp + 0x18]`.
2. The context base is passed in RSI to `0x4de0540` (`0x5afa0a0`). Its `jno 0x4de05f7` branch reaches the flat-map call at `0x4de05fa`. The only instruction between the branch target and call writes RDI, so RSI remains the context pointer.
3. `0x57f1690` saves RSI, then passes the saved context as RDI to `0x57d44d0` at `0x57f16f7`.
4. The callback loads `[rdi + 0x18]` as a pointer at `0x57d450b`, then reads an 8-byte scalar through it with `movsd` at `0x57d450f`.
5. The nearby conversion and threshold constructor slots resolve through `R_X86_64_RELATIVE` relocations at `0x64e0f70 -> 0x15ed960` and `0x64e0f78 -> 0x162a9a0`. These identify the call slots only; this packet does not infer the runtime scalar's meaning from them.

This establishes the selected callback input's address provenance. It does **not** establish what value is stored at `tracker + 0x88`, who writes it, whether it is elapsed or configured time, its unit, whether the branch is reached at runtime, concurrent mutation behavior, or the alternate tree/sentinel timer route.

## Reproduction

From the repository root:

```sh
python3 tools/replay_timer_delay_pointer_115.py --self-test
python3 tools/replay_timer_delay_pointer_115.py --write
(cd research/work-items/RE-017-node115-replay-timer-delay-pointer && sha256sum -c MANIFEST.sha256)
```

Collected on macOS 27.2.1 arm64 with Python 3.14.3, Capstone 5.0.7 and GNU objdump 2.47.20260726. The verifier authenticates the target SHA, requires exact FDE extents, decodes every byte in each selected extent, checks 17 instruction anchors and both relocation targets, and rejects one anchor-byte mutation per extent. `records.json` retains the machine-readable observations; the four `.asm` files retain raw `objdump -d -M intel` excerpts. The captured target is parsed statically and never executed.

## Results and limitations

- Four exact FDE windows were found: `0x5afa030..0x5afa1ee`, `0x4de0540..0x4de0907`, `0x57f1690..0x57f1874`, and `0x57d44d0..0x57d4aea`.
- Positive verification: 4/4 FDEs, 17/17 anchors, 2/2 relocations.
- Negative controls: 4/4 anchor mutations rejected.
- No implementation, source equivalence, runtime behavior, component acceptance gate or progress percentage is claimed.
- Next question: locate and validate all writers/initializers of `tracker + 0x88`, then determine whether another callback route shares this state.
