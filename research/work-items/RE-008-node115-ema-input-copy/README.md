# RE-008: conditional input copy before the latency EMA queries

- Component: consensus / latency EMA; one bounded #115 static input-handoff question.
- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source base: `a8616af9432b8d8517b2af677880e117b7c28ef3`; no reference source was copied.
- Coordinates: linked ELF virtual addresses, interval ends exclusive. The 93-byte excerpt is `[0x2e0a79e,0x2e0a7fb)` inside actual FDE `[0x2e098e0,0x2e11140)` at `0x11b2110`.
- Scope: local tag test, 24-byte stack copy, owner pointer and two relocated calls. The preceding buffer construction, helper semantics and runtime reachability are outside this packet.

## Gap and observation

Open PR #6665 maps the `0x5a71d90` latency-EMA projection entry and verifies its owner call at `0x2e0a7f5`; its remaining question is how the stack argument is prepared. The integrated `RE-001-node115-rpc-throttle-expiry` packet retains this owner's full disassembly as supporting context but does not claim this selected handoff. This packet answers the local copy question without re-crediting either body.

The target reads a result byte at `rsp+0x220` and compares it with `0x2e` at `0x2e0a7a6`. A nonmatch branches away to `0x2e0a9d8`. On the selected arm, `0x2e0a7ae..0x2e0a7c6` copies 16 bytes from `rsp+0x228` and an 8-byte tail from `rsp+0x238` into `rsp+0x1d0..0x1e7`. `0x2e0a7d2` forms R12 from the saved owner pointer plus `0x538`. The owner address is passed in RDI and the prepared buffer in RSI to calls through slots `0x64e8710` and `0x64e8718`; their `R_X86_64_RELATIVE` addends are `0x5a722f0` and `0x5a71d90` respectively. The second call's input pointer is reloaded after the first call.

This establishes the **preparation** of a 24-byte stack argument on one selected path. The second call's R12 handoff assumes the usual callee-saved-register convention across the first call. That callee could modify the buffer before the second call; its effects, the data type and the source buffer's earlier provenance are unproved. The `0x2e` value is an observed byte comparison, not a recovered public enum.

## Reproduce and controls

From repository root, with the pinned LFS artifact present:

```sh
python3 research/work-items/RE-008-node115-ema-input-copy/verify.py
```

`verify.py` uses Python standard library plus the repository's ELF/FDE readers. It authenticates the full target digest first, maps `.text`, checks the actual owner FDE, compares all 93 retained bytes and selected instruction operands, and resolves both call slots from `.rela.dyn`. Five controls change the tag, source offset, destination offset, second call displacement and relocation target; all must be rejected after bypassing the full-image digest guard. `result.json` is the observed output. Imported binary bytes retain upstream rights; new text and verifier use the repository's MIT terms. The captured binary is never loaded, executed or emulated.

Local check: macOS arm64, Python 3.14.3, `python3 .../verify.py` exited 0 with 93/93 excerpt bytes and 5/5 controls. `make catalogue-check` passed after `make catalogue`. `make doctor` failed because GNU objdump/readelf are absent; `make verify` and `make reproduce` stopped at the missing `upstream/node/pub_key.asc` submodule input after authenticating the artifact digests and signatures. `make test` was stopped after 25 seconds at file 10/1397, with no full-suite result. No hosted CI result is claimed.

## Limits and next question

No Rust implementation, runtime equivalence, complete caller semantics, comparison denominator, progress-gate change or network claim is made. The copy is conditional; source-buffer initialization and first-callee effects need separate analysis before claiming the second call's actual input contents.

Next: trace writers of `rsp+0x228..0x23f` on the selected branch and the first callee's possible writes to `rsp+0x1d0..0x1e7`.
