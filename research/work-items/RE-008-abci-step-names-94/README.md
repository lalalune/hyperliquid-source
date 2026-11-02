# RE-008: node #94 block-step name bytes

- Component ID: abci. Question: which fixed byte slices does `0x3b998a0` hand to the formatter for tag bytes 0 through 5?
- Target release and full SHA-256: node #94 `artifacts/node/94/hl-node`, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit: `e5c9b6436876b2a4a39daef813171f9879317699`. Reference commit `999556f6e0a474b8312db96ec3149e1c44e97c23` does not contain `RecoverUsers`, `DeliverSignedActions`, or `RespHashCheck`.
- Claim status: the table, the slices, the relocations, and the one load site are observations. The block-step reading of the names is an inference from those bytes.
- Scope included: FDE `0x3b998a0`..`0x3b99934` (148 bytes) and the data it reads. Scope excluded: the formatter body at `0x1573450`, the host FDE `0x4925f10` except the one load at `0x492619f`, and every producer of the tag byte. No gate changes.

## Reproduce

From the repository root:

```
python3 tools/abci_step_names.py --check
python3 -m unittest tests.test_abci_step_names
```

The tool reads the ELF. It does not execute the captured binary. It does not start objdump or readelf. Addresses are ELF virtual addresses.

## Evidence

`rdi` points at one tag byte. `rsi` is the formatter object. The function saves `rsi`, zero-extends the byte, and jumps through the relative table at `0x5b2e1c`.

Each arm puts a fixed slice in `rsi`, its length in `edx`, the saved formatter in `rdi`, and tail-jumps through `[0x576e000]`. That slot is `R_X86_64_RELATIVE` addend `0x1573450`. Existing packets already name `0x1573450` as the formatter string write. This packet does not decode that helper.

| Tag | Arm | Slice VA | Length | Bytes |
| --- | --- | --- | --- | --- |
| 0 | `0x3b998b6` | `0x5b6973` | 12 | `RecoverUsers` |
| 1 | `0x3b9990a` | `0x5b697f` | 10 | `BeginBlock` |
| 2 | `0x3b998e0` | `0x5b6989` | 20 | `DeliverSignedActions` |
| 3 | `0x3b998f5` | `0x20aea8` | 8 | `EndBlock` |
| 4 | `0x3b998cb` | `0x5b699d` | 6 | `Commit` |
| 5 | `0x3b9991f` | `0x5b69a3` | 13 | `RespHashCheck` |

Tags 0, 1, 2, 4, and 5 are one contiguous run at `0x5b6973`. There is no NUL between those names. `EndBlock` is a separate 8-byte slice. The next bytes are `fee_rate` and a NUL. The arm copies 8 bytes, so `fee_rate` is not part of the name.

The byte is not compared with 6 inside this FDE. The next table word targets `0x3b99a5c`, which is outside the FDE. A byte above 5 is not handled here.

One `R_X86_64_RELATIVE` relocation has addend `0x3b998a0`. It writes slot `0x5776290`. In the stated RIP-relative encodings, one instruction loads that slot: `0x492619f` inside FDE `0x4925f10`. That FDE is only an inventory row in the cumulative-minute packet. This packet does not say which tag that host requests.

Counts, over the one FDE: 6 arms, 6 table entries, 6/6 targets inside the FDE, 1 function-pointer relocation, 1 load of that slot in the stated encodings. This is not a count of every block-step string in the file.

## Results and limitations

No Rust is added. No progress gate is requested. The helper, the call target inside the formatter, the data after the copied slices, and the tag producer stay open.

Negative controls in `tests/test_abci_step_names.py` change one name byte, the `Commit` length immediate, one table word, and the writer addend. Each change fails the check.

Next question: which instruction writes the tag byte that `0x3b998a0` reads, and which of these six slices the load at `0x492619f` requests.
