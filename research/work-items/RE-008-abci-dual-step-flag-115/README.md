# RE-008: node #115 engine value flag +0x46d, its source, and what happens to the two step results (38th stage)

- Component ID: abci. Question: #6008 found that `0x5a6bfb0` runs the layout-B step `0x5a08720` on a clone and the layout-A step `0x5a07ec0` through `0x5a08f80`, and that `0x5a08f80` copies a byte into engine value `+0x46d`. It left open what that byte does, where the poller byte behind it comes from, and whether the two step results are compared.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues #6006 and #6008. The tool imports the merged `tools/freeze_snapshot_115.py` helpers and the merged #5892 tool `tools/output_flags_path_115.py`.
- Claim status: instruction bytes, offsets, constants, string bytes, relocations and direct-call censuses are observations. "Thread spawn", "closure", "call_once", "tar" and "prune" are inferred labels from the call shapes, the Rust runtime strings in the spawn functions and the error texts. The binary was not executed.
- Scope included: the flag reads in both steps and the spawn arguments; the two spawn functions' copy of the last argument; the two closure `call_once` functions; the thread body `0x4d98c40` up to its two slot calls; the copy of the poller block into `+0xae8` and the read of `+0xb00` in both pollers; the B/A result handling in `0x5a6bfb0` and `0x5a08f80`. Scope excluded: the bodies behind slots `0x64e9540` and `0x64e9548` (not disassembled), the rest of the spawn functions, the other step callers `0x5a05fc9` and `0x5a077e1`, and the slow-engine function `0x5649680`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/abci_dual_step_flag_115.py --check
python3 -m unittest tests.test_abci_dual_step_flag_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The six `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: both steps pass +0x46d to a thread spawn every 3-hour bucket

- A step `0x5a07ec0`: `0x5a0836d` `movzx ebp, byte [r14+0x46d]`, kept at `[rsp+0x48]`. It compares the current date with `[r14+0x460]` (`0x5a08395`) and the two hours divided by 3 (`imul 0xab`, `shr 9`; the tool checks this gives `h // 3` for hours 0..23). Only when either differs does it reload the flag (`0x5a08454`), push it as the last stack argument (`0x5a08482`) and call `0x56141f0` (`0x5a08485`).
- B step `0x5a08720`: the same instructions at `0x5a08bcd`..`0x5a08ce2`, calling `0x56150d0` (`0x5a08ce5`).
- Each spawn has exactly one direct caller. Both copy the last argument (`[rsp+0x268]`) to `[rsp+0x80]`, which is closure `+0x30` (closure at `rsp+0x50`), and use closure vtables `0x64aa788` (A) and `0x64aa7c8` (B). Their Rust runtime strings include "failed to generate unique thread ID" and "thread result panicked".

## Evidence 2: the thread body

- The vtables' `call_once` entries are `0x561f970` (A) and `0x5620120` (B). Each loads closure `+0x30`, masks it with 1 and calls the body through slots `0x64e86a0` (A) and `0x64eb2a8` (B). Both slots are relocated to `0x4d98c40`.
- `0x4d98c40`: `test esi, esi; je 0x4d98d51`. With a non-zero flag it takes today's date, moves it one day back (`mov esi, -1`) and calls slot `0x64e9540`; an error formats `tar_evm_checkpoints failed: ` (`0x44bf20`). Both flag values then call slot `0x64e9548`; an error formats `prune_lowest_evm_checkpoints failed: ` (`0x43905e`).
- Inference: the flag turns on archiving of the previous day's EVM checkpoints. The slot bodies are not disassembled.

## Evidence 3: where the flag comes from

- Both pollers (`0x2aeaef0`, `0x2cb6500`) copy state `+0x118..+0x158` to `+0xae8..+0xb28` and read `+0xb00` (`= +0xae8 + 0x18`, so state `+0x130`) into `+0x2a1a`.
- `+0x118` is the setter argument that #5892 maps (built at `+0x90`, copied to `+0xd8` and `+0x118`). Its byte `+0x18` is the constant 0 (`0x2aebb5c` `mov byte [rbx+0xa8], 0`). The tool runs the merged #5892 binder and fails unless that still holds.
- `0x5a6bfb0` sets `+0x431` to 1 only when the poller byte is non-zero (`0x5a6c5db`, `0x5a6c5e0`), and `0x5a08f80` copies `+0x431` into engine value `+0x46d` (`0x5a08fa8`, `0x5a0900c`).
- Inference: on the paths mapped here, `+0x46d` is 0, so the thread body skips the archive call and only runs the prune call.

## Evidence 4: the two step results are not compared

- B: `0x5a6bfb0` builds the B engine value with `+0x46d = 0` (`0x5a6c157`, value at `rsp+0x1240`), calls the B step (`0x5a6c16a`), reads its result tag (`0x5a6c179`) and frees the result.
- A: `0x5a08f80` calls the A step (`0x5a0901f`), reads its result tag (`0x5a09024`), frees it and returns the engine value. `0x5a6bfb0` passes that value with the name `node_slow_abci_engine` (21 bytes, `0x93afc4`) to slot `0x64ebc98` (relocated to `0x5649680`).
- Neither result is read after the step returns, so they are not compared.

## Implementation and comparison

The tool pins 57 instruction byte runs, 15 references, 5 relocations and three strings, recomputes the hour-bucket arithmetic and the direct-call census, and runs the merged #5892 binder. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: disassembling the archive and prune bodies (out of scope); emulation (not allowed for this repository).

## Results and limitations

- Result: engine value `+0x46d` gates a previous-day EVM checkpoint archive call in a thread started every 3-hour bucket; the poller byte behind it is the setter's constant-0 byte on the mapped paths; the B and A step results are freed unread.
- Limits: the step callers `0x5a05fc9` (A) and `0x5a077e1` (B) are not traced, so engine values reaching the steps from other paths may carry a different `+0x46d`. The archive and prune slot bodies, the rest of the spawn functions, the slow-engine function `0x5649680`, and the "fast"/"slow" engine labels (taken from the name strings only) are not mapped.
- Next lead: what `0x5649680` does with the engine value and the `node_slow_abci_engine` name.
