# RE-008: node #115 slow abci driver apply-block closure (44th stage)

- Component ID: abci. Question: open PR #6018 found that the slow driver passes its parallel-collect result and the message to `spawn_slow_abci_driver_apply_block` through `0x4e47900` with `edx = 1`. This packet asks what that closure does: which step it applies, what it locks, what it records, and what the greeting step after it is.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6016 and #6018. It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, strings, relocations, FDE extents and the direct-call census are observations. "Write lock", "wait", "hold", "draw", "per minute" and "layout A" are inferred labels from the call shapes and from #6006 / #6008. The binary was not executed.
- Scope included: the call site `0x5a34e49..0x5a34fb8`, the tail of `0x4e47900`, the body `0x4fcac10`, the return of `0x1562120`, the recorder `0x4770c90`, and four direct calls that link `0x59ec200` to the layout-A step. Scope excluded: the bodies of `0x4f152a0` beyond its calls, `0x59ec200` beyond its two calls, `0x56185e0`, `0x5a04e40`, `0x4780430`, `0x47718a0`, the greeting `0x4f18bd0`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/slow_abci_apply_block_115.py --check
python3 -m unittest tests.test_slow_abci_apply_block_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: the closure runs under a lock-ordering-checked runner

- The driver builds a 0x58-byte closure on the stack and calls `0x4e47900` with the name `spawn_slow_abci_driver_apply_block` (`0x93b00f`, 0x22 bytes) and `edx = 1` (`0x5a34f08`, `0x5a34f0d`).
- `0x4e47900` copies the closure and calls `0x4f152a0` with Location `0x649ee50` (`0x4e47a7c`). `0x4f152a0` references `lock ordering violations` and `base/src/lock_id.rs`.
- The body `0x4fcac10` has two direct calls, `0x4f1532c` and `0x4f15ae2`, both inside `0x4f152a0`.

## Evidence 2: the body applies one step under a write lock

`r15` is the slow runner (closure `+0x58`).

1. It reads runner byte `+0xb40` (`0x4fcac4d`), the flag #6010 found.
2. It reads the clock. If `[r15+0x128]` is not 1e9 (`0x4fcac68`), it stores an elapsed time at `+0x118`.
3. It takes the lock word `+0x6a8` from 0 to 8 with `lock cmpxchg` (`0x4fcac81`, `0x4fcac88`), with a slow path through slot `0x64e0ff0`.
4. It calls `0x59ec200` with the locked value `+0x6b0` in `rcx` (`0x4fcae24`, `0x4fcae48`).
5. It releases the lock, 8 to 0 (`0x4fcae4f`, `0x4fcae59`).
6. It converts start-to-acquire and acquire-to-release into f64 seconds (divide by 1e9; `inf` maps to 0).

## Evidence 3: the step is layout A, and it writes visor_abci_state

- `0x59ec200` has one direct caller, `0x4fcae48`.
- `0x59ec200` calls `0x56185e0` (`0x59ec2a7`), which calls `0x5a04e40` (`0x5618630`), which calls `0x5a07ec0` (`0x5a05fc9`). #6006 found `0x5a07ec0` is the layout-A step.
- `0x59ec200` also calls `0x5942b40` (`0x59ec380`), the `visor_abci_state` wrapper from #6002.

Inference: the slow driver applies each block with the layout-A step and is the `node.rs:659` writer of `visor_abci_state.json` named in #6004.

## Evidence 4: a random draw whose result is not used

- When the `+0xb40` byte is set and `[r15+0x3f8]` is 1 (`0x4fcaf3c`), the body calls slot `0x64e1028` (relocated to `0x1562120`) with `edi = 50` (`0x4fcaf46`, `0x4fcaf4b`).
- `0x1562120` returns `random % rdi == 0` (`test rdx, rdx; sete al` at `0x1562290`).
- The next instruction, `0x4fcaf51`, loads a stack value and does not test `al`. The result is not read.

## Evidence 5: the recorder ignores the times it is given

- The body calls slot `0x64eb1a8` (relocated to `0x4770c90`) with `rdi = runner+0xb20`, the name, `[runner+0x18]`, `[runner+0x20]`, the wait in `xmm0` and the hold in `xmm1` (`0x4fcafaf..0x4fcafd2`).
- In `0x4770c90` (extent `0x4770c90..0x4770f33`, pinned by SHA-256), `rsi`, `rdx`, `rcx` and `xmm0` are written before any read, and `xmm1` does not appear.
- What it does: it takes the byte lock at `+0x0`, computes the wall-clock time in ms, divides by `[+0x8]` (60000), stores the minute if it is greater than `[+0x10]`, records `profiled_rw_lock_increment` with (0.01, 0.05) through `0x4780430`, and adds 1 to `[+0x18]` with saturation.
- #6010 found the block `{0, 60000, 525600, 0}` at runner `+0xb20`. So 525600 is the starting "last minute" value.

Inference: the lock-wait and lock-hold times measured in Evidence 2 are dropped at this call. Only a per-minute call count is recorded.

## Implementation and comparison

The tool pins 19 instruction byte runs, 15 relative references, 5 strings, 4 relocations, the recorder extent's SHA-256 and its two f64 constants, and recomputes the direct-call census of `0x4fcac10` and `0x59ec200`. Eight tests change one byte in a copy of the image and expect rejection. The helpers come from the merged `tools/freeze_snapshot_115.py`.

## Results and limitations

- Result: the slow driver applies each block with the layout-A step under a write lock, writes `visor_abci_state` on that path, discards a 1-in-50 random draw, and records only a per-minute call count for the lock.
- Limits: what `0x59ec200` does between its calls; the 0x28-byte result it returns; what `[runner+0x3f8]` is; the `+0x118`/`+0x120`/`+0x128` timing fields beyond their use here; the mutex and call at `+0x28`/`+0x30` (`0x47718a0`); the greeting `0x4f18bd0` and its Location `0x64b8a38`; the meaning of `0x1a3` (not found on this path); where the 0.05 / 0.35 values from #6010 are read.
- Next lead: what `0x59ec200` does with the stage 43 result before and after it calls `0x56185e0`.
