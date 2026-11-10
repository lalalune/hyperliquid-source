# RE-008: node #115 await side of the `initial_slow_state_for_join` task (71st stage)

- Component ID: abci. Question: open PR #6064 found that `0x2b41b70` builds the 0x350-byte catch-up future and spawns it as `initial_slow_state_for_join`. It left open where the task's handle is awaited, what happens to the returned box, and what happens when the task fails.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6060 and #6064. It does not depend on their files.
- Claim status: instruction bytes, offsets, strings, relocations, Location records, FDE extents and call censuses are observations. "State machine", "handle", "pending", "box" and "join flow" are inferred labels. The binary was not executed.
- Scope included: the state switch, the call to `0x2af45f0`, the WARN log, the spawn, the handle poll and release, the error path, the success path up to the call at `0x2b42783`, and the starting-height panic. Scope excluded: the bodies of `0x2af45f0`, `0x2b3aba0`, `0x2e4aae0`, `0x2a90e10` and `0x25d3e50`, and the two callers `0x2af0660` and `0x2cbbbe0`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/join_initial_state_await_115.py --check
python3 -m unittest tests.test_join_initial_state_await_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: the function and its callers

`0x2b41b70` reads the byte at `[rsi]+0x21` (`0x2b41b96`) and jumps through the table at `0x60499c` (`0x2b41b9a`). Its only direct callers are `0x2af0a5f` (in `0x2af0660`) and `0x2cbc06b` (in `0x2cbbbe0`).

## Evidence 2: the non-validator call and the WARN log

- It logs through slot `0x64e0ae8` (`0x2b423ad`) with template `0x43460d` and the message at `0x605fe1`, "running non-validator to get initial abci state for consensus".
- It calls `0x2af45f0` once (`0x2b42429`). `0x2af45f0` has two direct callers in the binary: this one and `0x2af072f` in `0x2af0660`. A result dword of 2 (`0x2b4242e`) returns pending.

## Evidence 3: spawn and await

- The name `initial_slow_state_for_join` (`0x60601e`, length `0x1b`) is stored at state `+0x3d0`/`+0x3d8`. The 0x350-byte future is passed to `0x2b3aba0` (`0x2b4261c`, its only direct call) with Location `base/src/lu.rs:116:5` (`0x6447158`). The result is stored at state `+0x3f0`.
- `0x2e4aae0` polls the value at `+0x3f0` (`0x2b42641`). A non-zero first output byte stores 3 at state `+0x3f8` and returns pending.
- Otherwise the handle is released with `lock cmpxchg` 0xcc → 0x84 (`0x2b42682`..`0x2b4268c`), the same pattern as #5876's spawn wrapper.

## Evidence 4: task failure

A non-zero result word at `[rsp+0x438]` (`0x2b4269a`) jumps to `0x2b42bd8`. That path calls `0x2a90e10` and the `Result::unwrap()` panic (slot `0x64df6a0`, message `0x605542`, 0x2b bytes) with Location `node/src/startup.rs:337:49` (`0x64480b8`). So a failed or cancelled catch-up task stops the node with a panic.

## Evidence 5: the returned box

- The box is stored at state `+0x28` (`0x2b4272b`).
- When box `+0x28` (the height, per #5925) equals state `+0x48` (`0x2b42760`..`0x2b42764`), the function writes the box to `[r14]`, `r15` to `[r14+8]` and two more 16-byte fields, and returns with state 1 (`0x2b429ec`..`0x2b42a0a`).
- When they differ, it calls `0x25d3e50` with box `+0x2c20` plus 0x10 (`0x2b42774`..`0x2b42783`), then references the template `0x44c7fa` (`"{}/MARKED_FOR_DELETION"`). The body of `0x25d3e50` is not read.

## Evidence 6: the starting-height panic

`0x2b41eb8` compares `[r15]` with `rdx` and jumps to `0x2b42d07` when it is lower. That path panics through slot `0x64df6b8` with template `0x436a4e` ("invalid starting height= … last_applied_height=") and Location `node/src/startup.rs:206:37`.

## Results and limitations

- Result: the catch-up task is awaited inside the same startup state machine that spawned it. A task failure is a panic at `startup.rs:337:49`. On success the box is kept; the function returns it when its height matches a stored height, otherwise it first calls `0x25d3e50`.
- Inference: `0x2b41b70` is part of the join flow in `node/src/startup.rs`.
- Limits: where the two callers send the returned box (the fast/slow engine builder `0x5a6bfb0` is not reached in this function); what `0x25d3e50` does; what state `+0x48` holds; the meaning of `0x2af45f0`'s other result values; the state numbers beyond those pinned.
