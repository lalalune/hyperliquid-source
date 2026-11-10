# RE-008: node #115 startup last-applied-height check and where the startup box goes (72nd stage)

- Component ID: abci. Question: the join await packet (open PR #6065) found that `0x2b41b70` (`node/src/startup.rs`) spawns `initial_slow_state_for_join`, awaits it and returns a box. It left open where the box goes, what the state compared with the box height holds, and when the "invalid starting height" panic fires.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6064 and #6065. It does not depend on their files.
- Claim status: instruction bytes, offsets, relocations, strings and call censuses are observations. "starting height", "last applied height", "replica_cmds end heights" and "engine builder" are inferred labels from strings, earlier packets and call shapes. The binary was not executed.
- Scope included: the starting-height check in `0x2b41b70`; the head of `0x595b1a0`; the call sites of `0x2b41b70`, `0x2af0660` and `0x2cbbbe0`; the handoff in both pollers. Scope excluded: the body of `0x25d3e50` (MARKED_FOR_DELETION, a file-system cleanup path), the rest of `0x595b1a0`, the internals of `0x2af0660` after the box store, and the networking code. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/startup_initial_box_115.py --check
python3 -m unittest tests.test_startup_initial_box_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: the starting-height check

In `0x2b41b70`, when input byte `+0x0` bit 0 is clear (`test byte [rbx], 1` at `0x2b41bcd`):

- The starting height is input `+0x8` (`0x2b41bb3`), stored at state `+0x38` (`0x2b41d2e`); `r15` points at it.
- When input byte `+0x1` is 1 (`0x2b41bae`, `0x2b41d32`), it calls slot `0x64e7720` (relocated to `0x595b1a0`) at `0x2b41d3c`.
- `rax == 1` skips the check (`0x2b41d42`, `0x2b41d46`); otherwise `cmp [r15], rdx` / `jb 0x2b42d07` (`0x2b41eb8`, `0x2b41ebb`) panics through template `0x436a4e` ("invalid starting height= … last_applied_height=") when the starting height is below the returned height.
- After the check it calls slot `0x64e4f30` (relocated to `0x38d8240`, the periodic paths of #6001) with the starting height (`0x2b41f6d`, `0x2b41f75`).

## Evidence 2: where the last applied height comes from

`0x595b1a0` loads the root cell `0x64f06c0` through slot `0x64e0918`, formats template `0x448b77` (`{}/data/{}`) with the slice at `0x64b6828` (pointer relocated to `0x9383d2`, length 12: `replica_cmds`) and loads `0x439f32` ("no end heights found"). Inference: the last applied height is read from the end heights under `{root}/data/replica_cmds`, and the Err path (`rax == 1`) covers a missing record.

## Evidence 3: callers and the handoff

| Function | Only direct call | In |
|---|---|---|
| `0x2b41b70` | `0x2af0a5f`, `0x2cbc06b` | `0x2af0660`, `0x2cbbbe0` |
| `0x2af0660` | `0x2aec151` | poller `0x2aeaef0` |
| `0x2cbbbe0` | `0x2cb7771` | poller `0x2cb6500` |

- `0x2af0660` treats output `+0x8 == 0x8000000000000001` as pending (`0x2af0a64..0x2af0a72`), stores the returned box (output `+0x0`) at its state `+0x60` (`0x2af0ae1`) and compares box byte `+0xb9a` with state `+0x556` (`0x2af0b15`, `0x2af0b24`).
- Both pollers pass a stack buffer as the callee output (`0x2aec141` / `0x2cb7761`), load output `+0x380` into `rbp` (`0x2aec184` / `0x2cb77a4`) and later pass `rbp` as `rdi` (`0x2aec3e9` / `0x2cb7a09`) to slot `0x64e7440`, relocated to `0x5a6bfb0`, the engine builder of #5916 and #6008.

Both pollers are reached from both subcommand tags (#5902, #6006), so both subcommands reach both callers.

## Implementation and comparison

The tool pins 25 instruction byte runs, 12 rip/rel32 references, 5 relocations, the slice length and 4 strings, and recomputes the direct-call census of the three functions in one pass. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: tracing every state of `0x2b41b70` (bounded out); emulation (not allowed for this repository).

## Results and limitations

- Result: the startup state machine checks the requested starting height against the last applied height from `data/replica_cmds` and panics when it would go backwards; both validator-capable pollers pass their callee's output `+0x380` to the engine builder.
- Limits: that output `+0x380` of `0x2af0660` is the box returned by `0x2b41b70` is an inference; the box is stored at state `+0x60` and later at a stack record (`rsp+0x24d8`) whose copy into the output is not pinned. What state `+0x48` (compared with box height in #6065) holds is not bound here. Whether the mode byte (1/2) gates the join path is not mapped. `0x25d3e50` is not read.
- Next lead: the copy from `0x2af0660` state `+0x60` into its output `+0x380`, and the meaning of the box byte `+0xb9a` / state `+0x556` comparison.
