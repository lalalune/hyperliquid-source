# RE-008: node #115 block-step sampler state and its 15-second gate (17th stage)

- Component ID: abci. Question: #5925 found that the output setter's first optional value (setter `+0xae0`, box `+0x12a0`) is the state the five block-step sampler sites (`0x5b2a130`, #4718) test against `0x8000000000000001` before calling the sampler, and that the setter writes `0` and `15.0` into it when its byte `+0x18` is set. It left open what the sampler does with that state, what `15.0` means, and who uses the second optional value (box `+0x12d8`).
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #4460, #4718, #5045, #5861 and #5925. It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, string bytes, relocations, the Location record, FDE extents and call censuses are observations. "Ring", "interval", "gate", "None", "seconds" and "tag" are inferred labels from the layout, the shared callee and the constants. The binary was not executed.
- Scope included: the setter branch at `0x51d0856`; the observer, clock and gate calls at the head of both `group_and_seq_sampler` specialisations; the gate-closed exit and ring stride in `0x5b2a130`; the two `+0x12d8` checks at `0x54ab455` and `0x54ab49b`; direct-call censuses of both samplers. Scope excluded: what each ring item holds, the functions called per item (`0x4dc2420`, `0x4da4e80`, slot `0x64ebf88`), the per-tag lookup `0x4dc50c0` / `0x4dca370`, and the other 16 call sites of `0x5b298d0`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/block_step_sampler_state_115.py --check
python3 -m unittest tests.test_block_step_sampler_state_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the setter's two values are 0x38-byte sampler states

At `0x51d0856` the setter tests its byte `+0x18` (copied to `rsp+0x13`). The two values sit at its stack `+0x218` and `+0x250`, `0x38` apart, the same distance as setter `+0xae0` and `+0xb18`.

| Offset | Byte set | Byte clear |
|---|---|---|
| `+0x0` | `0` (`xor eax, eax`, `0x51d08b8`) | `rbp+1` = `0x8000000000000001` (`0x51d08bc`) |
| `+0x8` | `8` | not written |
| `+0x10`, `+0x18` | `0`, `0` | not written |
| `+0x20` | f64 `15.0` (`0x402e000000000000`) | not written |
| `+0x28` | dword `0` | not written |

Inference: `+0x0..+0x18` is an empty ring (capacity, buffer, head, length) and `0x8000000000000001` in the capacity word is None.

## Evidence 2: both samplers use `+0x20` as a gate interval

Both `group_and_seq_sampler` specialisations, `0x5b298d0` and `0x5b2a130`, start the same way:

1. Record a value into the shared value observer: slot `0x64e1010` → `0x1547530` (#5045), with Location `0x64bca88` = `node/src/group_and_seq_sampler.rs:169:10`.
2. Read the clock: slot `0x64e0990` → `0x1629690` (#5045's wall-clock tuple).
3. Call the time gate: slot `0x64e0008` → `0x154ce40`, with `rdi = state+0x20` and `rsi` = the clock result (`0x5b29a03`, `0x5b2a263`).

`0x154ce40` is the gate #5861 mapped for the liner flush. It reads an f64 interval at `[rdi]` and a stored time at `[rdi+0x8]` (date dword, 0 = empty). It returns 1 when the stored time is empty, or when the given time is strictly later than the stored time plus the interval. It then stores the given time. Applied here, the interval is state `+0x20` (`15.0`) and the stored date is state `+0x28` (`0` from the setter). Inference: the sampler's gated work runs at most once per 15 seconds of wall-clock time, in seconds as #5861 found for the gate's interval.

In `0x5b2a130`, a closed gate jumps to the exit (`0x5b2a272` `je 0x5b2a9e2`). An open gate reads the ring at `[rbx]` (`0x5b2a292`) and walks it in `0x268`-byte steps (`0x5b2a3b7`).

## Evidence 3: the second value (box `+0x12d8`)

In `0x54a9c70`, `0x54ab437` takes `rbx+0x12d8` and keeps it at `rsp+0x50`. `0x54ab455` and `0x54ab49b` compare `[rbx+0x12d8]` with `0x8000000000000001` and skip on equal; otherwise they call `0x5b298d0` with tags `0` and `1` and `rdi` = that pointer (`0x54ab46d`, `0x54ab4b6`).

| Sampler | Direct calls | Caller functions (FDE) |
|---|---|---|
| `0x5b298d0` | 18 | `0x54a9c70` |
| `0x5b2a130` | 5 | `0x54864a0`, `0x5a06600` (#4718, #5925) |

Inference: box `+0x12d8` is the state of the first sampler, as `+0x12a0` is for the second (#5925); that `rbx` here is the box is not traced.

## Implementation and comparison

The tool pins 36 instruction byte runs, 10 rip-relative and rel32 references, 4 relocations, the source path and the Location line and column, and recomputes the two direct-call censuses with their FDE frames. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: mapping the per-item calls (bounded out); emulation (not allowed for this repository).

## Results and limitations

- Result: `15.0` is the interval of the shared time gate `0x154ce40` for both block-step samplers. When setter byte `+0x18` is set, each sampler's ring starts empty and its gated work runs at most once per 15 seconds. When the byte is clear (both callers, #5892), both states are None and no sampler runs.
- Limits: the ring item layout and what the gated work emits; the per-tag lookup; whether all 18 `0x5b298d0` calls are guarded by `+0x12d8` (2 are pinned); that `rbx` in `0x54a9c70` is the box.
- Next lead: map the per-item work in `0x5b2a130` (`0x4dc2420`, `0x4da4e80`, slot `0x64ebf88` → `0x5962620`).
