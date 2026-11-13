# RE-008: node #115 `hardfork_hashes` read at the slow abci driver start (55th stage)

- Component ID: abci. Question: #6016 found that the slow driver closure `0x5a34440` reads `hardfork_hashes` before its receive loop and, when the closure's first byte is 0, sends the result once on a second channel. It left open what `hardfork_hashes` computes and what is sent.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6004 and #6016. It imports helpers only from the merged `tools/freeze_snapshot_115.py`.
- Claim status: instruction bytes, offsets, constants, strings, call targets, one relocation and direct-call censuses are observations. "Read lock", "per-minute counter", "serialised state", "height" and "message" are inferred labels. The binary was not executed.
- Scope included: the driver head up to the send; the read wrapper `0x5647720` up to its record; the body `0x4fc3490` up to the worker call; the worker `0x5484670`; the serialiser closure's config. Scope excluded: what `0x452aab0` computes for this caller, the receiver of the second channel, the writers of box `+0x18` (`hardfork_version`), and the bodies of `0x5480950` and `0x4e36140`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/hardfork_hashes_115.py --check
python3 -m unittest tests.test_hardfork_hashes_115
```

The tool reads the ELF only. The four `*.objdump.txt` files were made with GNU objdump 2.42 for review; the tool does not read them.

## Evidence 1: the driver head

- `0x5a34456` `mov rsi, [rdi+0x78]`, `0x5a3445a` `add rsi, 0x10`: the slow runner (#6016).
- `0x5a3445e` `lea rdx, [0x93b070]` with `0x5a3446d` `mov ecx, 15`: the name `hardfork_hashes`.
- `0x5a34472` `call 0x5647720`, its only direct call.
- `0x5a34517` `cmp byte [rax], 0` / `jne 0x5a345f8`: the send is skipped unless the closure's first byte is 0.
- The message (0x28 bytes at `rsp+0x2b8`) is result `+0x38` (`0x5a34520`, `0x5a34547`) followed by result `+0x40..+0x60`.
- `0x5a34554..0x5a3455d`: `lock inc [[closure+0x30]+0x10]`, channel = `[closure+0x28]`; `0x5a3459c` `call 0x581a4f0` pushes it.

## Evidence 2: the read wrapper `0x5647720`

- `0x5647762` `mov edx, 1`, `0x5647767` `call 0x4e46b50`: a blocking call with (runner, name). It runs `0x4f21a90`, which calls the body `0x4fc3490`.
- A once-per-minute block in the runner: `lea rbx, [r13+0xb50]` (lock byte), divisor `[r13+0xb58]`, last minute `[r13+0xb60]` (compared at `0x5647854`, stored at `0x5647873`), count `+0xb68`.
- When the minute changes it builds the name `slow_abci_engine_read_increment` (`0x92a7f5`, 31 bytes) with the pair (0.01, 0.05) from `0x453530`.
- Inference: the `{0, 60000, 525600, 0}` block that #6010 found at runner `+0xb50` is this counter: 60000 ms per minute, and 525600 as the starting "last minute".

## Evidence 3: the body `0x4fc3490`

- `0x4fc34ea` `lea rbp, [r12+0x6a8]` and `0x4fc351f` `lea rcx, [rax+0x10]` with `lock cmpxchg`: adds one reader to the runner's lock word.
- `0x4fc35a9` `cmp dword [r12+0x128], 1000000000`.
- `0x4fc3754` `lea rsi, [r12+0xb00]`, `0x4fc3764` `call 0x5484670`.

## Evidence 4: the worker `0x5484670`

| Output | Source |
|---|---|
| `+0x0..+0x38` | `0x4e48ee0` (`ecx = 1`, `0x54846a3`) → `0x4e36140` → closure `0x4e4b860`, which calls `0x5480950` with config dword `0x01000400` (`0x4e4b8c1`) and loads "serialized abci state" (`0x4e4ba2f`) |
| `+0x38` | box `+0x28` (`0x5484687`), the height |
| `+0x40..+0x60` | 32 bytes from `0x452aab0` (`edx = 1`, `0x54847aa`) |
| `+0x60..+0x80` | the abci digest: `0x4e46090` (`edx = 1`) then slot `0x64e7820` → `0x41c5140` (#6024) |

So the value sent on the second channel is (height, the 32 bytes from `0x452aab0`). The serialised state and the abci digest are both computed and both reach `0x452aab0` as arguments; what it computes from them is not mapped.

## Direct-call census

| Function | Direct calls |
|---|---|
| `0x5647720` read wrapper | 1 (`0x5a34472`) |
| `0x5484670` worker | 6 |
| `0x4e48ee0` | 3 |
| `0x452aab0` | 7 |
| `0x581a4f0` push | 4 |

## Implementation and comparison

The tool pins 32 instruction byte runs, 10 call targets, 5 RIP-relative references, 3 strings, one relocation and two f64 constants, then recomputes the census. Tests change one byte in a copy of the image and expect rejection (8 mutation tests).

## Results and limitations

- Result: `hardfork_hashes` is a timed read of the slow runner's engine value that returns (serialised state, height, 32-byte value, abci digest). The driver sends (height, 32-byte value) once at start-up.
- Limits: `0x452aab0` has 7 callers and its computation for this caller is not mapped; the receiver of the second channel is not traced; the writers of box `+0x18` (`hardfork_version`) are not mapped; the 5 other worker callers are not classified.
- Next lead: the receiver of the second channel (`[closure+0x28]`), stopping at the first networking boundary.
