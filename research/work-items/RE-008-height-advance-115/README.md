# RE-008: node #115 abci box height advance (85th stage)

- Component ID: abci. Question: open PR #6086 found that each step wrapper reads box `+0x28` (the height) before its step and asserts that the shared counter equals it, and that neither wrapper nor step stores to box `+0x28`. It left open where the height is advanced.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6085 and #6086. It does not depend on their files.
- Claim status: instruction bytes, constants, string bytes, relocations, FDE extents and call or byte-run censuses are observations. "Height", "round", "consensus time", "begin", "begin_block" and "stop height" are inferred labels from the field layout of #6004, the `begin_block.rs` Location records and the code shape. The binary was not executed.
- Scope included: the first 0x51 bytes of the begin functions `0x5483850` (layout A) and `0x5483f50` (layout B) from the height load to the stop check; their wrapper call sites; the explicit-panic target; the begin_block call. Scope excluded: the body of begin_block (`0x54b66b0`, `0x54a9c70`), the consensus-time update in detail, what writes the stop flag and stop height, and the function behind slot `0x64e0f38`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/height_advance_115.py --check
python3 -m unittest tests.test_height_advance_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: the height store

In both begin functions (`r13` = box, loaded from `[rsi]`):

```
mov  rsi, [r13+0x28]      ; height
inc  rsi
mov  rdx, -1
cmovne rdx, rsi           ; +1, saturating at u64::MAX
mov  [r13+0x28], rdx      ; store
mov  qword [r13+0x0], 0
mov  [r13+0x30], rcx      ; round (4th argument)
```

A: `0x54838d3`..`0x54838f1`, store at `0x54838e5`. B: `0x5483fd3`..`0x5483ff1`, store at `0x5483fe5`. The 21-byte load/inc/cmovne/store run occurs exactly twice in `.text`, at these two addresses. Before it, each function writes the new 12-byte consensus time to `+0x60` (old value to `+0x6c`) only when the new time is later.

## Evidence 2: order inside the wrapper

| | A | B |
|---|---|---|
| begin call (only direct call) | `0x5a04fe9` → `0x5483850` | `0x5a067ad` → `0x5483f50` |
| apply / entry builder | `0x5a055b0` → `0x54897e0` | `0x5a06db6` → `0x5486720` |
| height read (#6086) | `0x5a055e6` | `0x5a06e1e` |
| counter compare (#6086) | `0x5a0561a` | `0x5a06e4f` |

So each wrapper call raises the height by exactly 1 before it reads it. Together with #6086 (counter starts at h0, +1 per tag-2 check) the assert holds as long as every tag-2 wrapper call runs its begin function once.

## Evidence 3: the stop-height panic

Right after the store:

| | A | B |
|---|---|---|
| flag | `test byte [+0x39b0], 1` | `test byte [+0x4520], 1` |
| height | `cmp rdx, [+0x39a8]` | `cmp rdx, [+0x4518]` |
| byte | `cmp byte [+0xb9a], 3` | `cmp byte [+0x170a], 3` |
| target | `0x5483edf` | `0x54845ff` |

Both targets load `explicit panic` (14 bytes, `0x7db393`) with Location `l1/src/simulate_panic.rs:10:13` (`0x6492ef0`). So when the flag is set and the new height equals the stored height, and the byte is not 3, the node panics on purpose. The A/B offsets differ by `0xb70` (#6006).

## Evidence 4: begin_block

A calls `0x54b66b0` (`0x5483a78`); B calls `0x54a9c70` (`0x5484194`); each is the only direct call. Both reference Location records for `l1/src/exchange/begin_block.rs`.

## Implementation and comparison

The tool pins 26 instruction byte runs, 9 references, the panic string and its Location relocation, and recomputes the byte-run census, the begin callers and the wrapper FDEs. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). This corrects nothing in #6086: its "no store in wrapper or step" scan was right; the store is in a callee of the wrapper that runs before the read.

## Results and limitations

- Result: the height advance is one saturating `+1` per wrapper call, in the begin function, before begin_block and before the wrapper's height read.
- Limits: what writes the stop flag and stop height; what byte `+0xb9a`/`+0x170a` value 3 means; the slot `0x64e0f38` call after the panic call; the begin_block body; whether any other path writes box `+0x28` through a computed pointer or a wider copy (the census is one byte shape).
