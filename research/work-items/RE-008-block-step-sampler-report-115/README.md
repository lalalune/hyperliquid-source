# RE-008: node #115 block-step sampler post-walk collect and two observer day fields (19th stage)

- Component ID: abci. Question: #5934 found that after its per-item walk, sampler `0x5b2a130` calls `0x5b926e0` once when its local map has at least 3 entries, and again when it has at least 2 and a minute value is at least 6, and frees each result. It also read item `+0x208` (qword) and `+0x248` (dword) as observer `+0x200` and `+0x240`. It left open what `0x5b926e0` computes and what those observer fields hold.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5045, #5839, #5931 and #5934. It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, relocations, FDE extents and call censuses are observations. "Collect", "vector", "B-tree", "iterator", "alloc", "free", "date" and "day" are inferred labels from the call shapes, layout and the wall-clock provider of #5045. The binary was not executed.
- Scope included: all of `0x5b926e0`; the head of `0x51360a0` and its call census; the call census of `0x5963a10`; the two sampler call sites up to the overwrite at `0x5b2a6cb`; the date check and the two day sums in the record entry `0x1547530`; the matching constructor stores. Scope excluded: the body of `0x5963650`, the B-tree descent after the first edge, the other two callers of `0x51360a0` (`0x5b70d4c`, `0x5b70eb3`), the source of the constructor's `r13d`, and the reader of `+0x200` at `0x1547f78`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/block_step_sampler_report_115.py --check
python3 -m unittest tests.test_block_step_sampler_report_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: `0x5b926e0` collects pointers into a new vector

- Input tag `[rsi] == 2` (`0x5b926f4`): two contiguous runs of 0x20-byte elements; the size hint is the two run lengths (`shr 5`). Any other tag: each item comes from `0x51360a0` (`0x5b9273c`, `0x5b928a3`), and the hint is `[r14+0x40]`.
- `0x51360a0` counts down `[rdi+0x40]` (None at 0) and walks nodes with a u16 length at `+0x13e`, a u16 parent index at `+0x13c` and edges at `+0x140`/`+0x148`: a B-tree iterator `next` (inference).
- The first capacity is `max(4, hint + 1)` (`inc rax`, `cmp rcx, 5`, `mov ebx, 4`); the first pointer is stored at `0x5b927d7`; growth calls `0x5963a10` with element size 8 and alignment 8 (`0x5b928ec`, `0x5b928f1`). An empty input returns `(0, 8, 0)` (`0x5b92937..`).
- Call census of the whole FDE `0x5b926e0..0x5b92992`: `0x51360a0` (2), `0x5963a10` (1), slots `0x64df480` (1), `0x64df498` (2), `0x64df4a0` (1) and `_Unwind_Resume`. No strings, Location records or other calls. `0x51360a0` calls only slot `0x64df830` (relocated to `0x1680c10`, the `Option::unwrap` panic of #5861). `0x5963a10` calls only `0x5963650` and slot `0x64df498`.

## Evidence 2: the sampler never reads the collected vectors

At both call sites (`0x5b2a51a`, `0x5b2a662`) the next instructions read the capacity `[rsp+0x8]` and pointer `[rsp+0x10]`, shift the capacity by 3 and call the free slot `0x64df4a0`. The length `[rsp+0x18]` is not read. `0x5b2a6cb..` stores new values over `rsp+0x8..+0x48` before any later read; the only jumps into `0x5b2a6cb..0x5b2a720` come from the loop after it (`0x5b2a89e`, `0x5b2a8b0`, checked on the listing). `0x5b926e0` has no other direct callers.

Result: the post-walk work in the sampler builds one or two vectors of pointers and frees them unread. Apart from the allocation, it has no observable effect.

## Evidence 3: observer `+0x240` is the date of the day sums `+0x200` and `+0x208`

In the record entry `0x1547530`:

- `0x1547559` calls slot `0x64e0990` (relocated to `0x1629690`, the wall-clock tuple provider of #5045) with `rdi = rsp`.
- `0x1547562` compares `[rbx+0x240]` with the first dword of the result. On a difference it zeroes `+0x200..+0x218`, clears `+0x50`/`+0x58`, stores the dword at `+0x240` and the next qword at `+0x244`.
- `0x154770d..0x1547729`: `+0x200 += r14`, saturating; `r14` is the second argument (`0x154754a mov r14, rsi`), the count.
- `0x1547730..0x154773e`: `+0x208 += 1`, saturating.

The constructor stores `r13d` at `+0x240` (`0x1548d37`) and zero at `+0x200` (`0x1548d42`). Inference: `+0x240` is the UTC date of the current day, `+0x200` the day's summed count and `+0x208` the day's record calls. #5934's walk therefore groups items by their observer's date and pushes the day's count sum.

## Implementation and comparison

The tool pins 50 instruction byte runs, 8 call targets, 2 relocations, three call censuses and the direct-caller lists of `0x5b926e0` and `0x51360a0`. Tests mutate one site at a time in a copy of the image and expect rejection (9 mutation tests). Alternatives considered: emulation (not allowed for this repository); a data-flow proof for the unread vectors (out of scope; the listing check is stated).

## Results and limitations

- Result: the sampler's post-walk collect is dead work. Its vectors are freed unread. Observer `+0x240`/`+0x200`/`+0x208` are the date and two per-day sums that #5045 named per-UTC-day fields.
- Limits: the census decodes `E8` calls to FDE starts or PLT and every `FF 15`; register-indirect calls are not counted. The control-flow claim for the overwrite at `0x5b2a6cb` was checked on the listing, not by the tool. The other two `0x51360a0` callers, `0x5963650`, the constructor's `r13d` and the `+0x200` reader at `0x1547f78` are not mapped.
- Next lead: map the `+0x200` reader at `0x1547f78` in the window record path, and the two other B-tree `next` callers `0x5b70d4c`/`0x5b70eb3`.
