# RE-008: node #115 block-step sampler items and the per-item walk (18th stage)

- Component ID: abci. Question: #5931 found that the block-step sampler state is 0x38 bytes (a list at `+0x0..+0x18`, a 15.0 s gate interval at `+0x20`) and that an open gate in `0x5b2a130` walks the list in `0x268`-byte steps. It left open where items enter the list, what each item holds, and what the walk computes.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #4460, #4718, #5045, #5925 and #5931. It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, relocations, FDE extents and call censuses are observations. "Map", "entry", "key", "vec", "push", "observer", "collect" and "free" are inferred labels from call shapes, sizes and constants. The binary was not executed.
- Scope included: the sampler head from the tag store to the record call; the list lookup `0x4dc50c0` up to its search call and its free size; the walk and the push in `0x5b2a130`; the two length checks and the minute-of-day check after the walk. Scope excluded: the bodies of `0x4da7e20` (mapped as the step-name host in #4460), `0x57f4db0`, `0x4dc2420`, `0x4da4e80`, `0x5b926e0` and `0x5962620`; the other sampler `0x5b298d0`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/block_step_sampler_items_115.py --check
python3 -m unittest tests.test_block_step_sampler_items_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: items enter the list inside the sampler, keyed by the tag

Before the gate, `0x5b2a130`:

1. stores its tag argument (`ebp`, from `esi`) as a byte at `rsp+0xe0` (`0x5b2a1fd`);
2. calls `0x4dc50c0` with `rdi = rsp+0x8`, `rsi = state`, `edx = tag` (`0x5b2a21a`);
3. calls `0x4da7e20` with that result, `rsi = &tag` and `rdx` = a zero byte (`0x5b2a232`);
4. passes the returned pointer as `rdi` to the shared value observer's record (`0x5b2a243`, slot `0x64e1010` → `0x1547530`, #5045).

`0x4dc50c0` stores the tag byte at `rsp+7`, tests whether the state's first word is `0x8000000000000000` (`cmp 0, [rsi]; jo`), searches through `0x57f4db0`, and frees vec-mode storage as `len * 0x268` bytes (`0x4dc517c`). It has one direct caller, this sampler.

Inference: the list is a map from the u8 tag to an observer; `0x4da7e20` inserts the observer when the tag is missing (as #4460 found, it builds the `seq_task/l1/<step>` name per tag). The `0x8000000000000000` first word selects a second storage mode not mapped here.

## Evidence 2: what the walk reads from each item

For each 0x268-byte item at `rax`:

| Read | Instruction | Use |
|---|---|---|
| byte `+0x0` | `0x5b2a3e2` `movzx ebp, byte [rax]` | key byte, pushed |
| `r12 = item+0x8` | `0x5b2a3c3` | payload base |
| dword `+0x248` | `0x5b2a3e5` `mov edx, [r12+0x240]` | grouping key |
| qword `+0x208` | `0x5b2a403` `mov r15, [r12+0x200]` | pushed value |

Inference: the item is the u8 tag (padded to 8 bytes) followed by a 0x260-byte observer, so the dword is observer `+0x240` and the qword is observer `+0x200`. What those two observer fields hold is not mapped here.

## Evidence 3: the walk groups items into a local map

The sampler builds a local value at `rsp+0x50` = `{0, 8, 0, 0}` and reads its length at `rsp+0x68`. Per item it calls `0x4dc2420` (`rsi` = that local value, `edx` = the dword) and then `0x4da4e80`, which returns `{cap, ptr, len}`. It pushes a 16-byte element, the qword at `+0` and the key byte at `+8` (`0x5b2a36b`, `0x5b2a36f`), growing through slot `0x64ebf88` → `0x5962620` when `len == cap`. Both callees have one direct caller, this sampler.

Inference: the sampler groups the tag observers by observer `+0x240`, each group a list of (observer `+0x200`, tag).

## Evidence 4: after the walk

- If the local map has at least 3 entries (`0x5b2a436`), it goes to `0x5b926e0` (`0x5b2a51a`).
- Then, if it has at least 2 entries (`0x5b2a53f`) and `floor(seconds of day / 60)` is at least 6 (`0x5b2a57f`), it goes to `0x5b926e0` again (`0x5b2a662`).
- Each call's result is a `{cap, ptr}` of 8-byte elements, freed right after (`0x5b2a534`, `0x5b2a67c`).

The seconds of day are the clock result's second word (`rsp+0x130`; the clock writes `rsp+0x12c`). The tool recomputes the minute arithmetic from its constants (`0x91a2b3c5 >> 0x2b` = /3600, `0x88888889 >> 0x25` = /60, `0x8888889 >> 0x21` = /60) and checks six samples: the value is `seconds / 60`.

Inference: `0x5b926e0` collects from the map; whatever it does besides building the freed vector is not mapped.

## Implementation and comparison

The tool pins 50 instruction byte runs, 7 direct calls, 4 slot calls and 2 relocations, recomputes the minute arithmetic, and recomputes four direct-call censuses with their FDE frames. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: mapping `0x5b926e0` and the two map callees (bounded out); emulation (not allowed for this repository).

## Results and limitations

- Result: the sampler itself fills its list, one item per tag, through `0x4dc50c0` and `0x4da7e20`; every 15 s (the #5931 gate) it groups the items by a dword from each item and hands groups of 3 or more, or of 2 or more after 00:06 UTC, to `0x5b926e0`.
- Limits: the second storage mode, what observer `+0x200` and `+0x240` hold, what `0x5b926e0` computes, and why its vector is dropped are not mapped. The other sampler `0x5b298d0` is not checked for the same shape. Whether "seconds of day" is UTC follows #5045's clock label.
- Next lead: map `0x5b926e0` (callees `0x51360a0`, `0x5963a10`) and the observer fields `+0x200` and `+0x240`.
