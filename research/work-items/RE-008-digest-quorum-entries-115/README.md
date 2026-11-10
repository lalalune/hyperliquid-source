# RE-008: node #115 abci digest quorum entries (60th stage): where the step wrappers' 0x68-byte entries come from

- Component ID: abci. Question: #6023 found that the step wrappers `0x5a04e40` (layout A) and `0x5a06600` (layout B) walk 0x68-byte entries and compare each entry's `+0x48..+0x68` with the computed abci digest; #6042 found the slice at wrapper `[rsp+0x180]`. Where does that slice come from?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6023 and #6042. It imports the merged helpers in `tools/freeze_snapshot_115.py` and nothing from unmerged packets.
- Claim status: instruction bytes, offsets, constants, call censuses and FDE extents are observations. "Vec", "take", "pending store", "quorum digest", "dispatcher" and "drop glue" are inferred labels from call shapes, strides and earlier packets. The binary was not executed.
- Scope included: the wrapper result slot, the result copy in `0x54897e0`, the two Vec builders `0x5afa1f0` / `0x5afa030` and their B-twin calls, the entry drop glue, the store insert `0x5afa5d0` and its callers, and the store's membership in the hash input builder and serialiser. Scope excluded: the body of `0x4de1d80` / `0x4de0540` (what moves entries from the store map into the Vec), the body of `0x5afa5d0` past its map insert, the dispatcher cases that reach `0x54cae80`, and the meaning of entry fields other than `+0x0`, `+0x8`, `+0x20` and `+0x48`. No networking code was entered. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/digest_quorum_entries_115.py --check
python3 -m unittest tests.test_digest_quorum_entries_115
```

The tool reads the ELF only. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the slice is a field of one call's result

- A wrapper: `0x5a055a0` `lea rdi, [rsp+0x160]`, `0x5a055b0` `call 0x54897e0` (its only direct call). The compare loop reads the length at `0x5a05649` (`[rsp+0x188]`, result `+0x28`) and the pointer at `0x5a05671` (`[rsp+0x180]`, result `+0x20`), with stride `imul rdi, rbx, 0x68` at `0x5a05686`.
- B wrapper: `0x5a06da9` `lea rdi, [rsp+0x160]`, `0x5a06db6` `call 0x5486720` (its only direct call).

## Evidence 2: the result field is a Vec built from box `+0x3d98`

- `0x54897e0` calls `0x5afa1f0` at `0x548bf13` with `rdi = rsp+0xc0`, `rsi = box +0x3d98` (`0x548beed`), `rdx = rsp+0x220` (a time copied from box `+0x60`) and `rcx = box +0x3f08` (`0x548bef5`).
- It then calls `0x5afa030` at `0x548bf4b` with `rsi = box +0x3e50` and result `rsp+0x130`.
- Before returning it copies `rsp+0xc0..0xd8` to `rsp+0x48..0x60` (`0x548c019`..`0x548c02e`) and then writes result `+0x20` (pointer) and `+0x28` (length) at `0x548c22d` / `0x548c231`; result `+0x30..+0x48` carries the `0x5afa030` Vec.
- The B twin `0x5486720` makes the same two calls at `0x5488dd2` and `0x5488e0c` with box `+0x4908`, `+0x49c0` and `+0x4a78`, each 0xb70 above layout A (#6006).

## Evidence 3: what `0x5afa1f0` does

- `threshold = max(0, [store+0x78] - 1000)` (`0x5afa208`..`0x5afa214`).
- `call 0x4de1d80` (`0x5afa260`) with the store's map at `+0x60` and a context holding the time, the store, `&store+0x48`, `&store+0x88`, the aux pointer and the threshold.
- Takes the Vec at `store +0x48` and leaves `{0, 8, 0}` (`0x5afa26e`..`0x5afa287`).
- Keeps entries whose qword `+0x20` is non-zero (`0x5afa2b0`), moving kept entries down with a 0x68 stride (`0x5afa2f8`) and dropping the others through `0x5b0d830` on entry `+0x8`.
- `0x5afa030` has the same shape with `0x4de0540` as its fill helper.

## Evidence 4: entry layout

| Offset | Content | Source |
|---|---|---|
| `+0x0` | height (u64) | #6023 compare key |
| `+0x8` | owned buffer; `0x5b0d830` frees `len * 0x60` bytes (`0x5b0d88b`..`0x5b0d88f`) | drop glue |
| `+0x20` | qword; entries with 0 are dropped by `0x5afa1f0` | `0x5afa2b0` |
| `+0x48..+0x68` | quorum digest | #6023 |

The Vec drop glue `0x5626ce0` walks 0x68-byte elements (`0x5626d06`) and frees `cap * 0x68` (`0x5626d1f`).

## Evidence 5: the store is filled inside the engine

- `0x54cae80` calls `0x5afa5d0` with `rdi = box +0x3d98`, `rsi = box`, `rdx = box +0x3f08` (`0x54cb042`..`0x54cb058`), and `0x5afa3b0` with `box +0x3e50` (`0x54cb062`..`0x54cb078`).
- `0x5afa5d0` inserts into `store +0x60` through `0x4dbe1e0` (`0x5afa6da`, `0x5afa6eb`). Its direct callers are `0x54cb058` and `0x54ca888` (in `0x54ca6b0`, which passes box `+0x4908`).
- `0x54cae80` has five direct callers. Four are in the layout-A dispatcher `0x538cd30` (#6006) at `0x539200b`..`0x5392032`, with `esi = 0, 1, 2, 3`; the fifth is `0x54cf27f` in `0x54cf1b0`.
- Box `+0x3d98` and `+0x3e50` are also loaded by the abci hash input builder `0x4e34ce0` (`0x4e35128`, `0x4e35137`) and the rmp serialiser `0x5480950` (`0x54815ff`).

Inference: the entries are produced inside the engine state, written by the dispatcher path, kept in a store that is part of the hashed and serialised abci state, and handed to the step wrapper once `0x5afa1f0` moves them out. No networking boundary was reached on this path.

## Implementation and comparison

The tool pins 62 instruction byte runs, recomputes seven call censuses and checks nine FDE owners. Tests mutate one byte at a time in a copy of the image (8 mutation tests). Alternatives considered: tracing the store fill helper `0x4de1d80` in full (bounded out) and following the dispatcher cases (variant tables are out of scope for this series).

## Results and limitations

- Result: the wrapper's quorum entries are taken from an engine store at box `+0x3d98` (layout A) or `+0x4908` (layout B), after a 1000-height threshold step and a non-zero `+0x20` filter.
- Limits: what `0x4de1d80` / `0x4de0540` move from the store map into the Vec and how the threshold is used; the second Vec from box `+0x3e50` and its consumer; the meaning of entry fields `+0x8..+0x48` other than the buffer at `+0x8` and the qword at `+0x20`; which dispatcher cases reach `0x54cae80`; what `esi = 0..3` selects in `0x54cae80`; `0x54cf1b0`.
- Next lead: the fill helper `0x4de1d80`, to see which store entries reach the Vec relative to the threshold.
