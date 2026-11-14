# RE-008: node #115 digest quorum entry builder `0x53779c0` (62nd stage)

- Component ID: abci. Question: the digest quorum store packets (open PRs #6046, #6048) found that the extract loop `0x51515f0` removes a height from the store map and calls `0x53779c0` to build each 0x68-byte quorum entry. They left open where the entry's 32-byte digest comes from, what the store delay `+0x88` is set to, and what the insert's `0x5376540(height - 50000)` call does.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6046 and #6048. It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, relocations, FDE extents and call censuses are observations. "Map", "B-tree", "ring", "collection", "key", "None", "clone" and "prune" are inferred labels from the access shapes. The binary was not executed.
- Scope included: all of `0x53779c0`; its call site in `0x51515f0`; the three writers of the store delay; the prune call site in the insert `0x5afa5d0`. Scope excluded: the bodies of the clone helpers (`0x583a870`, `0x52396c0`, `0x5856030`, `0x521b8a0`), the delay source `0x421e630` beyond its slot binding and result tag, the body of `0x5376540`, the second builder caller `0x57d4078` (in `0x57d3eb0`), and who fills store `+0x18`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/digest_quorum_entry_builder_115.py --check
python3 -m unittest tests.test_digest_quorum_entry_builder_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: the builder looks the height up in a second store map

`0x53779c0(rdi out, rsi store, rdx height)`; the extract loop calls it at `0x5151abb`.

- Store `+0x18` is tested for the `0x8000000000000000` niche (`mov rbx, [rsi+0x18]`; `neg`; `jno`).
  - Niche: a B-tree with u64 keys at node `+0x10`, length u16 at `+0x37a` and children at `+0x380`.
  - Otherwise: a ring with buffer `+0x20`, head `+0x28`, length `+0x30` and 0x50-byte elements, the value at element `+0x8` (`lea rcx, [rdx+rdx*4]`; `shl rcx, 4`; `add r15, 8`).
- Each value holds an inner map at `+0x0`, a byte at `+0x20` and a 32-byte key at `+0x21`. A non-zero byte returns None (`cmp byte [r15+0x20], 0`; `jne`).

## Evidence 2: the key selects two collections from the inner map

- The inner map is a B-tree (32-byte keys at `+0x2c0`, compared with length `0x20` through slot `0x64dfb50`; length u16 `+0x42a`; children `+0x430`) or a ring of 0x60-byte elements with the value at `+0x20`.
- A key that is not present returns None: `0x8000000000000000 + 1`.
- The value is two 0x20-byte collections. Each is cloned (B-tree or the other form) into the output.

## Evidence 3: the output is the quorum entry body

- Output `+0x0..+0x20`: clone of the first collection. `+0x20..+0x40`: clone of the second. `+0x40..+0x60`: the 32-byte key (`movups [r12+0x40]`, `[r12+0x50]` from `[r14]`).
- The extract loop skips a None result (`lea rax, [r15+1]`; `cmp [rsp+0x18], rax`).
- With the height in front, this is the 0x68-byte entry of #6046: entry `+0x48..+0x68` is the key stored with that height in store `+0x18`. It is not read from the engine's own digest map at `+0x400` (#6023), which is what the entry is later compared with.

## Evidence 4: the store delay

Store `+0x88` (box `+0x3e20` in layout A, `+0x4990` in layout B) is written at three places: `0x539025b`, `0x539b07b` and `0x28d0cde`. Each copies the f64 at `+0x8` of the result of slot `0x64e6ae8` (relocated to `0x421e630`) after the result tag equals `0x1a2`. Which inputs reach those three sites is not mapped here.

## Evidence 5: the prune call

The insert `0x5afa5d0` computes `max(0, height - 50000)` (`sub r13, 0xc350`) and calls `0x5376540(out, store, bound, ...)` at `0x5afa72f`. `0x5376540` has one other caller, `0x5afacce` in `0x5afa7f0`. Inference: it removes per-height records below the bound; its body is not mapped.

## Implementation and comparison

The tool pins 37 instruction byte runs, three slot calls, three result-tag checks, one relocation and two call censuses (FDE extents). Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests).

## Results and limitations

- Result: a quorum entry is built from a per-height record in store `+0x18` that names one 32-byte key; the key's two collections are cloned into the entry.
- Limits: what the two collections hold; who fills store `+0x18`; the second builder caller `0x57d4078`; the delay value source and its range check inside `0x421e630`; the body of `0x5376540`.
- Next lead: who writes store `+0x18`, starting from `0x5374b70`, which the insert calls first.
