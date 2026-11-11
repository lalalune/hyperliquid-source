# RE-008: node #115 output flags (14th stage): where the setter's result goes, and the second parent future

- Component ID: abci. Question: #5902 showed that setter `0x51cf360` stores two optional values (an empty list and 15.0 each) at its result `+0xae0` and `+0xb18` when setter byte `+0x18` is set, and mapped the parent `0x2ae41e0` of poller `0x2aeaef0`. Two points stayed open: who reads result `+0xae0` / `+0xb18`, and the parent `0x2cde430` of the second poller `0x2cb6500`.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5892 and #5902. It does not depend on their files.
- Claim status: instruction bytes, offsets, sizes, relocations, the jump-table entries, the command-name bytes and FDE extents are observations. "Result", "state", "block", "box", "command name", "tag", "error" and "parent future" are inferred labels from the call shapes and layout. The binary was not executed.
- Scope included: the hand-off of the setter result in both pollers; its copies in `0x5a6bfb0` and `0x548ce30` up to the boxed allocation; the parent `0x2cde430`'s CLI call, copy, switch and two poller calls; the CLI wrapper `0x2b7b640`, the converter `0x564cce0` and the matcher's tag stores. Scope excluded: who reads the box at `+0x12a0` / `+0x12d8`; what the 15.0 means; the bodies of `0x163a4b0`, `0x564d700`, `0x165de90` (called by `0x2b7b640` before the converter). No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/output_setter_consumers_115.py --check
python3 -m unittest tests.test_output_setter_consumers_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The seven `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the setter result is copied three times and boxed

| Step | Where | Bytes |
|---|---|---|
| Setter call | `0x2aec025` / `0x2cb7645` (slot `0x64e7428`) | `rdi = rbx+0xb30` (`0x2aec013`, `0x2cb7633`) |
| Hand-off | `0x2aec3c2` / `0x2cb79e2` | `r12 = rbx` (`0x2aec369`, `0x2cb7989`); 0xb70 bytes from `r12+0xb30` to `rsp+0x3e0` / `rsp+0x730`; call slot `0x64e7440` (→ `0x5a6bfb0`) with `rsi` = that copy |
| `0x5a6bfb0` | `0x5a6c01d`, `0x5a6c08e .. 0x5a6c0aa` | `r14 = rsi`; 0xb70 bytes to `rsp+0x1240`; `call 0x548ce30` with `rsi = rsp+0x1240` |
| `0x548ce30` | `0x548ce9b`, `0x548d6f5 .. 0x548d852` | `r14 = rsi`; 0xb70 bytes to `rsp+0x7e0`; 0x1700 bytes from `rsp+0x20` to `rsp+0x1720`; allocate 0x4e38 bytes and copy 0x4e38 bytes from `rsp+0x1720` into it |

`rsp+0x7e0` is `rsp+0x20 + 0x7c0`, inside the 0x1700-byte block that starts the box. So the setter's result is at box `+0x7c0`, and its `+0xae0` / `+0xb18` are at box `+0x12a0` / `+0x12d8`.

A displacement scan for `+0x12c0` / `+0x12f8` (the 15.0 slot of each value) finds only `mov reg, [reg+0x12f8]` chains, which look like linked-node walks, not readers of these values. The readers are not mapped (Limits).

## Evidence 2: the second parent future `0x2cde430`

- `0x2cde52b`: `call 0x2b7b640` with `rdi = rsp+0x410`; `cmp dword [rsp+0x410], 0x10`; `je 0x2ce00c2`.
- `0x2cde5f9 .. 0x2cde631`: `rsp+0x410 .. +0x450` → `r13+0xc0 .. +0x100`.
- `0x2cde64b .. 0x2cde67a`: `[r13+0xc0] - 2` (12 when below 2) indexes table `0x60bfc0`. Tag 2 → `0x2cde67c`; tag 3 → `0x2cdf519`. Both are in the parent's FDE.
- Both cases copy `+0xc8 .. +0xf0` to `+0x220 .. +0x248`, store mode byte 2 (tag 2) or 1 (tag 3) at `+0x248`, and call `0x2cb6500` with `rdi = r13+0x220` (`0x2cde6f4`, `0x2cdf58b`).

This is the same shape as `0x2ae41e0` (#5902), with table `0x60bfc0` in place of `0x60411c`.

## Evidence 3: on this path the tagged value comes from the subcommand matcher

- `0x2b7b640`: `rbx = rdi` (`0x2b7b64c`). It builds the 7-byte string at `0x92a890` (`hl-node`) with two dword loads. If a result's first qword is `0x8000000000000001`, it stores `0x10` at `[rbx]`. Otherwise it calls slot `0x64e73c8` (→ `0x564cce0`) with `rdi = rsp+0x2a0` and copies 0x98 bytes from `rsp+0x2a0` to `rbx`.
- `0x564cce0`: `rbx = rdi` (`0x564ccf4`). It calls slot `0x64ebcb0` (→ matcher `0x5654bf0`) with `rdi = rsp+0x20`, rejects tag `0x10`, and copies `rsp+0x20 ..` to `rbx+0x0 ..` (`0x564ce92`, `0x564ceb2` and the stores before `0x564ceb5`).
- Matcher: `rbx = rdi` (`0x5654c01`); it calls the reader slot `0x64ebcb8` with `rdi = rbx+0x8` and stores tag 2 (`0x56550e4`) or 3 (`0x56551ef`) at `[rbx]`.
- objdump check (not done by the tool): in the matcher, `0x2b7b640` and `0x564cce0`, the only other writes to `rbx` are `mov rbx, rax` after each function's last `ret` (each FDE has an LSDA).

So for parent `0x2cde430`, the tag at `+0xc0` and the 0x28 bytes at `+0xc8` that reach poller `0x2cb6500` are the matcher's tag and the reader's struct. This closes, for this parent, the inference left open in #5902 for `0x2ae41e0`.

## Implementation and comparison

The tool pins 74 instruction byte runs, 23 references, 5 relocations, the command name, two jump-table entries and 8 FDE starts. Tests change one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: following the box to its readers (bounded out, see Limits); emulation (not allowed for this repository).

## Results and limitations

- Result: the setter's two optional values end up at `+0x12a0` / `+0x12d8` of a 0x4e38-byte box built by `0x548ce30`. The second parent future feeds poller `0x2cb6500` from the subcommand matcher's tagged value, with mode byte 2 or 1, as `0x2ae41e0` does for `0x2aeaef0`.
- Limits: the readers of box `+0x12a0` / `+0x12d8` and the meaning of 15.0 are not mapped. The box is returned by `0x548ce30`, and its later moves are not traced. The `rbx` write check is by objdump only. The functions `0x163a4b0`, `0x564d700` and `0x165de90` are named by address only. The matcher-to-parent path for `0x2ae41e0` is still not traced.
- Next lead: follow the box returned by `0x548ce30` in `0x5a6bfb0` (`0x5a6c0af` onward) to its owner, and find the readers of `+0x12a0` / `+0x12d8`.
