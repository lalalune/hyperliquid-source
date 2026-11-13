# RE-008: node #115 `fast_height` read and the shared height counter (stage 81)

- Component ID: abci. Question: #5916 found a call to `0x4f1b280` with the name `fast_height` (node.rs:623:40) on the shared `fast_abci_engine` runner allocation, and left its body unmapped. This packet maps what that call returns, where the result goes, and who reads and writes it.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). Continues #5916 and #6014.
- Claim status: instruction bytes, offsets, constants, strings, relocations, Location records and call censuses are observations. "Read lock", "Arc clone", "lock-order tracker", "height counter" and "fast/slow engine" are inferred labels. The binary was not executed.
- Scope included: `0x4f1b280` up to its tail jump, `0x4fc1660` up to its return, the `fast_height` call site and the slow-engine input build in `0x5a6bfb0`, the `+0x428 -> +0x458` move in `0x5a08f80`, and the counter block in both step wrappers. Scope excluded: the thread-local list walk in `0x4f1b280`, the level-gated path in `0x4fc1660`, the other four reads of `+0x458` in the wrappers, and which engine values carry tag `2` at run time. No gate changes.

## Reproduce

From the repository root:

```
python3 tools/fast_height_115.py --check
python3 -m unittest tests.test_fast_height_115
```

The tool reads the ELF only. It does not execute the binary and does not start objdump or readelf. The five `*.objdump.txt` files were made with GNU objdump 2.42 for review only.

## Evidence 1: `fast_height` is a tracked read that returns an Arc clone

- `0x4f1b280` has one direct caller, `0x5a6c364` in `0x5a6bfb0`. It is called with `rdi` = allocation `+0x140`, `rsi` = the runner (allocation `+0x10`), `rdx` = `{0, "fast_height", 11}`, `ecx` = 0 and the Location `node/src/node.rs:623:40`.
- When byte `[rdi+0x20]` is 0 it tail-jumps to `0x4fc1660` with (runner, name) at `0x4f1b30c`. Otherwise it walks a thread-local list of 0x38-byte entries first and then calls `0x4fc1660` at `0x4f1bace`, the only direct call to it. Reading the list as a lock-order tracker follows `base/src/lock_id.rs` from #6019 and is an inference.
- `0x4fc1660`:
  1. adds a reader (`+0x10`) to the lock word at runner `+0x6a8`, with a slow path that passes 1000000000;
  2. checks runner `+0x128` against 1000000000;
  3. clones the Arc at runner `+0xb08` (`lock inc [rax]`);
  4. releases the reader (`lock xadd` with `-0x10`);
  5. times the wait and the hold in f64 seconds (nanoseconds / 1e9) and enters a path gated by the level mask `0x10078c000` when their sum is above 3.0;
  6. returns the clone.
- Runner `+0xb08` is engine value `+0x458`, because the engine value sits at runner `+0x6b0` (#5916).

## Evidence 2: the slow engine gets the same counter

In `0x5a6bfb0`, right after the call:

- It builds a fresh `{1, 1, box+0x28}` Arc (`0x5a6c389`..`0x5a6c398`) and stores it at `rsp+0x1668`.
- It stores the box at `rsp+0x1660` and the word 2 at `rsp+0x1240`.
- It drops the fresh Arc (`lock dec` at `0x5a6c3c2`) and writes the `fast_height` clone to `rsp+0x1668` (`0x5a6c3d6`).
- It copies 0x438 bytes from `rsp+0x1240` and passes them to the layout-A builder `0x5a08f80` (`0x5a6c5f8`). That builder reads input `+0x420` (box) and `+0x428` and writes them to engine value `+0x450` and `+0x458`.
- The result is then passed to `0x5649680` as `node_slow_abci_engine` (#6010).
- So the slow engine value's `+0x458` is a clone of the fast engine's `+0x458`: both point at one Arc.

## Evidence 3: the wrappers increment and check it

Both step wrappers (A `0x5a04e40` at `0x5a055f2`, B `0x5a06600` at `0x5a06e2a`):

1. test dword `[engine value+0x0] == 2`;
2. if so, `lock inc` the u64 at `[+0x458]+0x10`;
3. read it back and compare it with box `+0x28` (the height);
4. on a mismatch, call slot `0x64e1e68` with Location `l1/src/abci/engine.rs:262:17`.

Reading this as an `assert_eq!` on the height is an inference.

## Implementation and comparison

The tool pins 40 instruction byte runs, 12 references, two Location records, the `fast_height` string, the 3.0 and 1e9 constants and the two call censuses. Eight mutation tests change one byte in a copy of the image and expect rejection.

## Results and limitations

- Result: `fast_height` is not a metric or a gauge. It is a one-time tracked read that clones the fast engine's height counter Arc so the slow engine shares it; each step wrapper whose engine value has tag dword 2 increments that counter and checks it against the box height.
- Limits: which engine values have dword `+0x0 == 2` at run time (the value is produced by the fill `0x38c6590`, not mapped here); the thread-local list in `0x4f1b280`; what the level-gated path after the 3.0 s check logs; the four non-incrementing reads of `+0x458` at `0x5a057ed`, `0x5a05c95`, `0x5a0701b` and `0x5a074c5`; and no separate lag threshold between the two engines was found.
