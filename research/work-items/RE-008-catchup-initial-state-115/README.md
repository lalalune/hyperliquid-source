# RE-008: node #115 catch-up task: initial engine value, spawn and output (70th stage)

- Component ID: abci. Question: #6060 (69th stage) mapped the non-validator catch-up poll `0x2b1df60`. It calls a shim `0x2d275d0` once before its loop, and on catch-up it copies a 0x470-byte engine value out. It left open what the shim does, where the poll's starting value comes from, and who receives the value at the end.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6058 and #6060. The tool imports only the merged `tools/freeze_snapshot_115.py` helpers.
- Claim status: instruction bytes, offsets, constants, strings, relocations and call or reference censuses are observations. "Box", "Arc", "engine value", "singleton", "task cell", "future", "spawn" and "output" are inferred labels from layouts, sizes, strings and #5916/#6006/#6008. The binary was not executed.
- Scope excluded: the body of `0x2af45f0` (it builds the result whose `+0x380` becomes the box, and also builds the network-facing writers from #5874); the block receiver `0x2b149d0` (networking); the JoinHandle that awaits the task; `0x1560e30` beyond its template and panic text. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/catchup_initial_state_115.py --check
python3 -m unittest tests.test_catchup_initial_state_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only.

## Evidence 1: the shim is the layout-A builder with a different step

The tool compares 0x109 bytes at `0x2d275d0` with `0x5a08f80`, the layout-A engine value builder from #6008. 22 bytes differ, all inside six rel32 fields. Five of those fields resolve to the same target. The sixth is the step call at `0x2d2766f`: `0x2d25620` (the #6058 step) here, `0x5a07ec0` there.

So the shim:

1. reads the input's box `[in+0x420]`, Arc `[in+0x428]` and two bytes `[in+0x430]`, `[in+0x431]`;
2. fills 0x450 bytes through slot `0x64e80e8` (`0x38c6590`);
3. sets `+0x450` box, `+0x458` Arc, `+0x460` `0xf6401a`, `+0x468` 0, `+0x46c` and `+0x46d` the two bytes;
4. runs the step once and returns the 0x470-byte engine value.

`0x38c6590` copies the input's first 0x420 bytes. When the input's first dword is 2 (`0x38c65aa`) it registers the key `abci_engine` (11 bytes, `0x7a14dc`) with value `true`; otherwise with `false` (`0x38c65f1..0x38c65f9`: length `(tag == 2) ^ 5`). It registers through slot `0x64e11e0` → `0x1560e30`, which formats `{}::{}` (`0x440f12`) and references the panic text `Singleton already created: ` (`0x43777f`).

## Evidence 2: the poll's starting value

- The poll reads the task cell `+0x40`, writes 2 there, and takes the panic path if it already held 2 (`0x2b1e104..0x2b1e110`). It copies 0x350 bytes of the future to `rsp+0x670`.
- `rbx = [rsp+0x990]`, which is future `+0x320` (`0x2b1e18c`).
- The shim input is `+0x0` = 2, `+0x420` = that box, `+0x428` = a new Arc `{1, 1, [box+0x28]}`, `+0x430` = word 0 (`0x2b1e198..0x2b1e1d9`). The shim's only direct caller is `0x2b1e1f8`.

So the catch-up engine value starts from the box in the future, with tag 2. That tag selects the `abci_engine = true` singleton.

## Evidence 3: who builds and spawns the future

`0x2b41b70` builds it:

- It references the WARN message `running non-validator to get initial abci state for consensus` (`0x605fe1`, at `0x2b42331`).
- It calls `0x2af45f0` and copies its 0x3b8-byte result to `rsp+0x430` (`0x2b42442..0x2b4244f`). It stores result `+0x380` (`[rsp+0x7b0]`) at `[state+0x50]` (`0x2b42473`), then at future `+0x320` (`state+0x80` + 0x320, `0x2b42525`/`0x2b42597`).
- It names the task `initial_slow_state_for_join` (`0x60601e`, length 27 at `0x2b425cb`) and calls `0x2b3aba0` at `0x2b4261c`, the constructor's only direct call. The constructor copies the 0x350-byte future, sets state `0xcc` and loads vtable `0x6449fb0`. That vtable's first entry is relocated to the poll `0x2b1df60`, and the vtable's only `.text` reference is `0x2b3ac57`.

## Evidence 4: the poll's output

On catch-up the poll:

1. copies the 0x470-byte engine value from `rsp+0xd18` to `rsp+0x200` (`0x2b1ecb9..0x2b1ecc9`);
2. keeps the box from copy `+0x450` (`0x2b1ecd4`);
3. drops the rest through `0x2df7710` (`0x2b1ed02`). That function skips tag 2 and drops the maps at `+0x3e0` (l1, #6042) and `+0x400` (digest, #6023);
4. writes its task output: dword 1 at `+0x0`, the box at `+0x10`, 0x358 bytes (`0x2b1eef7..0x2b1ef63`).

So the task named `initial_slow_state_for_join` returns the caught-up box. Its digest and l1 maps are dropped.

## Implementation and comparison

The tool pins 47 instruction byte runs, 15 RIP-relative or call targets, 7 strings and 3 relocations. It recomputes the shim/twin comparison and a one-pass census of direct calls to the shim, the spawn constructor, the drop and the #6058 step, plus loads of the vtable and the task name. Tests mutate one byte at a time and expect rejection (8 mutation tests).

## Results and limitations

- Result: the catch-up task `initial_slow_state_for_join` starts from a box produced by `0x2af45f0`, builds a layout-A engine value with the `abci_engine = true` singleton, and returns the caught-up box as its output.
- Limits: what `0x2af45f0` builds and where its box comes from (it also builds network-facing parts and is out of scope); who awaits the task's output; the meaning of the two input bytes `+0x430`/`+0x431` (both 0 here); why `0x2df7710` has two other callers (`0x2b1f02f`, `0x2e043e1`).
- Next lead: the awaiting side of the `initial_slow_state_for_join` JoinHandle in `0x2b41b70`, and whether the returned box seeds the slow engine (#6010).
