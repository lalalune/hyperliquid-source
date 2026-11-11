# RE-008: node #115 output flags (15th stage): who holds the boxed setter result

- Component ID: abci. Question: #5908 showed that `0x548ce30` puts the output setter's 0xb70-byte result at `+0x7c0` of a new 0x4e38-byte allocation (here "the box") and returns it to `0x5a6bfb0`. It left open where the box pointer is kept and who reads box `+0x12a0` / `+0x12d8`, the two optional values with 15.0.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5902 and #5908. It does not depend on their files.
- Claim status: instruction bytes, offsets, sizes, immediates, strings, relocations and Location records are observations. "Box", "engine value", "runner", "shared allocation", "reference counts", "height" and "task name" are inferred labels from sizes, the `{1, 1, ...}` shape, strings and call shapes. The binary was not executed.
- Scope included: the box return in `0x548ce30`; `0x5a6bfb0` from the box return at `0x5a6c0af` to the `fast_height` call at `0x5a6c364`; the head and tail of `0x567bd50`; the first box check in `0x5a08720`. Scope excluded: the bodies of `0x567bd50` between head and tail, `0x4f1b280`, `0x567bc40`, `0x567bb70`, the rest of `0x5a08720`, and every reader of box `+0x12a0..+0x1318`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/output_setter_state_115.py --check
python3 -m unittest tests.test_output_setter_state_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the engine value

After `call 0x548ce30` (`0x5a6c0aa`), `0x5a6bfb0` keeps the box in `r14` (`0x5a6c0af`) and:

- reads box `+0x28` (`0x5a6c0b2`) and stores it in a new 0x18-byte block `{1, 1, value}` (`0x5a6c0b6 .. 0x5a6c0dc`);
- builds a 0x470-byte value at `rsp+0x1240`: the first 0x450 bytes are copied in (`0x5a6c132`), then box at `+0x450` (`0x5a6c10a`), the block at `+0x458` (`0x5a6c11a`), `0xf6401a` at `+0x460` (`0x5a6c140`), dword 0 at `+0x468`, byte 0 at `+0x46c` and `+0x46d`;
- calls `0x5a08720` with that value (`0x5a6c16a`). `0x5a08720` reloads the box from `+0x450` (`0x5a08737`), reads box `+0x28`, multiplies it by `0xd288ce703afb7e91`, rotates right by 4 and compares below `0x68db8bac710cc` (`0x5a08742 .. 0x5a08761`). The multiplier's inverse is 625, and `0x68db8bac710cc` is `floor((2^64-1)/10000) + 1`, so the test is `box+0x28 % 10000 == 0`. The tool recomputes this and checks it on eight sample values.

## Evidence 2: the runner `fast_abci_engine`

`0x5a6bfb0` copies the 0x470-byte value to `rsp+0x2b0` (`0x5a6c1cc`) and calls `0x567bd50` (`0x5a6c21c`) with:

- `rsi` = the value, `rdx` = `0x4519a0` `fast_abci_engine`, `ecx` = 16;
- `[rsp]` = Location `0x64b89d0`: `node/src/node.rs` (relocated pointer, length 16), line 608, column 9.

`0x567bd50` stores qword 0 at its `rsp+0x620` and copies 0x470 bytes from `rsi` to `rsp+0x628` (`0x567bd70 .. 0x567bd89`; `rsi` is not written before that call, checked by hand in `runner-head-567bd50.objdump.txt`). At the end it copies those 0x478 bytes to `+0x6a8` of its 0xb28-byte result (`0x567c0c7 .. 0x567c0dd`) and stores `1000000000` at `+0x128` (`0x567c165`). So in the runner the engine value is at `+0x6b0` and the box pointer at `+0xb00`.

## Evidence 3: the shared allocation and `fast_height`

`0x5a6bfb0` writes `{1, 1}` at `rsp+0x1240`, copies the 0xb28-byte runner after it (`0x5a6c2de`) and allocates 0xb38 bytes for the whole (`0x5a6c2ec`). The box pointer is then at allocation `+0xb10`. It calls `0x4f1b280` (`0x5a6c364`) with `rdi` = allocation `+0x140`, a `{0, 0x93afb9 "fast_height", 11}` argument and Location `0x64b89e8`: `node/src/node.rs` line 623, column 40.

## Implementation and comparison

The tool pins 40 instruction byte runs, two 64-bit immediates, 10 call or RIP-relative references, three strings and two Location records, and recomputes the divisor. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: a displacement scan for `+0x12a0..+0x1318` (it hits many unrelated structs, see Limits); emulation (not allowed for this repository).

## Results and limitations

- Result: the box with the setter result is owned by the engine value of the runner named `fast_abci_engine` (node.rs:608), inside a shared `{1, 1, runner}` allocation on which `fast_height` (node.rs:623) is registered. The engine reads box `+0x28` and tests it for a multiple of 10000. Reading box `+0x28` as a block height is an inference from the `fast_height` name.
- Not found: who reads box `+0x12a0` / `+0x12d8` and what 15.0 means. A scan for a load of the box pointer (`+0x450`, `+0xb00`, `+0xb10`) followed by an access at `+0x12a0..+0x1318` through the same register finds none, and neither does a scan for `lea reg, [base+0x7c0]` followed by `+0xae0..+0xb40`. The readers probably move the setter result out of the box first. This is open.
- Not mapped: the body of `0x567bd50` between the pinned head and tail, `0x4f1b280`, what `0x5a08720` does after the % 10000 test, and the use of `0xf6401a`.
- Next lead: map the rest of `0x5a08720`, which also reads box `+0x1c58` and `+0x1c60`, and the poll function of the runner.
