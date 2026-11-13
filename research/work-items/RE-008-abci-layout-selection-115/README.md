# RE-008: which node #115 code reaches abci box layout A and layout B (37th stage)

- Component ID: abci. Question: #6006 found two layouts of the abci box. Layout A is the 0x42c8-byte box. Layout B is the 0x4e38-byte box that `0x548ce30` builds by inserting the 0xb70-byte output-setter result at `+0x7c0`. Paired functions (steps `0x5a07ec0` / `0x5a08720`, dispatchers `0x538cd30` / `0x5397b50`) differ only by `+0xb70` box displacements. #6006 left open which run reaches each layout, and one instruction pair it could not explain (`add reg, 0xb9b` in A, `add reg, 0x7c0` in B).
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). Imports `read_va` and `direct_calls` from the merged `tools/freeze_snapshot_115.py`.
- Claim status: instruction bytes, offsets, constants, relocations, FDE extents and call censuses are observations. "Layout A/B", "box", "poller", "engine value", "step" and "twin" are inferred labels. The binary was not executed.
- Scope included: the two slot calls of `0x5a6bfb0`; the B path and the A path inside `0x5a6bfb0`; the A wrapper `0x5a08f80`; the direct callers of both steps and their wrappers; the two dispatcher instruction pairs and their callees. Scope excluded: what poller byte `+0xb00` means, what the A step does with engine value `+0x46d`, the bodies of `0x5a04e40`, `0x5a06600`, `0x4fcb590` and their callers above. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/abci_layout_selection_115.py --check
python3 -m unittest tests.test_abci_layout_selection_115
```

The tool reads the ELF only. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files were made with GNU objdump 2.42 for review; the tool does not read them.

## Evidence 1: both pollers call the selector the same way

`0x2aec3ef` (in `0x2aeaef0`) and `0x2cb7a0f` (in `0x2cb6500`) both call slot `0x64e7440`, which an `R_X86_64_RELATIVE` entry points at `0x5a6bfb0`. Before each call: `movzx edx, byte [r12+0x2a1a]`, `mov rdi, rbp`, `mov rsi, r14`, where `r14` holds a 0xb70-byte copy of poller `+0xb30` (#5908). Both pollers fill `+0x2a1a` from poller `+0xb00` (`0x2aebfa6` → `0x2aebfdc`; `0x2cb75c6`).

## Evidence 2: one function runs both layouts

`0x5a6bfb0` (FDE `0x5a6bfb0..0x5a6c8ec`) keeps its arguments as `rbx = rdi` (the caller's box), `r14 = rsi` (the setter result), `ebp = edx` (`0x5a6c01b..0x5a6c020`). Then, in this order:

1. B path: `mov edi, 0x42c8` and allocate (`0x5a6c05d`), copy, copy 0xb70 bytes from `r14` (`0x5a6c096`), call `0x548ce30` (`0x5a6c0aa`). The returned box goes to `rsp+0x1690`, which is `+0x450` of the engine value at `rsp+0x1240` (`0x5a6c10a`), and the B step `0x5a08720` is called on it at `0x5a6c16a`.
2. A path: `rbx` is stored at `rsp+0x1660` (`+0x420` of the struct at `rsp+0x1240`, `0x5a6c39c`). 0x438 bytes are copied to `rsp+0x5508` (`0x5a6c5c3..0x5a6c5d8`). Only when `bpl` is non-zero, `+0x431` of the copy is set to 1 (`0x5a6c5db..0x5a6c5e0`). Then `0x5a08f80` is called (`0x5a6c5f8`). It reads `[rsi+0x420]` as the box and `[rsi+0x431]` as a byte (`0x5a08f92`, `0x5a08fa8`), writes the byte to engine value `+0x46d` (`0x5a0900c`) and calls the A step `0x5a07ec0` (`0x5a0901f`).

`0x5a08f80` has one direct caller (`0x5a6c5f8`) and `0x548ce30` has one (`0x5a6c0aa`). Inference: each call of `0x5a6bfb0` clones the caller's layout-A box into a layout-B box that carries the setter result, runs one B step on the clone and one A step on the original. The poller byte only sets a flag in the A step's engine value. So the choice of layout here does not depend on which poller (subcommand) is running.

## Evidence 3: the other step callers

| Function | Direct callers |
|---|---|
| A step `0x5a07ec0` | `0x5a05fc9` (in `0x5a04e40`), `0x5a0901f` (in `0x5a08f80`) |
| B step `0x5a08720` | `0x5a077e1` (in `0x5a06600`), `0x5a6c16a` (in `0x5a6bfb0`) |
| `0x5a04e40` | `0x5618630` (in `0x56185e0`) |
| `0x5a06600` | `0x5618710` (in `0x56186c0`) |
| `0x56185e0` | `0x54439ad` (in `0x5443930`), `0x59ec2a8` (in `0x59ec200`) |
| `0x56186c0` | `0x4fcb795` (in `0x4fcb590`) |

`0x5443930` and `0x59ec200` are the `node/src/node.rs:659:50` `visor_abci_state` writers that #6004 found reading the freeze height at `+0x10e8`, layout A's offset. That agrees with their reaching the A step.

## Evidence 4: the dispatcher pair is a dead argument

The pair #6006 could not explain occurs twice: `0x5395f86` `add rbx, 0xb9b` / `0x53a0da6` `add rbx, 0x7c0`, and `0x5396821` `add rbp, 0xb9b` / `0x53a1641` `add rbp, 0x7c0`. In each case the register becomes `rcx` for a call to `0x5490540` (A) or `0x54905d0` (B). These callees are 0x8e bytes each. Their bytes differ only at offsets 36, 37, 76, 77 and 116, which lie in the displacements of three `call [rip+x]` instructions that name the same slots (`0x64e6480`, `0x64df508`, `0x64e6488`). Their first 0x20 bytes are pushes, the frame and moves of `edx`, `rsi`, `rdi` and `rbx`; at `+0x20` both write `ecx` (`mov ecx, ebp`) before any use. So the fourth argument is never read, and the 0xb9b / 0x7c0 difference has no effect.

## Implementation and comparison

The tool pins 36 instruction byte runs and 10 call targets, checks the slot relocation, recomputes 10 direct-call censuses and the FDE extents of `0x5a6bfb0` and `0x5a08f80`, and compares the twin callees byte by byte. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests).

## Results and limitations

- Result: both pollers call one selector that runs layout B on a clone carrying the setter result and layout A on the caller's box. The A step is also reached from the `node.rs:659` writers; the B step from `0x4fcb590`'s chain. The dispatcher pair left open by #6006 sets an unused argument.
- Limits: what poller `+0xb00` and engine value `+0x46d` mean; whether `0x5a6bfb0` returns before the A path on an error path (only the straight path between the two calls is pinned, by instruction order and FDE extent); the callers above `0x4fcb590` (`0x4f122c0`, reached from `0x5a6e1e0`) and above `0x5443930` / `0x59ec200`; what the A twin's ignored `+0xb9b` points to.
- Next lead: what the A step does with engine value `+0x46d`, and what sets poller `+0xb00`.
