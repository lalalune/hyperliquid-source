# RE-008: node #115 engine value tag, height assert and 3.0 s gate (stage 82)

- Component ID: abci. Question: #6081 found that both step wrappers increment and check a shared height counter when the engine value's dword `+0x0` is 2. It left open which engine values have tag 2, what the mismatch slot does, and what the 3.0 s path in the `fast_height` read does.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). Continues #6064 and #6081. Imports only the merged `tools/freeze_snapshot_115.py` helpers.
- Claim status: instruction bytes, relocations, strings, Location records and call censuses are observations. "Tag", "assert_eq", "log level" and "lazy cell" are inferred labels. The binary was not executed.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/engine_tag_counter_115.py --check
python3 -m unittest tests.test_engine_tag_counter_115
```

The tool reads the ELF only. The four `*.objdump.txt` files were made with GNU objdump 2.42 for review; the tool does not read them.

## Evidence 1: the fill keeps the input tag

`0x38c6590` is reached only through slot `0x64e80e8` (`R_X86_64_RELATIVE`), with three slot calls: `0x2d2760c` (in the catch-up shim `0x2d275d0`), `0x5a08fbc` (in the layout-A builder `0x5a08f80`) and `0x5a6c104` (in `0x5a6bfb0`). It has no direct caller.

- `cmp dword [rsi], 2` at `0x38c65aa`. When equal, it copies a local whose first qword is 2 (`0x38c65a1`); otherwise it copies the input (0x420 bytes).
- The copy becomes output `+0x0..+0x420` (`0x38c666c`), so the output tag equals the input tag.
- It registers `abci_engine` (11 bytes) with `true` (4 bytes) when the tag is 2, else `false` (5 bytes): `sete r14b; xor r14, 5; cmove rsi, rax`.

## Evidence 2: every path passes tag 2

| Path | Tag store | Into the fill |
|---|---|---|
| fast engine value | `0x5a6c0e0`: qword 2 at `rsp+0xe20` | `lea rsi,[rsp+0xe20]` then slot call `0x5a6c104` |
| slow (layout A) | `0x5a6c3b6`: qword 2 at `rsp+0x1240` (#6081) | direct call `0x5a6c5f8` to `0x5a08f80`, which calls the fill at `0x5a08fbc` |
| catch-up | `0x2b1e1d9`: qword 2 at `rsp+0x200` | `lea r12,[rsp+0x200]; mov rsi,r12`, direct call `0x2b1e1f8` to the shim, which calls the fill at `0x2d2760c` |

That `0x5a08f80` and `0x2d275d0` pass their own `rsi` to the fill unchanged was checked on the listing (no write to `rsi` between entry and the slot call); the tool pins the call sites, not that range. So every engine value built through the fill has tag 2, and the #6081 counter check runs in every step wrapper.

## Evidence 3: the mismatch is an equality assert that panics

- Slot `0x64e1e68` is relocated to `0x167bbeb`, a trampoline that stores the two value pointers and calls slot `0x64e1810` (relocated to `0x1680d35`).
- `0x1680d35` loads the template `assertion `left … right` failed` (`0x4338f7`, and `0x4317ce` with a message).
- Both wrappers pass `edi = 0`, `ecx = 0` and Location `l1/src/abci/engine.rs:262:17`. Reading: `assert_eq!(height, counter)`, which panics on mismatch.
- Seven slot calls reach `0x64e1e68` in all; only the two wrapper calls are bound here.

## Evidence 4: the 3.0 s path in the fast_height read

In `0x4fc1660`, when wait + hold (f64 seconds) is above 3.0 (`0x459608`):

1. It loads the root cell `0x64f06c0` through slot `0x64e0918`; if its state dword `+0x50` is not 0 it runs the Once path first.
2. It reads byte `+0x48` and tests it against mask `0x10078c000` (values 14, 15, 19, 20, 21, 22, 32).
3. On a hit, when lazy cell state `0x64f01d8` is not 0, it forces that cell through slot `0x64df9f0`, then jumps to the return at `0x4fc18fd`.

No string is loaded on this path in this function. Reading: a log-level gate whose emit is not present in this build (inference).

## Results and limitations

- Result: all three engine-value paths use tag 2, so the shared counter is incremented and asserted against the box height on every step; a mismatch panics at `engine.rs:262:17`.
- Limits:
  - whether the fast and slow engines increment the same counter object at run time without tripping the assert (both take tag 2 and #6081 shares the Arc) is not resolved here;
  - the other five callers of slot `0x64e1e68`, the meaning of the root cell byte `+0x48` and of lazy cell `0x64f01c0`, and the non-2 branch of the fill (no caller reaches it) are not mapped.
- Gates: no progress gate requested.
