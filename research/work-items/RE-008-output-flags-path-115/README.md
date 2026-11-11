# RE-008: node #115 output flags to the output setter's argument (twelfth stage)

- Component ID: abci. Question: the eleventh stage (open PR #5883) found that the flag reader `0x564d390` writes its flags at `+0x18 .. +0x24` and that the setter `0x51cf360` reads the same flags one byte later. It did not find the code between them and left setter bytes `+0x18` and `+0x23` unnamed.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5878 and #5883. It does not depend on their files; the reader lookups, the reader's struct writes, the setter's read block and the seven setter gates are pinned again here.
- Claim status: instruction bytes, displacements, run hashes, relocations and the branch targets are observations. "Poller", "future", "initial state", "argument", "struct" and "stack copy" are inferred labels from the code shape. That the 0x28-byte argument at future `+0x0` is the reader's output struct is an inference: the tool shows that, under that reading, all seven setter gates name the reader flag one byte lower, but it does not trace the argument from `0x5654bf0` into the future. The binary was not executed.
- Scope included: in both pollers that call the setter (`0x2aeaef0` and `0x2cb6500`), the initial argument copy, the String and flag loads, the build run that writes the setter struct, the four 0x40/0x28-byte copies to the setter's `rsi`, and the two calls. Scope excluded: the other branch at the style test (`[future+0x38] != 2`), the code between the build run and the `+0x118` reload, and how the future's `+0x0 .. +0x28` is filled. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/output_flags_path_115.py --check
python3 -m unittest tests.test_output_flags_path_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The three `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: two pollers, same conversion

The setter slot `0x64e7428` (`R_X86_64_RELATIVE` to `0x51cf360`) is called at `0x2aec025` (in `0x2aeaef0`) and `0x2cb7645` (in `0x2cb6500`). In both functions the conversion bytes are the same:

| Step | Poller 1 | Poller 2 | Bytes |
|---|---|---|---|
| Initial state copies the argument `+0x0 .. +0x28` to `+0x48 .. +0x70` | `0x2aeaf73` | `0x2cb6583` | identical |
| `lea r15, [rbx+0x78]`; String `+0x48` -> `+0x78`; `mov r13, [rbx+0x60]`; `movq xmm1, r13`; `movq xmm2, [rbx+0x68]`; `movzx ebp, byte [rbx+0x6c]`; `cmp byte [rbx+0x38], 2`; `je` | `0x2aeb5ad` | `0x2cb6bcd` | identical |
| Build run: String -> `+0x90`; `mov byte [rbx+0xa8], 0`; `movq [rbx+0xa9], xmm1`; `movd [rbx+0xb1], xmm2`; `mov [rbx+0xc8], bpl`; copy `+0x90` -> `+0xd8` -> `+0x118` (0x40 bytes each) | `0x2aebb0a` | `0x2cb712a` | 0x133 bytes, no jump, call or ret; the runs differ only in three scratch stack displacements, so each is pinned by SHA-256 |
| Reload `+0x118` (0x40) to the stack, then to `r13 = rbx+0xae8` | `0x2aebe97`, `0x2aebeed` | `0x2cb74b7`, `0x2cb750d` | pinned per poller |
| Copy `+0xae8` (`qword +0x20`, two xmm words = 0x28 bytes) to the stack, `lea rsi` to it, call the setter | `0x2aebfe9` | `0x2cb7609` | pinned per poller |

The `je` at `0x2aeb5dc` / `0x2cb6bfc` lands on the start of the build run.

## Evidence 2: the one-byte shift, from the displacements

The tool reads the displacements out of the pinned instructions:

- Argument base `0x48`; loads at `+0x60`, `+0x68`, `+0x6c` -> argument `+0x18` (8 bytes), `+0x20` (8 bytes, low 4 used), `+0x24` (1 byte).
- Struct base `0x90` (`lea r13, [rbx+0x90]`); stores at `+0xa8`, `+0xa9`, `+0xb1`, `+0xc8` -> struct `+0x18` (constant 0), `+0x19 .. +0x20`, `+0x21 .. +0x24`, `+0x38`.

So setter byte `s` = argument byte `s - 1` for `s` in `+0x19 .. +0x24`; setter `+0x18` is 0 on this path; the style byte goes to struct `+0x38`, past the 0x28 bytes the setter receives.

## Evidence 3: names

Joined with the reader's pinned lookups (`0x564d3a4 .. 0x564d544`) and struct writes (`0x564d5ad .. 0x564d628`):

| Setter byte | Source | Flag |
|---|---|---|
| `+0x18` | constant 0 | — |
| `+0x19 .. +0x1f` | argument `+0x18 .. +0x1e` | the seven `write-*` flags; each matches the setter's gate writer name (checked by the tool) |
| `+0x20` | argument `+0x1f` | `disable-output-file-buffering` (sets global byte `0x64ffe50`, #5878) |
| `+0x21` | argument `+0x20` | `batch-by-block` |
| `+0x22` | argument `+0x21` | `stream-with-block-info` |
| `+0x23` | argument `+0x22` | `serve-evm-rpc` |
| `+0x24` | argument `+0x23` | `serve-info` (not read by the setter) |

This confirms #5883's one-byte reading for the seven gates and the `+0x20` global byte, and names setter `+0x23`.

## Implementation and comparison

The tool pins five shared byte runs (one by two run hashes), three stack-copy runs per poller, the two setter calls, the two branch targets, 14 reader lookups with names, lengths and calls, the reader's struct-write block, the setter's read block and seven gates with their writer names. It derives the shift from the displacement bytes and refuses a result where any gate does not match the reader flag one byte lower. Tests change one byte at a time in a copy of the image and expect rejection (9 mutation tests). Alternative considered: tracing the argument from the subcommand enum into the future; bounded out.

## Results and limitations

- Result: in both pollers, the setter's argument is built by inserting a zero byte at `+0x18` and moving the reader flags up by one. Setter `+0x18` is 0 on this path, and setter `+0x23` is `serve-evm-rpc`.
- Limits: only the branch where `[future+0x38] == 2` is pinned; the other branch spills `xmm1`/`xmm2` to `[rsp+0x50]`/`[rsp+0x30]` and reloads them at `0x2aebafe` (not traced). The code between the build run and the `+0x118` reload has branches and calls that are not traced; a callee could write the struct through a pointer. Whether setter `+0x18` is ever non-zero on another path, what it means inside the setter (read at `0x51d0856`), and how the future's argument is filled from the subcommand payload are not mapped.
- Next lead: map setter `+0x18`'s use at `0x51d0856`, and trace the future's `+0x0 .. +0x28` from the `run-non-validator` / `run-validator` payload.
