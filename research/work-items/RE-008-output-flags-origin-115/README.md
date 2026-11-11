# RE-008: node #115 output flags (13th stage): where the flag struct comes from, and what setter byte `+0x18` does

- Component ID: abci. Question: #5883 mapped the output-flag reader `0x564d390`; #5892 showed that the pollers `0x2aeaef0` / `0x2cb6500` turn the struct at the start of their state into the setter `0x51cf360`'s argument, with setter `+0x18` = 0. Two points stayed open: whether that struct is the reader's output, and what setter `+0x18` controls.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5883 and #5892. It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, string bytes, relocations, the jump-table entries, FDE extents and the `[rsp+0x13]` byte census are observations. "Subcommand", "enum tag", "payload", "parent future", "Vec", "Option" and "None" are inferred labels from the call shapes and layout. The binary was not executed.
- Scope included: the two subcommand matches that call the reader; the parent future `0x2ae41e0`'s copy, switch and two cases that call poller `0x2aeaef0`; every `[rsp+0x13]` access in the setter's FDE and the code at `0x51d0856`. Scope excluded: the code between the matcher's enum and the parent future's `+0x10`; the parent of poller `0x2cb6500` (`0x2cde430`); the users of setter output `+0xae0` / `+0xb18`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/output_flags_origin_115.py --check
python3 -m unittest tests.test_output_flags_origin_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The six `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the matcher writes the reader's struct at enum `+0x8`

| Subcommand | Match | Reader call (slot `0x64ebcb8` → `0x564d390`) | Tag |
|---|---|---|---|
| `run-non-validator` | `0x56550a2`: 16 bytes against `0x454460` (`run-non-validato`) and byte `+0x10` against `0x453cb0` (`r`) | `0x56550de`, `rdi = rbx+0x8` | `mov qword [rbx], 2` at `0x56550e4` |
| `run-validator` | `0x5654e03`: `run-vali` at `+0` and `alidator` at `+5` (two 8-byte XORs); `je 0x56551d8` | `0x56551e9`, `rdi = rbx+0x8` | `mov qword [rbx], 3` at `0x56551ef` |

## Evidence 2: the parent future passes the payload to the poller

In `0x2ae41e0`:

- `0x2ae4548`: `+0x10 .. +0x50` is copied to `+0xc0 .. +0x100`.
- `0x2ae4586`: the qword at `+0xc0` minus 2 indexes table `0x60411c` (values below 2 select case 12). Case 0 (tag 2) is `0x2ae45b7`; case 1 (tag 3) is `0x2ae5421`. Both are in the parent's FDE.
- Both cases copy `+0xc8 .. +0xf0` (0x28 bytes) to `+0x220 .. +0x248`, store a mode byte at `+0x248` (2 for tag 2, 1 for tag 3) and call the poller `0x2aeaef0` with `rdi = +0x220`.

So the poller's state `+0x0 .. +0x28` is parent `+0xc8 .. +0xf0`, which is `+0x8 .. +0x30` of the tagged value at parent `+0xc0`. Tags 2 and 3 and the payload offset `+0x8` are the same as in Evidence 1.

Inference: the parent's `+0x10` holds the matcher's tagged value, so the poller's flag struct is the reader's output. The code that moves the value from the matcher to the parent is not traced.

## Evidence 3: setter byte `+0x18`

- `0x51cf383`: `movzx eax, byte [rsi+0x18]`; `0x51cf387`: `mov [rsp+0x13], al`.
- Census: in the setter's FDE (`0x51cf360 .. 0x51d0f70`), the only `[rsp+0x13]` ModRM/SIB disp8 forms are this store and the test at `0x51d0856`.
- `0x51d0856`: `cmp byte [rsp+0x13], 0`; `je 0x51d08bc`.
  - Set: two 0x38-byte values are built at `rsp+0x218` and `rsp+0x250`. Each is a zero qword, the value 8, 16 zero bytes, the f64 15.0 (`0x402e000000000000`) and a zero dword.
  - Clear: both first qwords get `rbp + 1` (`0x51d08bc`).
- `0x51d09e3 .. 0x51d0a59`: the two values are copied to the setter's output `r15+0xae0` and `r15+0xb18`.

With #5892 (both setter callers pass `+0x18 = 0`), the set branch is not taken on those paths. Labels: the shape matches two `Option`s, each holding an empty `Vec` and 15.0, with `rbp + 1` as the None niche. `rbp` is not pinned at `0x51d08bc`.

## Implementation and comparison

The tool pins 61 instruction byte runs, 9 references (two reader-slot calls, two string references, the `je`, the table `lea`, two poller calls and one plain prefix), two slot relocations, two subcommand names, two jump-table entries and the 15.0 constant. It also recomputes the `[rsp+0x13]` census. Tests change one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: tracing the matcher-to-parent move (bounded out); emulation (not allowed in this repository).

## Results and limitations

- Result: `run-non-validator` and `run-validator` both feed the reader's struct, as enum payload `+0x8`, into the parent future. The parent passes those 0x28 bytes to the poller that builds the setter argument. Setter `+0x18` builds two optional values with the 15.0 constant, and it is 0 on both mapped paths.
- Limits: the matcher-to-parent move is not traced (inference above). The parent of `0x2cb6500` is not mapped. `rbp` at the clear branch is not pinned. The meaning of 15.0 and the readers of output `+0xae0` / `+0xb18` are not mapped. The census is a byte pattern; it misses wider loads that cover `rsp+0x13`.
- Next lead: map who reads setter output `+0xae0` / `+0xb18`, and the parent `0x2cde430` of `0x2cb6500`.
