# RE-008: node #115 shared value observer `0x1547530` (seventh stage): who builds line writers and where they are stored

- Component ID: abci. Question: the sixth stage (open PR #5861) found that the observer constructor `0x1548bb0` stores both writer states (`+0x98`, `+0x148`) as None, and that the observer skips its path check and write while a state is None. It left open what ever fills those states, and where a writer's directory comes from.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5849, #5854, #5859 and #5861. It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, string bytes, relocations, FDE extents and call or copy censuses are observations. "Writer", "daily", "hourly", "root directory", "lazy cell", "None", "parent struct" and "next to, not inside" are inferred labels from the call shapes, sizes, strings and layout. The binary was not executed.
- Scope included: the head of the daily writer constructor `0x1546700` up to its first callee; the hourly byte store in `0x1546000`; the root cell `0x64f06c0` relocation and the one template its initializer formats; the call census of the three constructor slots; the writer and observer copies in `0x51c9cb0` and `0x5a6bfb0`; a census of 0xb0-byte copies. Scope excluded: the rest of both writer constructors, the body of the root initializer `0x17785f0`, the two other functions that call both constructors (`0x2af45f0`, `0x2cc1120`), and the 18 functions that build writers without an observer. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/abci_step_observer_logdir_115.py --check
python3 -m unittest tests.test_abci_step_observer_logdir_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: two writer constructors

| Slot | `R_X86_64_RELATIVE` target | `call [rip+slot]` sites |
|---|---|---|
| `0x64e0f98` | `0x1546700` (daily) | 32 |
| `0x64e0fa0` | `0x1546000` (hourly) | 27 |
| `0x64e1020` | `0x1548bb0` (observer constructor) | 35 |

The 59 writer calls sit in 22 functions (FDE extents). The hourly constructor stores `1` to writer `+0xa8` at `0x1546046` (`c6 83 a8 00 00 00 01`); the sixth stage read `+0xa8` as the hourly byte.

## Evidence 2: the daily constructor's directory

- `0x154673b` `cmp byte [r14+r15-1], 0x2f` and `0x1546747` `cmp byte [r14], 0x2f`: a name whose last or first byte is `/` branches to `0x154698a` and skips the build path. What `0x154698a` does is not mapped here.
- `0x1546758` loads slot `0x64e0918`, which is relocated to the cell `0x64f06c0`. The constructor checks the dword at `+0x50` and passes `+0x18` with display function `0x15433a0` as the first format argument.
- `0x1546799` loads template `0x448b77`, bytes `c0 06 2f 64 61 74 61 2f c0 00`: argument, `/data/`, argument. The second argument is the name.
- `0x15467ba` loads `0x466d9c` `daily_liner` with `mov edx, 0xb` (11 bytes) and passes it to the callee through slot `0x64e0fb0`.

## Evidence 3: the root cell

The value word of `0x64f06c0` is relocated to `0x17785f0`. That function formats template `0x43de2f`, bytes `c0 05 2f 63 6f 64 65`: argument then `/code` (`0x177866c`). The rest of the initializer is not mapped here.

## Evidence 4: writers are stored next to observers, not inside them

Four functions call both a writer constructor and the observer constructor: `0x2af45f0`, `0x2cc1120`, `0x51c9cb0`, `0x5a6bfb0`. In the two mapped here:

- `0x51c9cb0` builds three observers and one daily writer, then copies them into the struct at `r12`: observers (`mov edx, 0x260`) to `+0x0`, `+0x260`, `+0x4c0`; the writer (`mov edx, 0xb0`, from `rsp+0x58`, the daily constructor's output at `0x51c9e3e`) to `+0x720`. `+0x720` is `3 * 0x260`, the first byte after the third observer.
- `0x5a6bfb0` calls the daily and hourly constructors twice each, then the observer constructor, and copies the observer to `rsp+0x1260` (0x260 bytes) and two writers to `rsp+0x14c0` and `rsp+0x1570` (0xb0 bytes each). `0x14c0` is `0x1260 + 0x260`, the first byte after the observer.

## Evidence 5: 0xb0-byte copy census

The tool finds every `ba b0 00 00 00` (`mov edx, 0xb0`) in `.text` and decodes a `lea rdi, [base+disp]` in the 24 bytes before it.

- 1189 such moves; 571 with a decodable `lea rdi`.
- Copies to a non-stack base at a displacement congruent to `0x98` or `0x148` modulo `0x260`: exactly two, `0x1548dad` (`+0x98`) and `0x1548dc4` (`+0x148`). Both are in the observer constructor and copy the None states (sixth stage).

Inference: no code path found copies a built writer into an observer's writer state. The census is a byte pattern, not a data-flow proof (see Limits).

## Implementation and comparison

The tool pins 22 instruction byte runs, 15 RIP-relative references, 5 relocations, two templates and one name, then recomputes the censuses. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: tracing each of the 59 writer calls by hand (bounded out); emulation (not allowed for this repository).

## Results and limitations

- Result: the observer's writer states start as None and the census finds no other 0xb0 copy into them. In the two mapped mixed functions, writers are separate fields next to the observers. This is consistent with the sixth stage's None skip being the normal path.
- Limits: the census misses copies by other sizes (for example 0xa8 copies of the writer tail, one seen at `0x2af5a22`), stores through a computed `rdi`, stack-based observers, and field-by-field stores. The functions `0x2af45f0` and `0x2cc1120` are not mapped. The `/` branch target `0x154698a`, the rest of the root initializer, and where the 18 writer-only functions keep their writers are not mapped.
- Next lead: map the two remaining mixed functions and the writer-only callers, and the name each passes.
