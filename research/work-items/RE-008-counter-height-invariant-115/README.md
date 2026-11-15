# RE-008: node #115 shared height counter: start value and compare order (stage 84)

- Component ID: abci. Question: #6081 found that the fast engine shares one height counter Arc with the slow engine, and #6085 found that only tag-2 engine values run the check (`lock inc` the counter, compare with box `+0x28`, assert on mismatch). This packet pins the off-by-one: what the counter starts at, and whether box `+0x28` at the compare is read before or after the step.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main). Continues #6083 and #6085. Imports only the merged `tools/freeze_snapshot_115.py` helpers.
- Claim status: instruction bytes, call targets, FDE ownership and the store census are observations. "Height", "counter" and "step" are labels from #5916, #6006, #6081 and #6085. The binary was not executed.

## Reproduce

```
python3 tools/counter_height_invariant_115.py --check
python3 -m unittest tests.test_counter_height_invariant_115
```

The four `*.objdump.txt` files are GNU objdump 2.42 windows for review; the tool does not read them.

## Evidence 1: the counter starts at the box height

In the engine builder `0x5a6bfb0`:

- `0x5a6c0aa` calls the box clone `0x548ce30`; `0x5a6c0af` keeps the result in `r14`.
- `0x5a6c0b2` `mov r15, [rax+0x28]` loads the new box's height.
- After a 0x18-byte allocation, `0x5a6c0cd`/`0x5a6c0d4` write strong = 1 and weak = 1, and `0x5a6c0dc` `mov [rax+0x10], r15` stores the height as the counter value.

So `counter_0 == h0`, the box height at build time.

## Evidence 2: the compare reads the height before the step

| Wrapper | Height load | Increment | Compare | Step call |
|---|---|---|---|---|
| B `0x5a06600` | `0x5a06e1e` `mov rax, [rdi+0x28]` | `0x5a06e37` | `0x5a06e4f` `cmp rax, rcx` | `0x5a077e1` → `0x5a08720` |
| A `0x5a04e40` | `0x5a055e6` `mov rax, [rax+0x28]` | `0x5a05601` | `0x5a0561a` `cmp rax, rcx` | `0x5a05fc9` → `0x5a07ec0` |

In B, `je 0x5a077d9` at `0x5a06e52` leads to the step call; a mismatch calls the assert slot `0x64e1e68` at `0x5a06e73`. The height load, increment and compare all come before the step call in both wrappers.

## Evidence 3: no height store before the compare or in the steps

The tool scans for 8-byte `mov [base+0x28], reg` (REX.W `89 /r`, disp8 `0x28`) with a base other than `rsp`/`rbp`:

| Range | Hits |
|---|---|
| wrapper A start to `0x5a055e6` | 0 |
| wrapper B start to `0x5a06e1e` | 0 |
| step A (whole FDE) | 0 |
| step B (whole FDE) | 0 |

A positive control finds the known store `0x5489135` `mov [rax+0x28], rcx` (an output struct in `0x54897e0`), so the scanner is not empty by construction.

## Result

- Invariant (bytes): the counter after increment must equal the box height read at wrapper entry. With `counter_0 == h0`, the n-th tag-2 check passes only if the box height is `h0 + n`.
- Inference: the box height is advanced outside both wrappers and both steps, between one wrapper call and the next; otherwise the first check would compare `h0 + 1` with `h0` and assert. The writer of box `+0x28` is not bound here.

## Limits

- The census covers one store shape (8-byte register store, disp8). SIB-addressed, disp32, `inc`/`add` and vector stores covering `+0x28` are not scanned in these ranges.
- The steps' callees are not scanned. If the height were advanced inside a step (after the compare), the first check would compare `h0 + 1` with `h0` and assert. That argument assumes the box read at `0x5a6c0b2` is the box the wrapper later reads (engine value `+0x450`, #6006/#6085); this packet does not re-pin that link.
- Who advances box `+0x28` is not mapped.
- No Rust is added and no gate changes.
