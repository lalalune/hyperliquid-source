# RE-008: node #115 shared height counter, which engine values check it (stage 83)

- Component ID: abci. Question: #6081 found that the slow engine input takes an Arc clone of the fast runner's height counter, and #6083 found that the step wrappers lock-increment that counter and assert it against the box height when engine value dword `+0x0` is 2. If both engines incremented one shared counter for the same block, the second increment would trip the assert. Which engine values actually run the check?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). Continues open PRs #6081 and #6083; imports only the merged `tools/freeze_snapshot_115.py` helpers.
- Claim status: instruction bytes, offsets, call sites, relocations and FDE extents are observations. "Arc", "strong count", "fast", "slow", "tag" and "assert" are inferred labels. The binary was not executed.
- Correction: #6083 listed the slow layout-A path as passing tag 2 (`0x5a6c3b6`). That store is followed by a reset to 0 (`0x5a6c52f`) before the input reaches the fill, so the slow engine value carries tag 0.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/shared_counter_steps_115.py --check
python3 -m unittest tests.test_shared_counter_steps_115
```

The tool reads the ELF only. The five `*.objdump.txt` files were made with GNU objdump 2.42 for review; the tool does not read them.

## Evidence 1: the check only runs for tag 2

| Wrapper | Tag test | Increment | Compare | Equal | Unequal |
|---|---|---|---|---|---|
| A `0x5a04e40` | `0x5a055f2 cmp dword [r12], 2` / `jne` skips | `0x5a05601 lock inc [[r12+0x458]+0x10]` | `0x5a0561a` counter vs box `+0x28` read at `0x5a055e6` | `0x5a0561d` → step `0x5a07ec0` (`0x5a05fc9`) | `0x5a0563e` slot `0x64e1e68` |
| B `0x5a06600` | `0x5a06e2a cmp dword [r15], 2` / `jne` skips | `0x5a06e37 lock inc [[r15+0x458]+0x10]` | `0x5a06e4f` counter vs box `+0x28` read at `0x5a06e1e` | `0x5a06e52` → `0x5a077d9` | `0x5a06e73` slot `0x64e1e68` |

## Evidence 2: the counter is one shared Arc

- `0x4fc1660` (fast_height, #6081): `0x4fc174c mov rax, [runner+0xb08]`, `0x4fc1753 lock inc [rax]` (strong count). The value is shared, not copied.
- `0x5a6bfb0`: the clone comes back in `r12` (`0x5a6c369`). The fresh `{1,1,box+0x28}` Arc at `rsp+0x1668` is released (`0x5a6c3c2 lock dec`, drop through slot `0x64e6eb0` at `0x5a6c3d0` when zero), and `0x5a6c3d6` stores the clone there. `rsp+0x1668` is slow input `+0x428`.
- The fast counter starts at the new box height: `0x5a6c0b2 mov r15, [rax+0x28]`, `0x5a6c0dc mov [rax+0x10], r15`.

## Evidence 3: fast tag 2, slow tag 0

- Fast: `0x5a6c0e0` stores 2 at `rsp+0xe20`, passed to the fill (slot `0x64e80e8` = `0x38c6590`) at `0x5a6c104`.
- Slow: `0x5a6c3b6` stores 2 at `rsp+0x1240`; `0x5a6c518`/`0x5a6c520` drop the old value unless it is 2; `0x5a6c52f` stores 0; `0x5a6c5cb`..`0x5a6c5d3` copy 0x438 bytes to `rsp+0x5508`; `0x5a6c5f8` calls `0x5a08f80`, which keeps the input in `rsi` and calls the fill at `0x5a08fbc`.
- Fill `0x38c6590`: `0x38c65aa cmp dword [rsi], 2`; on 2 it builds a fresh value with tag 2 (`0x38c65a1`), otherwise (`0x38c65ad jne`) it copies the input, keeping tag 0.

## Evidence 4: which runner reaches which wrapper

| Runner | Body | Reads | Chain |
|---|---|---|---|
| fast | `0x4fcb590` | byte `+0xb20` (`0x4fcb5b0`) | `0x4fcb795` → `0x56186c0` → `0x5618710` → wrapper B `0x5a06600` |
| slow | `0x4fcac10` | byte `+0xb40` (`0x4fcac4d`) | `0x4fcae48` → `0x59ec200` → `0x59ec2a8` → `0x56185e0` → `0x5618630` → wrapper A `0x5a04e40` |

`0x56185e0` has one more caller, `0x54439ad` in `0x5443930`. The tool recomputes the five caller censuses in one scan of `.text`.

## Result

The fast engine value (tag 2) increments and checks the shared counter on each step, starting from the new box height. The slow engine value (tag 0) holds the same Arc but skips the increment and the assert. So the two engines do not both increment the counter for one block, and the slow engine cannot trip the assert from this check (inference from the tags above).

## Limits

- Whether box `+0x28` as read at `0x5a055e6`/`0x5a06e1e` is the height before or after the block advances it is not mapped, so the exact off-by-one of the compare is not stated.
- That nothing rewrites `rsi` between `0x5a08f8f` and `0x5a08fbc` is checked by hand and by a byte-pattern test, not by data flow.
- The four non-incrementing reads of the counter (#6081), the catch-up wrapper's own check, and the `0x5443930` caller of `0x56185e0` are not mapped.
- No gate changes.
