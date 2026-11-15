# RE-008: node #115 Locus `cls` clearinghouse lookup and the `ctr` counter flag (97th stage)

- Component ID: abci. Question: #6164 found that the tce handler `0x57c9f60` divides `[arg+0x38]` by 10000 and indexes Locus `cls` (0x510-byte elements at box `+0x7c8`, length `+0x7d0`). #6206 found that `0x5582180` loads `clearinghouses.rs:11:29` and increments Locus `ctr` (`+0xab0`) behind a local flag `[rsp+0x28]`. This stage binds what the `clearinghouses.rs` Location guards, the lookup arithmetic and checks, and the flag's writers.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). Continues open PRs #6164 and #6206; does not depend on their files.
- Claim status: instruction bytes, offsets, constants, string bytes, relocations, Location records, FDE extents and call or reference censuses are observations. "clearinghouse", "asset id", "local index", "list" and "flag" are inferred labels. The binary was not executed.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/clearinghouse_list_115.py --check
python3 -m unittest tests.test_clearinghouse_list_115
```

The tool reads the ELF only. The four `*.objdump.txt` files were made with GNU objdump 2.42 for review; the tool does not read them.

## Evidence 1: the Location records

| Record | File | Line:col | RIP-relative loads in `.text` |
|---|---|---|---|
| `0x648b990` | `l1/src/dex_registry/clearinghouses.rs` | 11:29 | 404 |
| `0x648b9a8` | `l1/src/dex_registry/clearinghouses.rs` | 17:33 | 152 |
| `0x64768a8` | `l1/src/perp_meta.rs` | 163:38 | 131 |

At every site read for this packet, `0x648b990` is passed to `Result::unwrap` failure (slot `0x64df6a0`, message `0x7d3212` "called `Result::unwrap()` on an `Err` value", length 0x2b) with error tag `0x156` stored just before.

## Evidence 2: the clearinghouse lookup (tce handler `0x57c9f60`)

1. `rbx = [rsi+0x38]`. `rdx:rax = rbx * 0x346dc5d63886594b`; `r12 = rdx >> 11`. That is `rbx / 10000` (the tool checks the constant on sample values).
2. `cmp r12, [box+0x7d0]` (`cls` length); `jae 0x57ca4b2` → error tag `0x156`, `Result::unwrap` panic at `clearinghouses.rs:11:29`.
3. Element = `[box+0x7c8] + r12 * 0x510`. `cmp r12, [element+0x50]`; mismatch → `0x57ca4a5`: Location `perp_meta.rs:163:38` passed to slot `0x64df830`.
4. `r13 = rbx - r12 * 10000`; `cmp r13, [element+0x10]`; `jae` → the same `perp_meta.rs:163:38` panic.
5. `[element+0x8]` indexed by `r13 << 5` (0x20-byte entries); byte `+0x1d` is read.

Inference: an id is `clearinghouse * 10000 + local`; each clearinghouse element records its own index at `+0x50` and owns a list of 0x20-byte entries at `+0x8/+0x10`.

## Evidence 3: the `ctr` flag in `0x5582180`

- `[rsp+0x28]` is set to 0 at `0x5582cb4` and `0x5583230`.
- At `0x55830d8`: if `[rsp+0x23] | [rsp+0x28]` has bit 0 set, the call is skipped. Otherwise `0x55817e0` is called (`0x5583117`, with `ecx = 0` and a value 2 at `rsp+0xb0`) and the flag is set to 1 (`0x5583120`/`0x5583122`).
- After the loop, `cmp [rsp+0x58], 0; setne al; test [rsp+0x28], al`; when both hold, Locus `ctr` (`+0xab0`) is incremented with saturation (`0x5583273`..`0x5583288`).

So within one call of `0x5582180`, `0x55817e0` runs at most once on this path, and `ctr` moves only when it ran and `[rsp+0x58]` is non-zero. This corrects #6206's wording that the condition is `r8 != 0`: the second operand is the stack word `[rsp+0x58]`.

## Evidence 4: callers

| Function | Direct calls | Containing functions |
|---|---|---|
| `0x5582180` | 4 | `0x54b66b0` (begin_block A), `0x5588d90`, `0x558b730` ×2 |
| `0x55817e0` | 4 | `0x5582180` ×2, `0x5588d90`, `0x55890d0` |
| `0x558b730` | 2 | `0x54b66b0` (begin_block A), `0x54d57b0` |
| `0x5588d90` | 19 | 17 functions including `0x54d57b0`, `0x557ac40` ×3, `0x5901dd0` |

## Results and limitations

- Results: the `clearinghouses.rs:11:29` site is the bounds `unwrap` on `cls`; ids split as `/10000` and `%10000`; the `ctr` flag is set once per call by the `0x55817e0` path.
- Limits: what `[rsp+0x58]` and `[rsp+0x23]` hold; what `0x55817e0` does; the meaning of entry byte `+0x1d`; the line 17:33 site (152 loads) is only counted; the roles of `0x558b730`, `0x5588d90` and `0x54d57b0` are not mapped (no strings found inside `0x558b730` and `0x5588d90`).
- Next lead: `0x55817e0`, the call that sets the flag.
