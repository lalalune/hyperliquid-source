# RE-008: node #115 slow abci step wrapper `0x59ec200` (45th stage)

- Component ID: abci. Question: open PR #6019 found that the slow driver's apply-block closure locks the slow runner and calls `0x59ec200` on the engine value. It left open what `0x59ec200` does around the layout-A step, when it writes `visor_abci_state`, and when it writes the freeze height file (the condition #5970 left out).
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6018 and #6019. It imports helpers from the merged `tools/freeze_snapshot_115.py` and does not depend on unmerged files.
- Claim status: instruction bytes, constants, string bytes, relocations, Location records, FDE starts and direct-call censuses are observations. "Engine value", "box", "height", "scheduled freeze height", "thread-local guard", "digest", "quorum", "save" and "changed" are inferred labels from the field use, the strings and the call shapes. The binary was not executed.
- Scope included: `0x59ec200` from entry to the freeze-file write and its assertion block; `0x56185e0`; the freeze reads, the step call, the result byte and the digest compare in `0x5a04e40`, and the head of its mismatch path. Scope excluded: the bodies of `0x5a07ec0`, `0x5942b40`, `0x4e4a740`, the rest of `0x5a04e40` and of `0x59ec200` after the freeze write. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/slow_abci_step_wrapper_115.py --check
python3 -m unittest tests.test_slow_abci_step_wrapper_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the call chain

| Function | Direct callers | Calls |
|---|---|---|
| `0x59ec200` | `0x4fcae48` only (#6019's closure body) | `0x56185e0` at `0x59ec2a8` |
| `0x56185e0` | `0x54439ad`, `0x59ec2a8` | `0x5a04e40` at `0x5618630` |
| `0x5a04e40` | `0x5618630` only | layout-A step `0x5a07ec0` at `0x5a05fc9` |

`0x59ec200` copies a 0x58-byte argument from `rdx`. Its word at `+0x50` is the engine value (`r13`), and the box is `[r13+0x450]` (#6008). `0x56185e0` sets a thread-local byte to 1 (`0x56185f8`), calls `0x5a04e40`, then clears the byte through `0x150bff0` (`0x561863f`).

## Evidence 2: the result byte is "the scheduled freeze height changed"

`0x5a04e40` loads box `+0x10e8` (Option tag) and `+0x10f0` (value) at `0x5a04ec3`/`0x5a04eca`, before the step. After the step it loads them again and computes `dl` (`0x5a05fd9..0x5a05fff`): if both tags are set, `dl = old value != new value`; otherwise `dl = old tag | new tag`. It stores `dl` at result `+0xf8` (`0x5a060d4`). The tool checks this rule on five samples: None→None 0, None→Some 1, Some→None 1, Some(h)→Some(h) 0, Some(h)→Some(h2) 1.

## Evidence 3: when `visor_abci_state` and the freeze height file are written

In `0x59ec200`, `cmp byte [rsp+0x3b8], 0` (`0x59ec2c7`) tests that byte (`0x3b8 - 0x2c0 = 0xf8`). Only when it is set does the wrapper build the visor value from box `+0x10`, `+0x10e8`, `+0x28`, `+0x60`/`+0x68` and call the `visor_abci_state` wrapper `0x5942b40` (`0x59ec380`). Inference: the slow driver writes `visor_abci_state.json` only on a block whose step changed the scheduled freeze height.

Then, for every block: when box `+0x10e8 == 1` (`0x59ec389`) and `+0x10f0 == +0x28` (`0x59ec3a2`), it formats the height in decimal and writes it through the freeze path cell (slot `0x64ebc88` → `0x64fdd00`, #5970) and the writer slot `0x64e09e8` → `0x15024a0` (`0x59ec4ef`). When the freeze height is below the height (`jb 0x59ed3db`), it panics with `assertion failed: freeze_height >= self.locus.context.height()` at `l1/src/exchange/exchange.rs:607:17`. This is the write condition #5970 listed under Limits.

## Evidence 4: the digest check in `0x5a04e40`

`0x5a04e40` compares 32 bytes at `r13+0x48..+0x68` with a second 32-byte value (`0x5a05d07..0x5a05d23`). When any byte differs (`jne 0x5a060ec`), it passes `/tmp/evm_db_bad_abci_digest` (27 bytes) and `/tmp/abci_state_bad_abci_digest.rmp` (35 bytes) to `0x4e4a740` with `edx = 1`, then panics through slot `0x64df6b8` with the template `computed abci digest at height={} {} does not match quorum value {}. Saved state at height={} ...`. The function also references `new abci digests reached quorum`. Inference: the step checks its state digest against a quorum value, and on a mismatch dumps state to `/tmp` and stops the node.

## Implementation and comparison

The tool pins 26 instruction byte runs, 16 RIP-relative or rel32 references, 3 relocations, 5 strings, one Location line and column, and 5 direct-call censuses. Tests change one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: tracing all of `0x5a04e40` (6072 bytes; bounded out) and emulation (not allowed for this repository).

## Results and limitations

- Result: the slow driver's step wrapper runs the layout-A step under a thread-local guard, writes `visor_abci_state` only when the scheduled freeze height changed, writes the freeze height file when the freeze height equals the height, panics when it is below, and dumps state and panics on a digest mismatch.
- Limits: where the second 32-byte digest comes from and what fills `r13+0x48`; the bodies of `0x4e4a740`, `0x5942b40` and `0x5a07ec0`; the code in `0x59ec200` after the freeze write (calls to `0x5a6db30`, `0x5a5c000`, `0x581a4f0` and others); the meaning of the thread-local byte; the other caller of `0x56185e0` (`0x54439ad`).
- Next lead: the quorum digest value compared at `0x5a05d23`: where it is read from and how the quorum is reached.
