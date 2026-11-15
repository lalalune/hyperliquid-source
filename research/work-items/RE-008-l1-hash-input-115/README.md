# RE-008: node #115 l1 hash input and its callers (57th stage)

- Component ID: abci. Question: open PR #6038 found that the slow driver's hardfork_hashes message is {height, l1 hash}, computed by the timed BLAKE3 function `0x457cf60` behind the blocking helper `0x452aab0`. It left open what bytes the l1 hash covers and who else computes it.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6037 and #6038. It imports helpers from the merged `tools/freeze_snapshot_115.py` only.
- Claim status: instruction bytes, offsets, constants, relocation-free RIP targets, string bytes, FDE extents and direct-call censuses are observations. "BLAKE3", "serialised abci state", "root digest", "height" and "blocking" are inferred labels from earlier packets (#6024, #6030, #6037, #6038) and the call shapes. The binary was not executed.
- Scope included: all of `0x457cf60` up to its output store; the two `0x452aab0` → `0x457cf60` call sites; the argument records at the seven `0x452aab0` call sites; the hardfork_hashes worker `0x5484670` up to its call. Scope excluded: the bodies of `0x4e48ee0` and `0x5485a60`, the inputs at the five non-worker call sites, and the logging tail of `0x457cf60`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/l1_hash_input_115.py --check
python3 -m unittest tests.test_l1_hash_input_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the l1 hash is BLAKE3 over a hash and a digest

`0x457cf60` keeps its argument record in `r14` (`mov r14, rsi`) and its output in `rbx`.

1. It loads `ptr = [r14]` and `len = [r14+8]`, sets up a hasher from the IV at `0x457ae0`, calls the update slot `0x64df510` with `(ptr, len)` and the finalize slot `0x64df518` into `rsp+0x130`. Call that `H1`.
2. It copies 32 bytes from `[[r14+0x10]]` to `rsp+0x150`.
3. It sets up a fresh hasher from the same IV, updates it with `H1` (`mov edx, 0x20`), then with the 32 bytes from step 2 (`mov edx, 0x20`), finalizes, and stores the 32-byte result at `[rbx]` and `[rbx+0x10]`.
4. It then logs through template `0x431bda` (`computed l1 hash: `).

So `l1 = BLAKE3(BLAKE3(bytes) || digest32)`. The update and finalize slots are the BLAKE3 functions `0x160b3a0` and `0x160bcd0` named in #6024.

## Evidence 2: one helper, seven callers

- `0x457cf60` has two direct calls, `0x452ac61` and `0x452ad4f`, both in `0x452aab0`. Both pass `rdi = rbx` and `rsi = r15` unchanged, so the helper's caller supplies the record.
- `0x452aab0` has seven direct calls. Each is preceded by `mov edx, 1` and passes a 4-word record `{ptr, len, &digest32, &height}`:

| Call site | Function | Note |
|---|---|---|
| `0x2ad8dc1` | `0x2ad7140` | record at `rsp+0x350` |
| `0x2cae5c8` | `0x2cad9b0` | record at `rsp+0x40` |
| `0x2d26391` | `0x2d25620` | record at `rsp` |
| `0x54847aa` | `0x5484670` | hardfork_hashes worker (Evidence 3) |
| `0x5a080b9` | `0x5a07ec0` | layout-A step; the digest is the 32 bytes the A digest step `0x548dad0` wrote at `rsp+0x130` |
| `0x5a08919` | `0x5a08720` | layout-B step |
| `0x5a6812a` | `0x5a64aa0` | record at `rsp+0x370` |

## Evidence 3: the hardfork_hashes worker

`0x5484670`:

- `rbx = [rsi]` (the box) and `r15 = [rbx+0x28]` (the height).
- `0x4e48ee0` returns a Vec at `rsp+0x18`; `r14 = [rsp+0x20]` (ptr) and `r12 = [rsp+0x28]` (len). #6037 tied this path to the `serialized abci state` closure.
- Slot `0x64e7820` (`0x41c5140`, the abci root digest from #6030) writes 32 bytes at `rsp+0x80`, copied to `rsp+0x60`.
- The record is `{r14, r12, &rsp+0x60, &rsp+0x58 (height)}`.

So for hardfork_hashes, `l1 = BLAKE3(BLAKE3(serialised abci state) || abci root digest)`. Unlike the abci digest (#6024–#6036), which hashes a 59-slot tree, the l1 hash covers the whole serialised state in one pass and then binds it to that digest.

## Implementation and comparison

The tool pins 39 instruction byte runs, 8 RIP or rel32 targets and the log template, recomputes both call censuses, checks each helper call site's enclosing FDE and its `mov edx, 1`, and writes `evidence.json`. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: tracing the inputs at all seven sites (bounded out); emulation (not allowed for this repository).

## Results and limitations

- Result: the l1 hash formula, its one helper, the seven call sites and the worker's three inputs.
- Limits: the bytes hashed at the five non-worker sites are not traced. The A-step `bytes` come from `0x5485a60` (which calls the `hyperliquid_data` path builder `0x5942870` of #6001) but its body is not mapped. `0x4e48ee0`'s serialisation is taken from #6037, not re-derived. The B step's digest source at `0x5a08919` is not traced. The logging tail of `0x457cf60` is not mapped.
- Next lead: `0x5485a60`, and whether the steps' l1 hash bytes are the same serialised state as the worker's.
