# RE-008: node #115 freeze height, snapshot divisor and periodic snapshot path (31st stage)

- Component ID: abci. Question: open PR #5925 found that the engine step `0x5a08720` labels a snapshot `freeze` from box `+0x1c58`/`+0x1c60` and `periodic` from height % 10000, and tests a second divisor at box `+0x4538`. It left open who sets the freeze height and the divisor, and what the step does after it picks a label.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PR #5925. It does not depend on its files.
- Claim status: instruction bytes, constants, string bytes, relocations, jump-table entries, FDE extents and store or call censuses are observations. "Freeze height", "snapshot divisor", "action dispatcher", "error tag", "hour", "yesterday", "root directory" and "cleanup" are inferred labels from the field use, the strings and the call shapes. The binary was not executed.
- Scope included: the setter `0x54c9b80`; dispatcher cases 31 and 108 of `0x5397b50`; the freeze-path initializer `0x5620340`; the two loads of its slot and their writer calls; the step `0x5a08720` from `0x5a0887e` to `0x5a08ac7`. Scope excluded: the body of `0x1563fc0`, the rest of the dispatcher, how actions reach it, the bodies of `0x5443930`, `0x59ec200`, `0x5485f80`, `0x452aab0` and `0x5a046f0`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/freeze_snapshot_115.py --check
python3 -m unittest tests.test_freeze_snapshot_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: one setter for the freeze height

- A census of `mov [reg+disp32], ...` stores (no SIB) finds one store to `+0x1c58` (`0x54c9be2`, `mov qword [rsi+0x1c58], 1`) and one to `+0x1c60` (`0x54c9bed`, `mov [rsi+0x1c60], rdx`). Both are in `0x54c9b80`.
- `0x54c9b80` has one direct call, `0x5399650`, in `0x5397b50`. Jump table `0x9226b4` entry 31 is `0x5399631`, which loads the value from `[r15+8]` and jumps to `0x53a0010` (stores tag `0x154`) when it is `>= 0x0ccccccccccccccc`.
- The setter, with `rdx` = new height and `rsi` = box:

| Condition | Result |
|---|---|
| `+0x1c58 == 1` (Some) and new `>=` `+0x1c60` | tag `0x77`, old value |
| new `<` `+0x28` (height) | tag `0x76`, new value |
| new `>` `+0x28` + 50000 (saturating at `u64::MAX`) | tag `0x76`, new value |
| otherwise | store Some(new), tag `0x1a2` |

A setter entry Once check on `0x64f01d8` is not mapped.

## Evidence 2: one store for the snapshot divisor

- One store to `+0x4538`: `0x539e19c` (`mov [r13+0x4538], rcx`), in `0x5397b50`.
- Jump table entry 108 is `0x53982f3`. It loads the value from `[r15+8]`, sends `>= 0x0ccccccccccccccc` to tag `0x154`, keeps remainder 10000 when the value is above 10000, else computes `10000 % value` with `div ecx` (`0x539831f`). A zero remainder jumps to the store; any other remainder stores tag `0x155`.
- No compare against zero precedes `div ecx` in this block (see Limits).

## Evidence 3: the freeze height file path

- The cell `0x64fdd00` is relocated to `0x5620340`. That function checks the root cell `0x64f06c0` (slot `0x64e0918`) Once state at `+0x50`, passes `+0x18`, and formats template `0x445085`: argument, then `/hyperliquid_data/freeze_abci_height` (36 bytes).
- Slot `0x64ebc88` (relocated to `0x64fdd00`) is loaded only at `0x5443ab7` (in `0x5443930`) and `0x59ec3b5` (in `0x59ec200`). Each later compares a value with 9999999 and calls slot `0x64e09e8` (relocated to `0x15024a0`), whose code loads template `0x44b7f0` (`fu_write_string_to_file_tmp/`).
- Inference: these two functions write the freeze height to that file through a temporary file. When they write it is not mapped.

## Evidence 4: the step after the label

In `0x5a08720`:

1. `0x5a0887e` calls `0x5485f80`; `0x5a08919` calls `0x452aab0`.
2. `0x5a0892a` calls slot `0x64e0f58` (`0x1567ad0`, the hour helper named in #5849). Below 2 it jumps to `0x5a08a40`.
3. Otherwise it formats template `0x448b77` (argument, `/data/`, argument) with the root cell `+0x18` and the `&str` at `0x646e9f0` (relocated to `0x7a1572`, length 20: `periodic_abci_states`).
4. It calls slot `0x64e0aa0` (`0x16290d0`, the date addition named in #5861) with `-1`, then formats template `0x43aa84` (argument, `/`, argument).
5. `0x5a08a3a` calls slot `0x64e1220` (`0x1563fc0`) with that path and box byte `+0x170a`.
6. `0x5a08ac7` calls `0x5a046f0`.

Inference: once the hour is 2 or later, the step hands yesterday's `periodic_abci_states` folder to `0x1563fc0`.

## Implementation and comparison

The tool pins 45 instruction byte runs, 18 references, 8 relocations, 5 strings and one `&str` length, two jump-table entries, a store census for three offsets and the setter's call census. Tests mutate one byte at a time in a copy of the image and expect rejection (9 mutation tests). Alternatives considered: tracing the dispatcher's action decoder (bounded out); emulation (not allowed for this repository).

## Results and limitations

- Result: the freeze height has one setter, reached from one dispatcher case, and it accepts only a height between the current height and 50000 above it, lower than any freeze height already set. The snapshot divisor has one store and must divide 10000.
- Limits:
  - The body of `0x1563fc0` is not read; "cleanup" is only a label from the call's arguments.
  - The store census misses SIB forms, stack-based stores and whole-struct copies.
  - A zero divisor reaches `div ecx` with no visible zero check in this block; whether the decoder rules out zero is not mapped.
  - When `0x5443930` and `0x59ec200` write the file, and the setter's Once check on `0x64f01d8`, are not mapped.
  - Which actions reach dispatcher cases 31 and 108 is not mapped.
