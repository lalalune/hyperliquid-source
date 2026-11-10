# RE-008: node #115 last applied height from `replica_cmds` (73rd stage)

- Component ID: abci. Question: stage 72 (open PR #6067) found that the startup state machine `0x2b41b70` calls slot `0x64e7720` when its input byte `+0x1` is 1, and panics with "invalid starting height … last_applied_height=" when the starting height is below the result. It left open how the slot target computes that height.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues open PRs #6067 and #5883. It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, strings, relocations, Location records, FDE extents and call censuses are observations. "read_dir", "next_back", "take", "date dir", "line count" and "last applied height" are inferred labels from the call shapes, strings and constants. The binary was not executed.
- Scope included: `0x595b1a0`, its mapper `0x595b520`, the iterator step `0x543dab0` and the head of `0x5152d00`, the head of `0x1500e50`. Scope excluded: the bodies of the listing collectors `0x15b5b00`/`0x15b59e0`/`0x15b58c0`, the filter that makes a file "non-zipped", the `.lz4` branch of `0x1500e50`, the command run and output parse after the `wc`/`-l` arguments, and what sets input byte `+0x1`. No deletion code was read. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/replica_cmds_last_height_115.py --check
python3 -m unittest tests.test_replica_cmds_last_height_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: the outer function `0x595b1a0`

- Slot `0x64e7720` is relocated to `0x595b1a0`; its one call is `0x2b41d3c` (in `0x2b41b70`).
- It formats template `0x448b77` (`{}/data/{}`) with the root cell (slot `0x64e0918`, +0x18) and `0x64b6828` → `0x9383d2` `replica_cmds` (12 bytes), then lists the path through slot `0x64e0968` → `0x1501290` with Location `node/src/startup.rs:364:19`. `0x1501290` calls slot `0x64e0970` → `0x5c9ca30`, which calls `opendir` through GOT `0x64ec5f8` (`0x5c9cb83`). An Err returns tag 1.
- It builds an iterator over the listing with `+0x48` = 5 (`0x595b2b9`). The step `0x543dab0` calls `0x5152d00` (`0x543db40`), decrements `+0x48` (`0x543db5c`) and maps each item through `0x595b520` (`0x543db64`, its only direct call).
- `0x5152d00` decrements the length at `+0x40` and reads the handle at `+0x20` (`0x5152d0e`..`0x5152d1e`). Inference: `next_back`, so the walk starts at the largest name and takes at most 5 entries.
- It keeps the maximum of the Ok results (`cmovbe r14, r9` at `0x595b3a7`). With no Ok result it formats `0x439f32` "no end heights found {}" with the path.

## Evidence 2: the mapper `0x595b520`

1. Lists the entry (slot `0x64e0968`, `startup.rs:376:21`).
2. Descends to the last key of the listing (`0x595b5c0`..`0x595b68a`, child pointers at node `+0x118`, length at `+0x112`); an empty listing formats `0x44ea70` "no date_dirs {}".
3. Lists that child through slot `0x64e09d0` → `0x15021d0`; an empty result formats `0x439085` "no non-zipped flns {}".
4. Takes the last name from the back (`0x595b726` → `0x5152d00`).
5. Parses the name as a decimal u64 (`0x595ba84`..`0x595bb65`): an optional leading `+`, digits `0`–`9` (`add edx, -0x30; cmp edx, 9`), base 10 (`mov edi, 10` with `jo` on overflow); errors go to `0x4ece7b0`.
6. Calls slot `0x64e0958` → `0x1500e50` with the file path and `startup.rs:384:19`, and returns `name + count`, saturating at `u64::MAX` (`0x595bba9`..`0x595bbb3`).

## Evidence 3: the per-file count `0x1500e50`

- `cmp dword [rdi+rsi-4], 0x347a6c2e` (`0x1500e71`): a path ending in `.lz4` takes a separate branch (not mapped).
- Otherwise it builds the argument pair `0x4659f2` "wc" and `0x4659f4` "-l" (length 2 each) with the path. Inference: the count is the file's line count from `wc -l`.

## Result

Inference from the evidence: the last applied height is, over the newest 5 entries of `{root}/data/replica_cmds`, the maximum of (the newest child directory's newest non-zipped file name as a height + that file's line count). With file names being the first height in the file and one command per line, that is the height after the last recorded command.

## Implementation and comparison

The tool pins 17 instruction byte runs, 19 references, 9 relocations, 7 strings, 3 Location records, 4 FDE extents and the `opendir` GLOB_DAT symbol, and recomputes a one-pass call census. Tests change one byte at a time in a copy of the image and expect rejection (8 mutation tests).

## Limits

- The filter behind "non-zipped" (inside `0x15021d0` / `0x15b59e0`) and the `.lz4` branch of `0x1500e50` are not mapped.
- The `wc -l` command execution and the parse of its output are not mapped.
- What sets input byte `+0x1` of `0x2b41b70` (for example a flag from the #5883 reader) is not tied by bytes.
- The other call through slot `0x64e0958` (`0x1563bf0`) is not mapped.
