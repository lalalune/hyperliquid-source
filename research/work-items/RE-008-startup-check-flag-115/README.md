# RE-008: node #115 startup check flag source, the .lz4 line-count branch and the second line-count caller (75th stage)

- Component ID: abci. Question: #6071 found that the startup state machine `0x2b41b70` runs the `replica_cmds` height check only when its future byte `+0x1` is 1, that the byte comes from poller `0x2aeaef0` stack `rsp+0x320`, that `.lz4` paths run a one-time setup on lazy cell `0x64f01c0`, and that the line count has a second caller `0x1563bc0`. It left their meaning open.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). Continues #5902 and #6071; imports only the merged `tools/freeze_snapshot_115.py` helper.
- Claim status: instruction bytes, offsets, constants, strings, relocations, Location records and call censuses are observations. "Mode", "join path", "replica_cmds check", "shared lazy cell" and "tolerance file" are inferred labels. The binary was not executed.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/startup_check_flag_115.py --check
python3 -m unittest tests.test_startup_check_flag_115
```

The tool reads the ELF only. The five `*.objdump.txt` files were made with GNU objdump 2.42 for review; the tool does not read them.

## Evidence 1: where the startup future's bytes +0x0 and +0x1 come from

| Step | Bytes | Effect |
|---|---|---|
| parent `0x2ae41e0` | `0x2ae4604` `c6 83 48 02 00 00 02`; `0x2ae5469` same with `01`; `0x2ae461d` `lea r14,[rbx+0x220]` | flag struct at `+0x220`, mode byte `+0x248` = 2 (tag 2) or 1 (tag 3); poller state = `+0x220` |
| parent `0x2cde430` | `0x2cde6d0` / `0x2cdf567` `mov byte [r13+0x248],2/1` | same for the second poller |
| poller entry | `0x2aeaf65` / `0x2aeaf69` | state `+0x28..+0x38` → `+0x38..+0x48` |
| setter argument | `0x2aebb0a`..`0x2aebb7b` | `[rbx+0x38]` → `rsp+0x3e3` → `rsp+0x180` → `[rbx+0xb5]`, so argument (`+0x90`) `+0x28` = state `+0x38` (mode), `+0x29` = state `+0x39` |
| carry | `0x2aebbaa`, `0x2aebc05`/`0x2aebc1d`, `0x2aebe97`, `0x2aebde4`/`0x2aebf45` | argument `+0x90` → `+0xd8` → `+0x118` → `+0xae8` |
| hand-off | `0x2aebfb3`/`0x2aebfbb`, `0x2aec10d`/`0x2aec116`, `0x2aec13a` | `+0xb10` (argument `+0x28`, 16 bytes) → `rsp+0x320` → `+0x1728` (startup caller state) |
| second poller | `0x2cb75d3` / `0x2cb7736` | same `+0xb10` → `+0x1728` |
| startup caller `0x2af0660` | `0x2af06c2` `movzx edx,[rbx]`, `0x2af06d9` `cmp dl,2`; `0x2af081c` `mov [rbx+0x28],dl`; `0x2af07ef`/`0x2af082f` bytes `+0x1..` → `+0x29..`; `0x2af087d` `[r12]` (= `rbx+0x28`) → future `+0x0` | byte 2 skips the startup future; otherwise future `+0x0` = byte `+0x0`, `+0x1` = byte `+0x1` |
| second caller `0x2cbbbe0` | `0x2cbbc47` / `0x2cbbc5e` `cmp cl,2` | same mode test |
| `0x2b41b70` | `0x2b41bcd` `test byte [rbx],1` / `je 0x2b41d2a`; `0x2b41bae` + `0x2b41d32` `cmp r12b,1` | bit 0 set → join path; clear → `replica_cmds` check iff `+0x1` == 1 |

So the future's byte `+0x0` is the parent's mode byte and `+0x1` is the byte after it (parent `+0x249`). With the only mode writers storing 1 or 2 (the four `mode_writers`), byte 2 never reaches the future and byte 1 has bit 0 set. Inference: on these two callers the startup future always takes the join path, and the `replica_cmds` check (#6069, #6071) is not reached. No byte store to parent `+0x249` was found on the tag paths.

## Evidence 2: the .lz4 branch

At `0x1500e71` the line count compares the last four path bytes with `0x347a6c2e` (`.lz4`). On a match it reads the state dword `0x64f01d8`; when it is not 0 it calls `Once::call` (slot `0x64df9f0`) on cell `0x64f01c0` and jumps back to `0x1500e89`, which loads `wc` / `-l` (`0x4659f2`) and builds the same shell command (#6071). The cell's value word is relocated to initializer `0x1568de0`; its Once Location is std `sync/once.rs`. The state dword is read 572 times in `.text`, so this is a shared lazy global, not an `.lz4` decoder. Inference: an `.lz4` file is counted with `wc -l` on its compressed bytes.

## Evidence 3: the second line-count caller

`0x1563bc0` is the only target of slot `0x64e1218`, called once at `0x2c7da78` in `0x2c7d950`. It forces the same lazy cell (`0x1563bd2`), calls the line count (slot `0x64e0958`, `0x1563bf0`) with Location `base/src/u.rs:388:11`, then formats `{}.tolerance` (`0x4388e5`) from the path and calls slot `0x64e09d8` → `0x1502320` with Location `base/src/u.rs:391:29`.

## Results and limitations

- Results: the startup check flag is the byte after the parent's mode byte; on the two known callers the join path is always taken; the `.lz4` branch only forces a shared lazy cell; `0x1563bc0` counts a file's lines and then handles a `.tolerance` companion path.
- Limits: the value of parent `+0x249` on the tag paths (no store found; union reuse at `+0x248` by 16-byte stores at `0x2ae5249`, `0x2ae677f` and others is not mapped); that `r13` keeps `rbx+0xae8` from `0x2aebde4` to `0x2aebf45` was checked by hand; the initializer `0x1568de0` body; `0x1502320` and the meaning of the `.tolerance` file; the caller `0x2c7d950`.
- No gate changes.
