# RE-008: node #115 shared value observer `0x1547530` (fourth stage): the window-record sink `0x1546570`

- Component ID: abci. Question: the third stage (open PR #5841) found that the observer passes a stack record (with the ×50 flag at `+0x17c`) and its state `+0x98` to slot `0x64e0f80` (`0x1546570`) at `0x15488a3`, and left open what that function does with them.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5045 (first stage), #5839 (second stage) and #5841 (third stage). It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, relocations, template and string bytes, the panic Location and the call censuses are observations. "Writer", "directory", "date", "hour", "rotate", "open" and "write" are inferred labels from the layout, the formatters and the call pattern. Reading the template byte `0xc0` as an argument slot is inferred, as in #5841. The binary was not executed.
- Scope included: all of `0x1546570` (FDE `0x1546570..0x15466f3`); the hour helper `0x1567ad0` fast path; the three formatter references; the observer code from the sink call to the end of its use (`0x154888a..0x1548a0b`) and the free at `0x154864f`. Scope excluded: the bodies of the open (`0x14c3b30`), drop (`0x154f2a0`), write (`0x14c3370`) and optional (`0x14c3c90`) callees beyond the open's panic Location; the record fields after `+0x8`; what sets `+0x142` and the global byte `0x64ffe50`; the other 103 sink call sites. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/abci_step_observer_record_115.py --check
python3 -m unittest tests.test_abci_step_observer_record_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The three `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the sink is a path-rotation check, not an exporter

`0x1546570` is small (387 bytes). It is reached only through slot `0x64e0f80` (`R_X86_64_RELATIVE` addend `0x1546570`): 104 `FF 15` calls in `.text`, no E8/E9. Arguments: `rdi` = a 0x20-byte result, `rsi` = a writer state (the observer passes its state `+0x98`), `rdx` = the record.

From the record it reads only two things: the dword at `+0x0` (`mov ebp, [rdx]` at `0x1546580`) and, in hourly mode, a byte returned by the hour helper (`mov rdi, rdx`; `call [0x64e0f58]` at `0x154659a`). It does not read the bucket fields or the ×50 flag byte at `+0x17c`.

From the writer state:

| Offset (writer) | Offset (observer) | Read as | Use |
| --- | --- | --- | --- |
| `+0x8` | `+0xa0` | 16 bytes (ptr, len) | directory, formatted by `0x15ebba0` (`mov rsi, [rdi]`; `mov rdx, [rdi+8]`; tail jump to the str Display slot `0x64df720`) |
| `+0x98` | `+0x130` | dword | cached date, compared with record `+0x0` |
| `+0xa8` | `+0x140` | byte, `cmp ..., 1` | hourly mode |
| `+0xa9` | `+0x141` | byte | cached hour, compared with the hour helper's result |

Decision:

- Hourly (`+0xa8 == 1`): if the hour equals `+0xa9` and the date equals `+0x98`, the result is None. Otherwise it formats template `0x43ab07` = `c0 08` `/hourly/` `c0 01` `/` `c0 00` with (directory, date, hour), and returns Some with `+0x4 = 1`, `+0x5 = hour`.
- Daily: if the date equals `+0x98`, None. Otherwise it formats template `0x43aa84` = `c0 01` `/` `c0 00` with (directory, date), and returns Some with `+0x4 = 0`.

Formatters (each passed as a `(value, fn)` pair to the format slot `0x64df6e8` → `0x141e3a0`): the date through slot `0x64e0b68` → `0x150ce90`, which loads the pattern `%Y%m%d` at `0x465bc9` with length 6; the hour through slot `0x64e0b70` → `0x150cf50`, a u8 decimal formatter using the two-digit table `00010203...` at `0x46ea12`. Inference: the paths are `{dir}/hourly/{YYYYMMDD}/{hour}` and `{dir}/{YYYYMMDD}`.

Result layout: `+0x0` date dword, `+0x4` hourly byte, `+0x5` hour byte (written only in hourly mode), `+0x8` the path String (cap, ptr, len). None is cap `0x8000000000000000` at `+0x8` (`movabs rax, 0x8000000000000000`; `mov [rbx+8], rax` at `0x154664c`/`0x1546656`).

## Evidence 2: the hour is seconds of day / 3600

`0x1567ad0` (FDE `0x1567ad0..0x1567b94`, slot `0x64e0f58`, 28 `FF 15` calls) loads the dword at record `+0x4` (`mov ecx, [rdi+4]`), multiplies by `0x91a2b3c5` and shifts right by 43. The tool checks for every value below 90000 that this equals `value // 3600`. It returns that byte when the value is below 90000 (`cmp ecx, 0x15f90`); larger values branch to panic paths that are not traced. Inference: the record starts with a date-time: a date dword at `+0x0` and seconds of day at `+0x4`.

## Evidence 3: what the observer does with the result

After `call [0x64e0f80]` at `0x15488a3` (result at `rsp+0x60`):

1. `cmp [rbx+0xe0], r15` with `r15 = 0x8000000000000000` at `0x15488ae`: the observer holds an optional object at `+0xe0` (writer `+0x48`).
2. No object: a None result skips (`je 0x1548657` at `0x15488ba`); a Some result frees its path (`jmp 0x154864f` at `0x15488ce`, then `call [0x64df4a0]`) and skips. Nothing is opened and nothing is written.
3. Object present and None result: jump to the write at `0x1548989` (`0x15488dd`).
4. Object present and Some result: call `0x14c3b30` through slot `0x64e0020` with the path (`0x154891f`), drop the old object with `0x154f2a0` (`0x1548928`), store the new 0x50 bytes at `+0xe0`, then cache date, hourly and hour at `+0x130`, `+0x140`, `+0x141` (`0x1548975`, `0x154897b`, `0x1548982`).
5. Write: `call 0x14c3370` at `0x15489bb` with the object, the record's first 12 bytes and `rsp+0xd8`; then store those 12 bytes at `+0x134..+0x140` (`0x15489ce`, `0x15489c4`).
6. If byte `+0x142` is not 0 and the byte at `0x64ffe50` (through `0x64e0f88`) is not 0, and the object is present, call slot `0x64e0038` → `0x14c3c90` (`0x1548a00`).

`0x14c3b30` (FDE `0x14c3b30..0x14c3c86`) has one `Result::unwrap` panic whose Location (`0x63f8e28`, loaded at `0x14c3bd9`) is `base/src/liner.rs`, line 28, column 38. Inference: the object at `+0xe0` is a `base` "liner" file writer, and the observer writes each window record as a line to a file that rotates per day, or per hour in hourly mode.

## Implementation and comparison

No Rust is added. The tool re-derives every address above from instruction bytes, the FDE index, relocations, template and string bytes and the Location record. Negative controls in `tests/test_abci_step_observer_record_115.py` change the hourly offset (`+0xa8` to `+0xa9`), the cached-date offset, the None niche, one template byte, the date pattern, the hour divisor constant, the hour limit, a cache store offset, the writer offset (`+0xe0` to `+0xe8`), the Location line (28 to 29), and turn the observer's slot call into a direct call. Each change fails the check (14 tests pass on the real image, none skipped).

## Results and limitations

Counts: 104 slot calls to the sink and 0 direct; 28 slot calls to the hour helper; 2 path templates; 3 formatters; 6 observer branches above. Denominators: E8/E9 rel32 and FF15/FF25 rip-relative in `.text`, plus `R_X86_64_RELATIVE` addends. No progress gate is requested.

Correction to the third stage: #5841 inferred that `0x1546570` receives the window record with the flag. It does receive the record pointer, but it reads only the date and time at `+0x0`/`+0x4`, not the flag at `+0x17c`. The write callee `0x14c3370` gets `rsp+0xd8`, a range that covers `+0x17c`; whether it reads the flag is not traced here.

Unknown: the record layout after `+0x8` and how `0x14c3370` serializes it, the bodies of the open/drop/optional callees, who sets `+0x142`, `+0xa8` and the directory, and what the global byte `0x64ffe50` is. The other 103 sink call sites share the same writer pattern; which loggers they belong to is not traced.

Next question: the write callee `0x14c3370` and the serialized line format of the window record.
