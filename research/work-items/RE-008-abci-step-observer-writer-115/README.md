# RE-008: node #115 shared value observer `0x1547530` (fifth stage): the line writer `0x14c3370`

- Component ID: abci. Question: the fourth stage (open PR #5849) found that the observer writes each window record with `call 0x14c3370` at `0x15489bb` into a `base` liner (`base/src/liner.rs`), and left open how the record is serialized and whether the ×50 flag at `rsp+0x17c` (third stage, #5841) is part of it.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5045, #5839, #5841 and #5849. It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, field-name bytes and lengths, relocations (including the `memcpy` GLOB_DAT symbol) and call targets are observations. "JSON", "serde", "ryu", "itoa", "BufWriter", "io::Error", "Option", "Display" and "flush" are inferred labels from the byte patterns (`{`, `"`, `:`, `,`, `}`, `null`, `true`/`false`, tag-1 checks, a 0x28-byte error box). The binary was not executed.
- Scope included: all of `0x14c3370`, `0x1548f40`, `0x14c37f0`, `0x14c3c90` and the flush gate `0x154ce40`; the value helpers' key branches; the lazy-open options in `0x14c3950`; the interval copy in `0x14c3b30`. Scope excluded: the bodies of `0x1533d60` (slow write), `0x1533e80` (flush), the f64 and u64 digit routines, the time Display `0x15608d0`, the interval global's initializer, and where the record fields are computed. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/abci_step_observer_writer_115.py --check
python3 -m unittest tests.test_abci_step_observer_writer_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: one line per record

`0x14c3370` (FDE `0x14c3370..0x14c34e5`, one direct caller: the observer at `0x15489bb`) gets `rdi` = the liner, `rsi` = the record's 12-byte time copy, `rdx` = the record (`lea rdx, [rsp+0xd8]` at `0x15489b0`).

1. Allocate a 0x80-byte buffer through slot `0x64df480` (`mov edi, 0x80` at `0x14c3384`).
2. Serialize the record into it with `0x1548f40` (`0x14c33c1`; its only direct caller).
3. On error: free the buffer and drop the 0x28-byte error box (`mov esi, 0x28` at `0x14c3422`); code 1 (`cmp rax, 1` at `0x14c33f7`) first drops an inner error with `0x14c4d00`. Nothing is written.
4. On success: append `0x0a` (`mov byte [rbx+rax], 0xa` at `0x14c345a`) and call the liner write `0x14c37f0` (`0x14c346d`) with the bytes.

## Evidence 2: the line is a JSON object with sixteen fields

`0x1548f40` (FDE `0x1548f40..0x15492b3`) writes `{` (`0x1548f60`), then for each field loads the name (`lea rsi`), its length (`mov edx`), the field address (`lea rcx, [rbx+off]`) and calls a value helper. It ends with `}` (`0x466d50`, length 1, through `0x153d250`).

| # | Name | Record offset | Helper | Value |
| --- | --- | --- | --- | --- |
| 1 | `time` | `+0x98` | `0x159ca40` | quoted string, Display `0x15608d0` |
| 2 | `total_n` | `+0x50` | `0x159b710` | u64 |
| 3 | `total_mean` | `+0x58` | `0x159c0f0` | f64, `null` if not finite |
| 4 | `n_buffer` | `+0x60` | `0x159b710` | u64 |
| 5 | `work_frac` | `+0x0` | `0x159c4f0` | Option<f64>, `null` if None or not finite |
| 6 | `mean` | `+0x68` | `0x159c0f0` | f64 |
| 7 | `med` | `+0x70` | `0x159c0f0` | f64 |
| 8 | `p90` | `+0x78` | `0x159c0f0` | f64 |
| 9 | `p95` | `+0x80` | `0x159c0f0` | f64 |
| 10 | `max` | `+0x88` | `0x159c0f0` | f64 |
| 11 | `std_dev` | `+0x90` | `0x159c0f0` | f64 |
| 12 | `bucket_mean` | `+0x10` | `0x159c4f0` | Option<f64> |
| 13 | `bucket_work_frac` | `+0x20` | `0x159c4f0` | Option<f64> |
| 14 | `bucket_n` | `+0x30` | `0x159bf00` | Option<u64>, `null` if None |
| 15 | `bucket_n_orig` | `+0x40` | `0x159bf00` | Option<u64> |
| 16 | `is_subsampled` | `+0xa4` | `0x1554100` → `0x159b8a0` | bool, `true`/`false` |

Value helpers: f64 masks the sign (`0x7fffffffffffffff`) and writes `null` when the rest is `>= 0x7ff0000000000000` (`0x159c1a5..0x159c1d9`), else calls slot `0x64e13d0` → `0x5d0e4c0`. Option<f64> checks tag 1 and loads the value from `+0x8` (`0x159c5a4`, `0x159c57d`), then the same check. Option<u64> checks tag 1 and calls `0x1599300` (a decimal writer with a two-digit table and 10000 steps), else `null`. The bool writer stores the dwords `true` or `fals` + `e` (`0x159b96a`, `0x159b994`, `0x159b98f`). The bool writer (`0x159b8a0`) shows the per-field framing: `,` unless the state byte says first (`0x159b8d5`), `"`, the escaped name through `0x159cbe0`, `"`, `:`; the other helpers call the same `0x159cbe0` (inference: same framing).

## Evidence 3: the ×50 flag is the field `is_subsampled`

The observer stores the flag at `rsp+0x17c` (`mov byte [rsp+0x17c], r15b` at `0x1548873`) and passes `rsp+0xd8` as the record. `0x17c - 0xd8 = 0xa4`, and the serializer's last field is `add rbx, 0xa4` (`0x1549221`), `call 0x1554100`, which loads the name `is_subsampled` (`0x466e2a`, length 13) and tail-jumps to the bool writer. So every line says whether the instance applies the ×50 scaling. Inference: the name means the values were sampled at 1 in 50.

## Evidence 4: buffered writes and a time-gated flush

`0x14c37f0` (FDE `0x14c37f0..0x14c389b`) gets the buffer through `0x14c3950`. That function opens the file lazily on first use with options `custom_flags 0, mode 0x1b6 = 0o666` (`movabs rax, 0x1b600000000` at `0x14c3976`), append = 1 (`0x14c3994`) and create = 1 (`0x14c3999`); the byte positions follow the std `OpenOptions` layout (inference).

- If the line fits the spare capacity (`cmp r15, rax` at `0x14c3819`), it is copied with `memcpy` (GLOB_DAT `0x64df508`). Otherwise slot `0x64e0010` → `0x1533d60` writes it; a returned error is dropped with `0x14c4d00` (`0x14c3894`).
- Then the gate `0x154ce40` (slot `0x64e0008`) runs on liner `+0x38` with the record time. It returns 1 (flush) when the stored date at `+0x40` is 0 (`0x154ce54`), or when the record time is later than the stored time plus the f64 interval at `+0x38`; the fallback deadline is `0x4679d0`, the same far-future constant as in #5839. On 1 it stores the record time (`0x154cfc6`) and flushes with `0x1533e80`; a flush error is dropped.
- At open (`0x14c3b30`) the interval is copied from a lazily initialised global at `0x64efce0` (`.data`, zero at rest; a nonzero state dword sends the open to an initialisation path) into `+0x38`, and the stored date at `+0x40` is set to 0, so the first line after a rotation is flushed.
- The observer's optional call `0x14c3c90` (fourth stage, step 6) is an unconditional flush of the same buffer; its error is also dropped.

## Implementation and comparison

No Rust is added. The tool re-derives every address above from instruction bytes, the FDE index, relocations, the dynamic symbol table and the field-name bytes. Negative controls in `tests/test_abci_step_observer_writer_115.py` change the flag store offset, the flag field offset, the flag name, another field name, a field offset, a field helper, the newline byte, the `null` literal, the `true` literal, the open mode and the flush-gate offset. Each change fails the check (13 tests pass on the real image, none skipped).

## Results and limitations

Counts: 16 fields; 1 direct caller each for the writer and the serializer; 5 value-helper kinds plus the time string. Denominators: E8 rel32 in `.text`; `R_X86_64_RELATIVE` and `R_X86_64_GLOB_DAT` entries. No progress gate is requested.

Correction carried from the fourth stage: #5841 said the flag is copied "unchanged into the window record". This stage confirms it is serialized, as `is_subsampled`.

Unknown: the interval value (the global's initializer is not traced), how the record fields are computed from the window bucket, the exact text of the time Display, the f64 digit routine, and the bodies of the slow write and flush. Error handling is observed only as "dropped" at the four call sites above; whether anything is logged inside the dropped paths is not traced.

Next question: the initializer of the interval global `0x64efce0` and where the record's percentile fields (`med`, `p90`, `p95`, `std_dev`) are computed.
