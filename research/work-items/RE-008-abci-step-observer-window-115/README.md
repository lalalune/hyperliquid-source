# RE-008: node #115 shared value observer `0x1547530` (second stage): 30-second window, constructor and ×50 flag

- Component ID: abci. Question: what does the observer behind slot `0x64e1010` do after its first stage (the `+0x228` section), and who sets byte `+0x25c` and qword `+0x1f8`?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PR #5045 (first stage, observer entry to `0x15478e8`). It does not depend on that PR's files.
- Correction to the first stage: #5045 labels `+0x60..+0x90` the "lifetime" bucket. This packet shows they are taken and reset on every rollover of a 30-second window (step 5 below). They are a per-window bucket, not a lifetime one.
- Claim status: instruction bytes, offsets, constants, relocations and the census are observations. "Window", "deadline", "mean", "date", "seconds" and "nanoseconds" are inferred labels from the arithmetic and layout. The helpers `0x15ed960`, `0x162a9a0` and `0x16290d0` are named by how their results are used, not by their bodies. The binary was not executed.
- Scope included: observer window `0x15478e8..0x1547b9c` (692 bytes); constructor FDE `0x1548bb0..0x1548f3d` from entry to its `ret` (window ends `0x1548e6f`, 703 bytes); the constructor slot census; the census of byte stores to `+0x25c`. Scope excluded: the observer after `0x1547b9c` (what it does with the taken bucket and the mean, from `0x1547dc1` and `0x1547b9c`), the helper bodies, the constructor's error paths after `0x1548e6f`, what `+0x0`, `+0x8`, `+0x10`, `+0x218`, `+0x238` and `+0x25d` mean, and what the 35 callers measure. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/abci_step_observer_window_115.py --check
python3 -m unittest tests.test_abci_step_observer_window_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The two `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence: observer window `0x15478e8..0x1547b9c`

On entry to this window `edi` holds the clock tuple's date (loaded from `[rsp]` at `0x154755f` and kept across the grow calls), `r13d` the seconds of day (`[rsp+4]`) and `r12d` the nanoseconds (`[rsp+8]`).

1. `0x15478f2..0x15478fa`: if dword `[rbx+0x228]` (window start date) is 0, jump straight to the rollover at `0x1547a83`.
2. Deadline length (`0x1547904..0x1547978`): f64 `[rbx+0x220]` is passed in `xmm0` to slot `0x64e0f70` (`R_X86_64_RELATIVE` to `0x15ed960`). The result `(rax, edx)` is combined as `rax * 1e9 + edx`, saturating at `i64::MAX` (`cmovae`, and `cmovne` on a carry), and split back into seconds (`mul` by `0x112e0be826d694b3`, `shr 26`) and nanoseconds.
3. Deadline time (`0x1547988`): slot `0x64e0f78` (`R_X86_64_RELATIVE` to `0x162a9a0`) gets the start time (seconds of day `+0x22c`, nanoseconds `+0x230`, copied to `rsp+0x84`) and the split length. It writes a time at `rsp+0xd8` and carried seconds at `rsp+0xe0`.
4. Deadline date (`0x1547996..0x1547a09`): two unsigned range tests keep the carried seconds in `(-9223372036854776, 9223372036854776)` and `[-185542587273599, 185542587187200)` (the second bound is `86400 * 2^31`). The seconds are divided by 86400 (`imul` by `0x1845c8a0ce512957`, `shr 13`, plus sign) and passed with the start date to slot `0x64e0aa0` (`R_X86_64_RELATIVE` to `0x16290d0`). If a range test fails or the call returns 0, the code at `0x1547a3d` uses the three dwords at `0x4679d0` instead: `(2147473118, 86399, 999999999)`. Inference: `2147473118` is `(262142 << 13) | (365 << 4) | 14`, a packed date for the last day of year 262142, so a deadline that cannot be built becomes "the largest time".
5. Compare (`0x1547a2f..0x1547a7d`): the deadline `(date, seconds, nanoseconds)` is compared with now. The date compare is signed (`setl`), the other two are unsigned (`setb`, `jb`). The code rolls over only when now is strictly later than the deadline; otherwise it jumps to the epilogue `0x154866c`.
6. Rollover (`0x1547a83..0x1547ae5`): store now at `+0x228` (date), `+0x22c` (seconds) and `+0x230` (nanoseconds). Take the vector (`+0x60` capacity, `+0x68` buffer, `+0x70` length) and the bucket (`+0x78` count, `+0x80` calls, `+0x88` sum, `+0x90` maximum) into registers. Reset `+0x60 = 0`, `+0x68 = 8` (an empty vector) and `+0x70..+0x97 = 0`.
7. Mean (`0x1547aed..0x1547b96`): no mean when the taken count is 0, when the sum is not finite (magnitude bits above `0x7fefffffffffffff`), when the sum is at most `-1e-15` (constant at `0x458fa0`), or when the result is not finite. Otherwise `mean = numerator / f64(count as u64)`, where the numerator is `0.0` for `-1e-15 < sum < 0` and the sum itself otherwise. A finite mean jumps to `0x1547dc1`; every other path reaches `0x1547b9c`.

## Evidence: constructor `0x1548bb0`

`0x64e1020` is an `R_X86_64_RELATIVE` slot with addend `0x1548bb0` and the only relocation that names it. No E8/E9 rel32 targets it. 35 `FF 15` calls (no `FF 25`) in `.text` go through the slot; the list is in `evidence.json`.

Arguments: `rdi` is the state (kept in `r14` and returned in `rax`), `esi` is a byte (`ebp`), `rdx`/`rcx` are a name pointer and length (copied to `+0x30`, length at `+0x28` and `+0x38`), `xmm0` is an f64 that is multiplied by the result of slot `0x64e1008` and stored at `+0x218` (that path is not bound here). The constructor calls the clock-tuple slot `0x64e0990` (`R_X86_64_RELATIVE` to `0x1629690`, the provider mapped in #5045) at `0x1548bd7`.

Initial values written by the constructor:

| Offset | Value | Store |
| --- | --- | --- |
| `+0x220` | `30.0` (`0x403e000000000000`), the window length in seconds | `0x1548dec` |
| `+0x1f8` | `2000`, the sample limit for both sample buffers | `0x1548d56` |
| `+0x25c` | `0`, the ×50 flag | `0x1548e0a` |
| `+0x228`, `+0x22c` | the clock tuple: the first window starts at construction | `0x1548df7`, `0x1548e03` |
| `+0x238` | `1000` (meaning not traced) | `0x1548e30` |
| `+0x25d` | the `esi` byte | `0x1548ddb` |
| `+0x0`, `+0x10`, `+0x40`, `+0x50..+0x5f`, `+0x60`, `+0x70..+0x97`, `+0x200..+0x217` | 0 | see `evidence.json` |
| `+0x48`, `+0x68` | 8 (empty buffers) | `0x1548d69`, `0x1548d7f` |

## Evidence: who sets the ×50 flag

The census of `mov byte [reg+0x25c], imm8` (`C6 /0`) and `mov byte [reg+0x25c], r8` (`88`) with a disp32 in `.text` finds 8 stores:

- `0x1548e0a`: the constructor writes 0.
- `0x16eeeca`, `0x250347a`, `0x47716da`, `0x477292d`, `0x5ab257a`: each follows a constructor call through `0x64e1020` and writes 1 through the same callee-saved register that held `rdi` for the call (`r14`, or `rbp` at `0x4772906`). The same five sites also write qword `+0x0 = 1` and f64 `+0x8` (`0.5` from an immediate at four sites; a caller stack value at `0x4772922`).
- `0x47832e9`, `0x47849a8`: write 0 after indirect calls; their base registers are not traced here.

So 5 of the 35 constructed observers count every observation 50 times (#5045 step 4); the other 30 keep the constructor's 0 unless a store outside this census sets it.

## Implementation and comparison

No Rust is added. The tool re-derives every address above from instruction bytes, the FDE index and relocations. Negative controls in `tests/test_abci_step_observer_window_115.py` change the window length immediate (30.0 to 31.0), the sample limit (2000 to 2001), the constructor flag value, the strict compare (`jb` to `jbe`), the rollover start store offset, the empty-vector reset, `divsd` to `mulsd`, one dword of the `0x4679d0` tuple and the first setter's value, and add an extra flag store and an extra constructor call in the int3 padding after the observer. Each change fails the check (14 tests pass on the real image).

## Results and limitations

Counts: 35 of 35 constructor slot call sites found (denominator: E8/E9 rel32 and FF15/FF25 rip-relative instructions in `.text`, plus `R_X86_64_RELATIVE` addends); 0 direct calls; 1 relocation. 8 byte stores to `+0x25c` (denominator: `C6 /0` and `88` with mod=10 and disp32 `0x25c`, optional REX, in `.text`); 6 attributed. Observer window: 7 numbered steps over 692 bytes. No progress gate is requested.

Unknown: what the observer does with the taken bucket and the mean after `0x1547b9c`/`0x1547dc1` (the export), the meaning of `+0x0`, `+0x8`, `+0x10`, `+0x218`, `+0x238` and `+0x25d`, the bodies of the three helpers, and what the 35 callers measure.

Next question: the observer from `0x1547b9c` to its epilogue, which holds the export of each finished 30-second window.
