# RE-008: node #115 shared value observer `0x1547530` (sixth stage): the liner flush interval and flush gate

- Component ID: abci. Question: the fifth stage (open PR #5854) found that the liner open `0x14c3b30` copies an f64 flush interval from the lazily initialised global `0x64efce0`, and that the gate `0x154ce40` flushes when a record time passes a stored time plus that interval. It left open where the interval comes from, the exact gate logic, and where the observer's log directory comes from.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5045, #5839, #5841, #5849 and #5854. It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, string bytes, relocations, Location records, FDE extents and call or reference censuses are observations. "Environment variable", "parse f64", "Once", "lazy cell", "time of day", "date", "add days" and "None" are inferred labels from the string, the call shapes, the state values and the layout. The binary was not executed.
- Scope included: all of the initializer `0x14c4770`, the Once closure `0x14c3f80`, the open `0x14c3b30`, the gate `0x154ce40`; the branch structure of the seconds conversion `0x15ed960`; the writer-state stores in the constructor `0x1548bb0` and the two observer checks. Scope excluded: the bodies of the environment lookup `0x5c9a340`, the f64 parser `0x16876b0`, the time addition `0x162a9a0`, the date addition `0x16290d0`, `Once::call` `0x5c87d50`, the rounding of `0x15ed960`, and the meaning of the two range checks in the gate. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/abci_step_observer_flush_115.py --check
python3 -m unittest tests.test_abci_step_observer_flush_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the interval global is a lazy cell, read in one place

`0x64efce0` is 16 bytes in `.data`:

- `+0x0`: the value word. Its file bytes are zero, and an `R_X86_64_RELATIVE` entry at `0x64efce0` gives it the address `0x14c4770` (the initializer) at load.
- `+0x8`: a state dword, `3` at rest.

References, counted over all `R_X86_64_RELATIVE` addends and all rip-relative (`mod=00 rm=101`) operands in `.text`:

- One relocation points into the cell: GOT slot `0x64e0030`.
- No `.text` instruction addresses the cell directly.
- One instruction loads the slot: `mov r13, [rip+...]` at `0x14c3b6d`, in the liner open.

The open (`0x14c3b30`) reads the state at `0x14c3b74` (`mov eax, [r13+8]`). When it is not 0, the open calls slot `0x64df9f0` → `0x5c87d50` at `0x14c3c1b`, with `rdi = r13+8`, `esi = 1` and the closure vtable `0x63f8d30` (Location `0x63f8d58`: std `once.rs` line 219). It then loads the value (`movsd xmm0, [r13]` at `0x14c3b7c`) into liner `+0x38` (`0x14c3ba8`) and sets the stored date at `+0x40` to 0 (`0x14c3bae`). The vtable is referenced only at `0x14c3c03`.

The closure (`0x14c3f80`, vtable `+0x18`) takes the initializer pointer from the captured cell and clears the capture (`0x14c3f81..0x14c3f87`). It panics if the state is poisoned (`cmp byte [rsi+4], 1` at `0x14c3f93`), calls the initializer (`call [rbx]` at `0x14c3f99`) and writes the returned f64 over the pointer (`movsd [rbx], xmm0` at `0x14c3f9b`). This is the only value store.

Inference: a std `LazyLock<f64>` (Once state 3 = incomplete, 0 = complete). Every liner opened through slot `0x64e0020` (104 `FF 15` calls in `.text`) gets the same interval.

Correction to the fifth stage: #5854 said the global is "zero at rest". The file bytes are zero, but the relocation sets the value word to the initializer address at load. The f64 exists only after the first open.

## Evidence 2: the interval is `LINER_FLUSH_PERIOD`, default 60 seconds

The initializer `0x14c4770` (FDE `0x14c4770..0x14c48cd`):

1. Loads the name `LINER_FLUSH_PERIOD` (`0x464990`, length `0x12`) and calls slot `0x64e0040` → `0x5c9a340` (`0x14c478a`).
2. If the result tag byte is not 0 (`cmp byte [rsp+0x20], 0` at `0x14c4795`), returns `60.0` (the f64 at `0x459718`). It first frees an owned string when one is present (`0x14c47a4`).
3. Otherwise parses the string with slot `0x64e0048` → `0x16876b0` (`0x14c47dc`). On a parse error (`cmp byte [rsp+0x10], 1` at `0x14c47e2`) it panics with `called \`Result::unwrap()\` on an \`Err\` value`, Location `base/src/liner.rs:17:74`.
4. Checks the parsed bits (`0x14c47f8..0x14c4845`). It accepts the value if it is ±0, a positive subnormal or a positive normal number. Otherwise it calls slot `0x64df830` → `0x1680c10` (`called \`Option::unwrap()\` on a \`None\` value`) with Location `base/src/liner.rs:17:84`.

| Parsed value | Accepted |
| --- | --- |
| `0.0`, `-0.0`, `5e-324`, `60.0`, `1e300` | yes |
| `-1.0`, `-5e-324`, `inf`, `NaN` | no: panic |

The tool evaluates this table from the check as written (`accepted()` in the tool). Inference: line 17 of `base/src/liner.rs` reads the environment variable once per process. A malformed, negative or non-finite value panics in the first thread that opens a liner. An unset variable (or a non-Unicode one, if `0x5c9a340` is `std::env::var`) gives 60 seconds.

## Evidence 3: the flush gate

The gate `0x154ce40` (FDE `0x154ce40..0x154cfe0`, slot `0x64e0008`, 23 `FF 15` calls) gets `rdi` = liner `+0x38` and `rsi` = the record time (date dword, seconds dword, fraction dword).

| Liner offset | Field |
| --- | --- |
| `+0x38` | f64 interval |
| `+0x40` | stored date (0 = empty) |
| `+0x44` | stored seconds of day |
| `+0x48` | stored fraction |

1. Stored date 0 (`0x154ce54`, `je 0x154cfbe`): flush.
2. The interval goes through slot `0x64e0f70` → `0x15ed960`, which returns seconds and nanoseconds. The gate forms `secs * 1e9 + nanos`, saturated to `i64::MAX` (`0x154cea4..0x154ceb8`), and splits it again by 1e9 (`0x112e0be826d694b3`, shift `0x1a`).
3. Slot `0x64e0f78` → `0x162a9a0` (`0x154cee3`) adds that to the stored seconds and fraction. It returns a new time of day and an overflow in seconds. Two range checks on the overflow (`0x154cf08`, `0x154cf24`) can send it to the fallback. The overflow divided by 86400 (`0x1845c8a0ce512957`, shift `0xd`) goes with the stored date to slot `0x64e0aa0` → `0x16290d0` (`0x154cf4f`). A 0 result also sends it to the fallback.
4. Fallback: the deadline is the tuple at `0x4679d0` = (`0x7fffd6de`, 86399, 999999999), the same far-future constant as in #5839.
5. Flush only when the deadline is earlier than the record time. The gate compares the date (signed, `setl` at `0x154cf77`), then the seconds (`setb` at `0x154cfa9`), then the fraction (`jb` at `0x154cfb4`). An equal time does not flush.
6. On flush it stores the record time at `+0x40..+0x4c` (`0x154cfc6`, `0x154cfcc`) and returns 1. Otherwise it returns 0.

The tool checks both magic divisors against `ceil(2^90 / 1e9)` and `ceil(2^77 / 86400)`.

Inference: with the default, a liner flushes its buffer on the first line after open and then on the first line that comes more than 60 seconds after the last flush. Lines between flushes stay in the buffer unless it fills (the slow write path in #5854). If the deadline cannot be computed (for example a very large interval), the gate never flushes again until the next open resets `+0x40`. The observer's optional flush `0x14c3c90` (#5849, step 6) is separate.

`0x15ed960` branch structure (`0x15ed964`, `0x15eda4d`, `0x15edae7`, `0x15edb6e`): x ≥ 0 or NaN takes a bit-decode path by exponent (< `0x3e0` → 0; < `0x3ff` fraction only; < `0x433` seconds and fraction; < `0x43f` seconds only). Larger values and x < 0 take a path that multiplies by 1e6 and clamps (inference: saturating microseconds). Its rounding is not traced.

## Evidence 4: the observer's two log writers start without a directory

The constructor `0x1548bb0` (FDE `0x1548bb0..0x1548f3d`, slot `0x64e1020`, 35 `FF 15` calls) stores `0x8000000000000000` at `rsp+0x28` and `rsp+0xd8` (`0x1548bdd..0x1548bec`). It then copies `0xb0` bytes from each into the observer at `+0x98` (`0x1548da1..0x1548db2`) and `+0x148` (`0x1548db5..0x1548dc9`) with `memcpy` (GLOB_DAT `0x64df508`). Nothing else in the constructor writes those two stack slots.

#5849 showed that the writer state's directory is a `(ptr, len)` at state `+0x8`. So the first qword is the directory's capacity, and `0x8000000000000000` is the None niche (inference: `Option<writer state>`). The observer tests both before use:

- `+0x98`: `xor eax, eax`; `cmp rax, [rbx+0x98]`; `jo 0x1548657` (`0x154887b..0x1548884`). Only `0 - i64::MIN` overflows, so a None state skips the path check, the open and the write (#5849, Evidence 3).
- `+0x148`: the same at `0x1547c02..0x1547c15`, skipping to `0x1547f47`. This second writer has its own liner at `+0x190` and writes through `0x14c34f0`, not traced here.

A byte scan of `.text` for `lea rdi, [reg+0x98]` (not `rsp`) followed within 24 bytes by `mov edx, 0xb0` finds one site: the constructor's `0x1548da1`.

## Implementation and comparison

No Rust is added. The tool re-derives every address above from instruction bytes, the FDE index, relocations, the dynamic symbol table, string bytes and Location records. Negative controls in `tests/test_abci_step_observer_flush_115.py` change the environment name, the default, the cell's state dword, a Location line, the sign test in the check, the gate's date and fraction comparisons, one divisor, the constructor's None constant, the observer's skip branch and the second state's offset. Each change fails the check (15 tests pass on the real image, none skipped).

## Results and limitations

Counts: 1 relocation into the cell, 0 direct `.text` references to it, 1 slot load; 104 open slot calls; 23 gate slot calls; 35 constructor slot calls; 1 object `0xb0` copy into `+0x98`. Denominators: `R_X86_64_RELATIVE` and `R_X86_64_GLOB_DAT` entries; `FF 15` rel32 and `mod=00 rm=101` operands in `.text`. No progress gate is requested.

Unknown:

- The observer's log directory. The constructor leaves both writer states None, and this stage did not find what sets them. The byte scan covers only the `lea` + `mov edx, 0xb0` shape. It does not cover field-by-field stores, a copy through another register or offset, or an observer embedded in a larger object (for example the getter statics in #5850, which are being traced separately). So it is not shown that the observer never writes files.
- Whether `0x5c9a340` is `std::env::var` (getenv is not traced).
- The rounding of `0x15ed960`, the meaning of the gate's two range checks, and the bodies of the time and date additions.

Next question: what sets the observer's writer state at `+0x98` (the log directory and the hourly flag `+0x140`), starting from the observer's owners in the #5850 catalogue.
