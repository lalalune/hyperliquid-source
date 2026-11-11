# RE-008: node #115 info_server request handler `0x2e3ed10` (24th stage): what `handle_request_rate_limiter` times, and the `user_ip.rs:28:48` future

- Component ID: info-api. Question: open PR #5956 found that the handler `0x2e3ed10` passes the `handle_request_rate_limiter` cell and an f64 from two clock calls to the wrapper `0x15494d0`. It left open which interval the two calls bracket, and what the `info_server/src/user_ip.rs:28:48` Location next to them belongs to.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5954 and #5956. It does not depend on their files. RE-012 (#1299, merged) mapped a different `user_ip` check, the fileSnapshot localhost gate; this packet does not repeat it.
- Claim status: instruction bytes, offsets, constants, string bytes, relocations, the dynamic symbol name and the Location reference census are observations. "Monotonic clock", "request dispatch", "response", "elapsed seconds", "inner future", "poll", "pending" and "completed" are inferred labels from the call shapes, the clock id, the arithmetic and the state values. The binary was not executed.
- Scope included: the handler bytes from the first clock read to the inner future's first poll (`0x2e3fb20..0x2e3fe76`), the panic arms that reference `user_ip.rs:28:48`, the clock helper `0x5c842e0` call shape and the difference `0x5c84210`. Scope excluded: the dispatch body `0x2ecf9d0`, the conversion `0x273bf30`, the inner future body `0x2d4f790`, where `bpl` (from `[rsp+0x10]`) is set, and the clock read at `0x2e3ff17` after the inner future completes. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/info_request_timing_115.py --check
python3 -m unittest tests.test_info_request_timing_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the two clock reads bracket one synchronous dispatch call

- `0x5c842e0` calls `clock_gettime` (GLOB_DAT slot `0x64e1248`) with the clock id in `edi`. The handler calls it with `edi = 1` at `0x2e3fb25` and again at `0x2e3fc63`. On Linux, clock id 1 is `CLOCK_MONOTONIC` (label).
- After the first read, the result is moved to `r14` (seconds) and `r12d` (nanoseconds) at `0x2e3fb2a` / `0x2e3fb2d`. These are callee-saved registers. They are stored as the start value at `0x2e3fc77` / `0x2e3fc7f`.
- Between the two reads, on the path that reaches the second read:
  1. `0x2e3fb42` calls slot `0x64e8918` (`R_X86_64_RELATIVE` → `0x2ecf9d0`) with `rdi = rsp+0x100` and `rsi = state+0x428`. The handler copied the 0x40-byte request to `state+0x428` just before (`0x2e3fa7e..0x2e3fa93`).
  2. `0x273bf30` converts the result into `rsp+0x908`, and `0x26b1890` drops the temporary.
  3. If the converted tag is not `0x8000000000000005`, the response is stored at `state+0x468..+0x4b0`.
- The tool pins the SHA-256 of the two straight-line spans `0x2e3fb2a..0x2e3fb82` and `0x2e3fbbe..0x2e3fca7`. I checked on the listing that neither span writes `r14` or `r12`. The other branch at `0x2e3fb82` reuses `r14` but leaves through `0x2e3fdad` without reaching the second read.
- Inference: the timed interval is one synchronous call of the request handler `0x2ecf9d0` plus the conversion and store. It is not an await, because no poll return sits between the two reads.

## Evidence 2: the recorded value

- `0x5c84210` is called with `rdi = rsp+0x100`, `rsi = &now`, `rdx = &start`. It writes tag 0, seconds and nanoseconds when `now >= start` (seconds signed, then nanoseconds). Otherwise it computes `start - now` and flips the tag with `xorps` against `0x453aa0`.
- The handler (`0x2e3fca7..0x2e3fd2b`):
  - tag 0: seconds converted to f64 through the `0x451210` / `0x450170` pair, plus `nanos / 1e9` (`0x458d50`);
  - any other tag: 0.0;
  - a result equal to `+inf` (`0x459010`): 0.0 (`je 0x2e3fccb` keeps `xmm0 = 0`).
- It then passes `xmm0` and the cell `0x64f3a18` to the wrapper through slot `0x64e1030` (`0x2e3fd4b`), as #5956 mapped.

## Evidence 3: `user_ip.rs:28:48` is an inner `async` block's state panic

- The Location `0x6450438` is `info_server/src/user_ip.rs`, line 28, column 48. A census of RIP-relative `lea` instructions in `.text` finds exactly two references, both in this handler:
  - `0x2e3fe69`, then slot `0x64e1368` → `0x1681e60`, which panics with "`async fn` resumed after completion";
  - `0x2e40f43`, then slot `0x64e1360` → `0x1681e80`, which panics with "`async fn` resumed after panicking".
- These arms belong to an inner future stored at `state+0x570`, with its state byte at `state+0x608`. The jump table `0x6164a8` (`0x2e3fe55`) sends state 0 to `0x2e3fd6f`, 1 and 2 to the two panics above, and 3 to `0x2e3fd87` (poll again).
- On first entry (`0x2e3fd5a`, only when `bpl != 0` at `0x2e3fd51`, after the wrapper call): state byte 0, the f64 `0.014` at `+0x570`, byte `+0x600 = 0`, then `0x2d4f790(state+0x570, [rsp+0x30])`. A non-zero return sets state 3 and returns (pending). Otherwise the handler drops an Arc it holds, sets state 1 (`0x2e3ff01`), drops the future (`0x2dd6e70`) and reads the clock again at `0x2e3ff17`.
- Inference: the Location names the async block whose state machine is inlined here. Its only use is in these resume panics, so this packet finds no IP-extraction logic and no header names at this Location. The literals `x-forwarded-for`, `X-Forwarded-For`, `x-real-ip` and `X-Real-IP` do not occur in the binary. What `0.014` means (a delay in seconds is one reading) is not mapped.

## Implementation and comparison

The tool pins 33 instruction byte runs, 4 direct calls, 13 RIP-relative references, 4 relocations, one GLOB_DAT symbol name, two f64 constants, two panic messages, one Location, the four used arms of the jump table, the `user_ip.rs:28:48` reference census and two span hashes. The tests change one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: following `0x2ecf9d0` and `0x2d4f790` (bounded out); emulation (not allowed for this repository).

## Results and limitations

- Result: `handle_request_rate_limiter` records, in seconds, how long one synchronous call of the request handler `0x2ecf9d0` (plus its result conversion) takes on the monotonic clock. A negative or infinite elapsed time is recorded as 0. `user_ip.rs:28:48` is an inner async block polled after that timing, and only when `bpl` is set; the Location appears only in its resume panics.
- Limits: the dispatch body `0x2ecf9d0`, the conversion `0x273bf30`, the inner future body `0x2d4f790` and the meaning of `0.014`, the source of `bpl`, the use of the clock read at `0x2e3ff17`, and the handler's other paths.
- Next lead: map the inner future `0x2d4f790` (what it does with `0.014` and `[rsp+0x30]`) and where `bpl` comes from.
