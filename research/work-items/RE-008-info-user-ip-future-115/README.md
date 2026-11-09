# RE-008: node #115 info_server request handler `0x2e3ed10` (25th stage): the inner future's flag and the 14 ms sleep

- Component ID: info-api. Question: the 24th stage (open PR #5957) found that the handler polls an inner future at state `+0x570` after the request timing, only when `bpl != 0` at `0x2e3fd51`, with the f64 `0.014` as its argument. It left open where `bpl` comes from, and what the inner future `0x2d4f790` does.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5956 and #5957. It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, relocations, Location records, jump-table entries, FDE extents and the operand censuses are observations. "Flag", "context", "Duration", "timer", "sleep", "poll", "ready" and "pending" are inferred labels from the call shapes, the Location paths and the state values. The binary was not executed.
- Scope included: the handler instructions that carry `bpl` from its sources to the test at `0x2e3fd51`; the handler's seven state-dispatch jump tables; the outer future `0x2d4f790` (whole FDE); the entry, the f64 check, the timer call, the poll call and the panic arms of `0x2d4f8b0`; the Location references in `0x5cf2150` and `0x5cf2d30`. Scope excluded: the bodies of `0x5cf2150` and `0x5cf2d30`, the rest of the Duration conversion, and the handler's other states. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/info_user_ip_future_115.py --check
python3 -m unittest tests.test_info_user_ip_future_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: where `bpl` comes from

Working back from the test `0x2e3fd51` `test bpl, bpl` / `je 0x2e3ff0e` (skip the inner future):

1. `ebp` is loaded from `[rsp+0x10]` at `0x2e3fcc5` and `0x2e3fd25`.
2. `[rsp+0x10]` is stored from `r12d` at `0x2e3fa34`, which also stores `r12b` to state `+0x520` (`0x2e3fa39`). On resume, `0x2e3f58b` reloads state `+0x520` into `[rsp+0x10]` (`0x2e3f592`) and jumps to `0x2e3fa5f`.
3. `r12d` is set from `ebp` at `0x2e3f941`. On resume, `0x2e3efc4` reloads it from state `+0x6b2` and jumps to `0x2e3f946`. State `+0x6b2` is stored from `bpl` at `0x2e3f91e`.
4. `ebp` is zeroed at `0x2e3f805` (`xor ebp, ebp`) on the straight path. On resume, `0x2e3ee64` reloads it from state `+0x6da` and jumps to `0x2e3f807`.
5. The only store to `+0x6da` in the handler is `mov word [rbx+0x6da], 0` at `0x2e3f7e2`.

Censuses the tool recomputes over the handler's FDE (`0x2e3ed10..0x2e414d3`):

- Every `[rbx+disp32]` operand naming `+0x6da`, `+0x6db`, `+0x6b2`, `+0x6b3`, `+0x520` or `+0x521`: 11 operands. 5 are stores: the zero word at `0x2e3f7e2` and the four copies in steps 2 and 3 (`+0x6b2`, `+0x6b3`, `+0x520`, `+0x521`).
- Every `[rsp+0x10]` operand: 13. None of the stores lies inside the three spans that carry the flag (`0x2e3f805..0x2e3f91e`, `0x2e3f946..0x2e3fa34`, `0x2e3fa5f..0x2e3fd51`).
- The seven state-dispatch jump tables (`0x616438` with 7 entries; `0x616454`, `0x616464`, `0x616474`, `0x616488`, `0x616498`, `0x6164a8` with 4 each): no entry lands inside those spans.

Checked by hand on the listing (not by the tool): no instruction inside those spans writes `ebp`, `r12` or `[rsp+0x10]`, and the only direct jumps into them from outside are `0x2e3ee7c`, `0x2e3efda`, `0x2e3f59d` and the lazy-init return `0x2e40e78` (to `0x2e3fd44`, which does not touch `ebp`).

Inference: on every path to `0x2e3fd51`, `bpl` is 0. The inner future is never started from this handler in this build. This matches a source flag initialised to `false` and kept in the async state, but never set.

## Evidence 2: the inner future sleeps for its argument in seconds

- The handler stores `0x3f8cac083126e979` (f64 `0.014`) at state `+0x570` (`0x2e3fd79`) and calls `0x2d4f790(state+0x570, [rsp+0x30])`. `[rsp+0x30]` holds `r13`, the handler's third argument (`mov r13, rdx` at `0x2e3ed30`, stored at `0x2e3ee5d`).
- `0x2d4f790` (state byte `+0x90`, table `0x6105f4`; its resume panics reference `base/src/lu.rs:63:46`): an argument equal to `0.0` (`ucomisd`, `jne`/`jp`) sets the returned state and completes at once. Otherwise it copies the argument to `+0x10` and calls `0x2d4f8b0` with `rsi` unchanged.
- `0x2d4f8b0` (state byte `+0x78`, table `0x610604`; its resume panics reference `base/src/lu.rs:74:57`):
  - A negative argument (`ucomisd xmm1, xmm0` / `ja 0x2d4fb47`), or one that fails the exponent and `1e9` checks (`0x2d4fb45`), reaches a format panic through slot `0x64df6b8` with the Location `core/src/time.rs:962:23`.
  - Otherwise it calls slot `0x64e13a0` (`R_X86_64_RELATIVE` → `0x5cf2150`) with the Location `base/src/lu.rs:75:5`, stores the 0x70-byte result at `+0x8`, and polls it through slot `0x64e0858` (→ `0x5cf2d30`) with the context in `rsi`.
  - `0x5cf2150` references `std/src/time.rs:429:33`. `0x5cf2d30` references the vendored `tokio/src/time/sleep.rs:467:23`.

Inference: `base/src/lu.rs:63` is an async helper that does nothing for 0 seconds and otherwise awaits a tokio sleep of that many seconds. Here it would sleep 14 ms.

## Implementation and comparison

The tool pins 46 instruction byte runs, 10 RIP-relative references, 3 relocations, 6 Locations and the f64 argument, and recomputes the two operand censuses, the jump-table entries and the Location reference census. Tests change one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: a full control-flow graph of the 0x27c3-byte handler (bounded out; the jump tables and direct jumps were checked instead); emulation (not allowed for this repository).

## Results and limitations

- Result: the `user_ip.rs:28:48` inner future is a 14 ms tokio sleep from the helper at `base/src/lu.rs:63`, polled after the request timing only when a flag is set. In this build that flag comes only from a zero store or `xor ebp, ebp`, so the sleep is not reached from this handler.
- Limits: the operand censuses are byte patterns for `[rbx+disp32]` and `[rsp+0x10]`; they miss stores through other base registers, memcpy into a range that covers the flag bytes, and stores made by the code that built the handler's state. The span checks and the direct-jump list are by hand. The bodies of `0x5cf2150` and `0x5cf2d30` are named only by their Location references.
- Next lead: find the source-level reason for the flag by mapping the handler states that write `+0x6b8..+0x6d8` next to it (`0x2e3f7a5..0x2e3f7e2`).
