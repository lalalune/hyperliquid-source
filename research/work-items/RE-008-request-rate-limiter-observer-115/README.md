# RE-008: node #115 `handle_request_rate_limiter` observer (23rd stage): an adaptively subsampled timer, not a request gate

- Component ID: abci. Question: open PR #5954 found that `0x2f19520` builds an observer named `handle_request_rate_limiter` and moves it 8 bytes into its output behind a byte 0. It left open what that output is, who uses it, and whether its fields decide anything about requests.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5865 and #5954. It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, relocations, FDE extents and reference censuses are observations. "Lazy cell", "lock byte", "thread-local random value", "clock", "elapsed time", "window rollover" and "stride" are inferred labels from the call shapes, the atomics and the arithmetic. The binary was not executed.
- Scope included: all of `0x2f19520`; all of the wrapper `0x15494d0`; the decision tail of `0x1562120`; the rollover output stores of the record entry `0x1547530`; the cell references and the call site in `0x2e3ed10`. Scope excluded: the random generator body of `0x1562120`, the lock slow paths `0x5bb59d0` / `0x5bb5650`, `0x5c842e0` / `0x5c84210` beyond their call shape, where the start time comes from, and the rest of the handler `0x2e3ed10`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/request_rate_limiter_observer_115.py --check
python3 -m unittest tests.test_request_rate_limiter_observer_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 for review only; the tool does not read them.

## Evidence 1: `0x2f19520` is a lazy-cell initializer

- `0x2f19520` has no direct callers. Its only reference is an `R_X86_64_RELATIVE` value word at `0x64f3a18`. The dword at `0x64f3a18 + 0x270` is `3` at rest. This is the same lazy-cell shape #5861 mapped for the flush interval.
- The only relocation that points into the cell is GOT slot `0x64e8920`.
- The initializer calls the observer constructor (slot `0x64e1020` → `0x1548bb0`) with the name `handle_request_rate_limiter` (27 bytes), `a = 0.001` (`0x459af0`) and `esi = 0`. It then sets observer `+0x0 = 1` and `+0x8 = 2.0`, the #5865 getter pattern.
- It writes the 0x270-byte value: byte `+0x0 = 0`, the observer at `+0x8..+0x268`, observer `+0x1f8 = 6000` (`rbx+0x200`, the window ring limit), and qword `+0x268 = 1`.

## Evidence 2: one user, in an info_server request handler

- `0x64e8920` is loaded three times (`0x2e3fccb`, `0x2e3fd2f`, `0x2e3fd44`), all in `0x2e3ed10`. That function references Location records in `info_server/src/handle_request.rs`, `router.rs`, `handler.rs` and `user_ip.rs`, and axum's `handler/mod.rs`.
- Two loads read the state dword `+0x270`. The third passes the cell to `0x15494d0` through slot `0x64e1030`, its only call site (`0x2e3fd4b`).
- The f64 argument comes from `0x5c842e0` with `edi = 1` (`0x2e3fc5e`) and then `0x5c84210` (`0x2e3fca2`). Inference: elapsed seconds from a stored instant to now.
- The handler does not use the wrapper's return value: the next instruction tests `bpl` (`0x2e3fd51`).

## Evidence 3: the wrapper subsamples, records, and adapts its stride

`0x15494d0` (cell in `rdi`, value in `xmm0`):

1. `N = [cell+0x268]`. `k = 1` when `N < 2000`; otherwise `k = ((N >> 4) * 0x20c49ba5e353f7d) >> 64`, which equals `N / 2000` on the tool's samples.
2. `0x1562120(k)` (slot `0x64e1028`) returns `random % k == 0` (`div`, `test rdx, rdx`, `sete al`). When false, the wrapper returns without recording.
3. It takes the lock byte (`lock cmpxchg [rbx], 1`) and records into the observer (`rdi = cell+0x8`) through slot `0x64e1010` → `0x1547530`, with the value and `count = k`.
4. It reads observer `+0x10`, `+0x18` and `+0x20`, and clears `+0x10`. When `+0x10` was `1`, it stores observer `+0x18` as the new `N`. The comparisons `N >= 2001` with `+0x20 < 200`, and `+0x20 > 20000`, only choose whether the store comes before (`0x154957a`) or after (`0x15495a9`) the unlock.

## Evidence 4: what the record entry leaves at `+0x10..+0x20`

In `0x1547530`, the window count sum `+0x78` gets `count` added (`0x1547852`), and the window call count `+0x80` is incremented (`0x1547877`). At a window rollover, both are copied into the local summary (`0x15482b2`, `0x15482ba`). When that summary is not None (`cmp [rsp+0x1d0], 2`), the entry stores observer `+0x10 = 1`, `+0x18 = ` the window count sum and `+0x20 = ` the window call count (`0x1547bf2..0x1547bfe`).

So `N` becomes the previous window's summed count. With `count = k`, that sum estimates the number of handler calls in the window. The next window samples about 1 call in `N / 2000`.

## Result

The `handle_request_rate_limiter` observer is a metrics timer with adaptive subsampling. No code found reads its fields to accept, delay or reject a request: its only user records into it and ignores the result. "Rate limiter" in the name refers to what it measures (inference), not to the observer gating requests.

## Implementation and comparison

The tool pins 55 instruction byte runs, 11 RIP-relative references and 6 relocations, checks the cell state, the `a` constant and the name, recomputes the reference censuses, and models the stride on 10 samples. Tests change one byte at a time in a copy of the image and expect rejection (9 mutation tests). Alternatives considered: emulation (not allowed for this repository).

## Results and limitations

- Limits: the start instant passed to `0x5c84210` is not traced; nor is the rest of `0x2e3ed10`, so whether the handler also uses a separate rate limiter is not answered here. The body of the random generator in `0x1562120` is not mapped. The reference census covers RIP-relative `mov` loads of the GOT slot and relocations into the cell; a pointer to the cell copied elsewhere at run time is not followed.
- Next lead: map the instant passed to `0x5c84210` in `0x2e3ed10`, and the `user_ip.rs:28:48` path next to it.
