# RE-008: node #115 shared value observer `0x1547530` (first stage) and its wall-clock tuple

- Component ID: abci. Question: what does the routine behind slot `0x64e1010` do with the `(state, count, Location, value)` arguments that the block-step recorder hands it, and which clock decides its daily buckets?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues the "Next question" of open PR #4718 (block-step recorder `0x5b2a130`, call `0x5b2a24c`). It does not depend on that PR's files. PR #625-era #94 notes and `RE-001-node115-latency-projection` name the same slot as an opaque observer; neither maps its body.
- Claim status: instruction bytes, offsets, constants, relocations and the call census are observations. "Per UTC day", "count", "calls", "sum", "samples" and "maximum" are inferred labels from the arithmetic and layout. The handling of non-finite and negative weighted values is a hand trace of the branch block `0x1547601..0x1547658`; the binary was not executed.
- Scope included: observer FDE `0x1547530..0x1548ba3` from entry to the running-maximum store (window ends `0x15478e8`, 952 bytes); provider FDE `0x1629690..0x1629795` from entry to its third output store (window ends `0x162974f`); the slot relocations named below; the census of references to the observer. Scope excluded: the observer after `0x15478e8` (the `+0x228` windowed section, the time-bound constants at `0x4679d0` and every call after it), the bodies of the grow helpers `0x152e190` and `0x14ca9a0`, the date helper `0x1628f50`, the provider's error paths (`0x162975d`, `0x1629788`) and the overflow target `0x1548a0b`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/abci_step_observer_115.py --check
python3 -m unittest tests.test_abci_step_observer_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The two `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence: who reaches the observer

`0x64e1010` is an `R_X86_64_RELATIVE` slot with addend `0x1547530`; it is the only relocation that names the observer. No E8/E9 rel32 instruction in `.text` targets `0x1547530`. Exactly 68 `FF 15` rip-relative calls (and no `FF 25` jumps) in `.text` go through the slot; `0x5b2a24c` (the block-step recorder) is one of them, and `0x51c9b84`/`0x51c9c12` (the latency sampler packet) are two more. The full site list is in `evidence.json`. The observer is therefore shared; this packet maps its common first stage, not any one caller's meaning.

## Evidence: observer first stage

Entry: `rdi` (state) is kept in `rbx`, `rsi` (count) in `r14`, `xmm0` (value) is saved at `rsp+0x10`. The recorder passes count 1. `rdx` (the Location) is neither read nor saved before the call at `0x1547559`, which may clobber it under the System V ABI; after that call the body has no copy of it, so it cannot use the Location argument.

1. `0x1547541`: if count is 0, `je 0x154866c` goes straight to the epilogue. Nothing is written.
2. `0x1547559`: call slot `0x64e0990` (`R_X86_64_RELATIVE` to `0x1629690`) with `rdi = rsp`. It fills a 12-byte tuple (see the provider section).
3. `0x154755f..0x15475ab`: if dword `[rbx+0x240]` differs from tuple dword `+0`, the code zeroes 24 bytes at `+0x200` (`movups` 16 bytes plus qword `+0x210`), sets `+0x58` and `+0x50` to 0, and stores the tuple: dword `+0` at `+0x240`, tuple bytes `0..7` at `+0x244`, dword `+8` at `+0x24c`.
4. `0x15475b1..0x15475cb`: if byte `[rbx+0x25c]` is 1, count is multiplied by 50 (`mov ecx, 0x32; mul rcx`); an overflow jumps to `0x1548a0b`.
5. `0x15475dc..0x15475fd`: `w = f64(count as u64) * value` (unsigned conversion through `0x451210`/`0x450170`).
6. `0x1547601..0x1547658` (hand trace): `w` is kept when it is a positive finite number or `±0`; a negative, infinite or NaN `w` becomes `0.0`.
7. Daily bucket at `+0x200`: `+0x200 += count` saturating at `u64::MAX` (`add; cmovb -1`), `+0x208 += 1` saturating (`inc; cmove -1`), `+0x210 += w`. Before the store at `0x1547758`, a sum whose magnitude bits equal `0x7ff0000000000000` (infinite) is replaced by `2^64` from `0x459090`.
8. Daily samples: a ring buffer with capacity `+0x40`, buffer `+0x48`, head `+0x50` and length `+0x58`. If full, it grows through slot `0x64e0ea0` (`0x152e190`). The head moves back by one with wrap-around (`dec rsi; add rax, rsi; cmovae rax, rsi`), the raw `value` (not `w`) is stored at the new head, length grows by one and is then capped at qword `[rbx+0x1f8]`. Inference: newest-first samples, limited to `[+0x1f8]`.
9. Lifetime bucket at `+0x78`: `+0x78 += count` saturating, `+0x80 += 1` saturating, `+0x88 += w` with the same `2^64` replacement (`0x154784a`, store `0x1547898`).
10. Lifetime samples: a vector with capacity `+0x60`, buffer `+0x68`, length `+0x70`. Only while length is below `[rbx+0x1f8]` (`jae 0x15478d4` skips otherwise) the raw `value` is appended, growing through slot `0x64e0080` (`0x14ca9a0`) when full.
11. `0x15478d4..0x15478e0`: `+0x90 = maxsd(+0x90, value)`.

Step 3 resets only the daily bucket and the ring buffer. The lifetime bucket, the vector and `+0x90` are not touched in this window.

## Evidence: the tuple provider

`0x1629690` (FDE `0x1629690..0x1629795`): `xor edi, edi; call 0x5c842e0` (the clock helper that RE-008 #4718 binds to the `clock_gettime` import; clock id 0 is `CLOCK_REALTIME` on Linux). It calls the difference helper `0x5c84210` against a zero `(0, 0)` pair, splits the seconds by 86400 (`imul rax, rdx, 0x15180`), adds 719163 to the day count (`add edx, 0xaf93b`) and passes it to slot `0x64dfff0` (`R_X86_64_RELATIVE` to `0x1628f50`). A zero result leaves this window. Otherwise it stores the result at `+0`, the seconds of the day at `+4` and the nanoseconds at `+8`. Inference: `+0` is a date value built from days since 0001-01-01 (719163 is the day count from 0001-01-01 to 1970-01-01), so the observer's step 3 resets the daily bucket when the UTC date changes.

## Implementation and comparison

No Rust is added. The tool re-derives every address above from instruction bytes, the FDE index and relocations. Negative controls in `tests/test_abci_step_observer_115.py` change the multiplier immediate (50 to 49), the rollover compare offset, the daily sum store offset, the ring head direction, `maxsd` to `minsd`, the provider clock id register, the epoch day constant, and add an extra slot call in the int3 padding after the observer. Each change fails the check (11 tests pass on the real image).

## Results and limitations

Counts: 68 of 68 slot call sites found (denominator: E8/E9 rel32 and FF15/FF25 rip-relative instructions in `.text`, plus `R_X86_64_RELATIVE` addends); 0 direct calls; 1 relocation. Observer window: 11 numbered steps over 952 bytes. No progress gate is requested.

Unknown: what the observer does after `0x15478e8` (the `+0x228` section, which reads the tuple's seconds and nanoseconds again), who sets byte `+0x25c` and qword `+0x1f8`, how the buckets are read out or exported, and what the other 66 callers measure.

Next question: the observer's `+0x228` section and the readers of `+0x200`/`+0x78`/`+0x90`.
