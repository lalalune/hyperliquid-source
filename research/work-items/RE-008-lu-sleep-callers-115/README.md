# RE-008: node #115 `base/src/lu.rs` sleep helpers (26th stage): who calls them, with what argument, and the info handler's packed fields

- Component ID: info-api. Question: the 25th stage (open PR #5960) found that the info_server handler `0x2e3ed10` would start `0x2d4f790` with 0.014 seconds behind a flag that is always 0, and that `0x2d4f790` returns at once on 0.0 and otherwise calls `0x2d4f8b0`, which sleeps for its argument. It left open who else calls these helpers, and what the handler stores next to the flag (`+0x6b8..+0x6d8`).
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5957 and #5960. It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, relocations, Location records, strings, FDE extents and the call census are observations. "Sleep", "interval", "unfold stream", "channel", "deadline", "now", "Option" and "IPv4-sized value" are inferred labels from the call shapes, Location paths, sizes and constants. The binary was not executed.
- Scope included: the `call rel32` census of both helpers; the argument set-up at each `0x2d4f790` call; the conversion in the two channel futures; the handler's Option byte and its two packed records. Scope excluded: the bodies of `0x1629690` and `0x162a290` (named only as the wall-clock and time-difference callees used in earlier stages), what the channel futures receive (`0x2ce0f40`), who builds the unfold state of `0x2cf08b0`, and where the handler's 12-byte values come from.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/lu_sleep_callers_115.py --check
python3 -m unittest tests.test_lu_sleep_callers_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: call census

No `R_X86_64_RELATIVE` entry names `0x2d4f790` or `0x2d4f8b0`. Every `e8 rel32` in `.text` that reaches them:

| Call | Target | Enclosing FDE | Locations in that function |
|---|---|---|---|
| `0x2cf0986` | `0x2d4f8b0` | `0x2cf08b0` | `futures-util/src/stream/unfold.rs:108:21`, `base/src/lu.rs:386:64` |
| `0x2cf09c7` | `0x2d4f790` | `0x2cf08b0` | same |
| `0x2d4f7de` | `0x2d4f8b0` | `0x2d4f790` | (the outer helper itself, 25th stage) |
| `0x2e072c6` | `0x2d4f790` | `0x2e071c0` | `node/src/channel.rs:16:9`, `node/src/channel.rs:20:33` |
| `0x2e076f0` | `0x2d4f790` | `0x2e075f0` | same |
| `0x2e3fd8f` | `0x2d4f790` | `0x2e3ed10` | (info handler, 24th and 25th stages) |

## Evidence 2: the argument at each call

- `0x2cf08b0` (an unfold stream poll; its panic text at `0x61671d` is ``Unfold must not be polled after it returned `Poll::Ready(None)` ``): it toggles the byte at `+0x8` (`xor al, 1`), loads the f64 at `+0x10 + 8 * byte`, and stores it to `+0x28` and to the sleep argument at `+0x38`. When the byte at `+0x30` is non-zero it calls `0x2d4f8b0` directly (`0x2cf0986`), skipping the zero check in `0x2d4f790`; otherwise it calls `0x2d4f790` (`0x2cf09c7`). Inference: a stream that sleeps for one of two intervals in turn.
- `0x2e071c0` and `0x2e075f0` (both reference `node/src/channel.rs:16:9`): each compares two 12-byte (date, seconds, fraction) tuples. The second comes from slot `0x64e0990` (`R_X86_64_RELATIVE` → `0x1629690`, the wall-clock call). If the first is earlier, the argument is 0. Otherwise slot `0x64e0fc0` (→ `0x162a290`) gives the difference, and the argument is `max(0, secs + nanos / 1e9)` (`0x458d50` = 1e9), with +inf (`0x459010`) turned into 0. It is stored at `+0x70` and passed to `0x2d4f790`. Inference: wait until a time carried by the received item, then continue. The tool checks the model on four samples.
- `0x2e3ed10`: the constant `0x3f8cac083126e979` (0.014), behind the flag the 25th stage found constant 0.

## Evidence 3: the handler's packed fields

- `0x2e3f526` tests bit 0 of `[rsp+0x160]`. When set, `al = 1` and `ebp` takes the four bytes `[rsp+0x164..0x168)` (`mov ebp, [rsp+0x162]` then `shrd ebp, eax, 16` with the word at `+0x166`). When clear, `al = 0` (`0x2e3f5a2`). The byte goes to `[rsp]` (`0x2e3f5e7`).
- The handler then writes the same packed shape twice: `+0x2d8` byte (`[rsp]`), `+0x2d9` dword (`ebp`), `+0x2dd` qword and `+0x2e5` dword (12 bytes from `[rsp+0x90]`), `+0x2e9` = 2; and `+0x6b8` byte, `+0x6b9` dword, `+0x6bd` qword and `+0x6c5` dword (12 bytes from `[rsp+0x80]`), `+0x6c9` = 2.
- `0x2e3f7e2` stores the word 0 at `+0x6da` (the flag pair of the 25th stage).

Inference: an Option of a 4-byte value (IPv4-sized) and a 12-byte value with a discriminant byte 2 after it. The packet does not name the source fields, and it does not find the source-level reason the flag stays 0.

## Implementation and comparison

The tool pins 46 instruction byte runs, 16 RIP-relative references, 2 slot relocations, 4 Location records, one panic string and the 1e9 and +inf constants, then recomputes the call census. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: tracing the unfold state's builder and the channel item (bounded out); emulation (not allowed for this repository).

## Results and limitations

- Result: the 14 ms call is one of four users of the sleep helper. The other three are live code shapes: an alternating-interval stream (`lu.rs:386:64`) and two channel futures (`channel.rs:16:9`) that wait until an item's time.
- Limits: the census covers `call rel32` and relocations only; a call through a register loaded another way would be missed. The unfold state's builder, the channel item type, the 12-byte values' sources and the meaning of the discriminant 2 are not mapped.
- Next lead: find who builds the unfold state of `0x2cf08b0` (its two intervals and the `+0x30` byte) and what the channel futures at `channel.rs:16:9` forward.
