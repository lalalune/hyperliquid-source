# RE-008: node #115 lu.rs unfold stream (28th stage): its seed, its 10-second tick, and the verify_peer request a tick starts

- Component ID: transport. Question: the 27th stage (open PR #5963) found the lu.rs unfold poll `0x2cf08b0` as one branch of a random-start two-way select `0x2ce0de0`, but not who builds the unfold state, its two intervals, its `+0x30` byte, or what a tick does.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5962 and #5963. It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, strings, relocations, a jump table and direct-call targets are observations. "Seed", "toggle", "tick", "interval in seconds", "random", "peer check" and "port" are inferred labels. The binary was not executed.
- Scope included: the seed path and completion path of `0x2cf08b0`; the two seed builders in `0x2accee0` and `0x2ad0db0`; the head of `0x1564620`; the select outputs of `0x2ce0de0`; the select wiring and the tag-1 check in `0x2accee0`; the request fields `0x2ae0920` writes at `0x2ae0b4f..0x2ae0b71`. Scope excluded: the rest of `0x2ae0920`, the message branch (tag 0), the other unfold poll sites in `0x2cdca20`, the body of `0x1501360`, and what the seed qword is used for. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/lu_unfold_state_115.py --check
python3 -m unittest tests.test_lu_unfold_state_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the unfold poll's seed and tick

`0x2cf08b0` reads a tag qword at `+0x0`. With tag 0 (seed) it reads:

| Seed | Read at | Copied to the future |
|---|---|---|
| `+0x8` byte (qword) | `0x2cf08ca` | `+0x8` |
| `+0x10` f64 | `0x2cf08ce` | `+0x10` |
| `+0xd0` f64 | `0x2cf08e0` | `+0x18` |
| `+0xd8` qword | `0x2cf08f4` | `+0x20` |
| `+0xe0` byte | `0x2cf08ed` | `+0x30` |

It then loads the f64 at `+0x10 + 8 * (byte(+0x8) ^ 1)` (`0x2cf0959..0x2cf0962`), so a 0 byte selects `+0x18` (seed `+0xd0`) and a 1 byte selects `+0x10`. It stores the value at `+0x28` and `+0x38`. When `+0x30` is set it calls `0x2d4f8b0` (no zero check); otherwise `0x2d4f790` (0.0 returns at once; #5960). Pending returns 2 (`0x2cf09d6`). On completion (`0x2cf0a39`) it sets the state byte `+0x31` to 1, drops the future, writes 16 zero bytes at `+0x0` (tag 0, byte 0) and returns 1. The resume table `0x60fa24` maps state bytes 0 to 4 to `0x2cf0959`, `0x2cf0a80`, `0x2cf0a73`, `0x2cf097f`, `0x2cf09c0`.

Inference: after each tick the byte at `+0x8` is 0, so every later tick sleeps seed `+0xd0`. The byte and `+0x10` read like an optional first delay.

## Evidence 2: the two seed builders

`0x2accee0` (at `0x2acf35e..0x2acf3c0`) and `0x2ad0db0` (at `0x2ad332b..0x2ad338d`) do the same:

- call slot `0x64e11d8` (relocated to `0x1564620`) and store the result at seed `+0xd8`;
- store `0x4024000000000000` (10.0) at seed `+0xd0`;
- store 0 at seed `+0xe0`;
- store 16 zero bytes at seed `+0x0`;
- allocate 0xe8 bytes (slot `0x64df480`), copy the seed (slot `0x64df508`) and store the box at state `+0x1248`.

Neither builder writes seed `+0x10`. So, in this build, the stream sleeps 10.0 (seconds, as #5960) between ticks, through `0x2d4f790`.

## Evidence 3: the seed qword

`0x1564620` calls slot `0x64e0978` (relocated to `0x1501360`), formats the result, and loads four words that, read as big-endian, are `somepseu` (`0x1564667`), `lygenera` (`0x1564676`), `dorandom` (`0x1564685`) and `tedbytes` (`0x1564694`); in SipHash order v0, v1, v2, v3 they spell `somepseudorandomlygeneratedbytes`: the SipHash initial state with a zero key. Inference: `+0xd8` is a hash of a per-process string. `0x1501360` reads a thread-local block of u32 words and the wall clock (`0x1629690`); this packet does not pin that body. The unfold poll copies `+0xd8` to the future `+0x20`; no read of `+0x20` is in the mapped paths.

## Evidence 4: the select and the tick action

In `0x2accee0`, `0x2ad01ab..0x2ad01e3` builds the select closure: `[state+0x12b8]` = the done mask, `[state+0x12c0]` = `&state+0x1280`, `[state+0x12b0]` = `&state+0x1248`. `0x2ce0de0` takes `r15 = &state+0x1280`, so `[r15+0x30]` is `&state+0x1248`, the unfold box. Its outputs: tag 0 with the message at `+0x8` (`0x2ce0eea`), word `0x101` for a tick (`0x2ce0f16`), 2 when both branches are done (`0x2ce0f27`), 3 when pending (`0x2ce0f22`).

On tag 1 (`0x2ad022f`), the caller calls `0x2ae0920` (`0x2ad028b`). `0x2ae0920` stores a pointer to `verify_peer` (`0x605ad5`, length `0xb`) at `+0x10`/`+0x18`, a dword at `+0x22` and the word `0xfa1` (4001) at `+0x26` (`0x2ae0b4f..0x2ae0b6b`), and refers to the `lu::timeout {}: {}` template (`0x4326d0`, at `0x2ae0f2e`). Inference: each tick sends a `verify_peer` request to an address with port 4001, under a timeout.

## Implementation and comparison

The tool pins 106 instruction byte runs, 9 RIP-relative references, 7 direct calls, 2 relocations, a 5-entry jump table, two strings and the SipHash words, and checks that both builders use the same interval. Tests mutate one byte at a time in a copy of the image (9 mutation tests). Alternatives considered: tracing `0x2ae0920` in full and the message branch (bounded out); emulation (not allowed for this repository).

## Results and limitations

- Result: the node_stream_connection select (#5963) has a 10-second ticker; each tick starts a `verify_peer` request with port word 4001.
- Limits: what the `verify_peer` request does, its timeout length and its target address are not mapped. The dword at `+0x22` is not traced. The other two unfold poll sites (`0x2cdca20`) are not mapped. The use of seed `+0xd8` is not found. The message branch is not mapped.
- Next lead: map `0x2ae0920` (the timeout value, the address source at `+0x22`, and the reply handling).
