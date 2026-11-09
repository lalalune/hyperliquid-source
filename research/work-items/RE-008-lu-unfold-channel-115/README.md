# RE-008: node #115 `node/src/channel.rs` forwarders and the `lu.rs` unfold stream's poll sites (27th stage)

- Component ID: abci. Question: the 26th stage (open PR #5962) found four users of the `lu.rs` sleep helper `0x2d4f790`: an unfold stream poll `0x2cf08b0` and two futures `0x2e071c0` and `0x2e075f0` that reference `node/src/channel.rs:16:9`. It left open who builds those futures, what deadline they sleep to, what they forward, and who polls the unfold stream.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5960 and #5962. It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, strings, relocations, Location records, vtable words, FDE extents and call or reference censuses are observations. "Forwarder", "channel", "capacity", "send", "receive", "deadline", "payload", "task name", "spawn", "select" and "closed" are inferred labels from the call shapes, strings, sizes and Location paths. The binary was not executed.
- Scope included: the two futures' vtables and builders, the four builder calls and their name arguments, the receive-sleep-send loop of both futures, and the direct callers of `0x2cf08b0` with the select shape at `0x2ce0de0`. Scope excluded: who builds the unfold state (its two intervals at `+0x10`/`+0x18` and the byte at `+0x30`), the bodies of the channel constructors, send and receive functions, the meaning of the send result 5, what the 8- and 16-byte payloads are, and the select at `0x2cdca20`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/lu_unfold_channel_115.py --check
python3 -m unittest tests.test_lu_unfold_channel_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: two boxed-future vtables

| Vtable | `+0x0` (reloc) | `+0x8` size | `+0x10` align | `+0x18` (reloc) | Referenced at |
|---|---|---|---|---|---|
| `0x6451ad8` | `0x2ddfd00` | `0x118` | 8 | `0x2e071c0` | `0x2e0702a` |
| `0x6451ab8` | `0x2de04b0` | `0x108` | 8 | `0x2e075f0` | `0x2e06caa` |

Each poll entry has exactly one `R_X86_64_RELATIVE` (the vtable slot) and no `e8` caller. Each vtable has exactly one 7-byte RIP-relative `lea` in `.text`.

## Evidence 2: the builders

`0x2e06e40` (vtable `0x6451ad8`) and `0x2e06ac0` (vtable `0x6451ab8`) have the same shape:

- Two channel constructors, each with `mov ecx, 0x1388` (5000): `0x2cef4d0` and `0x2cef6e0` in the first, `0x2cef2c0` and `0x2cef0b0` in the second.
- `test bpl, bpl` on the fourth argument. When set, the name argument is formatted with template `0x434b16`, bytes `c0 0a 5f 66 6f 72 77 61 72 64 65 72`: argument then `_forwarder`.
- Allocation of `0x118` or `0x108` bytes (slot `0x64df480`), a copy of the future into it, and a call through slot `0x64e1758` (relocated to `0x15d6ef0`, the spawn wrapper of the 9th stage, #5876) with the box and the vtable in `rcx`.

## Evidence 3: the four builder calls

| Call | Builder | Name (`lea rsi`) | Length | Fourth argument |
|---|---|---|---|---|
| `0x2af0b57` | `0x2e06e40` | `0x605f60` `client block or tx` | `0x12` | `mov ecx, 1` |
| `0x2cbc15c` | `0x2e06e40` | `0x60f345` `client block or tx` | `0x12` | `mov ecx, 1` |
| `0x2ace102` | `0x2e06ac0` | `0x6056b2` `node_stream_connection` | `0x16` | `xor ecx, ecx` |
| `0x2ad211e` | `0x2e06ac0` | `0x6056b2` `node_stream_connection` | `0x16` | `xor ecx, ecx` |

So the 0x118 forwarder is spawned with the task name `client block or tx_forwarder`, and the 0x108 forwarder without a name.

## Evidence 4: the forwarder loop

Both polls run the same loop (0x118 / 0x108 offsets):

1. Send the stored payload: `0x2ced920` with `[rbx+0x108]` (16 bytes) / `0x2cee110` with `[rbx+0x68]` (8 bytes), Location `0x6451b10` = `node/src/channel.rs:20:33`. A result other than 5 leaves the loop.
2. Receive the next item: `0x2ce0f40` / `0x2cddeb0`. A first dword of 0 in the item leaves the loop (`test eax, eax` at `0x2e073cf` / `0x2e077e4`); inference: the channel is closed.
3. Keep the item's first 12 bytes (date, seconds, fraction) as the deadline, and the payload: item `+0x10..+0x20` to `+0x108` (`0x2e0742b`) / item `+0x10` to `+0x68` (`0x2e0783a`, `0x2e0783e`).
4. Read the wall clock (slot `0x64e0990`), take the difference (slot `0x64e0fc0`), sleep `max(0, deadline - now)` (`maxsd` at `0x2e074ba`) through `0x2d4f790`, then go to step 1.

The panic Location of both polls is `0x6451af8` = `node/src/channel.rs:16:9`.

## Evidence 5: who polls the unfold stream

`0x2cf08b0` has four direct calls, two in `0x2cdca20` (`0x2cdcce3`, `0x2cdcdd9`) and two in `0x2ce0de0` (`0x2ce0e84`, `0x2ce0f04`). At `0x2ce0de0`, `[rsp+0x4] = 2` is passed to `0x5ce2080` to pick a start branch; one branch polls the unfold stream through the state pointer `[[rsi+0x8]+0x30]` and treats result 2 as not ready (`cmp al, 2` at `0x2ce0e91`); the other branch polls the receive `0x2ced6b0`. Inference: a two-branch `select!` with random start between the interval stream and a channel.

## Implementation and comparison

The tool pins 28 instruction byte runs, 36 RIP-relative or rel32 references, the two vtables, the spawn relocation, two Location records, the channel.rs path, one template and three names, then recomputes the builder, vtable-reference, poll-reference, unfold-call and sleep-call censuses. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: tracing the unfold state's builder through `0x2accee0` and `0x2ad0db0` (bounded out); emulation (not allowed for this repository).

## Results and limitations

- Result: the two `channel.rs` futures are delay forwarders: each receives a timestamped item, sleeps until its time, then sends the payload on. `client block or tx_forwarder` carries a 16-byte payload; the `node_stream_connection` forwarder carries an 8-byte payload and has no task name. The unfold stream is one branch of a random-start select beside a channel receive.
- Limits: the censuses cover `e8` calls, 7-byte RIP `lea`s and relocations only. Not mapped: who builds the unfold state and its intervals, the select at `0x2cdca20`, what the payloads are, the meaning of the send result 5, item `+0xc..+0x10`, and the channel internals.
- Next lead: the unfold state's builder in the functions around `0x2ce0de0` (callers `0x2accee0`, `0x2ad0db0`, which also call the `node_stream_connection` builder), and what is sent into the forwarders' input channels.
