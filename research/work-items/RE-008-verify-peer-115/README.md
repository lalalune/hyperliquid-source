# RE-008: node #115 verify_peer future `0x2ae0920` (29th stage): the 5-second check and what a failure does

- Component ID: transport. Question: the 28th stage (open PR #5964) found that each 10-second tick of the lu.rs unfold stream makes the caller in `0x2accee0` poll `0x2ae0920`, which writes a request named `verify_peer` with a dword at `+0x22` and 4001 at `+0x26`. It left open the timeout, the source of the dword, what runs first, and how the result is handled.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5963 and #5964. It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, strings, relocations, a jump table and direct-call censuses are observations. "Future", "await", "timeout", "Tokio sleep", "socket address", "IPv4", "node IP", "success counter" and "event" are inferred labels. The binary was not executed.
- Scope included: the resume table and start state of `0x2ae0920`; the head of `0x2ae0100`; the request fields; the deadline and the poll of the inner future and the sleep; the result tags; the caller's success and failure paths at `0x2ad0260..0x2ad06fa`; the head of `0x4fac470`. Scope excluded: the body of `0x2ae0100` and of the inner poll `0x2b782e0` (transport and reply format), the event writer `0x2d4e730`, the second builder `0x2ad0db0` and its two calls, and the source of the caller's `+0x1268` dword. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/verify_peer_115.py --check
python3 -m unittest tests.test_verify_peer_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The five `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: two steps, gossip_rpc_request first

`0x2ae0920` dispatches on its state byte through table `0x604058` (targets `0x2ae094d`, `0x2ae11ae`, `0x2ae11bb`, `0x2ae096d`, `0x2ae099d`). The start state (`0x2ae094d`) copies the dword at `+0x1` to `+0x5` and `+0x9`, stores `1` at `+0x10` and `&+0x9` at `+0x28`, and calls `0x2ae0100`. That function writes the name `gossip_rpc_request` (18 bytes, `0x605aac`) and `10.0` at its `+0x470` (`0x2ae015e`, `0x2ae0175`).

- Result tag `0x45`: pending.
- Result tag `0x44`: continue to the second step.
- Any other tag: returned as is (`0x2ae0b12` → `0x2ae10e9`).

## Evidence 2: the verify_peer request and its 5-second deadline

At `0x2ae0b4c..0x2ae0b82` the future writes `verify_peer` (11 bytes) at `+0x10`/`+0x18`, word `0` at `+0x20`, the dword from `+0x5` at `+0x22`, word `0xfa1` (4001) at `+0x26`, and the f64 `5.0` at `+0x110`. The same value is loaded from `0x4593d0`.

Inference: `+0x20..+0x28` is a V4 socket address: tag 0, the 4-byte address, port 4001.

The deadline: clock id 1 through `0x5c842e0` (`0x2ae0c71`), `5.0` converted by `0x15ed960` (slot `0x64e0f70`, as in #5861), added with nanosecond carry. The runtime field `+0x90` equal to 1e9 panics with the 0x73-byte text "A Tokio 1.x context was found, but timers are disabled. …" (`0x2ae1193`).

The poll:

- inner future `+0x188` through `0x2b782e0`; `3` means pending (`0x2ae0e82`);
- while pending, the sleep through slot `0x64e1358` (`0x5ce94c0`); a non-zero result is pending (`0x2ae0ea4`);
- on expiry the name is formatted with the `lu::timeout` template `0x4326d0` (`0x2ae0f3d`) and the result tag is `0x34` (`0x2ae1012`);
- an inner result `2` also gives `0x34` (`0x2ae1003`); any other inner result gives `0x44` (`0x2ae10c7`).

## Evidence 3: what the caller does with the result

The caller `0x2accee0` copies its `+0x1268` dword into the future at `+0x1289` (`0x2ad0260..0x2ad026d`) and calls `0x2ae0920` (`0x2ad028b`).

- Tag `0x44` (`0x2ad0302`): if the counter at `+0x1250` is 0 it calls slot `0x64e7340` → `0x4fac470` with the same dword (`0x2ad031f`). That function logs `marking node_ip as verified` (27 bytes, `0x919921`) with the dword. The counter is then incremented with saturation (`0x2ad0339..0x2ad0347`).
- Any other non-pending tag (`0x2ad051f`): formats `peer verification failed: {}` (template `0x44900c`), records an event with `dropping connection` (19 bytes, `0x6056de`), the dword, the counter and the 12 bytes at `+0x126c` through `0x2d4e730` (`0x2ad0683`), and releases the unfold seed at `+0x1248` (`0x2ad06e4`).

Inference: the caller's `+0x1268` dword is the peer's IPv4 address ("node_ip"). Every 10 seconds the node asks that peer for `verify_peer` on port 4001 with a 5-second limit. The first success marks the IP as verified; a failure or timeout drops the connection and stops the ticks.

Census: `0x2ae0920` has four direct callers (`0x2acd8c1`, `0x2ad028b`, `0x2ad17db`, `0x2ad42b3`); `0x2ae0100` has three (`0x2adacc4`, `0x2adee64`, `0x2ae097f`); `0x4fac470` has none (reached through the slot).

## Implementation and comparison

The tool pins 52 instruction byte runs, 14 RIP-relative references, 6 direct calls, 4 slot relocations, 7 strings, the resume table and the 5.0 constant, then recomputes the three call censuses. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: mapping the transport inside `0x2b782e0` (bounded out); emulation (not allowed for this repository).

## Results and limitations

- Result: the verify_peer check has a 5-second limit and runs after a `gossip_rpc_request` step that carries 10.0. A failure or timeout drops the connection; the first success logs the node IP as verified.
- Limits: the transport and the reply format (inside `0x2ae0100` and `0x2b782e0`) are not mapped; what the 10.0 in `0x2ae0100` does is not mapped; the meaning of inner result `2` is not mapped; the other three callers of `0x2ae0920` were not traced; where `+0x1268` is written is not found by a direct store in `0x2accee0`.
- Next lead: map `0x2ae0100` and the inner poll `0x2b782e0` to find the connection and the reply.
