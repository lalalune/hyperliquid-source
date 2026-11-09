# RE-008: node #115 `gossip_rpc_request` before `verify_peer` (30th stage)

- Component ID: transport. Question: the 29th stage (open PR #5966) found that the `verify_peer` future `0x2ae0920` first awaits `0x2ae0100`, which writes the name `gossip_rpc_request` and `10.0`, and continues only when that step returns tag `0x44`. It left open what `0x2ae0100` and its inner future do, and where the caller's `+0x1268` dword comes from.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5964 and #5966. It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, string bytes, FDE extents and call and operand censuses are observations. "Timeout", "socket address", "IPv4", "port", "retry count", "retry delay" and "pending" are inferred labels from the constants, strings and layout. The binary was not executed.
- Scope included: the start state and inner poll of `0x2ae0100`; the connect-address, connect-message, retry and send sites of `0x2b69d20`; direct-call censuses; the `+0x1268` operand census of the caller `0x2accee0`. Scope excluded: the rest of `0x2b69d20`, the send poll `0x2b7a290`, the request and reply format, and whoever builds the caller's state. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/gossip_rpc_request_115.py --check
python3 -m unittest tests.test_gossip_rpc_request_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: `0x2ae0100` wraps one inner future with a 10-second name and limit

- The start state stores the name pointer `0x605aac` (`gossip_rpc_request`) at `+0x38` and length 18 at `+0x40`, and `0x4024000000000000` (10.0) at `+0x470`.
- The poll moves 0x498 bytes to `+0x8e0` and calls `0x2b69d20` directly (`0x2ae0454`) with `rsi = rbx+0x8e0`.
- Inner tag `0x46`: the outer writes `0x45` and returns. The 29th stage reads `0x45` as pending.
- Inner tag `0x45`: the outer formats the `lu::timeout` template `0x4326d0` with the name and returns tag `0x2f`.
- Any other inner tag is stored unchanged at `0x2ae0796` (`mov [r12], bpl`). So the `0x44` that `verify_peer` waits for is the inner future's own tag.

## Evidence 2: the inner future connects to port 4002 with retries

In `0x2b69d20`:

- `0x2b69da8..0x2b69dcd`: it loads a pointer from `+0x70`, reads a dword through it, and writes word `0` at `+0x80`, the dword at `+0x82` and word `0xfa2` (4002) at `+0x86`. This is the same layout the 29th stage found for `verify_peer` on port 4001 (`0xfa1`).
- `0x2b69de4`: it formats `rpc connect {}` (`0x4422f7`) with `&+0x80`.
- `0x2b69e4d..0x2b69e69`: beside the message it stores `11` at `+0x158` and `2.0` at `+0x160`.
- `0x2b6a074`, `0x2b6a0d4`: the retry-exhausted path formats `async_sleep_retry retries exhausted: {}` (`0x444d45`) and `[n_retries: {}]` (`0x434a4e`) with `+0x1a8`.

Inference: the node opens a TCP connection to the peer IP on port 4002, retrying up to 11 times with a 2-second delay.

## Evidence 3: the inner future then sends the request with a 60-second name and limit

`0x2b6a60b..0x2b6a6a6`: it loads the request pointer from `+0x78`, stores the name `send gossip rpc request` (`0x605abe`, 23 bytes) at `+0x140/+0x148`, stores `0x404e000000000000` (60.0) at `+0x170`, and calls `0x2b7a290`.

## Evidence 4: censuses

| Target | Direct calls |
|---|---|
| `0x2ae0100` | `0x2adacc4`, `0x2adee64`, `0x2ae097f` (the last is `verify_peer`) |
| `0x2b69d20` | `0x2ae0454`, `0x2cb2101` |
| `0x2accee0` (the 29th stage's caller) | `0x2b1db89`, `0x2b26b09` (task-harness polls; the future sits at `+0x38`) |

In the FDE of `0x2accee0` (`0x2accee0..0x2ad0db0`), every `[reg+0x1268]` operand without SIB is a load (8 sites). There is no store. So `+0x1268` is set before the first poll, by whatever builds the future.

## Implementation and comparison

The tool pins 30 instruction byte runs, 8 references, 6 strings, three direct-call censuses and the `+0x1268` operand census. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). Alternatives considered: following the request into `0x2b7a290` and the reply reader (bounded out); emulation (not allowed for this repository).

## Results and limitations

- Result: before `verify_peer` on port 4001, the node connects to the same kind of address on port 4002 with up to 11 retries, under a 10-second `gossip_rpc_request` limit, and sends a request under a 60-second `send gossip rpc request` limit.
- Limits: the request and reply format is not mapped. The string `TcpRead::bincode err: {}` exists at `0x444d6e`, but no RIP-relative `lea` in `.text` points at it, so it is not linked to this path. The link between the inner future's `+0x70` pointer and the caller's `+0x1268` dword is not traced. Which inner tag means success other than the `0x44` the 29th stage observed, the meaning of `0x2b7a290`, the second caller of `0x2b69d20` (`0x2cb2101`), and who builds the caller's state are not mapped.
- Next lead: map `0x2b7a290` and the reply path to find the request and reply format.
