# transport: node #94 TCP socket-call census (socket types, socket options, listen backlogs, accept4 flags)

Question: which socket types, socket options, listen backlogs and `accept4`
flags can node #94 pass to libc, and which socket helpers do the NodePort
connect and listen paths reach? Where does the can1357 `tcp_listener.rs` lead agree or
differ?

- Component ID: `transport` (`docs/COMPONENTS.md`: TCP framing, LZ4,
  channels, rate limits and reconnects).
- Target: `artifacts/node/94/hl-node`, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `main` `1f8c67c63ca4794c9689235471c60297f8a5c985`. Reference lead:
  `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`
  (`net_utils/tcp/tcp_listener.rs`), used only for seed addresses and claims;
  no code, comments or names copied.
- Claim status: observation for byte-level facts, inference where marked,
  unresolved where listed. Partial `transport` research; no gate change.
- Scope: every `call [rip+slot]` to libc `socket`, `setsockopt`, `listen`,
  `accept4`, `bind` and `connect`, the constant arguments loaded immediately
  before each, and the call-graph links from the NodePort FDEs to the connect
  and listen helpers. Excluded: which crate owns each call site (std, mio, socket2,
  hyper), run-time values of non-constant arguments, `getsockopt`/`shutdown`,
  and release #115.

## Reproduce

```sh
make verify
python3 tools/socket_calls_static.py --out research/work-items/transport-socket-calls-94
python3 -m unittest tests.test_socket_calls_static -v
```

The producer authenticates the input against `provenance/artifacts.json`. It
parses sections, `.eh_frame` FDEs and `.rela.dyn`, and resolves
`R_X86_64_GLOB_DAT`/`JUMP_SLOT` symbol names through `.dynsym`/`.dynstr`.
Each libc function must have exactly one slot. Every `ff 15|25` call to that
slot in `.text` is counted, and the arguments are decoded from exact
instruction sequences that end at the call. Pure Python 3 (3.14.7 here),
under 2 s; nothing is executed.

`excerpts.objdump.txt` holds GNU objdump 2.47 windows (36), each decoded
linearly from the owning FDE start, so the window boundaries are instruction
starts. All 78 code VAs in `records.json` are instruction starts in those
windows.

## Evidence

### Call counts

| libc function | Slot | Call sites |
| --- | --- | ---: |
| `socket` | `0x5775210` | 5 |
| `setsockopt` | `0x576f0d0` | 18 |
| `bind` | `0x5775220` | 4 |
| `listen` | `0x5776450` | 2 |
| `accept4` | `0x5776448` | 1 |
| `connect` | `0x576f150` | 8 |

### `socket`

All five calls use `SOCK_STREAM | SOCK_CLOEXEC`. Two of them also set
`SOCK_NONBLOCK` (`0x80801`): `0x3cd6353` (FDE `0x3cd6330`) and `0x3cd66b3`
(FDE `0x3cd6690`). The other three use `0x80001`:

- `0x4ee12e4` and `0x4ee134f` (FDE `0x4ee12c0`) pass `AF_INET6` and `AF_INET`
  as constants.
- `0x29c333e` (FDE `0x29c3300`) passes protocol 6 (`IPPROTO_TCP`).
- The rest compute the domain as `flag*8 + 2` (`AF_INET` or `AF_INET6`).

### `setsockopt`

All 18 calls end with `mov esi,level; mov edx,optname; mov r8d,4; call`, and
each (level, optname) pair is one of 8 known options. Where the option value
is a constant 4-byte store to the slot that `rcx` points at, the tool records
it.

| Option | Sites | Constant value |
| --- | ---: | --- |
| `SO_REUSEADDR` (1,2) | 4: `0x29c3897`, `0x3cd66de`, `0x4ee1313`, `0x4ee137e` | 1 at all 4 |
| `SO_KEEPALIVE` (1,9) | 2: `0x29af121`, `0x29c33ea` | 1 at both |
| `SO_SNDBUF` (1,7), `SO_RCVBUF` (1,8) | 1 each, FDE `0x29c3300` | from a clamped register |
| `TCP_NODELAY` (6,1) | 4: `0x140ca9c`, `0x1611241`, `0x242aa45`, `0x29af348` | a byte loaded from memory |
| `TCP_KEEPIDLE` (6,4), `TCP_KEEPINTVL` (6,5), `TCP_KEEPCNT` (6,6) | 2 each, FDEs `0x4ecd970`, `0x4ecda60` | from registers (`cmovb` against `0x7fffffff` visible in the excerpts) |

### `listen` and `accept4`

- `listen` at `0x3cd677c` (FDE `0x3cd6690`) uses backlog **1024**. That FDE
  creates a non-blocking socket, sets `SO_REUSEADDR` = 1, and binds before
  listening.
- `listen` at `0x4ee13d3` (FDE `0x4ee12c0`) uses backlog **128**. That FDE
  creates a blocking `SOCK_CLOEXEC` socket, sets `SO_REUSEADDR` = 1, and binds
  before listening.
- The only `accept4` call (`0x3cd6244`, FDE `0x3cd6220`) passes
  `SOCK_NONBLOCK | SOCK_CLOEXEC` (`0x80800`).

### NodePort connect path (call graph only)

Slot `0x57737f8` is relocated to `0x3cd6330`. That FDE contains exactly one
`socket` call (`SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC`) and one `connect`
call (`0x3cd63db`). It is called through the slot from exactly three FDEs:
`0x20487f0`, `0x439efe0` and `0x4b399a0`.

The two NodePort table-shape FDEs call the first two of these directly:
`0x2037ac0` calls `0x20487f0` at `0x2037d9b`, and `0x43831e0` calls
`0x439efe0` at `0x43834bb`. These are the FDEs whose u16 port tables are
mapped in the separate NodePort packet. Whether the port built there is the
address that reaches `connect` is not established; only the call edges are.

### NodePort listen path: backlog 1024

- **Into the wrapper:** slot `0x5773d08` is relocated to `0x4f78960`. Its only
  callers are one call each in the three NodePort FDEs that compute listen
  ports: `0x22c5c3b` in `0x22c54a0`, `0x4391062` in `0x438ed70`, and
  `0x47b68fa` in `0x47b4950`.
- **Into the helper:** `0x4f78960` makes exactly one listen-helper call
  (`0x4f78970`), through slot `0x5776490`, to `0x3cd6690`. That is the
  non-blocking socket, `SO_REUSEADDR` = 1, bind, `listen(1024)` path.
- **The backlog-128 helper:** `0x4ee12c0` has a single slot caller
  (`0x29ae938` in FDE `0x29ae8f0`), which is not a NodePort FDE.
- **No direct calls:** neither helper has any direct `call`/`jmp rel32`
  caller.

So by call graph, NodePort listeners reach the backlog-1024 helper, not the
backlog-128 one.

## Comparison with the lead

Agreements:

- `0x4ee12c0`: `SOCK_CLOEXEC` socket for IPv4/IPv6, `SO_REUSEADDR`, bind,
  listen with backlog 128.
- `0x3cd6220`: `accept4` with `SOCK_NONBLOCK | SOCK_CLOEXEC`.
- `0x4b399a0` (the lead's reconnecting-client seed) uses the same
  non-blocking connect helper.

Additions and corrections:

- **Listen backlog:** the lead's `tcp_listener.rs` ties its listen-with-retry
  future (`0x22c54a0`) and gossip listener (`0x47b4950`) to the `0x4ee12c0`
  helper with `LISTEN_BACKLOG = 128`. By call graph, those FDEs (and
  `0x438ed70`) reach only `0x3cd6690`, which listens with backlog **1024** on
  a non-blocking socket. `0x4ee12c0` is reached from an unrelated FDE.
- **Not modeled by the lead:** `SO_KEEPALIVE` = 1 (2 sites), `TCP_NODELAY`
  (4 sites, value from memory), `SO_SNDBUF`/`SO_RCVBUF`, and
  `TCP_KEEPIDLE`/`KEEPINTVL`/`KEEPCNT` setters.

Corruption controls (all must refuse):

- unknown option number
- `optlen` 4→8
- removed `listen` backlog load
- `socket` type changed
- injected 19th `setsockopt` call
- connect-helper slot relocation changed
- listen wrapper's inner call retargeted to the backlog-128 slot
- injected fourth listen-wrapper caller
- injected direct call to a listen helper
- NodePort call retargeted
- truncated ELF

## Results and limitations

| Metric | Value |
| --- | ---: |
| `socket` / `setsockopt` / `bind` / `listen` / `accept4` / `connect` call sites | 5 / 18 / 4 / 2 / 1 / 8 |
| Distinct socket options set | 8 |
| Listen backlogs (all sites / NodePort path) | 1024, 128 / 1024 |
| Code VAs that are GNU objdump instruction starts | 78 / 78 |

Validation on this branch (macOS arm64, Python 3.14.7, GNU binutils 2.47 for
the full suite): `make verify`, `make test`, `make catalogue-check`. The new
module (18 tests) also passes with only macOS LLVM tools on `PATH`.

Not established:

- Crate ownership of each FDE. That `0x4ee12c0` is std's
  `TcpListener::bind` and `0x3cd6690`/`0x3cd6330` are mio's is an inference
  from the flag and backlog shapes only.
- Run-time values of `TCP_NODELAY`, buffer sizes and keepalive timings.
- Which listeners and connections the node actually opens at run time, and
  whether calls through other paths (raw `syscall`, other symbols) exist. The
  NodePort links are call edges, not data flow.

Gate: none requested; `transport` gates stay false. Next question: the address
data flow from the NodePort port computation into `0x3cd6330`/`0x3cd6690`, and
what owns the backlog-128 path (`0x29ae8f0`).
