# node-runtime: node #94 accept loops `0x22c0d30` / `0x22c15e0` (accept errors print to stdout and continue; IPv6 peers rejected in `0x22c47a0`)

Question: what does the node do when accepting a peer connection fails? The
can1357 lead (`node/connections.rs` `accept_*_stream_connections` and
`net_utils/tcp/tcp_listener.rs` `run_accept_loop`) uses `accept().await?`,
so any accept error ends the loop and is returned. It accepts both IPv4 and
IPv6 peers. Where does the binary differ?

- Component ID: `node-runtime` (`docs/COMPONENTS.md`; path rule `node/*`).
  `research/catalogue/seed-candidates.json` lists `0x22c0d30` and `0x22c15e0`
  as `node/connections.rs` seeds and lists the accept poll `0x22c47a0` as a
  `transport` seed (`net_utils/tcp/tcp_listener.rs`).
- Target: `artifacts/node/94/hl-node`, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `main` `1f8c67c63ca4794c9689235471c60297f8a5c985`. Reference lead:
  `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`, used
  only for claims to test; no code, comments or names copied.
- Claim status: byte-level facts are observations; inferences are marked as
  such, and open questions are listed under Unresolved. This is partial
  `node-runtime` research; no gate changes.
- Scope:
  - In both loops: the loop body from the accept poll to the two back-jumps
    (`0x22c11c3..0x22c12a4` and `0x22c1337..0x22c14d0`, plus the twin at
    `+0x8b0`) and the Pending return `0x22c12a4..0x22c12ee`.
  - In the accept poll `0x22c47a0`: the `accept4` call and io::Error
    classification, the WouldBlock readiness clear, registration and error
    results, the IPv4 gate, the Pending result and the fd -1 panic.
  - The kind formatter `0x4b6f890`, the head of the stdout print `0x4edba50`,
    and the label, task-name and flag stores in the spawn helpers `0x225e3b0`
    and `0x225e860`.
  - A whole-`.text` census of direct `e8` calls to the accept poll and to the
    two spawn helpers.
- Excluded:
  - The bodies of the handler futures and of `0x22b8310`, `0x288d0d0`,
    `0x288cab0` and `0x4f76f80`.
  - The IPv4 path after `0x22c4f5d` (slot `0x5773800`).
  - The lazy prefix initialiser `0x143ed40`.
  - The sibling loop family `0x203f3e0` / `0x2041c60`, which polls the other
    accept monomorph `0x2048f10`. It uses the same template `0x1fb0d4` and
    the same spawn helpers, but none of its claims are checked here.

## Reproduce

```sh
make verify
python3 tools/connections_accept_loop_static.py --json > research/work-items/connections-accept-loop-94/records.json
python3 -m unittest tests.test_connections_accept_loop_static -v
```

The producer authenticates the input against `provenance/artifacts.json`. It
parses sections, `.eh_frame` FDEs (`tools/fde_extents.py`), and the `.rela.dyn`
`R_X86_64_RELATIVE` and `R_X86_64_GLOB_DAT` entries. It never executes the
target. It needs only Python 3 (run here with 3.14.7 on macOS arm64; about
1 s). `records.json` is its complete output, and the test suite regenerates
it and compares the two.

`excerpts.objdump.txt` is raw supporting text from GNU objdump 2.47. It has
20 windows (470 instructions), one for each checked byte window. All 142
`records.json` VAs that fall inside a window are instruction starts there.
The tool refuses unless each of the 84 `FACTS` entries and each of the 113
decoded call, branch and RIP-relative operands lies inside a checked window.
It also resolves and checks eight slots (six RELATIVE, two GLOB_DAT).

## Evidence

### Twins (observation)

The FDEs `0x22c0d30` and `0x22c15e0` have the same length (`0x8a9`). All 708
checked bytes of the three twin window pairs are equal, except inside the 34
rel8/rel32 operands. In those operands:

- Every target inside the loop's own FDE moves by `+0x8b0`.
- Every external target is the same in both loops.
- The one exception is the spawn call: `0x22c14c6` calls `0x225e860` and
  `0x22c1d76` calls `0x225e3b0`.

The two spawn helpers store a different label and flag, but the same task
name:

| Spawn helper | Label | Task name | Flag word `[rsp+0x2a8]` |
| --- | --- | --- | --- |
| `0x225e860` (from `0x22c0d30`) | `validator` | `handle_stream_connection` | 0 |
| `0x225e3b0` (from `0x22c15e0`) | `gossip` | `handle_stream_connection` | 1 |

The census finds that only `0x22c11e6` and `0x22c1a96` call the accept poll
`0x22c47a0`, and no RELATIVE slot holds its address. Each spawn helper has
one more caller, in the sibling family: `0x203ffe3` and `0x2042863`.

### Loop body (observation; validator twin addresses)

```text
loop:                                         ; 0x22c11c3
    r = 0x22c47a0(&out, state+0x170, cx)      ; 0x22c11e6
    if r.tag == 3:                            ; Pending
        state[0x242] = 3; return 1            ; 0x22c12a4, 0x22c12da
    copy payload; unlink waiter at [state+0x1e0] when states 0x238/0x230/0x1b8/0x228/0x220 are all 3
    if r.tag == 2:                            ; 0x22c1337
        print_stdout(template 0x1fb0d4,
                     now (0x151cba0) as "%Y-%m-%dT%H:%M:%S%.3fZ",
                     lazy &str 0x577ab58,
                     kind byte [state+0x240],
                     r.error)                 ; 0x22c1443 via slot 0x576e968 -> 0x4edba50
        drop r.error                          ; 0x22c146c
        goto loop                             ; 0x22c146e
    h = 0x22b8310(state+0xe8)                 ; 0x22c14af
    spawn 0x225e860(state+0xa0, &r, .., &h)   ; 0x22c14c6
    goto loop                                 ; 0x22c14cb
```

The template decodes to
`{} ERROR >>> {} @@ node failed to accept {} connection: {}\n\n`. The print
sink `0x4edba50` loads the label `stdout`. The kind formatter `0x4b6f890`
writes `gossip` when the byte is 1 and `validator` otherwise. In the checked
window, the error arm `0x22c1341..0x22c1473` has no `ret`. Its only calls are
the wall clock, the print, the timestamp-string free (`0x576e010`) and the
error drop, and then it jumps back. The branch to `0x22c14dc`, taken when
the lazy prefix is not yet initialised, is not decoded.

### Accept poll `0x22c47a0` (observation)

| Case | Path | Result tag |
| --- | --- | --- |
| listener fd is -1 | `0x22c5040` panic, Location `tokio-1.44.2/src/io/poll_evented.rs:288:26` | none |
| `accept4` (`0x3cd6220`) error, WouldBlock | io::Error repr table `0x3d67ac`: kind byte 13 (SimpleMessage, Custom), Os 11 (EAGAIN) or Simple kind 13 → `0x22c4cb7`, clears readiness bits | none from this block |
| `accept4` error, any other | `0x22c4e13` → `0x288d0d0` | 2 |
| Tokio registration `0x4f76f80` (interest 3) fails | close the fd (GLOB_DAT `close`) | 2 |
| Tokio context shutting down (block `0x22c4df5`; its entry is not decoded) | message `A Tokio 1.x context was found, but it is being shutdown.` (kind `0x28`) | 2 |
| peer `SocketAddr` tag bit 0 set (V6) | `0x288cab0("ip not v4")`, close fd if not -1, drop stream | 2 |
| IPv4 peer | continues at `0x22c4f5d` | not decoded |
| not ready | `0x22c501f` | 3 |

## Lead comparison

| Point | Binary | Lead |
| --- | --- | --- |
| Accept error | prints one `ERROR >>>` line to stdout, drops the error and polls again; the loop never returns it | `accept().await?` returns the error and ends the loop |
| Retry pacing | no sleep call on the checked path between a failed accept and the next poll | not applicable |
| IPv6 peer | rejected inside the accept poll with `ip not v4`, fd closed, reported as an accept error | accepted (`decode_sockaddr` handles `AF_INET6`) |
| Handler | spawned (`handle_stream_connection`), not awaited | `run_accept_loop` awaits the handler and returns its error; `connections.rs` spawns |
| Per-loop identity | validator / gossip label and flag in the spawn helper; error kind text from byte `+0x240` | `gossip` / `abci` function names |
| Log target | stdout via `std` print | `log_warn` with `dropping connection` (handler errors only) |

## Inference

- The lazy `&str` at `0x577ab58` is probably a process-wide prefix such as a
  host or node name. Its initialiser is not decoded.
- Because the error arm loops without pausing, a persistent accept error
  (for example `EMFILE`) would print one stdout line per poll. This follows
  from the control flow but has not been run.
- The `0x22c47a0` / `0x2048f10` pair looks like two monomorphs of the same
  accept wrapper, since both have the same `ip not v4` gate.

## Unresolved

- Which value of the kind byte `[state+0x240]` each loop holds.
- What `0x22b8310` clones and what the spawned handler does.
- The IPv4 path and the payload layout after `0x22c4f5d`.
- The sibling family `0x203f3e0` / `0x2041c60`.

## Controls

- `tests/test_connections_accept_loop_static.py` checks:
  - the models `accept_result`, `loop_step` and `lead_step`;
  - the template text, the twin layout, the spawn labels, the kind text, the
    accept-poll cases and the caller census;
  - regeneration of `records.json`, and the CLI.
- Corruption tests (each must raise `EvidenceError`):
  - an error arm that returns, a removed IPv4 gate and a changed kind compare;
  - the template text, the `ip not v4` string, a jump-table entry and the
    panic Location line;
  - the print and lazy-initialiser RELATIVE slots, and the `close` GLOB_DAT
    symbol;
  - twin bytes that differ outside an operand;
  - a planted extra `e8` call to the accept poll.
- Both toolchains: the module passes with GNU binutils on `PATH` and with
  only LLVM; the tool itself uses neither.
