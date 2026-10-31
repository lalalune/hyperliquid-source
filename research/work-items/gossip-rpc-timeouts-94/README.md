# node-runtime: node #94 gossip RPC timeout seconds and connect-retry record

Question: which f64 second constants do the gossip RPC request paths store
next to their descriptors, what retry record do the request futures build, and
is there a 60-second connect timeout in those futures as the can1357
`node/gossip_rpc_client.rs` lead claims?

- Component ID: `node-runtime` (`docs/COMPONENTS.md`: CLI, startup, gossip,
  stream services; path rule `node/*`).
- Target: `artifacts/node/94/hl-node`, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `main` `1f8c67c63ca4794c9689235471c60297f8a5c985`. Reference lead:
  `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`
  (`node/gossip_rpc_client.rs`), used only for seed addresses and claims to
  test; no code, comments or names copied.
- Claim status: observation for byte-level facts, inference where marked,
  unresolved where listed. Partial `node-runtime` research; no gate change.
- Scope: six fixed instruction windows in five FDEs (`0x1fd4570`,
  `0x226bb20`, `0x435cb20`, `0x2039060`, `0x4387f40`), the strings and f64
  constants they reference, and every f64 `movabs`/RIP `movsd` in the two
  request futures. Excluded: the retry loop body (`0x22689f0`), how the stored
  values are consumed beyond the seconds-to-microseconds conversion, callees
  of the request futures, and release #115.

## Reproduce

```sh
make verify
python3 tools/gossip_rpc_timeouts_static.py --json > research/work-items/gossip-rpc-timeouts-94/records.json
python3 -m unittest tests.test_gossip_rpc_timeouts_static -v
```

The producer authenticates the input against `provenance/artifacts.json`, parses
sections, `.eh_frame` FDEs (`tools/fde_extents.py`) and `.rela.dyn`
`R_X86_64_RELATIVE` entries, and never executes the target. It needs only
Python 3 (run here with 3.14.7 on macOS arm64; under 1 s). `records.json` is
its complete output; the test suite regenerates and compares it.

`excerpts.objdump.txt` is raw supporting text from GNU objdump 2.47, in 18
windows. All 30 instruction VAs in `records.json` are instruction starts in
those windows.

## Evidence

### Timeout seconds stored with a descriptor (observation)

Each window below is checked as exact bytes. It LEAs a descriptor, stores its
length, stores an f64 `movabs` immediate into the future state, and loads the
same value again from a `.rodata` constant.

| FDE | LEA | Descriptor (VA, len) | Immediate | `.rodata` constant |
| --- | --- | --- | --- | --- |
| `0x1fd4570` | `0x1fd4656` | `gossip_rpc_request` (`0x3c4610`, 18) | 10.0 at `0x1fd4678` | `0x20a8a8` = 10.0 |
| `0x1fd4570` | `0x1fd4eff` | `verify_rpc` (`0x3c4639`, 10) | 5.0 at `0x1fd4f26` | `0x20a890` = 5.0 |
| `0x226bb20` | `0x226bb82` | `gossip_rpc_request` (`0x3d7a0d`, 18) | 10.0 at `0x226bba4` | `0x20a8a8` = 10.0 |
| `0x435cb20` | `0x435cb73` | `gossip_rpc_request` (`0x6f10af`, 18) | 10.0 at `0x435cb95` | `0x20a8a8` = 10.0 |

Each of these FDEs multiplies an f64 by the `.rodata` constant `0x20ae60`
(1e6). It does so at `0x1fd475e` and `0x1fd500c`, at `0x226bcd0`, and at
`0x435ccc6`. Each multiply is followed by a call through RELATIVE slot
`0x576f6d8` (to `0x565f410`, not identified here) and a saturating f64 to u64
conversion. Finite negative values give 0, finite values above the largest
double below 2^64 give `u64::MAX`, and NaN or infinity gives 0 (the
`jg` exponent test skips the clamp with the operand zeroed).

Inference: these are timeout durations in seconds, converted to an integer
microsecond count. The 10 s value is shared by all three `gossip_rpc_request`
sites, and the verified path at `0x1fd4570` also has a 5 s `verify_rpc` step.

### Connect-retry record in the request futures (observation)

`0x2039060` and `0x4387f40` both execute the same sequence:

1. LEA a format template at `0x1f2107`, whose literal text starts with
   `rpc connect `.
2. Call through RELATIVE slot `0x576e040` (to `0x1344760`).
3. Copy the resulting 24-byte value to `[rbx+0x170]`.
4. Build a record at `[rbx+0x148]`: `r14`, the pointer and length taken from
   that value, the integer `10` at `+0x18` (`0x20392ba` / `0x438819a`), and
   the f64 `2.0` at `+0x20` (`0x20392c5` / `0x43881a5`).

Inference: the call formats an `rpc connect …` descriptor string, and the
record is a sleep-retry policy: descriptor, try count 10, sleep 2.0 s. This
reading fits the `AsyncSleepRetry::retry desc=[…] n_tries=… failed` template
at `0x1f2257`, but this packet does not tie that template to this record.

### Census: the (10, 2.0) record shape across `.text` (observation)

The instruction pair `mov QWORD [rbx+d],10; movabs rax,2.0` occurs exactly 8
times in `.text`. This is a byte scan pinned to that count; it would also catch
a misaligned match. Four of the sites store a static descriptor directly before
the count: `lea rax,[rip+desc]`, then a store to `[rbx+d-0x10]`, then an
immediate length store to `[rbx+d-8]`.

| FDE | Count store | Descriptor |
| --- | --- | --- |
| `0x2039060` | `0x20392ba` | formatted `rpc connect …` (above) |
| `0x4387f40` | `0x438819a` | formatted `rpc connect …` (above) |
| `0x22689f0` | `0x2268bb4` | static `gossip rpc height` (`0x3d7953`, 17) |
| `0x22c54a0` | `0x22c55c2` | static `NodePort::listen` (`0x209360`, 16) |
| `0x438ed70` | `0x438f2c1` | static `NodePort::listen` |
| `0x47b4950` | `0x47b4b79` | static `NodePort::listen` |
| `0x439fa90` | `0x439fb54` | formatted `tcp_stream_with_retry …` (`0x1ffb5e`) |
| `0x4b399a0` | `0x4b39c79` | formatted `tcp_stream_with_retry …` (`0x1ffb5e`) |

`0x22c54a0`, `0x438ed70` and `0x47b4950` are the three NodePort
listen-port FDEs. Inference: a {descriptor, 10, 2.0} sleep-retry record is
a shared default for NodePort listen, the gossip RPC connect, and the
`gossip rpc height` step of the wrapper the lead seeds as `AsyncSleepRetry`
(`0x22689f0`).

Note: whether a given loop actually stops after the stored 10 is not checked
here. The open packet
[#451](https://github.com/lalalune/hyperliquid-source/pull/451) reads the
loops of all eight sites above. In each, the attempt bound is
`max(-1, 1)` = `u64::MAX`, and no record-pointer load reads the 10 at `+0x18`.
So the "try count 10" reading is not supported for any of them.

For each of the other four sites, the tool takes the last call through
`0x576e040` within 0x90 bytes before the count store. It then takes the last
`lea rsi,[rip+t]` within 0x40 bytes before that call. It reads the template's
first byte as a literal length N and requires the next N bytes to be
printable. This gives `rpc connect ` (12) twice and `tcp_stream_with_retry `
(22) twice (`0x439fb14`, `0x4b39c22`). The header-length reading is an
inference from rustc 1.94's packed format templates; the two pinned literals
are what the tests check.

### The only 60.0 in the request futures is a writer argument (observation)

A scan of every `movabs r64,imm64` and every RIP-relative `movsd` load from
`.rodata` finds exactly one 60.0 in each request future. In `0x2039060` it is
the immediate at `0x20399c0`; in `0x4387f40` it is at `0x43888a0`. Each sits
within 0x40 bytes before a direct call to a TCP frame writer: `0x20399f7` calls
`0x204b340`, and `0x43888d7` calls `0x43a17c0`. The distinct f64 immediates
with magnitude between 1e-6 and 1e7 in each future are exactly {2.0, 60.0}.

The scan matches bytes, not decoded instructions. A false match could only
add sites, and the tool refuses to run unless exactly one site is found.

The TCP frame-write packet
(`research/work-items/transport-tcp-frame-write-94`, open PR) decodes those two
writer calls. Both pass flag 0, which selects the writer's 20 s chunk timeout,
so the 60.0 goes unused there.

## Comparison with the lead

- `REQUEST_TIMEOUT = 10 s` labelled `gossip_rpc_request`: consistent with all
  three `gossip_rpc_request` sites.
- `VERIFY_TIMEOUT = 5 s`: consistent with the `verify_rpc` 5.0 in `0x1fd4570`.
- `CONNECT_TIMEOUT = 60 s` (`connect_rpc_stream`): not supported by the two
  request futures. Their only 60.0 is the frame-writer argument described
  above. A connect timeout inside a callee is not excluded (see Unresolved).
- `retry_tries: 10` on a policy labelled `gossip_rpc_request`: the binary's
  count 10 (with 2.0 s) sits in a record built from the formatted
  `rpc connect …` descriptor inside the request future. It is not stored next
  to the `gossip_rpc_request` timeout descriptor. The same (10, 2.0) pair also
  appears with `NodePort::listen` and `gossip rpc height` (census above).
  The lead's 2 s retry delay for connect errors matches the 2.0 in this
  record. Its other delays (`RETRY_DELAY_*`) are not tested here.

## Controls

`tests/test_gossip_rpc_timeouts_static.py` (18 tests) regenerates
`records.json`. It also refuses each of these corruptions:

- Any timeout immediate replaced by 60.0.
- The shared 10.0 constant changed.
- Either descriptor's first byte changed.
- Both 1e6 multiplies in `0x1fd4570` redirected.
- The retry count changed to 11, or the 2.0 changed to 60.0, in either future.
- The template text changed.
- An extra 60.0 `movabs` planted in `0x2039060`.
- An extra (10, 2.0) census site planted, or a static census descriptor made
  non-printable.
- A census format call redirected, or a template literal made non-printable.
- The writer call opcode removed.
- A window attributed to the wrong FDE.

The module passes with GNU binutils or with LLVM tools only on `PATH`; the
producer does not use either.

## Unresolved

- What `0x565f410` does to the scaled value (for example, rounding), and which
  timer consumes the microseconds.
- The meaning of the record's first word (`r14`), and the retry loop that reads
  the record. The lead seeds that loop at `0x22689f0`. That FDE's own 2.0 is
  the `gossip rpc height` census record; its `.rodata` loads of 540.0 and
  840.0 are not interpreted here.
- Whether any callee of `0x2039060` / `0x4387f40` applies its own connect
  timeout.
