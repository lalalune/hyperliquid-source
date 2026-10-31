# transport: node #94 `net_utils/src/channel.rs` panic Locations (93:47 is an `async fn` resume Location in 21 FDEs, not an unwrap; 117:30 is the caller Location of Tokio's blocking path in four FDEs)

Question: what do the `net_utils/channel.rs` seeds do with the source
Locations they carry? The can1357 lead (`net_utils/channel.rs`, header) says
the nine seeds `0x47b05f0` ... `0x4b3c560` are "monomorphized
`Receiver<T>::recv` futures; they poll Tokio `UnboundedReceiver::recv` and
unwrap the `Option<T>` at `channel.rs:93:47`". It says `0x474bfa0` is a
"request/response future; allocates a Tokio oneshot, enqueues
`(request, reply_to)`, awaits the reply, and unwraps at `channel.rs:117:30`".
Its `Sender::send` is `send(message).unwrap()`. What do the bytes show?

- Component ID: `transport` (`docs/COMPONENTS.md`; path rule `net_utils/*`).
  `research/catalogue/seed-candidates.json` lists 19 `net_utils/channel.rs`
  seeds. No earlier packet or open PR covers this file.
- Target: `artifacts/node/94/hl-node`, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `main` `1f8c67c63ca4794c9689235471c60297f8a5c985`. Reference lead:
  `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`, used
  only for claims to test; no code, comments or names copied.
- Claim status: byte-level facts are observations; inferences are marked as
  such, and open questions are listed under Unresolved. This is partial
  `transport` research; no gate changes.
- Companion: open PR #625 covers the ABCI latency sampler. Its constructor
  `0x3d22aa0` is the one two of the blocking receive loops here call.
- Scope (36 windows):
  - the two `lea` / call pairs at 93:47 in each of 21 FDEs;
  - the two const panic functions `0x157b540` and `0x157b560`;
  - the three callers of the blocking helpers, from their entry to the None
    test, plus each None arm to its `ret`;
  - the three blocking helpers `0x437f970`, `0x437f580` and `0x437fdb0`:
    from their entry to the `Result::unwrap` call, plus the inlined recv
    resume panics;
  - the inlined blocking path in `0x2017c80` (`0x201889d..0x20188e3`).
  - Also: the path string, all seven Locations, the panic messages, and a
    whole-`.text` census of references to the Locations and of calls to the
    helpers.
- Excluded:
  - the async state machines around the 93:47 pairs (which state reaches
    which panic, and what they poll);
  - the loop bodies of the three receive loops;
  - the future driven in `0x2017c80`;
  - the panic runtime behind the slots.

## Reproduce

```sh
make verify
python3 tools/channel_locations_static.py --json > research/work-items/channel-locations-94/records.json
python3 -m unittest tests.test_channel_locations_static -v
```

The producer authenticates the input against `provenance/artifacts.json`. It
parses sections, `.eh_frame` FDEs (`tools/fde_extents.py`), and the `.rela.dyn`
`R_X86_64_RELATIVE` entries. It never executes the target. It needs only
Python 3 (run here with 3.14.7 on macOS arm64; about 1 s). `records.json` is
its complete output, and the test suite regenerates it and compares the two.

`excerpts.objdump.txt` is raw supporting text from GNU objdump 2.47. It has
36 windows (536 instructions, 2668 bytes), one for each checked byte window.
All 244 `records.json` VAs that fall inside a window are instruction starts
there. The tool refuses unless each of the 215 decoded call, branch and
RIP-relative operands, and every instruction it checks, lies inside a checked
window.

## Evidence

### Locations (observation)

The file holds `/net_utils/src/channel.rs` once, inside
`/home/ubuntu/hl/code_Mainnet/net_utils/src/channel.rs` at `0x1e9781`
(53 bytes). Exactly seven RELATIVE-backed Locations point at it:

| Line:column | Locations |
| --- | --- |
| 93:47 | `0x56973b8`, `0x56a0aa0`, `0x571edd0`, `0x572fcc8`, `0x573e268` |
| 117:30 | `0x56a0a88`, `0x572fcb0` |

No RELATIVE slot holds any of them. The census covers every disp32 in
`.text` that follows a RIP-relative ModRM byte. It finds 47 references, all
REX.W `lea`: 42 to a 93:47 copy and 5 to a 117:30 copy.

### 93:47 (observation)

Each of 21 FDEs has exactly two references, and each is
`lea rdi, [93:47]` directly followed by `call [slot]`. One of the two calls
goes through slot `0x576f040` and the other through `0x576f038`:

| Slot | Function | Message |
| --- | --- | --- |
| `0x576f040` | `0x157b540` | "`async fn` resumed after completion" (`0x25d282`) |
| `0x576f038` | `0x157b560` | "`async fn` resumed after panicking" (`0x25d2a5`) |

Each function is `mov rdx, rdi` (the Location), `lea rdi, message`,
`mov esi, 2·len+1`, `call [0x576e098]`. No other instruction references a
93:47 copy.

The 21 FDEs:

- `0x1fd5b30`, `0x1fd5ec0`, `0x20312d0`, `0x204c220` (Location `0x56973b8`);
- `0x22713f0`, `0x2271820` (`0x56a0aa0`);
- `0x438cb90`, `0x438e060`, `0x4391840`, `0x4399360`, `0x4399e80`
  (`0x571edd0`);
- `0x47b05f0`, `0x47b0db0`, `0x47b12d0`, `0x47b1930`, `0x47b3b80`,
  `0x47b3f50`, `0x47b6f90`, `0x47b75e0` (`0x572fcc8`);
- `0x4b31030`, `0x4b3c560` (`0x573e268`).

### 117:30 (observation)

Three plain functions call one blocking helper each, passing a 117:30 copy
in `rdx`. Each helper has exactly one direct caller in `.text`, and no
RELATIVE slot holds a helper.

| Caller | Call site | Helper | Before the call | None test, then return path |
| --- | --- | --- | --- | --- |
| `0x432e4d0` | `0x432e597` | `0x437f970` | `0x3d22aa0("node_slow", 9, 0.5)` | `cmp [rsp+0xf8], r12` (r12 = `0x8000000000000000` on entry); `0x432e833..0x432e898` |
| `0x432f680` | `0x432f6c9` | `0x437f580` | none | `cmp dword [rsp+0x300], 0xb`; `0x432f92e..0x432f95c` |
| `0x474bfa0` | `0x474c0dc` | `0x437fdb0` | `0x3d22aa0("node_fast", 9, 0.25)` | `cmp qword [rsp+0x4b0], 0`; `0x474dc2e..0x474dc5c` |

Each return path makes direct calls (to drops, by inference) and
returns. It contains no call through a panic slot and no reference to a
Location.

Each helper, at the offsets listed in `records.json`:

1. saves the caller Location (`mov r15, rdx`) and restores it after a TLS
   initialiser;
2. if the runtime context byte is not 2, calls the `0x576e468` slot with
   `"Cannot block the current thread from within a runtime. This happens
   because ..."` (0xb8 bytes) and the caller Location in `rdx`;
3. after a TLS lookup that returns null, calls the `0x576e048` slot with
   "called `Result::unwrap()` on an `Err` value" (0x2b bytes) and
   `r8 = r15` (the caller Location);
4. inlines a future whose two resume panics carry Tokio
   `tokio-1.44.2/src/sync/mpsc/unbounded.rs:167:47` (Location `0x571e8c0`).

`0x2017c80` inlines the same two calls (expect at `0x20188b0`, unwrap at
`0x20188dd`), both with the 117:30 copy `0x56a0a88`.

## Inference

- **93:47 is an `async fn` body, not an unwrap.** The two const panics are
  rustc's resume guards for an `async fn`, and the Location they carry is the
  function body. Tokio supports this reading: line 167 of
  `tokio/src/sync/mpsc/unbounded.rs` at tag `tokio-1.44.2` is
  `    pub async fn recv(&mut self) -> Option<T> {`, with `{` in column 47,
  and that is the Location of the helpers' inlined future. A `channel.rs`
  signature of the same shape (`    pub async fn recv(&mut self) -> Option<T> {`)
  would also put its `{` at column 47. That is consistent with an
  Option-returning `recv`, but it is not proven here.
- **117:30 is a Tokio blocking call site.** The helpers match Tokio
  1.44.2 `future::block_on`, which is `#[track_caller]`: it calls
  `try_enter_blocking_region().expect("Cannot block ...")`, then
  `e.block_on(f).unwrap()`. The driven future is `UnboundedReceiver::recv`.
  Together this is `UnboundedReceiver::blocking_recv()`, whose
  `#[track_caller]` passes the `channel.rs:117:30` call site down.
- The None test in each caller checks the `Option` niche or tag. A closed
  channel makes these functions return.
- The esi value 2·len+1 is how this rustc passes a static message to
  `0x576e098`; the encoding is not decoded here.

## Lead comparison

| Point | Binary | Lead |
| --- | --- | --- |
| 93:47 | `async fn` resume guards (completion and panicking) in 21 FDEs | `Option` unwrap in nine `recv` futures |
| Closed channel in the 117:30 loops | returns on None | `recv().await.unwrap()` panics |
| `0x474bfa0` | blocking receive through `0x437fdb0` with 117:30, after building a `node_fast` sampler; returns on None | async request future awaiting a oneshot, unwrapping at 117:30 |
| 117:30 | caller Location of the blocking expect and `Result::unwrap` in `0x2017c80`, `0x432e4d0`, `0x432f680`, `0x474bfa0` | the oneshot reply unwrap in `0x474bfa0` only |
| `send` / `recv` unwraps | no channel.rs Location besides these seven; any such panic carries a Location from another file | `send(...).unwrap()` and `recv().await.unwrap()` in channel.rs |
| Coverage | 25 FDEs; 15 lead seeds have 93:47, 4 have 117:30, and 6 more FDEs have 93:47 (`0x204c220`, `0x22713f0`, `0x2271820`, `0x438e060`, `0x4399e80`, `0x47b0db0`) | 19 seeds |

The lead calls `0x2017c80` a seven-branch fair select, and `0x432e4d0` /
`0x432f680` a timed stats loop and a fanout receiver. Those roles are not
tested here; only their 117:30 use is.

## Unresolved

- Which state values reach which resume panic, and what each 93:47 state
  machine polls.
- The loop bodies of `0x432e4d0`, `0x432f680` and `0x474bfa0` (each has a
  back-edge to its blocking call, which is not checked here).
- The future driven in `0x2017c80` (its state is 0x3eb8 bytes).
- Whether the `node_fast` / `node_slow` samplers (#625) time each message.

## Controls

- `tests/test_channel_locations_static.py` checks:
  - the models: the blocking path returns an item, returns None when no
    sender is left, and panics with 117:30 inside a runtime or without a
    parker; the receive loop returns on None; the lead's `recv` panics on
    None;
  - the results: the Location counts, the census counts and helper callers,
    the 21 completion and panicking pairs, the `2·len+1` lengths, the
    samplers, the Tokio Location, and the lead seed split;
  - regeneration of `records.json`, and the CLI.
- Corruption tests (each must raise `EvidenceError`):
  - a Location line, a foreign Location retargeted to the path, a RELATIVE
    slot holding a Location, and a second copy of the path;
  - a planted `lea` to a 93:47 copy and a planted `e8` call to a helper,
    both in int3 padding;
  - window bytes, a const panic message, the Tokio Location line, and a
    sampler name;
  - with the window and operand pins updated as well: a pair that calls
    the same panic twice, the expect length, the register that carries the
    unwrap Location, a retargeted None branch, and a None path that calls a
    panic;
  - a window outside its FDE, and a lead seed without a channel.rs
    Location.
- Both toolchains: the module passes with GNU binutils on `PATH` and with
  only LLVM; the tool itself uses neither.
