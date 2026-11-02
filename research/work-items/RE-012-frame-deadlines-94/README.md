# RE-012: header and chunk deadline reconstruction

- Component: `transport`; source base `a142bea59d2df18f4bbebe4874bdb4c7bc31f514`
  (the asynchronous frame implementation in PR #1755).
- Target: Linux x86-64 node #94, 91,774,280 bytes, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Bounded question: when are the frame deadlines created and consulted, and
  which I/O phase does each cover?
- Result: selected native branches and an independently authored Rust API;
  no full transport, timer-driver, target ABI, machine-code or network claim.
- Files: `src/node94-tcp-frame/{Cargo.toml,README.md,src/lib.rs,src/deadlines.rs,tests/deadlines.rs}`,
  this packet and `tests/test_frame_deadline_evidence.py`.

## Scope and ownership

The existing stream implementation deliberately omits timeouts. This change
adds the opt-in `timed-stream` feature over caller-owned Tokio I/O: a conditional
40-second header deadline, a fresh 20-second deadline per payload chunk, and
20-second/default or explicit override write deadlines per complete-frame chunk.
The target's observed 60-second write override is tested. The untimed `stream`
API remains available; no caller defaults or arbitrary float-to-duration
conversion are invented.

Existing reader/writer packets already established the constants and chunk cap.
The evidence-only PR #1357 (`748184ff2ce4f887f15fa3e1b1c06592ad8f9d79`)
examines the writer timeout poll and caller cleanup. Its diff was inspected to
avoid presenting that work as new. This packet independently checks shared
writer instructions; the additional work is the conditional header path,
per-payload timer reset, relocated Sleep adapter, and source implementation.
No files from that unmerged packet are imported. The previous
[stream packet](../RE-012-tcp-stream-94/README.md) and its receipts remain
unchanged and apply to their original source revision.

## Native observations

`verify.py` authenticates the complete input before deriving `records.json`.
Its separate structural inspection entry point allows corruption controls but
never grants authentic origin. It checks 41 instructions and their relative
references, five exact FDE extents, two RELATIVE relocations including their
full `r_info`, and the Sleep source Location. Addresses below are linked ELF
virtual addresses, not file offsets or guessed loaded addresses.

| FDE extent | Bytes | Selected observation |
| --- | ---: | --- |
| `0x2049950..0x204ae15` | 5,317 | Conditional header wrapper and payload chunk lifecycle |
| `0x2037940..0x2037ab4` | 372 | Header I/O polled before timer |
| `0x2034eb0..0x203516e` | 702 | Payload exact-read controller and timeout result |
| `0x4f68f00..0x4f6903e` | 318 | Sleep adapter: ready versus pending |
| `0x2036460..0x20367c3` | 867 | Writer I/O polled before timer |

These are 7,576 inspected bytes, not matched reconstruction bytes. Complete
GNU and LLVM listings for the reader, header wrapper and Sleep adapter are
retained here. The payload/write listings are retained in the preceding stream
packet; the tests check instruction starts in both independent disassemblers.
Nearest exported C++ labels in objdump output are not ownership evidence.

### Header and payload

At `0x20499b1`, the reader tests its byte at offset `+8`. Zero branches to
`0x2049f28`, calling the direct header reader `0x20485e0` at `0x2049f47`.
Nonzero selects the `tcp_bytes` wrapper, stores f64 40 at `0x20499e0`, and
calls `0x2037940` at `0x2049e7c`. The two paths join before payload handling;
40 seconds is not a deadline for the entire frame.

The header wrapper calls the same header reader at `0x20379b8`. Its comparison
at `0x20379bd` and branch at `0x20379c2` forward completed I/O before the timer.
Only pending I/O consults slot `0x576f088`. A ready timer produces wrapper
result 2 at `0x2037a28`; a pending timer produces result 3 at `0x2037a16`.

The payload loop at `0x204a9e2` computes remaining bytes and the established
4,000,000-byte cap. Each new chunk stores f64 20 at `0x204aa70`, zeroes fresh
state at `0x204aa8c`, and jumps to initialization at `0x204a436`.
Polling at `0x204a7d7` calls the exact-read timeout controller. Its completed-I/O
branch skips the timer at `0x2034fff`; pending I/O polls the timer then ORs its
result with 2 at `0x2035084`. The caller distinguishes 3/pending from 2/elapsed.
This supports a new deadline for each chunk, not resetting after each short read.

### Timer and writer

Slot `0x576f088` has a symbol-zero RELATIVE relocation to `0x4f68f00`. This
adapter calls its inner timer at `0x4f68f88`. Inner tag 4 takes the pending
path, returning AL=1 at `0x4f68fe0`. Inner tag 0 returns AL=0 at `0x4f68fcd`;
other inner results reach the panic path. Cooperative yielding can also return
pending without polling the inner timer. Thus nonzero is not timer expiry.

The panic path's Location at `0x57550f8` is itself relocated to `0x1f359c`, a
96-byte source path ending in `tokio-1.44.2/src/time/sleep.rs`, line 450,
column 23. This binds the adapter to the pinned source, rather than reading an
unrelocated zero pointer as a valid Location.

The writer branches around its timer at `0x2036631` on completed I/O. Pending
I/O polls the same relocated adapter and increments its result at `0x2036685`:
0 becomes 1/elapsed, 1 becomes 2/pending. This agrees with PR #1357's bounded
writer finding. `records.json` also reruns the established writer selection:
20 seconds unless the flag selects the caller's f64, with one observed direct
call selecting 60. It does not claim all possible overrides equal 60.

## Source interpretation and implementation

Interpreting the selected tags as `Ready`/`Pending`, `Elapsed`, and a conditional
header flag is source correspondence, not recovery of the complete Rust ABI.
The exact-version Tokio `Timeout::poll` first polls I/O; only pending I/O polls
its `Sleep`, with an unconstrained-budget path when needed. `Sleep::poll`
returns ready for success and panics for a timer error. File hashes and exact
source URLs are retained in `source-evidence.json`; upstream licensing remains
MIT. No inferred can1357 source is copied or treated as authoritative.

`deadlines.rs` composes the existing independent codec and Tokio's licensed
`read_exact`, `write_all` and `timeout`. Admission still precedes payload
allocation/I/O. The caller supplies the header flag and an optional `Duration`
write override. Deadline errors report a phase and limit through a new API;
they do not recreate the target's errors or cleanup ABI. An active Tokio time
driver is required. The added runtime/test-util features are dev dependencies
for deterministic tests, not a claim about the target's full feature set.
The existing Cargo.lock is unchanged and remains this component's real build
lock, not a recovered node lock.

## Reproduce and controls

From the repository root, with GNU binutils and LLVM on PATH:

```sh
make doctor verify
python3 research/work-items/RE-012-frame-deadlines-94/verify.py
python3 -m unittest discover -s tests -p test_frame_deadline_evidence.py -v
cargo test --locked --manifest-path src/node94-tcp-frame/Cargo.toml
cargo test --locked --manifest-path src/node94-tcp-frame/Cargo.toml --features stream
cargo test --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-features
cargo test --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-features --release
cargo clippy --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-targets --all-features -- -D warnings
cargo fmt --manifest-path src/node94-tcp-frame/Cargo.toml -- --check
cargo build --locked --manifest-path src/node94-tcp-frame/Cargo.toml --all-features --release --target x86_64-unknown-linux-gnu
make verify test catalogue-check reproduce
```

`native-exports.json` records tool versions, commands and output hashes.
`build-receipt.json` and `VALIDATION.md` record actual results. The Python tests
alter all 41 instructions individually below the digest check, change the Sleep
Location/path and timer relocation, reject a truncated artifact, and check both
native disassemblers' instruction starts. They are sensitive-structure tests,
not a symbolic proof of every branch in an entire FDE.

Twelve Rust tests use paused local time and scripted I/O, with no sockets or
captured-target execution. They exercise the 40-second header and disabled
header mode, ready/error versus elapsed ordering, partial-I/O deadline retention,
20/60-second writes, per-chunk reset, admission, and separation of header and
payload deadlines. `rust-mutations.json` preserves output from seven changed
implementations that compiled but failed: wrong header duration, wrong chunk
duration, ignored header flag, ignored write override, timer-first polling,
one shared payload budget, and a whole-frame header timeout. The chunk tests
poll while the second chunk is pending, so ready-first behavior cannot hide an
incorrect expired global deadline.

## Remaining work

Timeout/cancellation can leave a partial frame consumed or transmitted. Discard
the connection unless its boundary is independently restored. This packet does
not establish the target's cleanup ownership, runtime timer-driver internals,
wall-clock behavior, logging, complete error ABI or every reader/caller copy.
No allocation-failure or arbitrary f64 duration conversion contract is claimed.

No component gate or byte-comparison denominator is advanced. The crate remains
a library: no socket setup, peer greeting, message decoding, synchronization,
node executable or Docker image is provided. The next bounded integration is
to review the pending greeting/caller work (PRs #1706 and #1723) against the
target, then join established wire types and error behavior to this framing
layer. Those PRs are leads for review, not accepted contracts for this change.
