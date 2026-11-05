# RE-005 node 115 — timeout cache object: what the park slow-path refresh caches

Question left open by the timeout-pair-writers packet
(PR #2944, open edge 2): the third slow-path body
`0x5cee650` (the "global refresh") maintains a cached
object at `0x64fee08` with a key word at `0x64fee10`
under the lock byte `0x64fee00`, resolving a fresh
object through `0x5cde710` when the cache is empty.
What is that object, who writes and reads it, when
does the refresh replace it, and what does it do in
the park / park_timeout slow path?

Base: `05bc2de303c05525b71e7e257426e741bc66a390`.
Artifact: `artifacts/node/115/hl-node`, 105,896,032
bytes, sha256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.

## Answer

The cached object is an Arc clone of the vendored
tokio **signal registry's entry object for signal 17
(SIGCHLD)** (`z_vendor/tokio/src/signal/registry.rs`).
The refresh keeps the clone so the park slow path can
watch the entry's event counter (`[obj+0x138] & ~1`,
snapshotted into the key word `0x64fee10`): when the
counter moves — i.e. a SIGCHLD was delivered — the
refresh runs the **orphan reap pass** `0x5cee900`
(`z_vendor/tokio/src/process/unix/orphan.rs`), which
retries `waitpid` on queued child records, closes
their fd words and drops their payloads. The cache
exists so the slow path pays one atomic load and one
compare per park cycle instead of a registry lookup,
and so the SIGCHLD entry object stays alive between
cycles.

## Observed

### The refresh `0x5cee650` (679 bytes, sha256 `99aec8bb…d4d01`)

Entry argument: the address of the pair's `+0x38`
slot (the selectors pass it directly: sel_timeout
`0x5ce0160` computes `r14+0x38` from the pair base,
sel_park `0x5ce0850` likewise, the park forwarder
`0x5cfdd00` computes `X+0x30` from `X = pair+8`; all
three are the refresh's only direct call sites in
`.text`).

1. Claims bit 0 of the lock byte `0x64fee00` by
   cmpxchg; if the bit was already set it unlocks
   nothing and returns at once.
2. Cache hit (`[0x64fee08] != 0`) and
   `[obj+0x138] & ~1 == [0x64fee10]`: unlock, return.
3. Cache hit, counter moved: stores the new snapshot
   into `0x64fee10`, claims the orphan lock byte
   `0x64fede0`, calls the reap pass `0x5cee900`,
   unlocks both, returns. No re-lookup.
4. Cache empty: claims `0x64fede0`; if the orphan
   queue length `[0x64fedf8]` is 0, unlocks both and
   returns. Otherwise calls the lookup
   `0x5cde710(out, 17, pair+0x38)` — the refresh is
   the lookup's only direct caller in `.text`.
   On a null object it drops the returned error value
   through `0x5cee460` and returns with the cache
   still empty. On an object it releases the old
   cached object (none on this path), installs
   `(object, snapshot)` into `0x64fee08`/`0x64fee10`,
   and calls the reap pass.

### The lookup `0x5cde710` (416 bytes, sha256 `4d3182ad…0b8b`)

Signature `(out, signum, liveness_cell_ptr)`. The
second argument is a **signal number**, validated as
one:

- `signum <= 0`, or `signum` in 1..=19 with bit
  `signum` of the mask `0x80b10` set — signals
  {4 SIGILL, 8 SIGFPE, 9 SIGKILL, 11 SIGSEGV,
  19 SIGSTOP} — builds the message
  "Refusing to register signal {n}" (string at
  `0x44ce8e`, length byte `0x1c`) and returns
  `out = (0, error)`.
- The liveness cell: `P = [cell_ptr]`; `P == -1` or
  `[P] == 0` returns the error "signal driver gone"
  (`0x94d26c`). The pair constructor `0x5ce01f0`
  writes the pair+0x38 slot once, from the first
  qword of its config (the builder `0x5cf9600`
  passes its own config field at `+0x60`).
- The registry globals sit at `0x64fee20`: vector
  base `[0x64fee28]`, count `[0x64fee30]`, stride
  `0x20`, entry index `signum - 1`. Index beyond the
  count returns "signal too large" (`0x452ef0`).
  A non-zero state dword `[0x64fee38]` first runs
  the globals once-helper `0x5cdf582`; a non-zero
  per-entry state `[entry+0x18]` runs the entry
  once-helper `0x5cdf535` (both forward to a
  std-once call through slot `0x64df9f0` →
  `0x5c87d50`; the Location file is
  `/rustc/…/library/std/src/sync/once.rs`).
- Entry state `[entry+0x10] == 2`: the getter
  `0x5cfcf90` (below) fills `out = (object, word)`.
  `== 0`: error "registering signal handler failed"
  (`0x94c765`). Any other value: `out = (0,
  ([entry+0x14] << 32) | 2)`, an error-shaped encoded
  word of the same family `0x5cee460` drops.

### The getter `0x5cfcf90` (127 bytes, sha256 `e878cca3…6f6f`)

Called only by the lookup. Panics through the
Location at `0x64c6e80` =
`z_vendor/tokio/src/signal/registry.rs:73:32` when
the signal number is 0 or the index is out of
range. Otherwise, with `entry = base +
(signum-1)*0x20`:

- `rax = [entry+0]` — the entry's object pointer;
- `lock inc [rax+0]` — the Arc strong count;
- `rdx = [rax+0x138]` — the event counter;
- `lock inc [rax+0x140]` — a second count;
- returns `(rax, rdx & ~1)`.

### The cached object (allocation 0x150 = 336 bytes)

Size from the weak-release body `0x5ce8860`
(30 bytes): it loads `[rdi]`, returns on `-1`,
`lock dec [obj+8]`, and at zero calls the dealloc
slot `0x64df4a0` → `0x635de30` with size `0x150`
(pin `0x5ce8870`).

| Offset | Meaning (observed from the getter/release/refresh/drain paths) |
|---|---|
| +0x00 | Arc strong count (inc in getter, dec last on release) |
| +0x08 | Arc weak count (dec in `0x5ce8860`; frees 0x150 bytes at zero) |
| +0x110 | tagged function word of an embedded deferred-drop sub-object |
| +0x118 | spin byte guarding that sub-object |
| +0x130 | lock word the SIGCHLD drain `0x5ce7380` CASes 0 → 8 (per #2944) |
| +0x138 | event counter; drain adds 2 per delivery; bit 0 is a separate flag; getter returns it `& ~1` |
| +0x140 | second reference count (inc in getter, dec first on release; at zero the closure runner `0x5ce57c0` through slot `0x64e01e8` executes the +0x110 drop) |

Release order in the refresh's swap-out path:
decrement `[obj+0x140]` first (running `0x5ce57c0`
with the closure `{obj+0x110, obj+0x118,
[obj+0x110]}` at zero), then `[obj+0]` (strong),
then the weak release through slot `0x64ecc58` →
`0x5ce8860`.

### The reap pass `0x5cee900` (465 bytes, sha256 `7833d850…f48`)

Panic Location at `0x64c6498` =
`z_vendor/tokio/src/process/unix/orphan.rs:118:20`.
It drains the global orphan queue (base word
`[0x64fedf0]`, length `[0x64fedf8]`, record stride
0x1c computed by lea arithmetic) from the last
record down, under the lock byte `0x64fede0`
(waiting through slot `0x64e0f38` → `0x5bb5650` on
contention):

- the helper `0x5c902e0` (227 bytes) converts a
  record: if `[record+0] == 1` the stored result at
  `[record+4]` is reused; otherwise it calls
  `waitpid@GLIBC` (slot `0x64ec8a0`, `WNOHANG`) on
  the pid at `[record+8]` and builds an
  ExitStatus-shaped encoded result;
- a record that produced no result is kept;
- a finished record is swap-removed (the length
  word is rewritten), its four i32 words at
  `+0xc/+0x10/+0x14/+0x18` are each closed through
  `close@GLIBC` (slot `0x64dfe78`) when not `-1`,
  and its attached value is dropped through
  `0x5cee460` when its tag word is non-zero.

### Static initial values (.data)

The block `0x64fede0..0x64fee38` lies in `.data`.
File-initial words: lock bytes 0, cache object 0,
cache key 0, registry vector pointer 0, count 0,
queue length 0; queue base word `0x64fedf0` = 4
(unpopulated marker — dereferenced only once the
length is non-zero); registry once-state
`0x64fee38` = 3 (the not-yet-run value the once
helpers test); the neighbouring id counter
`0x64fee18` = 1 (bumped by `lock xadd` in the
builder and in body `0x5ce20d2`; not part of the
cache).

### Census

- Refresh call sites (whole `.text`, rel32): exactly
  the three selector/forwarder sites above.
- Lookup call sites: exactly one (refresh
  `0x5cee6f9`). Getter call sites: exactly one
  (lookup `0x5cde802`). Reap pass call sites:
  exactly two, both in the refresh (`0x5cee6c4`,
  `0x5cee793`).
- RIP-relative references: `0x64fee00`, `0x64fee08`,
  `0x64fee10` are referenced only inside the
  refresh body. The queue words `0x64fedf0`/
  `0x64fedf8` are referenced only inside the reap
  pass. The registry globals are referenced by the
  lookup, the SIGCHLD drain `0x5ce7380` and one
  further registry-cluster body `0x5ce71f0`.
- Stored pointers / `.rela.dyn` addends: no stored
  qword and no RELATIVE addend anywhere in the file
  names the cache globals, the lookup, the refresh,
  the getter or the reap pass.

## Correction to PR #2944

The pair-writers README says the refresh "resolves
a fresh object pair through `0x5cde710` keyed by 17
bytes at the argument". The constant 17 is not a
byte count: it is the **SIGCHLD signal number**,
loaded as the lookup's second argument at
`0x5cee6f1` (`mov esi, 0x11`) and validated against
the refusal mask. The pointer argument is the
pair+0x38 slot address, forwarded unchanged
(`0x5cee6f6`: `mov rdx, rbx`).

## Inferred

- The object is the registry entry's per-signal
  state object (tokio's `SignalState` family): the
  identification rests on the registry.rs getter
  Location, the signal-number validation and
  messages in the lookup, the unix.rs Location
  (`0x64c6ff0`, line 28) referenced by the drain
  callback `0x5cfcc50`, and the orphan.rs reap
  pass the refresh drives. Field names beyond the
  observed offsets are not claimed.
- The pair+0x38 pointee is the runtime's signal
  driver liveness cell: the two-level check
  (`-1`, then a zero first word) is read
  mechanically; which source-level driver object
  the builder's config `+0x60` qword names is not
  settled here.

## Open edges

1. The orphan queue has no static pusher: no
   `.text` site outside the reap pass references
   the queue base/length words, so records arrive
   through a path that does not address these
   globals directly. Who enqueues a record, and
   the source-level name of the four closed i32
   words, stay open.
2. Cached-object fields `+0x10..+0x108` are not
   individually identified; only `+0x110` onward
   is pinned by the getter and release paths.
3. The exact source-level identity of the
   pair+0x38 pointee (see Inferred).

## Verification

`tools/timeout_cache_object_static.py` re-derives
every value above from the artifact (FDE body
hashes, the three censuses, slot resolutions,
Locations, messages, byte pins, .data initial
values) and fails on any drift; running it without
`--generate` compares against `records.json`.
`tests/test_timeout_cache_object_static.py` runs
the same analysis plus the MANIFEST check: 9 tests,
all passing on the materialised artifact (the suite
skips when the artifact is an LFS pointer).
