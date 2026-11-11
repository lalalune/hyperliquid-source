# RE-001-node115-lu-tls-state-continue

Packet #260. Continues packet #259's next question: per-leaf read/write
classification for the remaining control-tree leaves, the TLS state helper
`0x63ef5e0`, the global list helper `0x63ef410`, the writer census for
`prof.interval`'s value global `0x6712440`, and the `0x63ed090`/`0x63ed070`
slow paths.

## What this packet claims

### TLS state refresh: `0x63ef5e0..0x63ef640` (full FDE, 96B, 24 strict)

Reads the context state byte at `ctx+0x330` and installs the next state with
an `xchg`, retrying while the previous state was 2, then tail-calls the
bounds refresh `0x63eec10`:

- State > 2: the value is exchanged back unchanged, then the tail-call.
- State <= 2: the new state is 1 when the gate-neighbour byte `0x64ffab0`
  is nonzero, or `ctx+0` is zero, or `ctx+1` is positive (signed);
  otherwise the new state is (`global 0x6728880` != 0).
- After the `xchg`, an old state of 2 loops back to re-read; any other old
  state falls through to the tail-call at `0x63ef625`.

Callers: 82 `E8` sites + 1 `E9` site (at `0x63d7b87` in FDE
`0x63d7b30..0x63d7b8c`) across 24 distinct caller FDEs, including the
`tcache/enabled` handler (`0x636e2a9`) and the apply-global-default function
(`0x63ed881`). The census was verified per site by FDE disassembly, and a
full-file raw scan gives identical counts (no sites outside the code window).

### Global list insert: `0x63ef410..0x63ef4ed` (full FDE, 221B, 43 strict)

- Self-links the context node (`0xc8` prev / `0xd0` next := ctx).
- Trylocks mutex `0x67288e0`; on contention calls the wait helper `0x63bf680`
  on record base `0x67288a0`, sets the contended byte `0x6728908` := 1, and
  retries.
- Counters: `0x67288d8` += 1 on every entry; on a context change,
  `0x67288c8` += 1 and last-context `0x67288d0` := ctx.
- Insert-after-head into the list rooted at slot `0x6728910` (empty list:
  head := ctx). Clears the contended byte `0x6728908` := 0, then tail-jumps
  to `pthread_mutex_unlock`.
- Callers: exactly 1 `E8` site (`0x63ef7a5` in the TLS helper `0x63ef640`)
  and 1 `E9` site (`0x63efd14` in `list_reset`).

**Correction (parent-verified against the helper FDE):** the helper
`0x63ef640` itself contains an inline mutex/counter/list path — mutex
`0x67288e0` lea at `0x63ef66d`, counters `0x67288d8`/`0x67288c8` at
`0x63ef684`/`0x63ef695`, last-context `0x67288d0` at `0x63ef69d`, contended
byte `0x6728908` := 0 at `0x63ef705` with `pthread_mutex_unlock` at
`0x63ef70f`, wait-helper call `0x63bf680` at `0x63ef7c5` with contended byte
:= 1 at `0x63ef7ca`, and list-head stores at `0x63ef7ec`/`0x63ef7fc` — so
#259's mutex-path description stands as the helper's inline path. This
callee `0x63ef410` is the separate insert-after-head path the helper calls
at `0x63ef7a5` (and `list_reset` tail-calls at `0x63efd14`). #259's mode
mapping stands unchanged.

### Global list reset: `0x63efce0..0x63efd19` (full FDE, 57B, 14 strict)

Calls the lock helper `0x63bf970` with record base `0x67288a0`, clears the
list head `0x6728910` := 0, and — when the context state byte is <= 2 —
tail-calls `list_insert`; otherwise it returns with the head left at 0.
Sole caller: `E8` site `0x6350002` in FDE `0x634ffd0..0x635020a`.

### Disable slow path: `0x63ed070..0x63ed089` (full FDE, 25B, 7 strict)

If `ctx+0` is zero it returns; otherwise it tail-jumps to `0x63ec900` with
`rsi` = `ctx+0x358`. Callers: `E8` sites `0x636e2f8` (tcache/enabled
handler) and `0x63ef84c` (teardown gate). The target `0x63ec900` has no
`E8` sites and exactly 3 `E9` sites (the disable slow path plus FDEs
`0x63ee1f0` and `0x63ee2a0`).

### Enable slow path: head `0x63ed090..0x63ed167` (215B, 43 strict)

The full FDE is `0x63ed090..0x63ed862` (2002B); only the entry window is
exhibited, and the rest is characterized by a whole-FDE jump/call census
(never by a claimed global proof):

- Entry loads globals `0x6728858` and `0x6728860`; if `0x6728860` > `0x3800`
  or `0x6728858` > `0x1000` it takes the large-size branch at `0x63ed358`;
  otherwise it computes an aligned size (neg/and, capped at `0x1000`, branch
  at `0x63ed520`) and walks the size tables `0x67277c0` (byte class) and
  `0x6727a00` (sizes); a class above `0x3fff` takes the `0x4000` path via
  `0x6728140`.
- Rest of the FDE: all jumps stay inside the FDE (verified over the whole
  FDE); calls are `0x63ec4c0` x4, `0x634ebb0` x3, `0x63ec7a0` x2,
  `0x63d9880` x2, `0x63d9700` x2, and one each of `0x6365150`, `0x6352fc0`,
  `0x6352f60`, `0x63e91c0`, `0x63f1ad0` (PLT), plus the stack-check failure
  call. Single `ret` at `0x63ed350`. `ctx+0x128` is zeroed at `0x63ed260`,
  and a size-class dispatch (indices 2..7) sits at `0x63ed7c2..0x63ed82a`.
  The bin-setup callees are named only by this census, not decoded.
- Callers: `E8` sites `0x636e29c` (tcache/enabled handler) and `0x63ed89b`
  (apply-global-default).

### Interval-value reader: `0x63c3a90..0x63c3af2` (full FDE, 98B, 25 strict)

The `prof.interval` value global `0x6712440` gates a counter advance: if the
value is zero, or gate byte `0x67125d0` is zero, it returns. Otherwise it
atomically advances counter `0x67125e0` by its `rsi` argument with a `lock
cmpxchg` retry loop, wrapping modulo limit `0x67125e8`; on wrap it
tail-jumps to `0x63c3990`. Sole caller: `E8` site `0x63ef12a` in FDE
`0x63eec80..0x63ef230`.

### Teardown gate + destructor registration

- Head `0x63ef810..0x63ef830` (32B, 8 strict; full FDE
  `0x63ef810..0x63ef8d7`): the gate is `(1 << state) & 0x2b`; a zero result
  returns, so only states 0, 1, 3, 5 pass. The passing body (characterized,
  not exhibited) calls `0x63c3b70`, `0x63539d0`, `0x6353a20`, the disable
  slow path, and `0x63efd20` (`ctx+0xa38`), sets `ctx+1` := 1, and calls the
  TLS helper with mode 4.
- Window `0x63efbd3..0x63efbe6` (19B, 3 strict; FDE `0x63efbb0..0x63efc27`):
  the destructor registration — `rsi` = `0x63ef810`, `rdi` = key slot
  `0x672891c`, call to `pthread_key_create@plt`. On success the
  key-created byte `0x6728918` := 1, and a nonzero current-context state
  byte tail-jumps to the TLS slow path `0x63ef8e0`. This explains the
  gate's reachability: it has no direct `E8`/`E9` callers.
- TLS helper callers (for orientation, cited not claimed): 5 `E8` sites —
  `0x6367edd`, `0x63ef869` (teardown gate), and three in the TLS slow path
  (`0x63ef981`, `0x63efa58`, `0x63efb02`).

### Writer census for `prof.interval`'s value global `0x6712440`

Direct RIP-relative references in the full binary (all 135,313 FDEs,
18,827,581 instructions disassembled): exactly 4 sites touch `0x6712440`:

| site | kind | role |
|---|---|---|
| `0x6376813` | lea (read) | prof/interval handler — claimed by #259, cited here |
| `0x63c3a94` | cmpq $0 (read) | interval counter gate — exhibited here |
| `0x63c417e` | mov %rsi (WRITE) | latch — claimed by #258, cited here |
| `0x63c437a` | mov load (read) | consumer in FDE `0x63c41c0` — cited, not exhibited |

The single writer is the latch store at `0x63c417e` (latch FDE
`0x63c4140..0x63c41b1`, claimed by #258): value `1 << cl`, where `cl` is the
low byte of global `0x64ffce8`, stored only when the prof byte `0x6713606`
is nonzero and `[0x64ffce8]` >= 0 (signed). The latch's other arms set/clear
the prof byte and neighbours `0x6713605`/`0x6713603` without touching
`0x6712440`. The latch's sole caller is `0x634eea7` in the request-init FDE
`0x634ece0..0x634f09d` (packet #257's request-init): the interval value is
set once at init time.

Indirect stores were also checked: the 15 lea sites for neighbouring bases
(`0x6712400` +`0x40`, `0x6712438` +`8`, `0x6712460` -`0x20`) are the complete
set in the full binary, and all 15 were tracked through their enclosing
FDEs with register-overwrite and call-clobber rules (caller-saved registers
cleared on call, as in packet #258's classifier): 0 hits. Limitation: a
store through a spilled/reloaded pointer or across non-linear control flow
is outside that method's scope; no direct RIP-relative store exists
anywhere in the binary's FDE-covered code, so any missed writer would have
to use such an exotic path.

### Leaves classified here (5)

| leaf | class | evidence |
|---|---|---|
| `opt/abort` | read-only | flag byte at `0x651174d` (.bss); read copies it to oldp when oldlen == 1, returns 0; wrong oldlen returns `0x16` with the required size written back; a write attempt (newp\|newlen nonzero) returns 1 (EPERM) |
| `config/debug` | read-only | value is the build-time constant 0; same return contract as `opt/abort` |
| `experimental/utilization/query` | read-only | query: newp (query index) is required, newlen must be 8, `*oldlenp` must be `0x30`, else `0x16`; the 48-byte result is produced via callee `0x63bc730` from oldp-derived field pointers (`0x8`/`0x10`/`0x18`/`0x20`/`0x28`); returns 0. newp is the query input, not a write |
| `tcache/flush` | write | oldp\|oldlenp given returns 1 (EPERM); newp missing returns `0x16`; newlen != 4 returns `0x16`; otherwise the u32 arena index from `*newp` is passed to `0x63ee1f0` (which tail-jumps to `0x63ec900`), returns 0. Distinct from `thread/tcache/flush` (#257): this leaf flushes a named arena's tcache by index |
| `prof/thread_active_init` | read/write | read (newp == 0): value is 0 when the prof byte `0x6713606` is 0, else the getter `0x63c3ee0`'s return; oldp copy when oldlen == 1, else the `0x16` path. Write: prof byte 0 returns 2 (ENOENT); newlen != 1 returns `0x16`; otherwise the byte passes through setter `0x63c3f60` and lands in global `0x6712550` under mutex `0x6712520` (counters `0x6712518`/`0x6712508`/`0x6712510`); oldp copy on success, returns 0 |

Exhibit `thread_active_init_setter_head` (`0x63c3f60..0x63c3fa7`, 71B, 17
strict; full FDE `0x63c3f60..0x63c3fdb`) shows the setter's mutex trylock,
counters, and the store to `0x6712550`.

## Scope and honesty

- Classified here: 5 leaves (3 read-only, 1 write, 1 read/write).
  Previously classified: 23 (packets #257/#258/#259, cited not claimed).
  **Remaining unclassified: 176 of 204 leaves.** This packet does not claim
  exhaustive coverage; the 176 stay open for later packets.
- Surveyed but not decoded: the enable-slow-path bin-setup callees, the
  teardown-gate body callees, the interval-value consumer FDE `0x63c41c0`,
  and the `0x63ee1f0`/`0x63ee2a0` teardown functions — all named only by
  census above.
- Not determined from the file: the identities of globals `0x6728880`
  (ef5e0 fallback), `0x64ffab0` (gate-neighbour byte), and `0x64ffce8`
  (interval exponent source); only their roles are claimed. `.bss`
  contents are runtime-filled and cannot be read from the file.
- Exhibit totals: 14 exhibits, 1470 bytes, 367 strict mnemonic lines
  (address + bytes field + tab + mnemonic; objdump byte-continuation lines
  excluded). The `.hex` files contain raw binary bytes (not hex text), as
  in packet #255's format; the verifier, tests, and MANIFEST all treat them
  as raw.
- Disjointness method (packet #259's lesson): the collector gathers ONLY
  exhibited windows from prior packets' records — `range` fields (string
  or `[start, end]`) and `start`/`end` pairs inside `exhibits` lists or
  dicts and `windows` lists — never enclosing-`fde` annotation fields,
  and deduplicates by real path. Census/cited-only metadata ranges are
  excluded from the claimed set, per packet #253's rule.

## Verification

- Static verifier `tools/node115_tls_state_continue.py`: exit 0. Checks
  exhibit bytes against binary slices, strict counts, the small call-site
  censuses by exact byte arithmetic at the claimed sites, the `0x63ef5e0`
  census by raw scan over the code window (cross-checked at build time
  against a full-file scan with identical counts), the interval-value site
  list by exact byte checks, and disjointness against packets #183–#259.
- Unit tests `tests/test_node115_tls_state_continue.py`: 10/10 standalone
  (tamper test written first and confirmed to fail the verifier before any
  green run was trusted).
- `make verify`: exit 0. `make catalogue-check`: run and reported honestly
  in the PR body (it fails on this base with `Stale catalogue: README.md`,
  pre-existing on a pristine checkout, not a packet regression).
- Full `make test` was NOT attempted: the suite carries 584 test files on
  this base and a full run takes hours and is liable to be killed by a VM
  restart. No full-suite tally is claimed.
- Target binary verified, not assumed: 105,896,032 bytes, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  upstream base `05bc2de303c05525b71e7e257426e741bc66a390`.

## Next question

Continue leaf classification with the next value-family batch (`opt/prof`,
`opt/tcache`, `config/stats`, `thread/allocated`, `stats/allocated`); decode
the enable-slow-path bin-setup callees (`0x63ec4c0`, `0x63d9700` first);
decode the interval-value consumer FDE `0x63c41c0` and the teardown-gate
body callees.
