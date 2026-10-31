# node-runtime: node #94 gossip peer cap in `0x473f2e0` (limit max(n, 8) capped at 100, None = 8; set members uncounted)

Question: function `0x473f2e0` reads `n_gossip_peers` from the tracked gossip
config and compares it with a count of connected peers. What limit does it
derive? Which peers does it count? What does it return at the limit? Where
does the can1357 lead (`node/connections.rs`, `node/gossip_config.rs`) differ?

- Component ID: `node-runtime` (`docs/COMPONENTS.md`: CLI, startup, gossip,
  stream services; path rule `node/*`). The address is listed in
  `research/catalogue/seed-candidates.json` as a `node/connections.rs` seed.
- Target: `artifacts/node/94/hl-node`, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Base: `main` `1f8c67c63ca4794c9689235471c60297f8a5c985`. Reference lead:
  `references/can1357-hl` `999556f6e0a474b8312db96ec3149e1c44e97c23`, used
  only for seed addresses and claims to test; no code, comments or names
  copied. The lead calls this function `maybe_reject_peer_reason`. This packet
  uses the name only for cross-reference.
- Claim status: observation for byte-level facts, inference where marked,
  unresolved where listed. Partial `node-runtime` research; no gate change.
- Scope: seven fixed windows in FDE `0x473f2e0..0x4740482`, the u64 Display
  formatter FDE `0x1570900`, and a census of every `[rsp+0xe0]` operand over
  the whole `0x473f2e0` FDE. Covered: the path taken when the byte at `[rcx]` is
  nonzero. Excluded: the path for `[rcx] == 0` (`0x473f396..0x473f7c6`, span
  metrics), the step after code 3 when the `edx` flag is set (`0x473fe90..`),
  and release #115.

## Reproduce

```sh
make verify
python3 tools/gossip_peer_cap_static.py --json > research/work-items/gossip-peer-cap-94/records.json
python3 -m unittest tests.test_gossip_peer_cap_static -v
```

The producer authenticates the input against `provenance/artifacts.json`. It
parses sections, `.eh_frame` FDEs (`tools/fde_extents.py`) and `.rela.dyn`
`R_X86_64_RELATIVE` entries, and never executes the target. It needs only
Python 3 (run here with 3.14.7 on macOS arm64; under 1 s). `records.json` is
its complete output; the test suite regenerates it and compares.

`excerpts.objdump.txt` is raw supporting text from GNU objdump 2.47. It has 8
windows (411 instructions), one for each checked byte window. All 13
`records.json` VAs that fall inside a window are instruction starts there. The
`census` entries are ModRM-byte addresses, not instruction starts. Each of the
53 `FACTS` entries and the 14 decoded branch and RIP-relative operands must
lie inside a checked window, or the tool refuses.

Format templates are decoded as rustc 1.94 packs them: a byte below 0x80 is a
literal length, and `0xc0` is a placeholder followed by the length of the next
literal; `0x00` ends the template.

## Evidence

### Entry and config source (observation)

- The only RELATIVE slot that holds `0x473f2e0` is `0x57735f8`.
- `rdi` is self, `rsi` is the 5-byte incoming NodeIp (tag byte, IPv4), `edx`
  is a flag saved at `[rsp+0xd4]`, and `rcx` points to a byte.
- `0x473f30d` tests `[rcx]`. When it is zero, `0x473f310` leaves for
  `0x473f396`, so the cap below is not evaluated on that path.
- `r14 = [self]` (`0x473f31e`) and `r13 = [self+0x10]` (`0x473f321`). The byte
  at `[r13+0x10]` picks the config copy:
  - nonzero: `rbx = r13+0x18`, and `0x473f35f` jumps straight to the limit;
  - zero: the locked path sets `rbx = r13+0x20` (`0x473f7da`). When
    `[r13+0x98] != 0` it logs `Last load of FileModTimeTracker failed: {}`
    (template `0x1f3bf3`) at `base/src/file_mod_time_tracker.rs:63:13`.
- Every later config read uses the same offset: `ebx = 0x18` or `0x20` at
  `0x473f8e7`/`0x473f904`/`0x473f910` and at `0x473fd06`/`0x473fd12`, then
  `[r13+rbx+0x28]`.

### The limit (observation)

Window `0x473f853..0x473f915` reads an `Option<u64>` at config `+0x0`
(tag byte) and `+0x8` (value):

| Config | Stored to `[rsp+0xe0]` | Log |
| --- | --- | --- |
| `None` | 8 (`0x473f8f8`) | none |
| `Some(v)` | `min(max(v, 8), 100)` | when the result differs from `v` |

The bounds are the immediates `mov ecx,8` / `cmp rax,9; cmovae` and
`mov edx,0x64` / `cmp rcx,0x64; cmovb`. The log runs when the result differs
from `v` (`cmp rdx,rax; je` at `0x473f88f`). Its template is `0x1e8c2b`,
`n_gossip_peers clipped to {}`. The argument is `&[rsp+0xe0]`, formatted
through slot `0x576e090` (RELATIVE to the u64 Display formatter `0x1570900`).
The Location is `0x572eb78`, `node/src/connections.rs:513:13`, and the call
goes through slot `0x576e978`.

Census: the FDE has six `[rsp+0xe0]` operands. Four are in this window and the
gate: two stores (`0x473f886`, `0x473f8fa`), the log argument (`0x473f8a9`)
and the compare (`0x473fcc9`). The other two (`0x473f648`, `0x473f71c`) are in
the `[rcx] == 0` region, which leaves through `0x474001f` without reaching the
compare.

### What is counted (observation)

Window `0x473f97e..0x473fd06`:

- It walks a BTreeMap at `[r14]`: root `+0x18`, height `+0x20`, length `+0x28`.
  The node length is a u16 at `+0xba` and the edges are at `+0xf8`.
- Each key is a 5-byte NodeIp at node `+0xbc + 5*i`. If bit 0 of the tag is
  set, the key's IPv4 becomes `0x100007f` (127.0.0.1); otherwise it is the
  dword at `+0xbd`.
- That IPv4 is searched in a BTreeSet of 4-byte keys at `[config+0x28]`
  (height `+0x30`, keys `+0x8`, length u16 `+0x36`, edges `+0x38`). Keys are
  compared big-endian (`bswap` at `0x473fbf0`/`0x473fbf2`).
- A hit jumps to `0x473f9f7` and is not counted. A miss or an empty set
  reaches `0x473f9f0`: `inc r14; cmove r14,-1`, a saturating count.
- Gate `0x473fcc7`: `cmp r14,[rsp+0xe0]; jae 0x473fd06`. Below the limit,
  `r15b = 3`.

### At the limit (observation)

Window `0x473fd06..0x473fe90`:

- The incoming NodeIp, saved at entry, is reduced to an IPv4 the same way
  (tag bit 0 gives 127.0.0.1) and looked up in the same `[config+0x28]` set.
- A hit gives `r15b = 3` (`0x473fe47`). An empty set (`0x473fe53`) or a miss
  (`0x473fe37` → `0x4740051`) gives `r15d = 0`.
- `0x473fe7c`: if the code is 3 and the `edx` flag is set, a further step runs
  (`0x473fe90`, not covered). Otherwise `0x474001f` returns `r15d` in `eax`.

## Lead comparison

| Point | Binary | Lead |
| --- | --- | --- |
| Lower bound | 8 | 1 (`clamp(1, MAX_GOSSIP_PEERS_HARD)`) |
| Upper bound | 100 | 100 |
| Unset value | `Option` `None` → 8 | `usize` field, default 8 (`connections.rs`) or 16 for mainnet (`gossip_config.rs`) |
| `0` | becomes 8, logged as clipped | rejected (`invalid n_gossip_peers`; not in the binary) |
| Clip log | per call, here, against `[8, 100]` | once, in config normalization, against the candidate count |
| Counted peers | peers whose IPv4 is not in the `[config+0x28]` set | `peers.len()` |
| At the limit | admitted only when the incoming IPv4 is in that set | `MaxPeersReached` unless role is validator, sentry or reserved |

The two implementations diverge for `n_gossip_peers` in `0..7`. The binary
allows 8 peers; the lead allows `max(n, 1)` (for 0 it rejects the config).

## Inference

- The `[config+0x28]` set behaves like the lead's reserved-peer set: its
  members are neither counted nor capped. The field name is not in the binary.
- Code 3 reads as "not refused by the cap" and code 0 as "refused". The
  meaning of 3 as an enum niche is not checked.
- The `[r13+0x10]` byte selecting `+0x18` or `+0x20` is a FileModTimeTracker
  state, read from the tracker's own log site; which copy is current is not
  established.

## Unresolved

- The meaning of the `[rcx]` byte and the `edx` flag, and the `[rcx] == 0`
  path.
- What `0x473fe90..0x474001b` does after code 3 with the `edx` flag set.
- Who reads the RELATIVE slot `0x57735f8`. This packet checks the slot only;
  it does not scan for direct calls.
- How the config's `n_gossip_peers` and set are filled from
  `override_gossip_config.json`.

## Controls

- `tests/test_gossip_peer_cap_static.py` checks:
  - the models `peer_limit`, `lead_limit`, `counted_peers` and `cap_code`;
  - the decoded bounds, template, Locations, census and caller slot;
  - regeneration of `records.json` and the CLI.
- Corruption tests (each must raise `EvidenceError`): the low bound, the high
  bound, the gate branch, the clip template text, the clip Location path, the
  tracker template, the formatter RELATIVE addend, the caller RELATIVE addend,
  a planted `[rsp+0xe0]` read, and a fact placed outside every window.
- Both toolchains: the module passes with GNU binutils on `PATH` and with only
  LLVM; the tool itself uses neither.
