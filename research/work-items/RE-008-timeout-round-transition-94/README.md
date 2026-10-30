# RE-008 — node #94 timeout-to-round transition

Static, digest-bound evidence for `artifacts/node/94/hl-node` (SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`),
based on upstream commit `1f8c67c63ca4794c9689235471c60297f8a5c985`.

This packet continues the merged RE-008 inventory in PR #25. It does not
repeat that packet's diagnostic-string inventory, verifier discovery, or
shared quorum-helper proof. It locates the verifier callers in the consensus
state FDE, follows the individual-timeout and direct-certificate paths, and
pins one in-memory round-state write.

All names below are evidence labels. The ELF is stripped; they are not claimed
as recovered symbols or DWARF names. The `references/can1357-hl` source was a
navigation lead only and is neither copied nor treated as authoritative.

## Established transition

The bounded helper FDE `0x44b6670..0x44b7e10` receives a state pointer, an
accepted round, and a payload pointer. Its entry performs:

```text
0x44b668e  mov r12, [rdi+0x918]       ; current round
0x44b6695  cmp rsi, r12               ; accepted vs current
0x44b66a5  jb  0x44b66e6             ; stale cleanup, no round write
0x44b66a7  mov rax, r14
0x44b66aa  inc rax
0x44b66ad  mov r13, -1
0x44b66b4  cmovne r13, rax
0x44b66b8  mov [rdi+0x918], r13
```

Therefore the proven state transition is:

```text
if accepted_round < current_round:
    no write to state + 0x918
else:
    state[+0x918] = accepted_round.saturating_add(1)
```

There are two verified callers inside the state FDE: the direct TC path at
`0x44b17cf` and the individual-timeout quorum path at `0x44b2629`.

This establishes an in-memory write, not disk persistence or network
finality. Later calls and offsets show additional work, but their exact Rust
types and full semantics remain unresolved.

## Admission and rejection observations

| case | observed predicate / action | mutation ordering |
|---|---|---|
| Direct TC stale | `incoming_round < [state+0x918]` at `0x44af51f..0x44af526` | branches before `verify_tc` and before any observed state-method call |
| Direct TC verification | call `0x47594f0` at `0x44af543`; error sentinel branch at `0x44af55a` | failure exits before any caller-local state write; verifier transitive effects remain unresolved |
| Direct TC post-check | unknown helper `0x47593a0` at `0x44af570`; error branch at `0x44af587` | failure exits before any caller-local state write; helper transitive effects remain unresolved |
| Timeout round mismatch | `timeout_round != [state+0x918]` at `0x44b035e..0x44b0368` | branches before duplicate lookup and signature verification |
| Timeout duplicate | lookup using container `state+0x9b8`; present result avoids `0x44b1548` | no caller-local write and no signature verification; lookup-helper transitive effects remain unresolved |
| Timeout signature failure | call `0x454aa10` at `0x44b1560`, sentinel branch at `0x44b157d` | branches before first caller-local state-container update; verifier transitive effects remain unresolved |
| Unknown validator key | stake helper compares 20-byte keys and adds stake only on equality | no separate membership rejection is visible; an absent key contributes zero weight, subject to unresolved earlier signature/key semantics |
| Insufficient or exact 2/3 stake | `2*total >= 3*signed_weight` at `0x44b2544..0x44b255f` | branches away after timeout insertion and before the timeout-container move/clear and round call |
| Strict quorum | `2*total < 3*signed_weight` | moves/clears the timeout container, builds a payload, calls `0x44b6670` |
| Round helper stale | `accepted_round < current_round` | cleanup branch before the `+0x918` write |
| Round helper accepted | `accepted_round >= current_round` | saturating `accepted_round + 1` is written before downstream work |

The complete machine-readable branch table is in
`timeout-round-transition.json`. “Invalid validator” is intentionally not
reported as a dedicated rejection: the bounded stake-intersection path proves
zero weight for a nonmatching 20-byte key, while the signature/key binding and
TC key deduplication helpers are unresolved.

## Timeout-certificate verifier connection

The existing PR #25 packet proved `verify_tc` at
`0x47594f0..0x4759963` and its quorum callee. This packet adds these bounded
facts:

1. TC round at record offset `+0x18` must not exceed validator-history offset
   `+0x58`, followed by a round-snapshot lookup.
2. The record vector length at `+0x10` must be nonzero.
3. Every `0xb8`-byte record has a qword at `+0x50` equal to the TC round.
4. One selected record calls the signed-timeout verifier at `0x475974f`.
5. Remaining verification goes through `0x4768f80`; its complete signature
   scheduling/error semantics are not recovered.
6. `0x4451690` collects a 20-byte key per record; its deeper collection helper
   and duplicate policy remain unknown.
7. The relocation-backed quorum call at `0x4759865` reaches the previously
   proved predicate at `0x4ad90d0`.

Thus a string reference or quorum predicate alone is not treated as security
enforcement: the state caller actually reaches the verifier, checks its result,
then reaches the round helper only on its success path plus the unknown
post-verifier helper's success path.

## State-offset observations

These are byte-level observations, not complete struct-layout claims:

| offset | observed use |
|---|---|
| `+0x918` | current-round reads and saturating next-round write |
| `+0x930` | address passed to round/history lookup helpers |
| `+0x9b8/+0x9c0/+0x9c8` | three-word timeout container moved; `+0x9b8` and `+0x9c8` cleared |
| `+0xa68` | keyed container updated with `max(existing, timeout_round)` after signature success |
| `+0x4e8` | address passed with a copied `0x98`-byte record to relocated callee `0x4758390` |
| `+0x910` | pointer used for lock/wake-shaped operations |
| `+0x8a0..+0x8b0` | 32 payload bytes replace an existing container |
| `+0x8c0/+0x8c8/+0x8d0/+0x8d8` | values consumed by a call, then byte `+0x8d8` set |
| `+0x8e0/+0x8e8/+0x8f0/+0x8f8` | second analogous call, then byte `+0x8f8` set |
| `+0x9b0` | qword cleared |
| `+0xb00/+0xb01` | bytes cleared |

Calling these fields “queues,” “timers,” or “flags” is an inference from the
instruction and call shapes. The JSON retains the exact supporting bytes and
sites so those labels can be revised without changing the observations.

## Call/data graph

```text
state_dispatch FDE 0x44adfa0..0x44b303a
├─ direct TC
│  ├─ stale guard: state+0x918
│  ├─ verify_tc 0x47594f0
│  │  ├─ verify_signed_timeout 0x454aa10
│  │  ├─ remaining verifier 0x4768f80                 [unknown internals]
│  │  ├─ collect 20-byte keys 0x4451690              [dedup policy unknown]
│  │  └─ quorum slot 0x5776ae8 → 0x4ad90d0
│  ├─ post-TC helper 0x47593a0                        [unknown]
│  ├─ state helper 0x44ab560                          [unknown]
│  └─ round transition 0x44b6670
└─ individual timeout
   ├─ current-round guard: state+0x918
   ├─ duplicate lookup: state+0x9b8
   ├─ verify_signed_timeout 0x454aa10
   ├─ max-round keyed container: state+0xa68
   ├─ snapshot slot 0x57769e8 → 0x4b31d40
   ├─ insert timeout: state+0x9b8 via 0x493d940
   ├─ signed key/stake intersection 0x4b33990
   ├─ total stake 0x4b33770
   ├─ strict 2/3 compare
   ├─ construct payload 0x47be700
   └─ round transition 0x44b6670
      ├─ write state+0x918 = saturating(round+1)
      ├─ history lookups via 0x5773628 → 0x4b31e70
      ├─ record push via 0x5773648 → 0x4758390
      └─ further container, lock/wake, timer-shaped work [exact semantics unknown]
```

## Evidence ranges

All coordinates are ELF virtual addresses and all ends are exclusive.

| role | range |
|---|---|
| state dispatcher FDE | `0x44adfa0..0x44b303a` |
| direct TC admission blocks | `0x44af4fd..0x44af5f5`, `0x44b1797..0x44b17da` |
| timeout guards/admission blocks | `0x44b0356..0x44b0391`, `0x44b1548..0x44b1677` |
| stake/quorum/dispatch blocks | `0x44b24ba..0x44b2646` |
| round-transition FDE / entry blocks | `0x44b6670..0x44b7e10` / `0x44b6670..0x44b66f6` |
| TC verifier FDE | `0x47594f0..0x4759963` |
| validator snapshot helper | `0x4b31d40..0x4b31e61` |
| total-stake helper | `0x4b33770..0x4b33988` |
| signed-key/stake helper | `0x4b33990..0x4b33ea9` |
| 20-byte key compare/add blocks | `0x4b33be0..0x4b33c16`, `0x4b33c60..0x4b33c75` |

`timeout-round-transition.json` contains 39 bounded CFG blocks. Each record
retains every byte in its range, its SHA-256, and all direct terminal edges.
Targets outside the bounded records remain explicit external edges rather than
being presented as decoded semantics. `bounded-disassembly.txt` is a human
cross-check generated with Apple LLVM objdump 21.0.0.

## Independent narrow model

`src/consensus-timeout-transition` models only:

- current-round equality and duplicate admission for an already-verified
  individual timeout;
- 20-byte-key stake intersection, including zero weight for an unknown key;
- the strict `2*total < 3*signed` boundary;
- timeout-container clearing on the modeled transition; and
- stale/current/future acceptable-TC handling with saturating round advance.

Authentication and TC acceptability are explicit caller preconditions. The
model does not claim wire compatibility or recreate the unresolved helpers.

## Reproduce

Tested on macOS with Python 3.14.8, Apple LLVM objdump 21.0.0, and
rustc/cargo 1.94.1.

```bash
python3 -I -B tools/timeout_round_transition.py \
  --out research/work-items/RE-008-timeout-round-transition-94/timeout-round-transition.json
python3 -I -B research/work-items/RE-008-timeout-round-transition-94/verify.py
python3 -O -B research/work-items/RE-008-timeout-round-transition-94/verify.py
python3 -I -B -m unittest discover -s tests -p test_timeout_round_transition.py -v
cargo test --manifest-path src/consensus-timeout-transition/Cargo.toml
cargo fmt --manifest-path src/consensus-timeout-transition/Cargo.toml -- --check
make verify PYTHON=python3
PATH=/opt/homebrew/opt/binutils/bin:$PATH make test PYTHON=python3  # macOS/Homebrew
make reproduce PYTHON=python3
make catalogue-check PYTHON=python3
```

The Python collector is stdlib-only and does not require a disassembler. The
human disassembly export can be regenerated with GNU or LLVM objdump over the
listed ranges; the verifier relies on ELF bytes/FDEs/relocations, not rendered
assembly syntax.

`VALIDATION.md` preserves the exact pass counts and the initial unqualified
Apple-tool failure before the GNU-binutils rerun. It is a sanitized result
summary, not a claim that the unavailable exact-rebuild prerequisites exist.

## Corruption controls

The test suite mutates disposable in-memory copies only. It proves rejection
of a changed binary digest and, when the mutated digest is explicitly accepted
for the control, rejects changes to the round store, duplicate branch, quorum
branch, TC verifier call, and 20-byte stake-key width. No captured binary is
executed and no network, process launch, validator, key, or signing operation
is performed.

## Limitations and next question

- No captured-node execution, live P2P traffic, or persistence claim.
- No complete receipt/dispatch caller above the large state FDE.
- No recovered signature algorithm or exact error enum values.
- Rejection-before-write claims are caller-local unless the branch precedes
  all calls; transitive callee aliasing/mutation is not proved absent.
- No proof yet of the duplicate policy within a TC itself.
- `0x47593a0`, `0x4768f80`, `0x44ab560`, notification, queue, timer, and
  lock/wake callees retain unknown effects.
- No exact Rust struct types for the offset observations.
- No gate in `docs/PROGRESS.md` is changed; the broader consensus component is
  not complete.

The next bounded question is whether `0x4768f80` verifies every remaining TC
record exactly once and whether `0x4451690` rejects, coalesces, or preserves
duplicate validator keys before stake aggregation.
