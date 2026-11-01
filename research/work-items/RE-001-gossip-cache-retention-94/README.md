# RE-001: node94 gossip cache update and retention decisions

Component: `node-runtime`. Target: Linux x86-64 node #94,
SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
Base: `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.
Reference pin: `999556f6e0a474b8312db96ec3149e1c44e97c23`.

## Question and new result

What does the previously unvalidated `0x473ce40` seed do to its ordered
cache, when does it clear its flag, and what bounds the retained entry count?
The packet binds three complete FDE bodies, **1,730 bytes / 400 instructions**,
and three supporting windows, **83 bytes / 16 instructions**. No component
gate or byte-reconstruction percentage changes.

The update compares an incoming field with the greatest cached **key** (or
an external fallback for an empty map), clears a flag on inequality, inserts
or replaces a 32-byte value under a separate incoming key, and requests
leftmost-entry removals while the post-insertion count exceeds **150,000**.
The insertion wrapper increments the count only for a new key; its equality
arm replaces the value without incrementing. The removal wrapper selects the
leftmost leaf's index zero and decrements the count once after its delegate
returns. These are static control/data-flow observations, not captured-code
execution or a recovered Rust implementation.

Before this contribution, the catalogue supplied an unverified seed in
`node/gossip_rpc.rs`. No packet bound these bodies or this retention rule.
`overlap.json` records the all-state PR and repository searches. Closest PRs
#1335 (gossip RPC **client** Location census), #999 (non-validator client-block
admission and batch verification), and #211 (RPC timeouts) cover other questions
and functions. The prior IPv4-translation contribution #1378 is separate.
The supporting caller FDEs already appear in #681/#625/#1162 and the
startup/node inventories. Their raw indirect-call bytes are not claimed as new
function recovery: this packet adds the binding to the newly studied cache
update. Those earlier channel, sampler, codec and Location questions are not
repeated. No unlicensed reference implementation was copied. Only its seed address was
used; the findings below come from authenticated binary bytes.

## Observations

All addresses below are ELF virtual addresses; range ends are exclusive.
File offsets are decoded from section headers in `records.json`.

| Body | Extent | Bytes | Instructions |
| --- | --- | ---: | ---: |
| Update | `0x473ce40..0x473d120` | 736 | 174 |
| Insert/replace wrapper | `0x49344d0..0x49346ef` | 543 | 126 |
| Pop-first wrapper | `0x4947160..0x4947323` | 451 | 100 |

The FDE parser and independent `readelf` headers agree on these extents and
CIE references. Each complete GNU and LLVM export covers every original byte.
LLVM 18 prints `f0` / `lock` on a separate line; the verifier joins only that
literal prefix with its adjacent instruction before comparing boundaries.
No original byte is masked. FDE extents are unwind-described bodies, not
proof of complete source-function ownership or absence of cold code.

### Entry layout and the sticky flag

Let `owner` be the incoming `rdi`, `incoming` the incoming `rsi`, and
`shared = *owner`:

| Access | Observed role |
| --- | --- |
| `shared+0x10` (byte) | Lock word; fast acquire is `lock cmpxchg 0 -> 1` |
| `shared+0x30`, `+0x38`, `+0x40` (qwords) | Map root, height, and entry count |
| `shared+0x48` (byte) | Cleared on comparison mismatch |
| `owner+0x8` (qword) | Empty-map fallback comparison value |
| `incoming[0]` (pointer), then `+0x50` (qword) | Incoming comparison field |
| `incoming[0]` (pointer), then `+0x98` (qword) | Insertion key |
| `incoming+0..32` | Four words moved into the insertion wrapper |

At `0x473cea0` and the eightfold-unrolled `0x473ced0` sequence, the update
follows child `node[n]`, with `n = u16(node+0x1c2)` and children at `+0x1c8`.
At height zero, `0x473cf5a` computes `node + 8*n + 0x160`, which is the last
key at `node+0x168+8*(n-1)`. A missing root or zero-length leaf selects
`owner+0x8` instead (`0x473cf68..0x473cf77`).

`0x473cf7a..0x473cf87` compares the incoming `+0x50` value with that selected
qword. Equality skips the store; inequality writes **zero**, not one, at
`shared+0x48`. This happens **before insertion**. The body contains no store
setting that flag to one. Naming the flag "contiguous", "complete" or
"bootstrapped" would require its writer/reader closure, which is not established.
The key and comparison fields must not be conflated.

### Insert and replacement

`0x473cf87` loads the key from the incoming object's `+0x98`; `0x473cf8e`
and `0x473cf92` copy all 32 incoming bytes to the wrapper's value argument.
The direct call at `0x473cfae` reaches `0x49344d0`.

The wrapper searches qword keys at `node+0x168+8*i`. `cmp`, `seta`, and `sbb`
at `0x4934515..0x4934525` encode an **unsigned** three-way comparison. A
non-equal key descends the selected child while height remains. Equality
reaches `0x4934553`: the existing 32-byte value is returned, the replacement
is copied into its slot, and the branch at `0x4934579` skips the count increment.
A new key reaches `0x4934674`, increments map `+0x10` (shared `+0x40`), and
returns a zero first word. The empty-root path allocates a `0x1c8`-byte leaf,
initializes its parent/length, and stores the key and 32-byte value. The
nonempty insertion/growth delegate is `0x41f8140`; its balancing internals
are not reconstructed here.

The update releases two reference-counted fields of a returned old value,
using locked decrements and slow drop functions at `0x4761900` / `0x4761470`.
Their concrete types and complete destructors remain unknown.

### Count cap and eviction selection

Both count comparisons read `shared+0x40` **after insertion**:

| Instruction | Decision |
| --- | --- |
| `0x473cfe4` / `0x473cfec` | `cmp count,150001; jb unlock` |
| `0x473d010` / `0x473d018` | `cmp count,150000; jbe unlock` |
| `0x473d020` | Call the pop-first wrapper, then release its returned value |

The limit is a count, not bytes, elapsed time, or a key-distance threshold.
The first and subsequent unsigned comparisons are equivalent to continuing
while `count > 150000`. Replacement alone does not grow the map, although an
already-oversized map still enters the eviction loop.

The pop wrapper follows child zero at `node+0x1c8` until height zero
(`0x49471a0` and the unrolled `0x49471c0` sequence). It tests leaf length,
zeroes the height/index pair at stack `+0x40`, and passes that leftmost leaf
and **index zero** to `0x42b0060` at `0x4947232`. Its leaf route at
`0x42b0262..0x42b028e` forwards to `0x42a6e10`. On return the wrapper decrements
map count once (`0x494724b`). Tree rebalancing/root contraction and the complete
`0x42a6e10` removal implementation remain outside this claim.

On valid ordered-tree state and successful delegate completion, this is a
request to evict the least key, rather than insertion-order eviction. Thus a
new key below all existing keys can itself be selected when the cap is exceeded.
This consequence is an inference from the selected coordinates and unsigned
ordering, not a measured target execution.

A missing root/empty leaf returns a zero second word. The update checks that
word at `0x473d025` and reaches an unwrap panic on absence, with a relocated
Location for `node/src/gossip_rpc.rs:235:43`. The full 51-byte source path and
its pointer/length/coordinates are authenticated by the verifier. The state
must satisfy the original tree invariants; malformed arbitrary memory is not
an accepted input model.

### Calls, locking and limits of closure

The only `.rela.dyn` entry targeting the update is `0x5773578 -> 0x473ce40`.
A whole-`.text` scan finds two `ff 15` references to that slot, at `0x2017f3c`
and `0x474c242`. Both are instruction starts in full original disassemblies
of their respective FDEs (`0x2017c80..0x2018ded` and
`0x474bfa0..0x474e1a1`); compact argument/call windows are retained. This is
not an exhaustive register-indirect or computed-pointer caller census.
The same scan finds one direct `e8` candidate each for the insert and pop
wrappers, both inside the complete update body, and no direct `e8` candidate
for the update.

Fast unlock is `lock cmpxchg 1 -> 0` at `0x473d08c`. Contended acquire/unlock
calls use slots `0x576ef30` / `0x576ef38`, bound to `0x4e0f640` / `0x4e0f2c0`.
The acquire passes integer `1000000000` in `edx`; no duration or timeout
semantics are asserted for that parameter. The full exports retain the cleanup
and unwind paths. `records.json` lists all **30 call instructions** in the
three primary bodies and resolves their direct targets or RIP-slot relocation
records; register calls remain explicitly visible. This does not establish
full helper closure, synchronization correctness, original ABI/source types,
LSDA behavior, allocator behavior or live reachability.

## Reproduce and validation

From the repository root, with the pinned LFS inputs materialized:

```sh
python3 -I -B research/work-items/RE-001-gossip-cache-retention-94/verify.py --controls
python3 -m unittest discover -s tests -p test_gossip_cache_retention.py -v
make doctor verify test catalogue-check reproduce
```

`--write --controls` regenerates `records.json` and `controls.json` only. The
verifier otherwise compares regenerated records byte for byte. Its code uses
the standard library and existing section/FDE parsers; it launches no program,
network operation, captured-code interpreter or emulator. Test execution is of
the independently authored verifier and repository tests only.

To reproduce each raw disassembly, use the table's bounds, or the explicit
`SUPPORT` bounds in `verify.py`:

```sh
objdump -d -Mintel --insn-width=16 --start-address=0x473ce40 --stop-address=0x473d120 artifacts/node/94/hl-node
llvm-objdump -d --x86-asm-syntax=intel --start-address=0x473ce40 --stop-address=0x473d120 artifacts/node/94/hl-node
readelf --debug-dump=frames artifacts/node/94/hl-node
```

The readelf export retains the three FDEs and shared CIE. Its printed FDE/CIE
identifiers are offsets within `.eh_frame`, whereas parser records use ELF
VAs; the verifier explicitly accounts for the section base. Export tool
versions: GNU binutils `2.47.20260726`, LLVM `18.1.4`. Python `3.14.7` on
Darwin arm64. No Ghidra analysis profile or native rebuild was used.

There are **33 corruption controls**: lock/tree/value offsets, key ordering,
flag branch/store, both count limits/unsigned branches, insertion versus
replacement count flow, pop selection/count, caller slots, six relocations,
Location length/line and the FDE range. Every mutation is rejected with
**whole-image hash, body hashes and export-byte checks disabled**. An additional
test corrupts an otherwise unpinned NOP to exercise the full-export comparator.
These are evidence-verifier controls, not behavioral differential coverage.

Exact gate outcomes, complete test inventory and repeat-generation results are
recorded in `validation.json`. No Rust implementation, native execution,
reconstructed byte equivalence, hosted CI result or full component completion
is claimed by this packet.

## Next question

Locate the writers/readers of `shared+0x48` and bind their use of the incoming
`+0x50` comparison field, then close the insertion/removal delegates before
reconstructing the complete cache and its ownership behavior.
