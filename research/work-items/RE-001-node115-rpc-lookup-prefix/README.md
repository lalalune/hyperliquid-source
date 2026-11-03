# RE-001: node115 consensus RPC lookup-prefix collection

Component: `consensus`, bounded static research under RE-001. Question: when a
batch of 32-byte keys contains a lookup miss, does the collector retain the
successful prefix, and how are the returned handles acquired?

Target Linux x86-64 node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. New analysis and checker code
are independently authored under root MIT; imported inputs retain their rights.
No unlicensed reference code was used. Function names below are analyst roles.

## Evidence and result

GNU and LLVM independently decode all **3,881 bytes / 825 instructions** in
three complete FDEs. Addresses are ELF virtual addresses; ends are exclusive.
`records.json` records file offsets, body hashes, actual FDE/CIE records,
source/Location bytes, dynamic import and RELATIVE bindings, and call sites.
The denominator describes retained evidence, not reconstructed matching bytes.

| Role | Start | End | Bytes |
| --- | --- | --- | ---: |
| Collector | `0x5b9cab0` | `0x5b9cce7` | 567 |
| Lookup | `0x4fbba00` | `0x4fbbdb5` | 949 |
| Tracing wrapper | `0x4f13fd0` | `0x4f1490d` | 2365 |

The collector constructs an inline descriptor for
`node/src/consensus/rpc.rs`, length 25, line 139, before each lookup. The
separate relocated Location `0x64ab058` binds that path to 139:51. The inline
construction alone does not establish a column. One qualified E8 call to the
collector is at `0x50f9628`; the two wrapper calls are `0x5b9cb27` and
`0x5b9cbf0`. No RELATIVE slots name these three entries. The incoming census
covers E8 and RIP-relative FF15/FF25 in `.text`, not arbitrary indirect callers
or E9 tail calls. The wrapper's E9 tail to the lookup is checked separately.

For a valid iterator descriptor I in RSI, the collector reads I+0 as current,
I+8 as end, I+0x10 as environment pointer, and I+0x18 as failure-byte pointer.
RDI is a 24-byte output header with capacity, pointer and length at +0/+8/+16.
Normal-return behavior is:

1. Empty input produces `{0, 8, 0}` and leaves the failure byte unchanged.
2. Before the first lookup, I+0 is advanced by 32 bytes. Later iterations keep
   their cursor locally and advance by 32; they do not republish I+0. This
   packet therefore does not claim a fully updated resumable iterator cursor.
3. Each call obtains base B from the first environment word. The wrapper gets
   tracing state B+0x68 and forwards `(B+0x10, key_pointer)` to the lookup.
4. A zero first result sets the failure byte to 1 and returns the empty header.
   A nonzero first result allocates 32 bytes, sets capacity 4 and length 1,
   and stores the returned 8-byte handle.
5. Each later nonzero result appends one handle, growing through `0x5963a10`
   when required with arguments EDX=1, ECX=8, R8D=8. A later zero result sets
   the failure byte to 1 and returns the already collected prefix. No later
   keys are queried and the preceding successful handles are not discarded.
6. Exhaustion returns all collected handles without clearing the failure byte.
   There is no initial test of that byte and no collector-level deduplication.

Thus the local normal-return projection is `take until first zero`, with the
failure byte written only on a miss. This is not a public RPC response or a
claim that arbitrary integers are valid handles. The relation assumes valid,
aligned iterator/layout inputs, ordinary helper returns and successful growth.

## Lookup and reference acquisition

Let L be the lookup's first argument (B+0x10). After acquiring its lock, the
first word at L+0x28 selects the representation: the min-i64 sentinel uses the
tree; other valid header words use the flat route.

The tree compares 32-byte keys through the `memcmp` import at `0x64dfb50`.
Node key count is u16 at +0x1c2, key i starts at +32*i, value slot i is
+0x168+8*i, and child slot i is +0x1c8+8*i. A greater comparison continues
scanning; equality selects the value slot. A miss descends when the stored
height permits; an empty root or a leaf miss yields zero. Tree invariants,
construction and malformed nodes remain outside this claim.

The flat route calls the still-opaque search helper `0x57f5ee0`. Set AL bit 0,
or RDX index at least the length at L+0x40, yields zero. Otherwise, with
capacity c=L+0x28, base=L+0x30 and head h=L+0x38, the selected slot is:

```text
position = h + index
if position >= c: position -= c
slot = base + 40*position + 32
```

For valid `0 <= h < c` and `index < length <= c`, the one subtraction equals
modulo c. The search helper's comparator and the application meaning of the
keys/values remain unknown.

On either hit, the lookup loads the handle from the slot, executes
`LOCK INC qword [handle]`, then `JLE` to `UD2`. The branch tests `ZF || SF != OF`;
for INC this rejects signed-negative **pre-increment** words. It must not be
simplified to a sign check of the wrapped result: incrementing `INT64_MAX`
sets both SF and OF, so this JLE is not taken. `relations.json` retains the
boundary flag cases. This is a local reference-acquisition observation, not
an Arc type identification or proof of concurrent object lifetime correctness.

The lookup releases its lock and returns the handle (zero on miss), preserving
it around timing/reporting. With tracing disabled the wrapper tail-jumps to
this lookup; on its measured traced normal path it saves RAX across cleanup
and returns it. Full lock, tracing, timing, allocation, drop and unwind
semantics are not closed by this packet.

## Prior-work boundary

PR #1032 inventories node94 `consensus/rpc.rs` source Locations and literals;
it explicitly leaves functions, types and behavior unresolved. It does not
establish this collector's early-stop/prefix/flag relation. PR #2414 reconstructs
a `GossipRpcRequest` decoder at `0x5aac6a0`, not this consumer. PR #1335 inventories
the separate gossip RPC client path. #430 is node94 startup freshness/reply
handling, and #1441 is EVM RPC method-name dispatch. Those scopes are not
replicated. PRs #999/#1602 cover a client transaction join that releases the
built prefix and returns a missing-hash error. This collector returns its
prefix and writes a separate failure byte; it has no supplied-row bypass.
`scope-check.json` records the all-state PR and main-history audit,
including omitted-patch/API limits. No overlap was found within that audit;
this is not a guarantee about unpublished work.

## Reproduce and validation

From the repository root with Python 3.14.7, Capstone 5.0.7, GNU binutils
2.47.20260726 and LLVM 18.1.4 (validation host: macOS arm64):

```sh
python3 research/work-items/RE-001-node115-rpc-lookup-prefix/export_disassembly.py
python3 research/work-items/RE-001-node115-rpc-lookup-prefix/verify.py --controls
python3 research/work-items/RE-001-node115-rpc-lookup-prefix/relations.py
python3 -m unittest discover -s tests -p test_node115_rpc_lookup_prefix.py -v
make doctor verify test catalogue-check reproduce
```

GNU/LLVM must be on PATH (`/opt/homebrew/opt/binutils/bin` and
`/usr/local/opt/llvm/bin` on this host). Export regeneration authenticates the
whole capture before creating a private static input copy. No captured code is
executed or emulated. `--write` regenerates checker/relations JSON.

The checker binds instruction spans, source/Location data, import/RELA records
and complete unwind extents. **61 deep corruption controls** bypass the outer
image/body/export guards so each lower-level obligation must reject its own
mutation. Four actual operand/branch mutations change the projected prefix,
failure flag or input offsets. Relations cover 13,120 prefix/initial-flag cases,
53,040 valid small flat-header/index/tag combinations, and seven INC/JLE boundary
cases. These checks test static interpretations, not a native execution oracle.
`validation.json` records full repository checks, baseline provenance and skips.

No recovered Rust, build equivalence, public ABI, hosted CI, container run or
progress gate is claimed. Next: close the flat search helper and follow the
collector's consumer to establish the key/value types and public error mapping.
