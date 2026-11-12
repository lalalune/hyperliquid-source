# Node 115 HIP-3 disabled-state writer and serialization source

This packet closes one producer gap in backlog HL115-090: the actual selected
`disableDex` handler writes the same registry byte consumed by the existing
HIP-3 disabled-state serializer. It also identifies the early disabled-state
admission check and distinguishes it from the later transition table.

This is bounded static reconstruction, not a complete HIP-3 implementation.
The authorization helper, other disabled-state writers, trading admission,
durable restart and replay remain open. No native target is run or emulated.

## Target and reproduction

- Artifact: `artifacts/node/115/hl-node` (105896032 bytes).
- SHA-256: `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- `records.json` retains 38 instruction-boundary windows: 4270 bytes and
  1022 instructions, with FDE identities, bytes, addresses and disassembly.
- 1040 facts pin instructions, dispatch entries, strings and relocated callees;
  1040 independent corruptions must each fail the relevant fact check. A changed
  digest is rejected before the normal evidence checks. These are static
  regression checks, not executed native branch cases or behavioral equivalence.

```sh
python3 -m pip install capstone==5.0.7 pyelftools==0.32
python3 research/work-items/RE-007-node115-hip3-disabled-state-writer/verify.py \
  --target artifacts/node/115/hl-node
```

The verifier only reads the supplied ELF. A Git LFS pointer is not the target.

## Prior work and remaining scope

[PR #3390](https://github.com/lalalune/hyperliquid-source/pull/3390),
[PR #4855](https://github.com/lalalune/hyperliquid-source/pull/4855) and
[PR #4369](https://github.com/lalalune/hyperliquid-source/pull/4369) own the
variant codec and selected record encoding. They do not establish the writer.
[PR #3361](https://github.com/lalalune/hyperliquid-source/pull/3361) and
[PR #3364](https://github.com/lalalune/hyperliquid-source/pull/3364) are parent
and state-serializer prior art. This packet reuses those field identities and
pins the concrete registry-row join; it does not claim another codec discovery.

[PR #4549](https://github.com/lalalune/hyperliquid-source/pull/4549) concerns
sub-deployer action names. Its matcher indices must not be substituted for the
raw `Hip3DeployAction` tags below. The existing cancel-routing packet covers a
different arm of the shared `0x2c47660` dispatcher.

Overlap screening used the all-state PR title/body inventory, fresh semantic
and exact-address searches, and focused inspection of the closest packets.
This is not a claim to have inspected every historical diff. No matching
writer scope was located by that screening.

## Concrete action and owner

The same Action representation binds the serializer to the handler:
`0x2bd0ef0` reads its input qword tag; raw `0xca` selects index `0x44` in
`0x6098bc` and enters `0x2bd33a6`. This passes **Action+8** to `0x28c25c0`
at `0x2bd3405` with the outer type string `perpDeploy`. The actual action
router `0x2bda7c0` retains its input in R15; the same raw tag selects
`0x609f00[0x44] -> 0x2bdb124`, passes **Action+8** to `0x2c1c680`, and that
wrapper preserves/restores the payload pointer before passing it to
`0x29467e0` at `0x2c1c9e1`. The wrapper's preceding checks must succeed.
The packet pins the complete wrapper prefix, including temporary uses and
restoration of RBP; it does not assume that RBP is unchanged throughout.
With the same valid Action object as input, these are actual shared-payload
edges, rather than a correspondence inferred from equal tag numbers.

`0x28c25c0` is a serializer for the literal type `Hip3DeployAction`. It reads
its value's byte zero and dispatches through `0x5fbdf4`. Entry 14 targets
`0x28c281b`, passes payload `value+8`, variant number 14, and the exact ten-byte
name `disableDex` to `0x26134f0`. This names the raw representation being used;
it does not reconstruct its JSON decoder or signature checks.

The actual common preparation function `0x29467e0` retains state in R15,
identity in R14 and input in R12. After its preceding opaque identity/role
gate, table `0x5fe548[14]` enters `0x2946a93`: it clones the input string
(pointer +0x10, length +0x18), builds a tag-14 temporary with the owned
capacity/pointer/length at +8/+0x10/+0x18, and passes that temporary, the same
state and identity to `0x2c47660` at `0x294767d`. Empty input uses a non-dereferenced
sentinel pointer; allocation failure is outside the selected normal path.

In `0x2c47660`, raw tag 14 follows three separately pinned dispatch tables:

| Table | Entry 14 target | Work |
| --- | --- | --- |
| `0x60a7a8` | `0x2c47994` | Name length <=100 and initial registry lookup |
| `0x60a800` | `0x2c4830d` | Permission selector `0x13` |
| `0x60a848` | `0x2c489a8` | Selected action's second lookup and transition |

Let S be the handler's state pointer. Both lookup sites pass the descriptor
at `S+0x7c0`. The first calls `0x446af70`; the second calls `0x446b070`.
Both read descriptor+8 as backing storage and descriptor+0x10 as count,
walk 0x510-byte rows, and return the selected row pointer at result+8 with
status `0x1a2`. For a nonempty name, they skip rows whose +0x378 qword is
`i64::MIN`, compare the stored name length at `[row+0x4a0]+0x10`, and use
`memcmp` for equal-length names. A missing match returns `0x156`. Empty names
select the first row under a nonempty-registry premise; the empty-registry
unwrap path is excluded. No invented registry or callback supplies this row.

Before authorization, the handler tests the selected row D:

- If `D+0x378 != i64::MIN` and byte `D+0x468 != 0`, the selected raw-14 path
  returns error `0x178` inside outer result tag `0x0f`.
- If `D+0x378 == i64::MIN`, this action returns `0xf4`.
- Otherwise it compares the supplied 20-byte identity with the owner bytes
  at `[D+0x4a0]+0x70`. A match proceeds directly. The alternate path calls
  `0x469e170` with selector `0x13`; that helper's permission semantics remain
  opaque. This packet does not model it as an always-successful check.

The selected owner-match path has a zero-length auxiliary row list and reaches
the action-specific arm without claiming the semantics of other dispatch arms.
The prepared name is checked against 100 again and used for the second lookup.
Treating both lookups as the same D requires a stable, valid registry and the
same name during this interval. This is an explicit ownership/state premise.

## Actual transition and ordering

After the second lookup succeeds, `0x2c49c40` retains its returned D in RBX.
The loop at `0x2c49c5e` covers `i=0..[D+0x10]` (exclusive upper bound).
For each i, it computes `10000 * [D+0x50] + i`, with checked multiply and add,
and calls `0x243ca40` on the tree at `D+0x4c8` with that exact key.

`0x243ca40` reads tree root/height, compares unsigned qword keys, descends
through the selected child, and returns a nonzero node-associated pointer on
an exact match; an empty tree or missing key returns zero. Valid sorted tree
nodes and child ownership remain premises. A missing key returns error `0xf0`
with the exact text `all assets must be halted before disabling dex` and
bypasses the state write. Arithmetic overflow leaves the selected normal path.
The zero-count case skips the loop. No interpretation of a fabricated list of
helper answers is used as native validation.

After every required key is present, `0x2c4ac78` checks the HIP-3 parent
sentinel again. The late table at `0x60a968` then dispatches on byte D+0x468:

| Byte at late dispatch | Native branch | Selected result |
| --- | --- | --- |
| 0 | `0x2c4b080` | Write **1** to the same D+0x468; outer result `0x0e` |
| 1 | `0x2c4b087` | No state write; outer result `0x0e` |
| 2 | `0x2c4b830` | Error `0xf0`: `already disabled by validators` |
| 3 | `0x2c4b877` | Error `0xf0`: `already disabled by quote token migration` |

The early nonzero gate is essential: **the selected unchanged-registry path
reaches the late table with byte zero**. The late byte-1 branch does not prove
that another public `disableDex` call is idempotent; the earlier gate rejects
that unchanged byte with `0x178`. Likewise, the late byte-2/3 errors are real
native branches, but this packet does not claim they are reachable through
this path without an intervening state change. Values outside 0..3 are not
validated native inputs and are not assigned behavior.

Only the zero-to-one write is established here. No writer of values two or
three, enable transition, permission mutation, or global transaction rollback
is reconstructed.

## Same-state serialization join

The writer's address is connected to the existing serializer by actual
arguments and row strides, not by a matching displacement alone:

1. `0x3c13960` saves its RSI input wrapper and dereferences its first word at
   `0x3c139da` to obtain S. At `0x3c13b26..3c13b41`, it passes **S+0x7c0**
   as R8 to `0x419e240` under the literal name `Clearinghouses`.
2. `0x419e240` reads that descriptor's +8/+0x10 and walks **0x510-byte rows**.
   It passes each row as RSI to `0x4481380` at `0x419e49b`.
3. `0x4481380` retains that exact row in R15 and passes **row+0x378** in RDX
   to `0x44f6f40` at `0x448194e`.
4. `0x44f6f40` retains the parent in R14, forms **parent+0xd0** in RSI at
   `0x44f72d3`, and calls the state writer `0x449dbc0` at `0x44f7327`.
5. That state writer retains RSI in R15 and reads **state+0x20** at
   `0x449dd67` for `disabled_state`. Its raw byte-1 table entry targets
   `0x449de73`, which supplies the exact string `UserDisabled`.

Therefore, when serialization is invoked over the same S with the selected D
still present, it sources the writer's byte at
`D + 0x378 + 0xd0 + 0x20 = D + 0x468`. The adjacent state boolean at +0x21
is separate and is not modified by the selected write. This proves the
serialization input identity; it does **not** prove that a checkpoint was
written, that a restart reads it, or that trading admission observes it.

## Remaining gaps

The complete public decoder/action registration chain, cryptographic and role
validation, permission helper `0x469e170`, system-disabled writers, enable or
migration transitions, all trading-admission consumers, concurrent mutation,
unwind cleanup, crash persistence and restart equivalence remain unclosed.
The original target was inspected statically only. Existing codec work supplies
its own encoding contract; this packet adds the actual selected producer and
its guard ordering without replacing those prerequisites.
