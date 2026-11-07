# RE-001: node 115 chain-selector initialization and membership gate

Partial progress for [#3909](https://github.com/lalalune/hyperliquid-source/issues/3909).
This follows one valid raw selector value through lazy initialization and a
concrete consumer. It leaves all full-component gates false and does not assign
a chain name from an unrelated codec's tag order.

## Target and prior boundary

Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. Original node #115 ELF:
105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Coordinates are ELF virtual addresses, not file offsets.

`RE-001-node115-chain-dispatch-globals` / [#2285](https://github.com/lalalune/hyperliquid-source/pull/2285)
owns the selector table, selected global addresses and their state dwords; it
expressly leaves initializer contents, names and consumers unresolved.
Open [#4041](https://github.com/lalalune/hyperliquid-source/pull/4041) records a
different diagnostic caller edge into `0x3c377b0`, not the body/dataflow below.
The named `RE-015-chain-codec-115` tags are separate prior evidence; this packet
does not assume that their ordering proves this selector's domain labels.

## Selected initialization path

For raw tag 1, the signed table word at `0x7d92d8`, relative to `0x7d92d4`,
routes `0x46f3fc0` to `0x46f3fd9`. The selected payload is `0x64fdb50` and its
state dword is `0x64fdb68`, initially 3. A zero state returns the payload
directly; otherwise the selector calls `0x5c87d50` through `0x64df9f0` with
descriptor `0x6493680` and the captured payload pointer.

The acquired-initializer path calls descriptor+0x20 at `0x5c87e44`. Its relative
relocation resolves to `0x46dc4d0`. That callback consumes the captured pointer,
invokes the function pointer stored in the payload, and replaces the payload's
first 24 bytes with the returned descriptor. The original relocation at
`0x64fdb50` binds that function to `0x46e7ff0..0x46e83b8`. These are explicit
call/relocation and publication observations; they are not a complete proof of
Once scheduling, poisoning or concurrent memory-order behavior.

The initializer starts an empty collection descriptor and supplies the
following 20-byte values, in this order, to `0x37090e0`:

| Insertion call | Exact bytes, in memory order |
|---|---|
| `0x46e805a` | `7db9972a235370a311d0ae3dfc545a954c786599` |
| `0x46e8160` | `a40cf273de4f77278b911dd4c6a023d60647d979` |
| `0x46e8260` | `a89a7f8ab7bcf9c57542e22dc0e4b768b0101762` |
| `0x46e8370` | `f027b2abfa8de836d8cdcce22af88bb8aacef849` |

Each value is assembled from two little-endian u64 immediates and a u32
immediate at stack+0x48/+0x50/+0x58. The later three are also the exact 20 bytes
used by the initializer's membership searches. They are embedded public binary
data; no external account or live-chain meaning is inferred.

For the first empty insertion, the helper allocates a 0xe8-byte leaf, clears
its header/count, publishes its pointer, increments the leaf key count, and
copies the first 16 plus last 4 bytes to leaf+0x8 and leaf+0x18. It increments
collection length at `0x37091a9`. Later nonempty insertion calls delegate to
`0x34bd400`; their complete allocation/tree-rebalancing behavior is not proved
here. The initializer returns its three-qword collection descriptor at
`0x46e837f..0x46e838b`, which the callback publishes as described above.

## Concrete consumer boundary

At `0x3c377b0`, the incoming raw selector is SIL and the 20-byte lookup key is
RDX. Raw tag 1 follows `0x3c377f1..0x3c377fb` through the same selector slot
`0x64e5be8 -> 0x46f3fc0`; raw tag 3 has a distinct special path outside this
selected contract.

The consumer loads the returned root and height, examines the leaf key count
at node+0xe6, and compares 20-byte entries beginning at node+0x8 against the
supplied key. Slot `0x64dfb50` is an ELF type-6 import of **memcmp**, verified
through the dynamic symbol/string tables. A positive comparison advances to
the next entry; equality at `0x3c37884` reaches `0x3c378b1`. On a missing key,
the observed child-index traversal uses node+0xe8 and a decreasing height;
the exhausted search returns byte 1 through `0x3c37a73`.

The equal-key continuation prepares further context and calls `0x3d3b020` at
`0x3c37a25`; its result and a later `0x37c1f00` call can change the ultimate
return. This is a membership-dependent policy handoff, not proof that membership
alone grants or denies a particular operation. Valid collection layout and
normal helper returns are premises.

## Reproduction and limits

`records.json` retains **7 windows / 2,435 bytes / 562 instructions**, with
FDE bounds, hashes and retained instruction rows. It checks 63 explicit facts
and 14 corruption controls, covering the selector arm, initializer/callback,
four key constants, leaf/publication fields, comparator identity/width and the
equal-key branch. Controls bypass global digest/window comparisons and must
fail the relevant fact checks. Full retained function bytes do not expand the
semantic claims beyond the paths described above.

Use an existing Python environment with Capstone **5.0.7** and a hydrated
artifact (observed Python **3.14.7**):

```sh
python3 research/work-items/RE-001-node115-chain-set-initialization/verify.py
```

Expected: 7 windows, 2,435 bytes, 562 instructions, 63 facts and 14 rejected
corruptions. `verification.json` retains the observed result; `--target PATH`
requires the same digest. The existing registry-row-labels helper supplies
ELF/FDE parsing; no dependencies or inputs are downloaded by this verifier.

Named-chain identity, all selector arms, transitive insertion correctness,
downstream authorization semantics, Once concurrency and live deployment state
remain open. No captured instructions were executed or emulated. Interpretation
and tooling are independently authored; imported rights remain unchanged.
