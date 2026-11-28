# RE-017 Node #115 timed replay carrier handoff

- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Analysis base: `6d9382f821930b10d181cb90fe4a32756fd8e069`.
- Coordinates: original ELF VAs bounded by the captured DWARF FDEs.

The [scheduled-channel packet](../RE-001-node115-scheduled-channel-due-time/README.md)
establishes the due-time arithmetic and a retained qword. This packet
identifies that qword as the encoded-byte owner, traces its passage between
two queues, and identifies its release when the outgoing queue is closed
or the pending future is dropped.

## From the timed row to the saved owner

At `0x5a71330` and `0x5a71362`, the poll function `0x5a71040` passes
the shared input object's `+0x1a0` receive cursor and `+0x80` queue
state to `0x5819b20`. The reader checks the target slot bit in the
segment word at `+0x310`, computes `24 * (index & 31)`, and copies
the slot's first 16 bytes to result `+0x8` and its final qword to result
`+0x18`. The latter is the owner field in the 24-byte connection entry
written by `0x581a8b0`. Those matching offsets establish the layout
join for a common queue instance.

After the success tag and nonzero first payload dword, the poller copies
the payload to state `+0x20..+0x38`. The qword at payload offset
`+0x10` arrives as the last four bytes of the 16-byte move to state
`+0x24` plus the separate dword store to state `+0x34`. Together
they restore all eight bytes at state `+0x30`. At `0x5a7141f` /
`0x5a71423` the poller copies that qword to its retained owner field
`+0x68`.

## Forward or release

A pending sleep writes outer state 4. The signed-relative dispatch
entry for state 4 at `0x93970c + 16` returns to the same sleep poll.
On the selected ready and outgoing-open path, `0x5a711bd` loads
state `+0x68` into RSI and `0x5a71208` calls `0x581b4b0`.
That helper stores the owner itself in an 8-byte slot at segment
`+8 * slot`, then publishes the slot bit in the word at segment
`+0x110`. There is no read of the owner's byte span on this handoff.
The constructor `0x5a7c7d0` allocates the two segment shapes
(`0x320` and `0x120`) and attaches the poll/drop tables to a
`0x108`-byte future containing the queue handles. The poll slot at
`0x64b8c58` relocates to `0x5a71040`.

When the outgoing queue's state word has low bit 1, the selected
branch at `0x5a711e2` instead reaches a locked decrement on the retained
owner. The drop entry, resolved by `0x64b8c40 -> 0x5a3ede0`, also
decrements the owner at state `+0x68` when the outer state is 4.
Each calls the same drop slot `0x64e4cb8 -> 0x5a8e7c0` on zero.

The observed path preserves and transfers a reference to the serialized
bytes. It leaves live queue identity, runtime delivery, later file
persistence, and mutability through other aliases unproven. These are
static instruction and relocation checks, without captured execution.

## Reproduce offline

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-017-node115-replay-timed-carrier-handoff/verify.py
(cd research/work-items/RE-017-node115-replay-timed-carrier-handoff && sha256sum -c MANIFEST.sha256)
```

The [instruction windows](windows.txt) preserve the LLVM commands and
raw bytes. The [offline log](offline-log.txt) captures the verified
FDEs, dispatch/relocation targets and four rejected operand mutations.
