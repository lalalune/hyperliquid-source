# RE-017: bind the replay clock to the nested block input

The begin-block comparison and the finalizer's raw clock input were reported separately. This packet connects the selected wrappers to both ends and checks the layout-B counterpart.

The two apply wrappers at `0x5a04e40` and `0x5a06600` read the nested block pointer from their third argument's `+0x18`. They copy the qword at nested `+0x38` and dword at `+0x40` to contiguous stack slots, then pass that 12-byte tuple to the respective begin helper. The tuple originates in the nested block; the clock call earlier in each wrapper is a different data source.

The begin helpers' first 0x83 bytes match exactly. They compare the incoming and state tuples lexicographically, with a signed first dword and two unsigned dwords. Only a strictly later tuple rotates the old clock to state `+0x6c..+0x77` and installs the new one at `+0x60..+0x6b`. Equality or an earlier block tuple keeps the stored clock.

Each wrapper reloads the saved address of the state-pointer slot for its later finalizer. Both finalizers copy the current 12-byte state tuple to the stack and pass it to the same drain at `0x5afa030`. The tracker base passed alongside it is state `+0x3e50` for layout A and `+0x49c0` for layout B. Therefore the selected replay drain samples the stored block-derived clock. Reading the incoming block clock directly would differ for earlier tuples. This conclusion assumes normal calls and the same state object at both handoffs without intervening clock writes.

Run `python3 -B research/work-items/RE-017-node115-replay-block-clock/verify.py` from the root. It checks the pinned ELF, FDEs, both header-to-begin handoffs, identical clock logic, the two current-clock spills and the shared drain. This packet does not infer wall-clock synchronization or prove a replayed state root.
