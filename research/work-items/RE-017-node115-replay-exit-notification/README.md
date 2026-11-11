# RE-017 · Replay exit notification ordering

Node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301. The replay worker's known non-record exit calls 0x5a5a300 at 0x5a70097. The helper atomically decrements the object word at +0x1c8. Only a zero result calls 0x581be00 with object +0x80 and proceeds to the notification gate.

The gate uses a compare-exchange retry loop to set bit 1 of object +0x110. If the successful attempt replaced zero, it reads the saved table and argument from +0x100 and +0x108, clears the table slot, and exchanges the state word back to zero before calling table offset +8 if the table was non-null. An old nonzero state bypasses this immediate callback. Both paths then reach the two selected reference decrements, each with its own zero continuation. The helper's called bodies and the effects of concurrent registrations remain open.

From the repository root, run `python3 research/work-items/RE-017-node115-replay-exit-notification/verify.py` to check the authenticated artifact, edges and instruction windows.

On the selected same-segment arm, 0x581be00 reserves one index with a locked exchange-add at descriptor +8. It masks the old index down to a multiple of 32 and compares it to the segment base at +0xb00. A match sets bit 33 at segment +0xb10 using a locked OR and returns before the caller's separate notification gate. This identifies the terminal flag write for the selected segment layout. Cross-segment allocation and the corresponding reader remain open.

The normal record publication at 0x5a6fe24 has a second instance of the notification gate. It obtains the object from the saved stack slot +0x110 and likewise retries the state update, clears the table and resets state before calling offset +8. The two sites differ in their entry conditions. The exit helper's preceding decrement and terminal write have no counterpart in this selected post-publication window.
