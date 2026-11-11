# RE-009 · Checkpoint sink cleanup of staged rows

At call site `0x595abee`, the checkpoint sink passes a stack descriptor to `0x5957bc0`. The selected continuation reaches `_Unwind_Resume` when the later stack word is zero. This supplements the checkpoint entry and record growth packets with the selected unwind cleanup of staged rows.

The routine loads the initialized range from descriptor +8 and +0x18. For a valid 24-byte-stride range, its multiply-high and shift compute the number of rows. It advances by 24, skips rows whose first word is zero, and otherwise calls the shared indirect slot with row +8, row +0 and zero. It handles the backing buffer separately. A nonzero descriptor +0x10 supplies the count multiplied by 24, and descriptor +0 supplies the pointer for the tail call. These observations distinguish initialized rows from the backing extent. They leave callback identity, invalid descriptor behavior and other unwind paths open.

Run `python3 research/work-items/RE-009-node115-checkpoint-sink-cleanup/verify.py` from the root. This reads the pinned Node #115 image, validates the FDE and contiguous body and caller windows, and rejects a mutated direct call displacement.
