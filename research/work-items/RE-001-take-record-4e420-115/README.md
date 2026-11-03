# RE-001: take slot record 0x5d4e420 (node #115)

## Bounded question

What does the 380-byte routine at `0x5d4e420` do with its two
arguments — an out record in rdi and a source object in rsi — and
what happens to the source's `+0x650` slot on each path?

## Answer, end to end

The routine moves the source's slot record into the out record
under an acquire/release pair. The out record is 16 bytes: a
32-bit value at `+0x00`, a 16-bit flags field at `+0x04`, and a
pointer at `+0x08`. In instruction order:

1. Acquire: the acquire callee `0x606ca40` is called at
   `0x5d4e44e` with the source's `+0x658` field address. This
   happens before anything else is read, and the matching
   release below runs on every return path.
2. Out init: the out record is zeroed — `+0x00` (4 bytes),
   `+0x04` (2 bytes), `+0x08` (8 bytes). A pre-filled out
   pointer is dropped here, with no delete call: the init
   overwrites it before the move's old-pointer check runs, so
   the old pointer is never freed by this routine.
3. Slot test: the source's `+0x650` pointer is read. The two
   paths diverge here and rejoin at the release.

### Slot non-null path (the take)

4. Fill: the fill callee `0x61b3720` is called at `0x5d4e47c`
   with a stack temp record and the slot object. What the fill
   computes inside the slot object is not pinned; only that it
   leaves a (value, flags, pointer) temp record.
5. Manual move: the temp's value, flags and pointer are copied
   into the out record, and each temp field is zeroed right
   after it is read, so the temp ends fully zeroed. The move
   loads the out record's old `+0x08` pointer first and deletes
   it with delete[] when non-null — but the init in step 2
   already zeroed it, so that delete never fires on this path.
   Likewise the temp's pointer slot is read after it was
   zeroed, so its delete[] check at `0x5d4e4c9` never fires
   either. Both delete[] sites exist in the code and are
   recorded; both are dead on this routine's own paths.
6. Take: the source's `+0x650` field is re-read and then set
   to 0. The taken object is destroyed by the destroy callee
   `0x61b18d0` at `0x5d4e4e8` and then deleted with size
   `0x38` (56) at `0x5d4e4f5`. The slot is empty afterwards.

### Slot null path (the report)

4. Report: a 32-byte stack block is built — message pointer
   `0x43c424` with length `0x16` (22), path pointer `0x4376fd`,
   and a zero qword — and the report callee `0x61cf670` is
   called at `0x5d4e563` with (stack temp record, 5, 0, block,
   block + `0x10`, 0). The message bytes, verified byte-for-byte
   against the binary, read `No trace file to close`. The byte
   at `0x4376fd` is NUL; the path string itself begins at the
   next byte, `0x4376fe`, and reads
   `/home/ubuntu/hl/code_Mainnet/z_vendor/futures-channel/src/oneshot.rs`.
   What the report callee writes into the temp record is not
   pinned; only its argument list is.
5. Move-assign: the helper `0x5d49b10` is called at `0x5d4e56e`
   with (out record, temp record). Its body is pinned in full
   in `helper.txt`: if the two records are the same object it
   returns at once; otherwise it copies the six bytes (value +
   flags) zeroing the source bytes, moves the `+0x08` pointer
   zeroing the source's, and deletes the destination's old
   `+0x08` pointer with delete[] when non-null. Here the
   destination is the out record (zeroed in step 2, so no old
   pointer delete fires) and the source is the temp, so the
   out record ends holding exactly what the report callee left
   in the temp, and the temp ends zeroed.
6. The temp's `+0x08` pointer is then read at `0x5d4e573`
   and deleted with delete[] when non-null — but the
   move-assign just zeroed it, so this delete never fires
   either. The source's `+0x650` field is NOT touched on this
   path (it is already null); no destroy and no delete run.
   This path jumps straight to the release, skipping the take
   step entirely.

### Common tail

7. Release: the release callee `0x60d52f0` is called at
   `0x5d4e4fd` with the same source `+0x658` field address
   as the acquire. The stack-canary check follows, and the
   routine returns the out record pointer.

The routine's own transfers are exactly 11 direct calls
(acquire, fill, two delete[] sites, destroy, delete, release,
report, move-assign, one more delete[] site, stack-canary
failure), 0 indirect calls, 0 direct tail jumps out, and 1
landing-pad-stub tail jump: the stub at `0x5d4e590..0x5d4e59b`
moves the incoming value to rbp and jumps to the cleanup block
at `0x5d4e3ea`, which belongs to the neighbouring routine's
range. The cleanup block's semantics are not claimed here; it
is not a normal-flow exit.

## References

The routine is reached only through pointers: the executable
segment contains no direct call and no tail jump to `0x5d4e420`
(exhaustive E8/E9 scan, reproduced by census.py). Four
R_X86_64_RELATIVE slots in .data.rel.ro hold the address —
`0x64c9788`, `0x64cb500`, `0x64cb9e0`, `0x64cbfe0` — all four at
the same position in four parallel pointer tables, with
identical neighbour addends (`0x5e46100`, `0x5d4a770` before;
`0x5d548a0`, `0x5d48da0` after), read from the .rela.dyn
entries. The raw qword scan finds only the four addend fields
in .rela.dyn (file offsets `0x1049f8`, `0x109000`, `0x109e70`,
`0x10afe0`), because in this RELA binary the addend lives in
the relocation entry, not in the file bytes at the slot.

## Environment limits (stated openly)

This VM has no cargo/rustc, no git-lfs and no Ghidra/Java, so
no Rust reconstruction is attempted and the binary is used
only through objdump/readelf and digest checks. The full
repository test suite was not run: pytest is not installed on
this VM, and the repo baseline failures are pre-existing
LFS-artifact failures unrelated to this change. The packet's
own model tests run with plain python3 and pass.
