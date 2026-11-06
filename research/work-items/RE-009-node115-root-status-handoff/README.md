# RE-009 · Node #115 root reducer status handoff

The target is node #115 SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`, upstream base `05bc2de303c05525b71e7e257426e741bc66a390`. Coordinates are linked virtual addresses.

At `0x5b37597` the existing root-reduction path passes a pointer to its stack record at RSP+0x50 into `0x59ee6d0`. After normal return it selects DL if AL equals 4, and otherwise selects AL. Both candidates are zero-extended before selection. This bounds what an independent replay implementation needs to preserve at this boundary: a two-byte return projection and an explicit status-4 condition. The internal meaning of the values remains unassigned.

The target function covers `[0x59ee6d0,0x59ee774)`. It loads FS:-0x488. A nonzero result goes to `0x59df570` by tail jump with the original first argument and the TLS value. With a zero result it calls the indirect slot at `0x64e4e70`, obtains an object pointer from the returned pointer, and reads the TLS slot again. If now present and its qword at +0x110 matches that object pointer, it rejoins the same tail path. A mismatch passes the computed object+0x80, the TLS value and the original first argument to `0x59e7640`. If TLS is still zero it passes a length of 0xa8 to the indirect slot at `0x64df508`, stores object+0x80 at stack+0xa8, and calls `0x4f08fb0` with a fixed table address and the stack record.

The complete function body is 164 bytes, 44 disassembly rows. Local checks authenticated the artifact, independently decoded the FDE and direct caller displacement, reconciled every disassembly byte, and confirmed a one-bit displacement mutation changes the target. Existing PRs #3272, #3286 and #3304 record calls inside downstream FDEs. Those bodies are contextual boundaries only. This packet is pending fresh deduplication and repository checks. No digest calculation or target execution is claimed.

Replay from the repository root with `python3 research/work-items/RE-009-node115-root-status-handoff/verify.py`. It also checks the two tail-jump destinations and pins the caller's status comparison, zero extensions and conditional selection.
