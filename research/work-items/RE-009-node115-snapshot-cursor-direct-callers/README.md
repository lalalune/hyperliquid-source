# RE-009: direct callers of two snapshot cleanup cursors

The geometry in #7186 distinguishes two cursor layouts but leaves their callers open. In the pinned #115 ELF, 78 aligned direct transfers reach 0x2442070 and 32 reach 0x2442420. The 110 instructions are in 72 unwind extents. The two known calls from the inline tree cleanup body are included. The retained table identifies the owning extent and destination for each instruction, allowing a caller to be bound to the appropriate layout.

The verifier scans the entire pinned .text extent for rel32 call or jump candidates. It assigns each candidate to its containing FDE and disassembles each owner from its entry. It requires exact agreement between the raw-byte scan and the disassembled instruction starts. For each of the 110 instructions, it checks that an opcode corruption removes the transfer and that a displacement corruption changes the destination. Indirect calls and paths outside .text remain outside scope. No captured code executes.

Run the verifier from the repository root with llvm-dwarfdump and llvm-objdump on PATH. The offline log gives the target digest and exact commands.
