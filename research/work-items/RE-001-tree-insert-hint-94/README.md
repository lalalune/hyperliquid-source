# RE-001: bind node #94 tree insert-hint unique position 0x514c8f0 with its two insert consumers

Task ID: RE-001. Bounded question: given a tree container, a hint node and
a signed int32 key, what (first, second) pair does the 378-byte function
at 0x514c8f0 return, when does it fall back to the full search instead of
trusting the hint, and how do its two callers consume that pair? Answer:
it is the insert-hint unique-position routine. On an exact hit it returns
(node, 0); on a miss it returns an insertion position that the callers
feed straight into _Rb_tree_insert_and_rebalance, either (0, parent) or
(node, node) depending on which child link is empty; when the hint is not
adjacent to the key it falls back to the twin full search at 0x514b220.

## Target binding

- Binary: node #94, SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
  (provenance/artifacts.json), 91,774,280 bytes.
- Function: 0x514c8f0..0x514ca6a, 378 bytes, FDE at .eh_frame+0x0029a91c
  (length 0x80), 6 int3 padding bytes to the next FDE at 0x514ca70.
- This function has no endbr64: the entry starts with register pushes,
  and the nopl/nop bytes inside it are alignment padding, all verbatim
  from the target binary, not placeholders. Instruction-level detail
  lives only in the raw excerpt files below; records.json carries
  semantic records, not a per-instruction list.
- No stack canary is used: the function only reserves 8 bytes of stack
  and never calls __stack_chk_fail.
- Container header, matching the earlier RE-001 binds: root at +0x10,
  leftmost at +0x18, rightmost at +0x20, count at +0x28; the header node
  itself is at container + 0x8 and is the end sentinel. Node: parent
  at +0x8, left child at +0x10, right child at +0x18, signed int32 key
  at +0x20. The value bytes (node + 0x28) are never read here; this
  routine only positions, it does not return a value address.

## Observations (read from the bytes)

- Arguments: rdi = container, rsi = hint node (or the header node for
  end), edx = sought key, copied to r12d and compared as a signed
  int32 throughout (jle/jge/cmovl/setl/cmovg).
- Hint == header (end) arm, at 0x514c998: if the count at +0x28 is
  non-zero, the rightmost node is loaded; if the sought key is greater
  than the rightmost key the function returns (0, rightmost) at
  0x514ca09, otherwise it runs the full walk below. If the count is
  zero the walk runs and returns (0, header).
- Full walk, at 0x514c99f: from the root, go left when the sought key
  is less than the node key, else right, until the next child is null.
  The last visited node decides: if the walk ended going right, the
  result is (last, 0) when the sought key is less than or equal to the
  last key and (0, last) when it is greater; if it ended going left,
  the result is (0, last) when last is the leftmost, otherwise the
  predecessor is stepped to (decrement call at 0x514ca47) and the same
  less-or-equal/greater rule is applied to (predecessor, last). On a
  valid tree the less-or-equal arms coincide with equality (the walk
  only ends going right at a node whose key is at most the sought key,
  and only steps to a predecessor whose key is at most the sought key);
  the model transliterates the bytes exactly, including those arms.
- Hint arm, sought key less than the hint key (0x514c915): if the hint
  is the leftmost, return (hint, hint). Otherwise step to the
  predecessor (decrement call at 0x514c924); if the predecessor key is
  greater than or equal to the sought key, fall back to the twin
  (tail jump at 0x514ca30, rdi = container, esi = sought key).
  Otherwise the hint is adjacent: if the predecessor's right child is
  non-null return (hint, hint), else return (0, predecessor).
- Hint arm, sought key equal to the hint key (0x514c9f0): return
  (hint, 0), the exact hit.
- Hint arm, sought key greater than the hint key (0x514c958): if the
  hint is the rightmost, return (0, hint). Otherwise step to the
  successor (increment call at 0x514c96b); if the successor key is
  less than or equal to the sought key, fall back to the twin. Otherwise
  the hint is adjacent: if the hint's right child is non-null return
  (successor, successor), else return (0, hint).
- The fallback target 0x514b220 is the twin bracket search bound by the
  RE-001 bracket-search-twin item (FDE 0x0029a4a4, 138 bytes, SHA
  0f156d1e…); it is cited here as the fallback only, and its
  internals are not re-pinned. Its pair convention matches: (node, 0)
  on a hit, (0, neighbour) on a miss, (0, header) on an empty tree.
- Callees: _Rb_tree_decrement@plt (0x56604b0, GOT 0x5778f80,
  R_X86_64_JUMP_SLOT) and _Rb_tree_increment@plt (0x5660560, GOT
  0x5778fd8, R_X86_64_JUMP_SLOT); only their in-order
  predecessor/successor meaning is used, not their internals.
- Callers, exactly 2 direct e8 sites in a full .text scan, no tail
  jumps: 0x514cac7 in 0x514ca70..0x514cb31 (FDE 0x0029a9a0) and
  0x514cb97 in 0x514cb40..0x514cc01 (FDE 0x0029a9f0). The two 193-byte
  bodies agree byte-for-byte except the four e8 rel32 displacements
  (operator new, this function, insert_and_rebalance, sized delete).
  Each caller allocates a fresh 0x58-byte node, stores the int32 key
  loaded from [[arg3]] at fresh node +0x20, initializes fresh node
  +0x30..+0x50 with the literal stores (int32 0 at +0x30, qword 0 at
  +0x38, fresh node + 0x30 at both +0x40 and +0x48, qword 0 at +0x50),
  then calls this function with (container, hint, key). If the
  returned second is 0 it sized-deletes the fresh node (0x58 bytes)
  and returns the existing node (returned first). Otherwise it calls
  _Rb_tree_insert_and_rebalance with edi = 1 when the returned first
  is non-null, else 1 when the returned second equals the header
  (rcx = container + 0x8), else (sought key < [returned second +
  0x20]); rsi = fresh node, rdx = returned second, rcx = header;
  then it increments the count at container +0x28 and returns the
  fresh node. That edi rule is exactly the insert-left rule the
  returned pair is designed for.

## Inferences

- The (first, second) pair is an insertion position for
  _Rb_tree_insert_and_rebalance: first non-null means "insert as a
  child link of first" in the (node, node) arms, and first null means
  "insert under second, on the side the key comparison decides" in
  the (0, parent) arms. This is inference from the two consumers'
  identical use of the pair, not from a symbol name.
- The name "insert-hint unique position" is inference from the
  hint/end/adjacency/fallback shape and the consumers' hit-versus-
  insert split (a duplicate key frees the fresh node instead of
  inserting). The function itself carries no usable symbol in the
  stripped binary; the objdump label shown is a neighbouring
  dynamic-symbol artefact, not this function's name.

## Unknowns

- The source-level type name of the tree and its owning component.
- The member type stored at fresh node +0x30 in the callers; only the
  literal stores are recorded.
- The decrement/increment and insert_and_rebalance callee internals.

## Packet contents

- records.json: semantic records only (behavior arms, caller records,
  calls, layouts, PLT slots, function ranges and hashes).
- window.objdump.txt: 0x514c8f0..0x514ca70, whole function plus its
  6 int3 padding bytes, verbatim.
- caller1.objdump.txt: 0x514ca70..0x514cb40, whole first consumer plus
  its 15 int3 padding bytes, verbatim.
- caller2.objdump.txt: 0x514cb40..0x514cc10, whole second consumer
  plus its 15 int3 padding bytes, verbatim.
- plt.objdump.txt: both PLT stubs, verbatim.
- frames.txt: the four FDE lines (function, both consumers, twin
  fallback target), matching readelf --debug-dump=frames-interp.
- relocations.txt: the two JUMP_SLOT relocations for the PLT GOT slots.
- verify.py + export_excerpts.py: the runnable packet checker and the
  excerpt generator, committed in the packet.
- MANIFEST.sha256: SHA-256 of every packet file except itself.

Excerpt commands (run from the repository root):

    objdump -d --start-address=0x514c8f0 --stop-address=0x514ca70 work/hl-node-94.bin
    objdump -d --start-address=0x514ca70 --stop-address=0x514cb40 work/hl-node-94.bin
    objdump -d --start-address=0x514cb40 --stop-address=0x514cc10 work/hl-node-94.bin
    objdump -d --start-address=0x56604b0 --stop-address=0x56604c0 work/hl-node-94.bin
    objdump -d --start-address=0x5660560 --stop-address=0x5660570 work/hl-node-94.bin
