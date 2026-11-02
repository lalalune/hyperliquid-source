# RE-001: map node #94 callback flush-and-teardown 0x5165b80 with its sort-dedup flush, callback-list drain and member lists

Task: RE-001 (#94 function map). Bounded question: how does the node #94
routine at `0x5165b80` destroy the 0xe8-byte record a wrapper holds at
`+0x38` — what does the dirty flag change, in what order are the pending
callbacks flushed, and which member lists and vectors does the teardown
free?

- Component: node #94 callback flush-and-teardown, window `0x5165b80..0x5165f18`
  (920 bytes, FDE 0x1316d74, LSDA 0xbd8a51, 8 bytes of int3 padding to
  `0x5165f20`), plus the insertion sort `0x5164af0` (213 bytes),
  the introsort loop `0x5164da0` (680 bytes), the tree teardown
  `0x5165380` (457 bytes) and the callback-list drain `0x541cab0`
  (81 bytes). The sized-delete PLT target is used by contract only.
- Target release and full SHA-256: node #94, `work/hl-node-94.bin`,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Claim status: observation for the window bounds, the dirty/clean
  branch, the sort comparator and threshold, the dedup rule, the
  callback signatures, the drain rules, the list layouts, the vector
  spans and free order, the delete sizes (0x20, 0x28, 0x30, 0xe8) and
  the census; inference for the string shape (std::string layout
  inferred from the pointer/capacity-plus-one free pattern) and for
  the tree child/successor role names (inferred from traversal order);
  unresolved for the wrapper/record class names, the dirty-flag setter,
  the vector element types, the unreached fields, and the owning table
  behind the 0x575b310 slot. No WAL attribution is claimed: the window
  itself carries no WAL string or WAL-specific field, even though
  neighbouring functions map WAL pieces.
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in it (including
  `endbr64` at the window entry) are genuine instructions present in
  the target binary, not placeholders; the packet checker re-verifies
  sampled instructions byte-for-byte against a fresh objdump run and
  the raw binary.
- Relationship to earlier work: no open WalkCrypto PR covers this
  window (checked this cycle: 55 open, no 0x5165b80 title). The
  neighbouring WAL windows (#1969, #1966, #1964, #1958, #1948) map
  different functions; this window shares no code with them except the
  sized-delete PLT target and the generic std::sort instantiation.
  The per-byte census method is the corrected one from #1966 (a regex
  scan silently skips call opcodes starting inside a previous match).

## Tool versions

- objdump: GNU objdump (GNU Binutils for Ubuntu) 2.42
- Python: 3.12.3
- Invocation: `objdump -d --start-address=<start>
  --stop-address=<end> work/hl-node-94.bin` from the repository root
  with the relative binary path; frames.txt rows are verbatim from
  work/fde94/node-94-fde.tsv.
- Environment limits, stated honestly: `make doctor` reports
  analysis_ready false on this VM (no cargo/rustc, no git-lfs, no
  Ghidra/Java, no pinned REA package); the REA server path in AGENTS.md
  is therefore unavailable and this packet is grounded in objdump
  disassembly plus relocation and FDE records only. pytest is not
  installed, so the pytest-style test file runs under plain python3
  via its `__main__` runner.

## Answer

`flush_and_destroy(wrapper)` returns void. The wrapper holds a pointer
at `+0x38`; when it is null the routine returns without touching
anything else. Otherwise the record it points to is 0xe8 bytes, and
the routine destroys it in the order below. The wrapper itself is
never freed here.

Record layout (only fields the window reads are claimed):

- Vectors, each freed with a sized delete of size end minus begin,
  skipped when begin is null: A at `+0x00/+0x10`, B at `+0x18/+0x28`,
  C at `+0x30/+0x40`. Their element types are unknown.
- Tree list: head pointer at `+0x60`. Each 0x28-byte node carries a
  tree root at `+0x18` and its successor at `+0x10`; per node the
  window calls the tree teardown `0x5165380` on the root and then
  frees the node (0x28). Node fields `+0x00/+0x08` are unknown.
- String list: intrusive list with its sentinel at `+0x80`. Each
  0x30-byte node carries its successor at `+0x00` and a std::string at
  `+0x10` (pointer `+0x10`, size `+0x18`, capacity-or-inline-buffer
  `+0x20`). Per node the heap buffer is freed with size capacity+1
  only when the pointer differs from the address of the `+0x20`
  field (the SSO inline case); the node is then freed (0x30). The
  node `+0x08` field is unknown.
- Callback list: inline head at `+0x98` (fn `+0x98`, arg0 `+0xa0`,
  arg1 `+0xa8`, next `+0xb0`). Tail nodes are 0x20 bytes (fn `+0`,
  arg0 `+8`, arg1 `+0x10`, next `+0x18`). The drain `0x541cab0`
  invokes the head fn(arg0, arg1) and then each tail node in order,
  freeing tail nodes (0x20). A null head fn returns immediately and
  leaves the tail untouched.
- Callback-pair array at `+0xc0/+0xc8/+0xd0`: 16-byte pairs (arg `+0`,
  fn `+8`). Dirty flag byte at `+0xb8`.
- Fields `+0x48/+0x50/+0x58` and `+0x68/+0x70/+0x78` are never read
  here and are not claimed.

Dirty path (flag set): the flag is cleared first. The array range
`[begin, end)` is sorted ascending by (arg, fn) with std::sort: the
introsort loop `0x5164da0` with depth `2*floor(log2(count))`, then
the final insertion sort — `0x5164af0` over the whole range when it
is at most 16 pairs (0x100 bytes), otherwise `0x5164af0` over the
first 16 pairs plus the inline unguarded insert for the rest. The
comparator is pinned from the insertion shift rule (shift while the
previous pair exceeds the current pair, lexicographic arg then fn)
and the identical inline insert rule. Adjacent duplicate pairs are
then removed, keeping the first occurrence, and the deduped end is
stored to `+0xc8` when it changed. Each surviving pair invokes
fn(arg) in sorted order. The callback list is then drained inline
and the head fn and tail head are zeroed, so the later common
teardown drain is a no-op. An empty array skips the sort and the
callbacks but still goes through the list drain.

Clean path (flag clear): the sort, the dedup, the array callbacks
and the inline drain are all skipped. The array callbacks therefore
run if and only if the flag was set; the list callbacks run on both
paths, but on the dirty path they run before the array storage is
freed and on the clean path after it.

Common teardown order, both paths: free the array storage (sized
delete, size capacity_end minus begin) when begin is non-null;
drain the callback list via `0x541cab0` on the `+0x98` subobject;
drain the string list; drain the tree list; free vectors C, B, A
in that order; sized-delete the record (0xe8).

Tree teardown `0x5165380`, pinned from its own disassembly:
teardown(n) returns on a null node; otherwise it tears down the
child at `+0x18` first, deletes n (0x28), then tears down the
successor at `+0x10`. Free order is children before parents and
successors in order. The `+0x18` descent is unrolled six levels in
the binary before the recursive call; the rule above is what the
unrolled code implements.

Census (per-byte scan, see census.py): 0 direct calls, 0 tail
jumps, and exactly one qword reference — the R_X86_64_RELATIVE slot
at VA `0x575b310` (relocation file offset 0x189438) in
.data.rel.ro, whose neighbouring slots `0x575b308` and `0x575b318`
hold `0x5164820` and `0x5164940`. The window is reached indirectly
through that slot; the owning table's class is not pinned.
