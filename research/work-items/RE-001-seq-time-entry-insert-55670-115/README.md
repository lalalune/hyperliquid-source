# RE-001: sequence-number time-entry insert routine 0x5d55670 (node #115)

## Bounded question

What does the routine at `0x5d55670` do with its holder? How is the
producer chosen from the holder's `+0x540` chain, what value is
resolved for the locked call that follows, and when does the routine
log the sequence-number failure?

## Answer (established semantics)

The routine `0x5d55670` takes one argument, a holder `H` in `rdi`,
and returns nothing. Its observable behaviour is, in order: resolve
a producer from a four-node chain, call it, free its heap side
result, resolve a value, and under a lock pair call the insert
routine `0x5f391b0` — logging a failure message when that call's low
return byte is zero. It is a complete behaviour end to end, not a
lone window: chain resolution, producer call, value resolution,
locked insert, and conditional log are all pinned.

### The chain walk and the producer call

`H+0x540` is the head of a chain whose links live at `+0x20` per
node. Each node carries a slot value at `+0xc0`. The walk compares
each node's slot to a running expected value, starting from the
qword at `0x64ed3e8` — whose `R_X86_64_RELATIVE` relocation addend
is `0x5d4b100`, the same expected slot value the node-link routine
of #2661 compares its first node against — and then taking the
previous node's slot after each match:

1. Node 0's slot against the global (`0x5d4b100` after relocation).
   On mismatch, call node 0's slot (site `0x5d557e0`).
2. Node 1's slot against node 0's slot. On mismatch, call node 1's
   slot (site `0x5d55798`).
3. Node 2's slot against node 1's slot. On mismatch, call node 2's
   slot (site `0x5d557e0`).
4. If nodes 0..2 all match in sequence, call node 3's slot
   unconditionally (site `0x5d5570e`).

The chosen slot is called as a virtual function with three
arguments: `rdi` = an out pair on the stack at `+0x10`, `rsi` =
the chosen node, `rdx` = the address of a shared length slot on the
stack at `+0x08` (initialized to `0` before the walk). The producer
itself is call-shape only here: what it writes at the out pair's
`+0x00` slot, and whether it writes the shared length slot, are
not claimed. What is pinned is what this routine does next: it
frees the heap pointer at the out pair's `+0x08` slot (stack
`+0x18`) with `delete[]` when that pointer is non-null, and it
never reads the out pair's `+0x00` slot again.

### The resolver phase

After the producer call and the free, the routine resolves `r13`:

- Read `[[H]+0x320]` and compare it to `0x5d48710`.
- On mismatch, call that slot value with `rdi = H`; `r13` is the
  call's return (site `0x5d557f8`).
- On match, `r13 = [[H+0x68]+0x108]` (site `0x5d5573d`).

### The locked insert and the conditional log

- Acquire: call `0x606ca40(H+0x700)` (site `0x5d55752`) — the same
  lock pair the node-link routine (#2661) and the lazy-cache
  routine (#2685) pin in call-shape only.
- Insert: call `0x5f391b0(H+0x18c8, r13, L)` (site `0x5d55766`),
  where `L` is the shared length slot's value after the producer
  returns. Only the argument list, position, and return-byte rule
  are pinned; what the insert computes internally is not claimed.
- Release: call `0x60d52f0(H+0x700)` (site `0x5d55770`).
- If the insert's low return byte is non-zero, the routine checks
  its stack canary and returns silently.
- If the low return byte is zero, it first calls the log routine
  `0x5fcf060` (site `0x5d557d4`) with `edi = 2`, `rsi = H+0x360`
  (passed by address), `rdx` = the format string at `0x958d58`,
  `rcx` = the file string at `0x4451b9`, `r8 = r13`,
  `r9 = L`, and then returns. The two string literals are verbatim
  from the binary's read-only data:

  - file: `db/db_impl/db_impl.cc`
  - format: `[%s:5963] Failed to insert sequence number to time entry: %lu -> %lu`

  The six log arguments line up with the format's three
  conversions in order (the string at `H+0x360`, `r13`, `L`). The
  log callee itself is call-shape only, so that mapping is the
  observed argument order, not a verified format consumption. The
  failure reading — the insert is the "insert sequence number to
  time entry" attempt, and a zero low byte means it failed — comes
  from this log text plus the zero branch, and is stated as such.

### The entry wrapper and the landing pad

The entry wrapper `0x5d55820` (15 bytes) dereferences its argument
twice (`rdi = [rdi]`, then `rdi = [rdi]`) and tail-jumps to
`0x5d55670` at `0x5d5582a`. It is the routine's only code
reference, and it is the adapter a caller uses when it holds a
pointer to a pointer to the holder.

The landing pad `0x5d55644` (its own FDE) is reached from the tail
fragment at `0x5d5580a` inside the main FDE range: on an exception
during the locked region it calls `0x60d52f0(H+0x700)` (the
release), checks the canary, and resumes unwinding with the
exception object in `rbx`. The main routine's frame is `0x38`
bytes with a canary at stack `+0x28`, checked before every return
and in the landing pad.

## Consumers

The main routine has exactly 1 tail jump (the wrapper's jump at
`0x5d5582a`) and 0 direct calls, 0 stored references, and 0
`R_X86_64_RELATIVE` relocations, by the exhaustive
executable-LOAD-segment scan reproduced by `census.py` and re-run
inside `verify.py`. The wrapper itself has 0 direct calls, 0 tail
jumps, and 0 stored references by the same scan — how the wrapper
is reached is recorded as an unknown below, not filled in with a
vtable guess, because no stored reference to it was found.

## Unknowns (recorded, not filled in)

- What the holder, the chain nodes, the producer, the resolved
  value, or the insert target denote beyond the field offsets
  above; no class or source names are claimed. The
  `db/db_impl/db_impl.cc` literal is quoted as binary data, not
  as a claim about which source tree built this binary.
- What the producer writes at the out pair's `+0x00` slot, or
  whether it writes the shared length slot.
- What the lock pair `0x606ca40` / `0x60d52f0` computes beyond
  the acquire/release pairing, and what the insert routine
  `0x5f391b0` or the log routine `0x5fcf060` compute internally.
- How the entry wrapper `0x5d55820` is itself reached: no direct
  caller and no stored reference was found.
- Behaviour on null chain links or dangling pointers (the model
  raises on a chain that ends before node 3, stated openly).

## Relation to neighbouring packets

- #2661 (node-link `0x5d54630`) pins the same chain idiom — head
  at holder `+0x540`, `+0x20` links, `+0xc0` slots, first node
  against the relocated global `0x5d4b100` at `0x64ed3e8` — and
  the same lock pair. This packet's routine is a different
  behaviour on that idiom (producer + locked insert + failure
  log), not a re-pin of #2661's list append.
- #2685 (lazy-cache adapter `0x5d548a0`) pins the same lock pair
  and sits in the same holder neighbourhood; it does not cover
  `0x5d55670`.

## Evidence

- `main.txt`, `wrapper.txt`, `landing.txt`: whole-function
  verbatim objdump excerpts (header normalized to the bare binary
  name; the only modification). Short tokens such as `endbr64` in
  these excerpts are genuine instructions present in the target
  binary, not placeholders.
- `frames.txt`: the three FDE lines for the routines above.
- `records.json`: semantic records only — field layouts, branch
  outcomes, call sites, and the consumer census. No per-step list.
- `callers.tsv`, `relocations.txt`: the census in tabular form.
- `verify.py`, `export_excerpts.py`, `census.py`: the checker and
  the generators, committed in the packet.
- Model: `tools/seq_time_entry_insert_55670_115.py`; tests:
  `tests/test_seq_time_entry_insert_55670_115.py`.
- Artifact: `artifacts/node/115/hl-node`, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
  per `provenance/artifacts.json`; the local copy is
  `work/hl-node-115.bin`.
- Environment limits: no cargo/rustc, no git-lfs, no Ghidra/Java on
  this VM; the packet was verified against the materialized node
  #115 binary only, by static inspection plus the Python model.
