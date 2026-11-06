# RE-001: node #115 shard refresh routine 0x605e170

The shard re-selection helper behind the node's arena-style
allocator: when an allocation window finds its selected shard
locked, this routine picks a (possibly) new shard, records the
selection in the thread's selector slot, and returns the shard
entry — all without looking at the entry it returns.

## Bounded question

What exactly does the refresh routine 0x605e170 compute when an
allocation window calls it: where does its selector come from on
each path, how is the shard index formed, what does it write to
the thread-local selector slot, and what does it do when no CPU
selector is available?

- Component: node #115 shard refresh, one whole function end to
  end, extracted from the digest-verified work binary (SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
  provenance/artifacts.json path `artifacts/node/115/hl-node`):
  window `0x605e170..0x605e20d` (157 bytes; FDE .eh_frame offset
  0x3677d0, length 0x2c, CIE at section offset 0x0, augmentation
  `zR`, FDE augmentation data empty — no LSDA, no landing pads).
- Claim status: observation for the window bounds, the two
  callees and their call sites, the selector/index arithmetic,
  the TLS store, the fallback step and both fixed points;
  inference for the names "shard refresh", "selector" and
  "selector slot" and for the ConcurrentArena association
  (which rests on the consumer packets' TLS symbol
  `_ZTHN7rocksdb15ConcurrentArena9tls_cpuidE` and the shared
  object layout, not on anything inside this window);
  unresolved for the items under Unknowns.
- Note on evidence text: the raw disassembly excerpt is verbatim
  objdump output. Instruction mnemonics appearing in it
  (including `endbr64` at the window entry) are genuine
  instructions present in the target binary, not placeholders;
  the packet checker re-verifies every excerpt instruction
  byte-for-byte against the raw binary.

## Reproduce

```sh
python3 research/work-items/RE-001-shard-refresh-605e170-115/verify.py
# (equivalent: objdump -d --start-address=0x605e170
#  --stop-address=0x605e20d work/hl-node-115.bin)
```

The model is `tools/shard_refresh_605e170_115.py`; its tests are
`tests/test_shard_refresh_605e170_115.py`. Beyond the packet
checker, the model was differentially tested against the window
bytes under Unicorn emulation (callees hooked at their call
sites): 1,014 cases across selector values (including -1, other
negatives, 0, APIC-range and 0x7fffffff), shift dwords
(including 0, 31, 32, 33, 63, 64, 65 and values with noise in
the upper bytes) and seed words (including 0, 2^31-1, 2^31 and
2^32-1), plus 600 random triples — zero divergence in the
returned entry, the TLS slot value and the stored-back seed
word, with the descriptor fields and neighbouring state checked
untouched.

## Evidence

- `main.txt` — objdump excerpt of the whole window.
- `frames.txt` — readelf frames-interp FDE lines for the window
  and its two callees.
- `callers.tsv` / `census.py` — the transfer census: exactly 2
  direct calls (0x5f11931, 0x5f11cf7), 0 tail jumps, no qword
  hit, no RELATIVE slot. Every site was confirmed against an
  objdump disassembly of its enclosing FDE.
- `relocations.txt` — why no relocation or PLT entry is
  involved in-window.

## Object layout (pinned by the disassembly)

- rdi = the allocator object ("this"); the routine reads only:
  - the shard array pointer at `this + 0x48` (entries are 64
    bytes — the `shl $0x6` in the entry formula);
  - the shift dword at `this + 0x50`, read as a dword on both
    paths. Only its low 6 bits are observable: bits 0..4 feed
    the index-mask count, bits 0..5 feed the TLS bit index.
    (The consumer packets describe the field as a byte; this
    window cannot distinguish the two, see Unknowns.)
- Writes, total: the qword at `fs:0 - 0x408` (the thread's
  selector slot — the same slot the consumer packets document
  as the allocator's cpuid slot) on every call, and the
  fallback seed word on the fallback path only. The descriptor
  fields +0x48/+0x50 are never written.
- Saved/restored: r12, rbp, rbx. Single exit: `ret` at
  0x605e1c6. The fallback block (0x605e1d0..0x605e20c) sits
  after that `ret`, inside the FDE, reached only by the entry
  branch.

## Algorithm (verified against the excerpt)

1. Call the CPUID selector 0x60d5cd0 (by contract: CPUID
   leaf-1 EBX bits 31:24, the initial APIC id, as a
   non-negative int; -1 when CPUID leaf 0 reports a maximum
   leaf of 0). A non-negative result is the selector, used
   verbatim as a u32.
2. A negative result falls back: call the seed getter
   0x61c4080 (by contract: a pointer to a per-thread 32-bit
   seed word), advance the word by one Park-Miller step and
   store it back; the NEW word is the selector. The step is
   coded literally as t = seed * 16807 in 64 bits,
   s = (t & 0x7fffffff) + (t >> 31), and s -= 0x7fffffff when
   the 32-bit sum's sign bit is set. That is the minimal
   standard step mod 2^31-1 with two coded fixed points the
   exact arithmetic does not have at 0: seed 0 stays 0, and
   seed 2^31-1 stays 2^31-1 (its sum is exactly 0x7fffffff,
   which has no sign bit, so the conditional subtract never
   fires).
3. index = selector & ((1 << (shift & 31)) - 1). The mask is a
   32-bit `shl`/`sub` pair, so the count is the field's low 5
   bits: shift 32 wraps the mask to 0 (index forced to 0) and
   shift 33 gives mask 1.
4. The TLS selector slot receives index | (1 << (shift & 63))
   — the `bts` count uses the field's low 6 bits. That bit is
   never inside the index (the mask leaves it clear), so the
   stored value is index + 2^(shift & 63).
5. Return array + index * 64. The routine does not inspect
   the returned entry — it never reads the entry's lock byte
   (offset +0x28 within the entry, per the consumer packets'
   layout); spinning on the new entry's lock is the caller's
   next step, not this routine's.

Detail checked on both paths: the shared tail is entered with
the index in rbx — sign-extended by an explicit `movslq` on the
fast path, zero-extended by the last 32-bit `ebx` write on the
fallback path (which jumps over the `movslq`). The index is
below 2^31 on both paths, so the two agree.

## Consumers (the 2 transfer sites)

- 0x5f11cf7, in the outer Allocate window
  0x5f11c40..0x5f12162 (packet RE-001-allocate-115).
- 0x5f11931, in the shard AllocateAligned window
  0x5f117a0..0x5f11c38 (packet RE-001-shard-allocate-115).

Both pass their own rdi unchanged. Per the consumer packets,
the call runs when the selected shard's lock byte is set and
again when a LOCK CMPXCHG on an entry lock loses its race; the
returned entry replaces the caller's selection and the caller
spins on the new entry's lock. No other code transfers here:
no tail jumps, no vtable or stored pointer, no relocation.

## Relations to other work

The two consumer packets cite this routine by address and FDE
only and list its internals among their unknowns ("internals
of callees 0x605e170, 0x5f07200 and 0x5f0b5e0"); this packet
pins the first of those three. The sibling unknowns 0x5f07200
(47-byte post-direct window) and 0x5f0b5e0 (37-byte
guard-release window) remain unpinned. The address sweep for
this cycle — the merged work-item corpus (README / records /
owners pins, all notations) plus the open-PR set — shows
0x605e170 nowhere as a subject: no open PR covers this window
and no merged packet's window starts here. The two callees are
cited by contract: the CPUID selector has 5 further direct
callers elsewhere, and the seed getter has 16 further direct
callers; neither is modelled here.

## Unknowns

- Why the stored TLS value marks the index with the
  2^(shift & 63) bit; the consumer packets read the slot as a
  plain cpuid value, so the bit's consumer-side role is not
  established by this window.
- Whether the +0x50 dword's upper three bytes are ever nonzero
  in practice; both counts mask them away.
- Whether the fallback seed word is shared with the seed
  callee's other callers' purposes or dedicated to shard
  selection; this window observes only the read/advance/store
  of its first dword.
- The exact source-level identity of the routine (see Claim
  status on the ConcurrentArena association).

## Environment limits

Verification is static plus emulation: the window bytes were
executed under Unicorn with the two callees hooked, never in a
running node, and no captured node execution is claimed. The
packet checker, the model tests and `make verify` pass (the
last in full: 558 evidence-packet manifests, 7,154 entries).
The repository's full `make test` did not run to completion
inside this lane's window: it progressed through the suite
with no failure in the files it reached, and neighbouring
lanes observed it stall inside a pre-existing packet's
mutation test in this environment; either way the incomplete
suite is unrelated to this packet, whose own verifier and
tests pass on both the working tree and a git-archive
cleanroom.
