# RE-001: map node #94 sharded member access (0x516a390)

Task: RE-001 (#94 function map). Bounded question: how does node #94
pick, lock and lazily initialise one member out of a sharded bucket
array, and what wrapper does it return for that member — what index
rule, what bucket protocol, what double-checked install, and what do
the two wrapper constructors record?

- Component: node #94 sharded member access. One window, extracted
  from the digest-verified work binary (SHA-256
  `3b7179cd…c0459f`): `0x516a390..0x516aa1c` (1676 bytes, FDE
  0x1317078, LSDA 0xbd8b85). It is a neighbour of the memtable
  iterator family mapped in the #1984/#1985/#1989/#1991/#1994/#2001
  packets and of the callback-flush teardown family (#1982, 0x5165b80
  and the 0x516aa50 wrapper variant): it reuses that teardown only
  for the defensive old-member destroy, and it reuses the 0x80-object
  construction prologue first read in 0x5169da0. The new ground here
  is the shard index, the bucket load/lock protocol, the lazy member
  install and the two 0xc8 wrapper constructors.
- Claim status: observation for the window bounds, the argument
  roles, the CPUID index rule, the minstd_rand fallback, the bucket
  array layout and mask, the atomic shared_ptr load with refcount
  bump, the mutex lock and double-checked install, the installed
  flag, the wrapper layouts of both constructors, the thunk guard
  and the two call sites; inference for the names "shard", "member"
  and "wrapper" (the code holds a bucket array of shared_ptr
  objects each carrying one lazily installed member pointer and one
  installed flag, and returns a 0xc8 object built from that member);
  unresolved for the identity of the host object, the meaning of
  the host +0xce0 member, the internals of the 0xe8 member
  constructor 0x5196de0 (2593 bytes, used by contract), the identity
  of the 0x80 object built alongside it, and the purpose of the
  options object's +0x58 field beyond its nulling rule.
- Note on evidence text: the raw disassembly excerpts are verbatim
  objdump output. Instruction mnemonics appearing in them (including
  `endbr64` at each window entry) are genuine instructions present
  in the target binary, not placeholders; the packet checker
  re-verifies sampled instructions byte-for-byte against a fresh
  objdump run and the raw binary.
- Relationship to earlier work: no open WalkCrypto PR covers this
  window (checked this cycle: open-PR snapshot, no 0x516a390 or
  shard title; repository search for 516a390 returns nothing). The
  #1982 packet mapped the callback-flush teardown that appears here
  only as the defensive old-member destroy; that teardown is not
  re-claimed here beyond the call order. The 0x5169da0 replace
  function (not itself submitted) shares the 0x80-object
  construction prologue and the +0xa60 guard; this window's
  contribution is the sharded access around a fresh member, not the
  replace itself.

## Tool versions

- objdump: GNU objdump (GNU Binutils for Ubuntu) 2.42
- Python: 3.12.3
- Invocation: `objdump -d --start-address=<start>
  --stop-address=<end> work/hl-node-94.bin` from the repository root
  with the relative binary path; frames.txt rows are verbatim from
  work/fde94/node-94-fde.tsv.
- Environment limits, stated honestly: `make doctor` reports
  analysis_ready false on this VM (no cargo/rustc, no git-lfs, no
  Ghidra/Java, no pinned REA package); the REA server path in
  AGENTS.md is therefore unavailable and this packet is grounded in
  objdump disassembly plus relocation and FDE records only. pytest
  is not installed, so the pytest-style test file runs under plain
  python3 via its `__main__` runner.

## Answer

`access(host, opts, arg3, use_global) -> wrapper*` (0xc8 bytes).

### Global path (use_global byte nonzero)

Allocate 0xc8 and build it with 0x5190d50 from the host's +0xce0
member (see "wrapper, global variant" below). No bucket is touched.

### Shard index

With use_global clear, the index seed comes from 0x53356a0: CPUID
leaf 0 first; if it reports no leaves, the stub returns -1
(0xffffffff). Otherwise CPUID leaf 1 and the stub returns EBX
shifted right 24 — the leaf-1 EBX top byte (the initial APIC ID
byte, by the Intel leaf-1 layout). A negative seed takes the
fallback: 0x5423a50 returns the calling thread's RNG state pointer
(a TLS slot; seeded on first use from Hash_bytes(pthread_self, 8,
seed 0xc70f6907) masked to 31 bits, or 1 when that mask is 0), and
the caller advances it by minstd_rand — state = state * 16807 mod
(2^31 - 1), computed with the 32-bit reduction (x & 0x7fffffff) +
(x >> 31), subtracting 0x7fffffff when the sum's sign bit is set —
and stores the new state back. Bucket count is 1 << (host +0xd18
shift); index = seed & ((1 << shift) - 1). Bucket entries are
16-byte shared_ptr slots at host +0xd10 + index * 16.

### Bucket load and double-checked install

The bucket's shared_ptr is loaded under a _Sp_locker guard and its
control block count is bumped (+0x8, plain when the
__libc_single_threaded flag at GOT 0x5777ed8 is nonzero, locked
otherwise); the loaded shard pointer is then read unconditionally,
so buckets are pre-populated with shard objects and only the member
is lazy. If the shard's +0x30 installed byte is set, the wrapper
is built at once. Otherwise the shard mutex (the shard object
itself, via pthread_mutex_lock; a lock failure throws a system
error) is taken and the shard's +0x28 member slot is re-checked:
nonzero means another thread installed it meanwhile, so the mutex
is released and the wrapper is built. Zero runs the lazy build:

1. Allocate 0x80, zero its +0x0 and +0x18 fields via 0x541ca90,
   and fill it from the host: +0x0 = vtable address point
   0x575b230, +0x28 = 0, +0x30 = host +0xc58, +0x38 = pointer
   0x575b1f8, +0x40 = pointer 0x5757be0, +0x48 = host +0x10,
   +0x58 = 0, +0x5a = host +0x31 byte XOR 1, +0x60 = host +0x6c,
   +0x68/+0x6c = 0, +0x70 = 0, +0x78 = host +0x60, +0x50 = the
   +0x90 virtual result of the host +0xa58 object.
2. Allocate 0xe8 and build it with 0x5196de0 (by contract) from
   the host +0x8 object, the stack struct holding the 0x80 object
   and the loaded shard shared_ptr, and a zero flag.
3. Read the old shard +0x28 value, store the new 0xe8 pointer
   there, and if the old value was nonzero destroy it with the
   callback-flush teardown (sort/dedup/callbacks when its +0xb8
   flag is set, then the member-vector frees) and a sized 0xe8
   delete. In the mutex path the old value is zero by the
   re-check, so this destroy is defensive only.
4. Release the 0x80 object through its vtable +0x8 virtual, free
   the constructor stack struct's vector buffer when present, set
   the shard +0x30 installed byte to 1, and release the mutex.

The wrapper is then built (shard variant) and the caller's bucket
shared_ptr copy is released (control block release 0x4f94a90).

### Wrapper, global variant (0x5190d50)

`wrap_global(new, member, host8, arg3, opts58, 0)`:

- +0x0 = wrapper vtable address point 0x575b6d8; +0x8 subobject
  zeroed by 0x541ca90 (+0x0 and +0x18 relative to +0x8).
- +0x28/+0x30 = host8 +0x8 duplicated; +0x38/+0x40 = host8
  pointer and host8 +0x8; +0x48/+0x50/+0x58/+0x60 = 0 (no
  shared_ptr held).
- +0x68 = member; +0x70 = arg3; +0x78 = 0; +0x80 = opts58.
- +0x88/+0x90 = member +0x8 and member +0x20; +0x98/+0xa0 = the
  same pair again.
- +0xa8 = address of its own +0xb8 field (an empty SSO string:
  +0xb0 size 0, +0xb8 first byte 0).

### Wrapper, shard variant (0x5190f70)

`wrap_shard(new, shard_shared_ptr, host8, arg3, opts58, 0)`:
same header, +0x28/+0x38 and zero fields as the global variant,
plus:

- +0x58/+0x60 = the shard shared_ptr copy (ptr and control block);
  the control block count is bumped (+0x8, plain or locked by the
  same single-threaded flag).
- +0x68 = shard +0x28 (the installed member).
- +0x80 = {opts58-or-null, member +0x8}, where opts58 is nulled
  when it is nonzero but its +0x8 field is zero; +0x90 =
  {member +0x20, member +0x8}; +0xa0 = member +0x20.
- +0x88/+0x98 start zeroed and stay zero in this variant; +0xa8
  is the same self-pointing empty SSO string.

### Thunk and callers

The 35-byte thunk 0x516aa20 forwards to this window only when the
options byte at +0x35 is zero AND the host +0xa60 byte is zero
(the same +0xa60 guard as the 0x5169da0 replace); otherwise it
returns null, passing the flag byte zero-extended. Caller census
(per-byte e8/e9 scan of .text, whole-file qword search, .rela.dyn
parse — see census.py): one direct call (0x516da31, inside
0x516d110) and the thunk's tail jump (0x516aa38), no qword
references, no RELATIVE slot.
