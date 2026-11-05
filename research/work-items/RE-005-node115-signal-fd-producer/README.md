# RE-005 node 115 signal fd producer

- Component ID: RE-005 (node 115 signal registration)
- Target: node/115, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301
- Base commit: 05bc2de303c05525b71e7e257426e741bc66a390
- Claim status: observation (static, FDE-bounded,
  relocation-resolved); source-level identities of
  the two table consumers are inference and are
  labelled as such below.
- Question (open edge 4 of the tag-3 supply packet,
  PR #2950): the signal-attach body 0x5ce71f0 reads
  a lazily initialised global signal state (flag
  word 0x64fee38, fd word 0x64fee24) and dups the fd
  onto the poll's epoll. Which body creates and
  posts the fd at 0x64fee24, and from what?

## Answer

The fd is one end of a Unix **socketpair**, created
exactly once by the get_or_init closure of the
global signal state itself -- vendored tokio's
signal global state (its unwrap panic Location is
`/home/ubuntu/hl/code_Mainnet/z_vendor/tokio/src/
signal/unix.rs`, line 71, col 53). It is not an
eventfd, not a signalfd, and not the read end of a
pipe: the producing call is libc `socketpair`.

## The global

A 32-byte static at 0x64fee20: a 24-byte value
followed by a std Once state word at +0x18. The
file image is all zero except the state word,
born 3 (incomplete). Value layout after
initialisation:

| Offset | Contents |
| --- | --- |
| +0x00 | socketpair end sv[1] |
| +0x04 | socketpair end sv[0] -- the fd word |
| +0x08 | entries table pointer |
| +0x10 | entries count (SIGRTMAX at init) |
| +0x18 | Once state word |

## The producer chain

1. A consumer that sees the state word at
   0x64fee38 nonzero calls the lazy accessor
   0x5cdf582 with rdi = 0x64fee20. The accessor
   calls std `Once::call_once_force` 0x5c87d50
   through GOT slot 0x64df9f0 (RELATIVE relocation)
   with the Once vtable at 0x64c5760; the
   call_once_force panic Location at 0x64c5788 is
   std/src/sync/once.rs line 219 col 20
   (rustc 59807616e1fa2540724bfbac14d7976d7e4a3860).
2. call_once_force invokes the closure through
   vtable +0x20 (`call *0x20(%rax)` at 0x5c87e44) =
   shim 0x5cdf4f0 (the vtable's +0x18 slot is a
   second shim, 0x5cdf6c0). The shim calls the
   init closure 0x5cfcec0 and bulk-stores the
   returned 24-byte value into the static
   (`movups %xmm0,(%rbx)` plus the third qword) --
   the only write the value fields ever receive.
3. The init closure calls the socketpair wrapper
   0x475b160 (its only call site in the artifact).
   The wrapper ORs the caller's type word with
   0x80800 (SOCK_NONBLOCK | SOCK_CLOEXEC) and calls
   libc `socketpair` (GOT 0x64eb078, dynsym
   resolved) with domain AF_UNIX (1) and protocol
   0, returning {disc, sv[0] at +4, sv[1] at +8}.
4. The closure then calls
   `__libc_current_sigrtmax` (GOT 0x64ecba0) and
   the table builder 0x5ce1320, which builds (via
   the allocator body 0x5cfe910) a table of that
   many 32-byte entries, and assembles the value:
   a pshufd swap puts sv[1] at +0x00 and sv[0] at
   +0x04, the entries pointer at +0x08 and the
   count at +0x10.

## Consumers (whole-.text census in records.json)

RIP-relative disp32 census in both disp-final and
disp+immediate encodings; zero imm64 occurrences
of 0x64fee20/0x64fee24/0x64fee38 in the file; no
.text body stores to any field directly.

- The fd word +0x04 has exactly one reader:
  signal_attach's `mov edi,[0x64fee24]` at
  0x5ce7211 (the #2950 dup/epoll path).
- Entries pointer +0x08 and count +0x10 are read
  by the entry-lookup body 0x5cde710 (bounds check
  `signal - 1 < count`, per-entry OnceLock at
  entry+0x10, Arc clone via 0x5cfcf90) and by the
  table-drain body 0x5ce7380 (drains the dup fd the
  driver struct holds at +0x28, then walks the
  entries invoking callbacks). Both are named by
  observed behaviour only; their source identities
  are not established by this packet.
- The Once state word +0x18 is tested by
  signal_attach, entry-lookup and the lazy
  accessor itself.

## Open edges

1. The +0x00 word (sv[1]) is never loaded by any
   .text body: every base reference is a lea
   feeding the accessor, the Arc-clone helper or
   field loads of +8/+0x10/+0x18. Who writes to
   sv[1] at run time (tokio's signal driver wakes
   the state through it) is not identified here.
2. Source-level identities of entry-lookup
   0x5cde710 and table-drain 0x5ce7380 beyond the
   byte-level roles above.
3. Field names (sv[0]/sv[1], entries) are inferred
   from use; the artifact carries no debug info.

## Files

- `tools/signal_fd_producer_static.py` re-derives
  every hash, census, relocation resolution and
  instruction pin in `records.json` from the
  artifact alone; `--generate` rewrites
  `records.json` and `frames.txt` (the readelf
  FDE lines for all twelve pinned bodies).
- Twelve FDE-bounded bodies are SHA-256-pinned in
  records.json: the six chain owners plus the
  second vtable shim, the table builder and
  allocator, the entry lookup, its Arc-clone
  helper and the table drain.
- Eleven objdump excerpts cover every owner,
  shim, consumer and the table builder.
- `tests/test_signal_fd_producer_static.py`
  (9 tests) asserts the artifact hash, the born
  state of the global, the socketpair resolution
  and sole call site, the vtable-only path to the
  closure, the single fd reader, the consumer
  census, and both source Locations.

## Reproduce

Materialise artifacts/node/115/hl-node (LFS), then
from the repository root:

    python3 tools/signal_fd_producer_static.py
    python3 -m unittest tests.test_signal_fd_producer_static

The first prints {"matches": true} when the
on-disk records equal a fresh derivation.
