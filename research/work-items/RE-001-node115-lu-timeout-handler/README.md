# RE-001: the node #115 lu timeout handler — a bucket re-claim for unlink, not a node recorder

- Component: `base/src/lu.rs` conversion context, the hash-bucket entry-word
  family shared by the park queue, the lookup, and the cleanup helper.
- Target: node #115, 105,896,032 bytes; SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source: `8fd8db680ec4bfef40996e5616bce3d5156d0b86` (upstream main, node-115-only migration).
- Question: packet #190 (PR #2206, open) left open the timeout handler
  `0x5bb3ca0` end to end, "to see what it records on the timed-out
  node". Answer, in one paragraph: it records nothing on the node. The
  handler takes a waiter node, reads only its first qword (the slot
  key), claims the hash bucket for that key with the #188 lookup shape
  (golden-ratio hash, 64-byte entries, `lock cmpxchg 0 -> 1`,
  contention helper on race, table creation when the table is null,
  release-and-retry when the table or the node key changed), and
  returns the slot key in `rax` and the claimed bucket entry in `rdx`.
  The unlink itself happens in the caller after the handler returns:
  all three call sites walk the returned bucket's list for the node,
  unlink it, and release the bucket with `lock xadd -1`. This packet
  cites #183 (PR #2106), #184 (PR #2125), #185 (PR #2137), #186
  (PR #2158), #187 (PR #2179), #188 (PR #2190), #189 (PR #2197), and
  #190 (PR #2206, the inviting prior packet) as prior work; their
  bodies are cited, not re-claimed. The new bytes claimed here are
  the `0x5bb3ca0` body only. The lookup, park, cleanup,
  contention-helper, table-creation, and timed-wait bodies are prior
  claims or context, referenced here by address for the transition
  sites.

## Exact scope

| Role | FDE half-open VA range | Bytes | Native instructions |
| --- | --- | --- | ---: |
| timeout handler (characterized) | `0x5bb3ca0..0x5bb3e41` | 417 | 107 (106 excluding 1 nop padding) |
| lookup (cited, #188) | `0x5bb4d00..0x5bb4f78` | 632 | — |
| park (cited, #188) | `0x5bb42e0..0x5bb4663` | 899 | 257 |
| cleanup (cited, #188) | `0x5bb66b0..0x5bb678b` | 219 | — |
| contention helper (cited, #189) | `0x5bb6790..0x5bb68d9` | 329 | 104 |
| timed wait (cited, #190) | `0x5bb2440..0x5bb35ed` | 4525 | 1164 |
| table creation (context) | `0x5bb6400..0x5bb645f` | 95 | — |

All bodies are hash-pinned without normalization. Coordinates are ELF
virtual addresses (PIE); `.text` file offset = VA − 0x1000,
`.data.rel.ro`/`.got` file offset = VA − 0x2000, `.rodata` file offset = VA.
The handler FDE's CIE is `0x00000000` (eh_frame-confirmed); it has one
`ret`, at `0x5bb3e23`. The body proper to the ret is 388 bytes
(`0x5bb3ca0..0x5bb3e24`); the tail `0x5bb3e24..0x5bb3e41` (29 bytes)
holds the three panic stubs, followed by `int3` padding to the next
function at `0x5bb3e50`. The handler body SHA-256 is
`861103e78cc356cb3a41a673b24a1dd995c0dc3f4cd7669c434d9c55985b547d`.

## Signature and returns

`handler(rdi = waiter node pointer) -> (rax = slot key, rdx = claimed bucket entry)`:

- The only node read is `[rdi]`, the node's key (the slot pointer, node
  layout `+0x0` per #190). No instruction in this body writes to the
  node: the only memory writes are stack spills (`[rsp+0x8]`,
  `[rsp+0x10]` across the helper/cleanup calls), the bucket-entry
  `lock cmpxchg`, and the bucket-entry `lock xadd -1` on the release
  path. The "what it records on the node" premise therefore dissolves:
  the handler's effect is the bucket claim, and the caller performs
  the unlink.
- The returned entry's word is `1` on the fast claim path, or the old
  word with bit 0 set (lock held) on the contention-helper path; in
  both cases the caller releases it with `lock xadd -1` after the
  unlink, with the standard cleanup condition (old `>= 4`, bit 1
  clear).

## The claim loop, in order

`handler` (table variable GOT `0x64ec148` → `0x64fff28`, table
creation GOT `0x64ec158` → `0x5bb6400`, cleanup GOT `0x64ec150` →
`0x5bb66b0`, contention helper GOT `0x64ec160` → `0x5bb6790`,
claim value `rbp = 1`):

1. **Table.** `rbx = [table variable]`; if null, jump directly to the
   table-creation path (step 5) with nothing claimed yet.
2. **Hash and bounds.** `r14 = [rdi]` (the key); `ecx = 0x40 -
   [table+0x18]` (the shift, from the table's bucket-bits field). A
   borrow (`[table+0x18] > 64`) panics (see below); `ecx >= 0x40`
   (bits `== 0`, a shift by 64) panics; bits `== 64` gives shift 0,
   leaving the index unshifted for the bounds check to decide.
   `r8 = (key * 0x9e3779b97f4a7c15) >> shift`; if `r8 >=
   [table+0x8]` (the bucket count), the index panic fires. Otherwise
   `rdx = [table] + (r8 << 6)` (64-byte stride) is the bucket entry.
3. **Claim.** `lock cmpxchg [entry], 1` at `0x5bb3d5c`. On success,
   check the table is unchanged (`[table variable] == rbx`) and the
   node key is unchanged (`[rdi] == r14`); either change goes to the
   release path (step 4). On failure (a race), save `rdi`/`rdx` to
   the stack and call the contention helper at `0x5bb3d8a` with
   `rdi = entry` — the helper returns with bit 0 held — then reload
   the cleanup/table-creation GOT entries, restore `rdx`/`rdi`, and
   run the same two stability checks.
4. **Release and retry.** `lock xadd [entry], -1` at `0x5bb3cf7`;
   call cleanup at `0x5bb3db3` exactly when the old value is `>= 4`
   with bit 1 clear (the same condition as #188/#189); then reload
   the table: null → step 5, otherwise restart at step 2.
5. **Table creation.** Called at `0x5bb3de1` with `rdi = node`; it
   returns the new table in `rax`. The handler restores `rdi`,
   re-reads the key, recomputes the shift (borrow → panic, otherwise
   into the bounds check at step 2), and proceeds. The table-creation
   argument's role beyond the call shape is context only.
6. **Return.** `rax = r14` (the key) at `0x5bb3e12`, `rdx = entry`,
   single `ret` at `0x5bb3e23`.

## The panic paths (parking_lot provenance)

All three panic stubs' `Location` structs name the same 73-byte file
string (resolved through `R_X86_64_RELATIVE` relocations, since the
file fields read 0 before relocation):

`/home/ubuntu/hl/code_Mainnet/z_vendor/parking_lot_core/src/parking_lot.rs`

| Path | Trigger | Location | Wrapper message prefix |
| --- | --- | --- | --- |
| `0x5bb3e05` | shift subtraction borrows (`[table+0x18] > 64`) | parking_lot.rs:352:45 | `attempt to subtract with overflow` |
| `0x5bb3e24` | shift amount `>= 64` (`[table+0x18] == 0`) | parking_lot.rs:352:5 | `attempt to shift right with overflow` |
| `0x5bb3e31` | bucket index `>= [table+0x8]` | parking_lot.rs:390:23 | bounds-check format ` index out of bounds: the len is {} but the index is {}` |

The two arithmetic wrappers pass `&str` lengths (73 and 67) that extend
past the individual message texts into the following packed messages
(the string table packs the overflow messages adjacently with no
separators: shift 36 bytes, subtract 33 bytes, then the assertion
messages). The checks are therefore identified here by their message
prefixes and `Location` line/column, not by the full passed span; the
length quirk does not affect any claim about the handler body itself.
The index path calls the bounds-check helper at `0x1680cbf` (index in
`rdi`, count in `rsi`, format string at `0x4400ef`), while the
arithmetic paths call the thin `panic` wrappers at `0x1681e40`
(subtract) and `0x1681e20` (shift), each forwarding its `Location`
pointer in `rdx` to the panic runtime at `0x1680e80`.

## Call-site census: who calls the handler

Direct `E8` callers over all of `.text`: exactly 3; GOT-indirect
callers: none (no relocation addend in the binary equals
`0x5bb3ca0`):

| Site | Caller | Argument and post-call use |
| --- | --- | --- |
| `0x5bb264d` | timed wait `0x5bb2440` (#190), first-phase timeout | `rdi = r15` (the stack waiter node); caller walks `[rdx+0x8]` for the node, unlinks it, releases `[rdx]` |
| `0x5bb2df2` | timed wait `0x5bb2440` (#190), second-phase timeout | `rdi = [rsp+0x28]` (the TLS node); caller keeps `rdx` in `r12`, walks/unlinks, releases `[r12]` |
| `0x5bb1f09` | family FDE `0x5bb1a60` (#189's census) | `rdi = [rsp+0x10]` (that function's waiter node); identical post-call shape — bucket-list walk keyed by `rax`, unlink, `[rdx]` release |

Note for #190's census: its "2" counts the timed-wait sites only; the
whole-binary count is 3. The handler is a shared timeout-path
primitive across the family, not a timed-wait-only helper. The family
FDE's own role beyond its timeout path is not decoded here.

## How this differs from #188's lookup

The lookup (`0x5bb4d00`) and the handler share the table layout, the
golden-ratio hash, the `0 -> 1` claim, the contention helper, the
table creation, and the release-and-retry shape — but they are
distinct functions, not aliases:

- The lookup hashes **two** arguments (`rdi` and `rsi`, each multiplied
  by the golden ratio and shifted) and returns the entry in `rbx`.
- The handler hashes **one** key (`[rdi]`, the node key) and returns
  the pair `(key, entry)` in `(rax, rdx)`, adding an explicit
  node-key stability recheck after the claim that the lookup does not
  have (the lookup rechecks the table only).
- The handler's panic set is its own (parking_lot.rs:352/390 above);
  the lookup's bounds/shift checks are separate sites.

## What this does not claim

- The Rust type/trait names of the table, the bucket, the waiter node,
  and the queue are not asserted; "timeout handler", "bucket", and
  "unlink" are behavior descriptions from the atomic operations and
  call sites, not symbols.
- The table-creation helper's argument semantics (beyond `rdi = node`
  in, table in `rax` out) and its internals are context only.
- The family FDE `0x5bb1a60`'s role beyond its timeout path is not
  decoded; the timed-wait unlink walks themselves are #190's claims,
  cited here only for the handler's return contract.
- No gate is requested by this packet; the next question is either
  the vtable dispatch site that would settle the wake-site `rdx`
  question (still open since #188), or the family FDE `0x5bb1a60`
  end to end, whose timeout path already shares this handler.

## Verification

`tools/node115_lu_timeout_handler.py` passes (target digest, handler
body hash, single ret, claim/helper/cleanup/table-create/release
sites, shift and bounds checks, GOT resolutions, panic `Location`
file/lines and message prefixes, census 3 E8 / 0 GOT, no node writes);
`tests/test_node115_lu_timeout_handler.py` passes (7 tests, including
corruption controls); `make doctor` reports `analysis_ready` true;
`make verify` and `make catalogue-check` pass.
