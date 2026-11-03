# RE-001: the node #115 lu free target and its sibling field drops — one shared deallocator, TLS free lists

This packet answers packet #201's explicitly stated next question:
**decode the free target `0x5a8e3c0` and its sibling field drops
(`0x5a8c9f0`, `0x5a8c110`): what deallocation family frees the pair
at refcount zero, and what happens to the freed memory?**

## The answer

**1. Three drops, one template, one deallocator.** All three
functions load the inner object (`mov (%rdi),%rbx`), dispose of
one field (or a buffer), skip a `-1` inner pointer as a
none-sentinel, then run the shared tail: `lock decq 0x8(%rbx)`,
and at zero a tail jump through the single shared GOT slot
`0x64df4a0` (RELATIVE addend `0x635de30`) with
`(ptr, size, 0)`. The sizes differ per type; the family does not.

| drop | body | size at zero | field disposed first |
| ---- | ---- | ------------ | -------------------- |
| free `0x5a8e3c0` | 211B / 59 instrs | `0x38` (56) | buffer at `[rbx+0x20]` (see 2) |
| field drop `0x5a8c9f0` | 60B / 21 instrs | `0xb80` (2944) | `[rbx+0x10]` via `0x5a50a10` |
| field drop `0x5a8c110` | 60B / 21 instrs | `0xc8` (200) | `[rbx+0x18]` via `0x5a4d200` |

Each drop's landing pad repeats the same dec-and-dealloc tail
with a `call` instead of the tail jump, then `_Unwind_Resume`;
the pads are cited by address, not claimed as exhibits.

**2. The free target is not a bare free.** Before its tail,
`0x5a8e3c0` disposes of the buffer at `[rbx+0x20]` keyed by the
signed length at `[rbx+0x18]`: if the length is nonzero and its
negation does not overflow, the buffer is freed directly with
size `24 × length` (element size 24) through the same GOT slot;
in the negation-overflow case (`length == INT64_MIN`) it drains
element-by-element through helper `0x51e8720` until the helper's
out-word at `[rsp+0x48]` is zero; a null buffer builds empty
iterators. Only then does the shared tail free the `0x38`-byte
inner block itself. The drain helper is out of scope for this
packet and is not decoded here.

**3. The deallocator is a thread-local size-class free list,
not a syscall and not a zeroing free.** `0x635de30` (150B /
29 instrs) takes `(ptr, size, align/flags)` and its fast path
requires all of: `size ≤ 0x1000`, third argument `== 0`,
pointer not page-aligned, the per-thread byte budget
(`fs:0x348` used + class size `< fs:0x350` limit, TLS base
`-0x10a8`) not exceeded, and the per-class list head (`+0x360`
in a 24-byte slot) not at its bound (`+0x372`, low-16
compare — read as the list-full guard). On success it pushes
the pointer onto the calling thread's free list for its size
class (class index from table `0x67277c0[(size+7)/8]`, class
size from table `0x6727a00[class]`; both tables live in
`.bss`, so they are runtime-initialized, not static), updates
the budget, and returns. **The freed block's own bytes are
never touched, never zeroed, and never returned to the OS on
this path** — the block is cached for reuse at the same size
class. Any guard failure tail-jumps to the same allocator's
general free at `0x635c6d0` (same size-class tables; its
sub-paths are out of scope). The pair sizes (`0x38`, `0xc8`,
`0xb80`) are all fast-path eligible by size.

**4. Census: no direct caller anywhere; the deallocator is
binary-wide.** A whole-`.text` scan finds 0 direct E8 calls,
0 E9 tail jumps, 0 rip-relative LEA sites, and 0 absolute
8-byte references outside `.rela.dyn` for all three drops.
Each lives behind exactly one RELATIVE GOT slot, and every
static path is an `FF 15` call through it: free 46 sites via
`0x64e7278`, field drop `0x5a8c9f0` 27 sites via `0x64e7270`,
field drop `0x5a8c110` 141 sites via `0x64e7208`. The
deallocator slot `0x64df4a0` itself has 98,976 `FF 15` call
sites across the binary (raw scan; four sites spot-verified
genuine by disassembly: `0x141960a`, `0x14198ea`,
`0x14218e3`, `0x143a5a0`) — it is the binary's shared
deallocation routine, not a helper private to this chain.

## Corrections to earlier packets

None. #201's free-slot resolution (`0x64e7278` → `0x5a8e3c0`)
and its release template (release, `lock dec`, free at zero)
are confirmed; this packet only names what that free does.

## Files

- `research/work-items/RE-001-node115-lu-free-dealloc/README.md`
- `research/work-items/RE-001-node115-lu-free-dealloc/EVIDENCE.md`
- `research/work-items/RE-001-node115-lu-free-dealloc/records.json`
- `research/work-items/RE-001-node115-lu-free-dealloc/free.hex`
- `research/work-items/RE-001-node115-lu-free-dealloc/free.objdump.txt`
- `research/work-items/RE-001-node115-lu-free-dealloc/drop9f0.hex`
- `research/work-items/RE-001-node115-lu-free-dealloc/drop9f0.objdump.txt`
- `research/work-items/RE-001-node115-lu-free-dealloc/drop110.hex`
- `research/work-items/RE-001-node115-lu-free-dealloc/drop110.objdump.txt`
- `research/work-items/RE-001-node115-lu-free-dealloc/dealloc.hex`
- `research/work-items/RE-001-node115-lu-free-dealloc/dealloc.objdump.txt`
- `research/work-items/RE-001-node115-lu-free-dealloc/MANIFEST.sha256`
- `tools/node115_lu_free_dealloc.py`
- `tests/test_node115_lu_free_dealloc.py`

## Verification

- Static verifier `tools/node115_lu_free_dealloc.py`: exit 0
- Unit tests `tests/test_node115_lu_free_dealloc.py`: 8/8 pass
- MANIFEST: 13/13 entries match
- `make doctor`: analysis_ready true
- `make verify`: exit 0
- `make catalogue-check`: exit 0
- `make test`: 77 files attempted, 1 failed — the single failure is
  the pre-existing test_node115_catalogue Errno 18
  cross-device-link error; this packet's file [36/77] passes 8/8

## Next question

Decode the deallocator's slow path `0x635c6d0`: where do blocks
refused by the fast path (oversized, aligned, page-aligned, or
list-full) actually go — central pool, page return, or OS
release? (Behind it: the drain helper `0x51e8720`, the field-drop
callees `0x5a50a10` / `0x5a4d200`, and #200's delegates
`0x51f3e20` / `0x57ec1b0` and unwind callee `0x1680cab`
remain open.)
