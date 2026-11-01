# Slot restore: full body and alias relation

Target #94 SHA-256 `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, ELF VA `[0x3290130,0x3290192)`, 98 bytes. Let entry registers RDI, RDX and RCX be addresses `o`, `a`, `s`. RSI is not consumed before ESI is replaced with the kind byte. These register names do not establish an original source signature.

## Entry observations

All reads precede the first store. In their machine order they are:

1. `h=LE64(M[a+0xd8..a+0xe0])` into R8.
2. `selector=LE64(M[s..s+8])`; `q=16` iff this entire qword is zero, otherwise `q=0`.
3. `kind=M[s+q+0x40]`, zero-extended to ESI.
4. Snapshot 16 bytes `old=M[s+q+0x30..s+q+0x40]`, plus a duplicate qword load of the first eight bytes. Stable ordinary memory makes the duplicate agree with the snapshot.
5. `link=LE64(M[h+0x238..h+0x240])` before any write.

Entry RDX supplies the first hop. Its later replacement with the selected slot address cannot retroactively change that hop. The object/table meanings of these addresses are unknown. A pointer value `h` need not itself be mapped; only its accessed field at `h+0x238` must be available.

## Restore bands

The first comparison is unsigned `(kind-16) mod 2^32 < 6`. Since kind is in 0..255, this holds exactly for 16..21. Those kinds restore only the first qword. All remaining kinds reach the unsigned `kind>4` test: 0..4 restore all 16 bytes; 5..15 and 22..255 restore none. The subrange edges 4/5, 15/16 and 21/22 are all material. There is no signed-byte interpretation or assumed kind enum.

The historical packet says both conditional branches are forward. The second `ja` at `0x3290189` actually targets `0x3290182` backwards. This is not a loop: that target writes the tag and returns, without revisiting the comparison. The new disassembly binds the actual direction; imported historical evidence remains unchanged.

## Immutable pointwise final image

Define `L=s+q+40`, `S=s+q+48`. The eight-byte link range `[L,L+8)` and 16-byte slot range `[S,S+16)` are adjacent and disjoint under nonwrapping addresses. Define a retained length `r=16` for kind 0..4, `r=8` for 16..21, otherwise `r=0`. For every memory address `x`, the final byte is

```
M'(x) = 5                 if x=o
        old[x-S]          if S <= x < S+r
        0                 if S+r <= x < S+16
        link_byte[x-L]    if L <= x < L+8
        M(x)              otherwise
RAX = o
```

Here `old`, `link_byte`, `kind` and `q` are all entry observations. The formula has explicit last-write priority for the tag. It therefore preserves arbitrary output/slot/link/selector/kind/owner/hop aliases in the admitted memory domain. In particular, output inside a cleared slot becomes byte 5, output inside a restored byte overwrites that old byte with 5, and output inside the link replaces one byte of the fetched link. A hop field that aliases the destination link or slot supplies its entry bytes; it is not reloaded after clearing. Selector/kind may be overwritten but are not read again.

## Safe image API

`restore(image, base, output, owner, state)` treats a mutable byte slice as ordinary memory at abstract u64 base and accepts three u64 address **values**, not dereferenceable host pointers. It returns original output as raw RAX. The slice's last byte must fit the u64 address space. All used field addresses are formed without u64 wrap and must fit the image, including the 16-byte snapshot even on no-restore paths. Only selected state fields are required; no full object, alternate slot, or hop base allocation is required. An object/hop base below `base` is accepted if the actually accessed positive-offset field is in the image.

The API validates every required input/output range before writes and snapshots all entry data. Refusals leave the image unchanged. This added safe policy does not reproduce native partial faults, volatile/MMIO operations, concurrent changes, wrapping address aliases, ABI/flags/vector clobbers or access permissions. Ordinary writable image bytes and nonwrapping stable reads are the correspondence domain. Transient zero stores may be elided by source/compiler because only final ordinary-memory effects are claimed; final tag priority must remain observable.

## Oracle independence and closure

The oracle performs field extraction from an immutable byte string, classifies kind by disjoint mathematical sets and constructs each final byte with the priority formula. It does not execute instructions or reproduce a zero/restore store sequence. Fixtures and oracle source are hashed and frozen with a guard requiring the new Rust source directory absent.

The body has no calls, no control transfer outside its FDE, and no RIP-relative data read. Complete FDE inventory and both disassemblers bind its bounds. All immediate offsets/branches are part of those bytes. A full `.text` E8 scan finds zero direct call sites; indirect/computed callers remain unknown. All 80,300 RELA entries are scanned, yielding exactly 30 type-8, symbol-zero records with this addend. Each eight-byte destination slot is separately mapped and its raw zero bytes pinned; applying the relocation yields `load_bias+0x3290130`. Slot membership does not identify a vtable, callback signature or actual consumer. No source identity, wider family or whole-node equality is inferred.
