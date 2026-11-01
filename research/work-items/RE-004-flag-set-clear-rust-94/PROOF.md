# Pointer snapshot, dword flag and ordered conditional byte clear

Target node94 SHA-256
`3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
The complete function is `[0x53cf560,0x53cf57e)`,30 bytes/seven instructions.
Two following INT3 bytes are padding, and the next function's dynamic behavior
is excluded. No semantic class, flag name or source-library identity is assumed.

## Exact memory and register relation

Let N=2^64, O be entry RDI, and I the stable entry memory. Field addresses
`A=(O+416) mod N` and `F=(O+264) mod N` are formed independently. First,
MOV loads all eight bytes I[A..A+7] little-endian into full RAX=P. Second,
MOV stores the four little-endian bytes of integer1 at F..F+3. Third, TEST
compares the entire P to zero; P!=0 stores exactly one zero byte at P. P=0
does not access that address. The final RET follows immediately.

Define J as I overlaid with bytes `[1,0,0,0]` at F. If P=0, final data is J;
otherwise it is J overlaid with one zero byte at P. Full RAX at return is P
from the entry snapshot even if the clear changes one of its source bytes.
RDX and all other non-control GP registers are untouched; the API explicitly
returns RAX and supplied entry RDX. Original flags/stack/return state are not
projected. A pointer result here describes an observed full register, not a
claim about the original source return type.

The ordered overlays matter. P=F clears the just-written low flag byte, so its
final dword is0. P=F+1/F+2/F+3 clears an already-zero byte, leaving dword1. A
clear anywhere else affects exactly that byte, including any of the eight
pointer-source bytes. The source qword must not be reread after either store.
The two fixed fields themselves differ by152 modulo N and cannot overlap as
their short valid spans; the optional pointed byte can alias either field.

Every raw P value is supported, not only Boolean or aligned addresses. TEST
uses all64bits. A nonzero P with low32bits zero still takes the clear branch.
Zero O is ordinary numeric input if both reached fields exist. Unlike O,
P=0 has an actual observed branch meaning and must skip the pointed-byte read
and write even when address0 is mapped and contains nonzero data.

## Safe image and admission

A slice with numeric base B represents `[B,B+len)`, with mathematical endpoint
at most N. A's eight bytes and F's four bytes must fit that interval. When
P!=0, only one byte at P must fit; P=0 needs no such span. Field arithmetic
may wrap modulo N independently; individual memory spans do not wrap beyond
the image. Unaligned fields, arbitrary stable read/write aliases and a final
byte at N-1 are supported. The library has no fixture-sized image cap and never
converts numeric addresses into host pointers.

The safe implementation validates the image, loads P once, and validates every
required destination before writing. It then performs exactly the four-byte
store followed by the selected one-byte clear. Consequently None leaves every
image byte unchanged. This is new safe refusal, not original fault behavior:
an original invalid pointed store can fault after the flag has already changed.
The API does not claim to reproduce that partial-fault execution or access order
on invalid inputs. Original successful correspondence requires stable ordinary
memory, valid normal control state and control/return storage disjoint from the
data image. MMIO, volatile effects, races, native ABI and stack/data aliases are
excluded. Those premises justify treating valid byte stores as ordered overlays.

Checked address subtraction yields an offset; checked offset+width establishes
the whole required span. The global interval check uses u128, so B+len cannot
overflow its check. Wrapping u64 additions implement each effective address.
The only data arithmetic is decoding P and materializing integer1; no signed
cast, truncating pointer or implicit host dereference is used. With destinations
prevalidated, every later slice operation is in bounds and cannot return None.

## Evidence and independent qualification

The complete unique FDE/CIE and exact selected bytes are independently decoded
by GNU, LLVM and Capstone. The sole conditional edge targets its own RET; no
helper, indirect call, static data or import is required. All direct E8/E9
candidates are checked within complete caller FDEs, and every RELA record is
scanned for entry naming and selected-code writers. Context callers are not
reconstructed algorithms; an E8/E9 scan is not complete indirect reachability.
The adjacent function calls further code and is not an artificial sibling claim.

Before Rust, an independent immutable-address-map oracle decoded the entry qword
with positional integer powers and composed two dictionary patches. Native
Rust uses checked byte slices and mutable stores. Frozen cases exercise every
possible fixture clear-byte offset, all flag/pointer overlap positions, pointer
nullness, numeric zero object, wrapped fields, exact interval endpoints, missing
selected spans, image overflow and arbitrary preserved-register bits. Every image
byte and full RAX/RDX are compared, not just a reported flag or digest.
Finite comparison qualifies new host code; the full-domain relation is established
above. Captured execution, instruction emulation, original compiled-byte identity,
whole-node equivalence and milestone completion remain unclaimed.
