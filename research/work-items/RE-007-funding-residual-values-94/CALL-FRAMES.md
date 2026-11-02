# Ordinary-call and memory premises

Premises for the supplied-summary contract. Every admitted function is exported
in full, including cold paths. Ordinary value correspondence does not infer a
callee is noreturn and does not cover LSDA/unwind/abort behavior.

The frame separates: users and position records; ARU nodes; auxiliary-map
nodes; users-with-positions nodes; the supplied linked chunks and104-byte
records; each nested72-byte allocation; intermediate80-byte summary values;
owned rate-map nodes; output descriptor/records; stack frames; diagnostic
location records; allocator metadata and fresh allocations. All live spans are
nonwrapping and sufficiently aligned for the actual instructions. A generic
native allocator/copy premise does not replace the visible map algorithms:
all three required insertion cascades and traversal/cleanup bodies are proved.

Imported memcpy at slot576dfe0 copies exactly n readable source bytes to a
valid disjoint writable destination and preserves all other live storage.
Imported memmove at576e0e0 provides exact overlap-safe copying and its frame.
Imported memcmp at576e488 reads the specified20 bytes without modifying them,
returns zero exactly for equal bytes, and otherwise has the sign of the first
unequal unsigned pair. No particular positive/negative integer is assumed.
The Linux man-pages primary interface contract is cited as a generic premise,
not proof of this captured dynamically linked implementation.

Allocation slot576dfd8 and resize helpers return the requested aligned fresh
nonoverlapping storage, preserving existing unrelated state. Reallocation
preserves the live prefix and ownership transfer required by32d6740. Free
slot576e010 consumes only the specified owned allocation and changes no other
admitted live value. Source-location/error helpers do not receive permission to
mutate arbitrary previously escaped pointers. Normal-return diagnostic slot
5773190 and Once slot576e8b8 preserve summary/user/position/map state and all
live stack values across the precise call sites. Process-state effects outside
this frame and diagnostic content are unobserved by the value API.

The opaque worker bridge38dc6a0 and recursive scheduler behind343ac20 are the
input boundary. Their result is a finite uniquely owned linked sequence of
chunks, each with exact cap/ptr/len for104-byte records and valid nested row
vectors. Their user-state changes have already completed in the explicit
snapshot. The direct user-pointer enumeration proves occupied entries are
listed once under a valid control table; it does not prove parallel-worker
coverage, completion order, or summary provenance. Those are supplied premises.

Selected-user lookup reads a stable valid seeded hash table with unique keys,
exact control mirrors, mask/load/terminating-empty properties, and placements
consistent with the bound seed/hash chain. Selected-position lookup reads a
stable valid ordered u64 tree. The occupied paths must return the matching
existing object; no vacant constructors execute in the native domain. ARU and
auxiliary insertions may allocate/rearrange their own nodes but preserve user,
position, summary, output and the other map's bytes. User size/leverage/count
must not alias the debited destination or either mutable map.

The node count, leaf/internal capacity11, parent/index links, balanced heights,
sorted separator bounds and owned node uniqueness justify the tree induction.
Pointer arithmetic for20/80/104/72/16-byte strides and8-byte children must fit
the mapped allocation. Capacity growth must fit the native checked size bound;
no proof admits an allocation merely from a small logical row count when its
retained capacity is corrupt. Final rate-map cleanup follows output stores and
may free only that independently owned map. Partial output publication under
panic/allocation failure is outside ordinary-return correspondence.
