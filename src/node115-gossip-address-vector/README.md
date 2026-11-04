# Node115 selected Gossip response vector

Real no_std+alloc decoder for the full vector payload selected by response
variant0. It starts at the count (outer tag already selected), decodes each
actual NodeIp-tag0 element, and preserves cursor/count on all read errors.
The logical record is zeroextended fixed4 bytes, a raw scalar and boolean;
network units and original enum ABI are not inferred.

Vec stores a24-byte repr(C) record with real fallible allocation. Count read
reuses the existing MIT u64 Reader dependency. Field1-5 scalar decoding reuses
its validated value/cursor relation while projecting that native family's
specific error fields; whole native wrappers/slow helper are independently
bound in the packet. The u32 read is credited unchanged existing MIT code.
No allocator, callback or reader stub is provided. Native failure/unwind and
exact growth strategy are not represented as recovered behavior.

See research/work-items/RE-005-gossip-address-vector-115 for frozen fixture,
full static contexts/relocations, actual builds and controls. New code MIT.
