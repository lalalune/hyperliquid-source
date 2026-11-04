# Node115 ClientBlocksError logical payload

A real no_std Cargo library decoding all seven variants at the nested error
selection of GossipRpcResponse variant1. `index` stays raw: 0/2/3/4 have no
payload, 1/5/6 contain two independently read u64 values. Field units and native
enum ABI are unknown. Decode errors preserve partial cursor/charged state.
The reused MIT u64 Reader is a real path dependency through the existing
record adapter, not a stub. The u32 reader is credited unchanged MIT reuse
from the existing Gossip request component on base05bc2de303c05525b71e7e257426e741bc66a390.

See research/work-items/RE-005-client-blocks-error-115 for complete parent,
reader helpers, dispatch table, frozen expectation hash and compiled controls.
No outer response tag/result, successful vector branch, node integration or
compiled native-byte identity is claimed. Caller supplies disjoint valid slices
and canonical limited/unlimited state. New code MIT.
