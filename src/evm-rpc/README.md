# `evm-rpc` (Node #115)

Independently authored Rust reconstruction of the `evm-rpc` component
(`evm_rpc/src/{evm_rpc,evm_store,evm_write_forwarder,expensive_call_limiter,method_router,reth_rpc_helpers_copied}.rs`)
targeted strictly at Linux x86-64 node #115
(`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).

Joins the existing verified node #115 micro-crates (`node115-storage-key-builder`,
`node115-block-number-text`) with `evm` and `global-constants` and implements:
- All 29 binary-verified EVM JSON-RPC methods (`0x2a05f60`, `0x2e375a0`, `0x17512f3`)
  and duplicate-rejecting `MethodRouter` (`-32601` `"Method not found"`).
- Two-selector `ExpensiveCallLimiter` (`0x2a04070`, `0x175d250`, clip mask
  `0x1fff_ffff_ffff_ffff`) and 5-way `<= 1000` filter limit check (`0x2a2cb70`).
- `eth_sendRawTransaction` forwarder (`0x17480e0`, chain-selector URL routing,
  strict `0x167afd0` hex decoder, JSON-RPC request/error framing).
- `eth_feeHistory` (`0x2a1fd20`, 5-block cap, percentile monotonicity, weighted
  reward selection, `786432.0` blob gas divisor).
- EVM store key builders (`Es` storage suffix + big-endian height range keys).

See `research/work-items/RE-011-node115-evm-rpc-crate/README.md` for
target-bound binary evidence and explicit non-claims.


For a valid `pending` selector, a requested count of zero takes the immediate
empty-result path. A requested count of one decrements to zero after capping,
then goes through the resolved-height and range-order checks. The inclusive
range would start one block past its end, so the Rust API returns
`InvalidBlockRange`. A resolved height of `u64::MAX` reaches the increment
overflow check first. The [retained range cases](../../research/work-items/RE-011-evm-fee-history-115/synthetic-cases.json)
and the [branch table](../../research/work-items/RE-011-evm-fee-history-115/branches.tsv)
record the distinction. The error here is the reconstructed crate's result;
the RPC wire error representation is a separate boundary.
