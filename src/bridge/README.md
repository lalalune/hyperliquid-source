# `bridge` (Node #115)

Independently authored Rust reconstruction of the `bridge` component
(`l1/src/bridge2.rs` and `l1/src/bridge_request.rs`) targeted strictly at
Linux x86-64 node #115
(`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).

Joins the five verified node #115 bridge micro-crates
(`node115-bridge-event-name-decoder`, `node115-bridge-preimage`,
`node115-bridge-request-abi`, `node115-bridge-request-mutation`,
`node115-bridge-word-flatten`) with:
- Complete 8-variant `BridgeRequest` Solidity ABI encoder and Keccak-256 inner
  hash (`0x4526230`, jump table `0x7d3708`).
- Complete `BridgeRequest` EIP-712 `Agent` payload derivation (`0x4526e40`,
  `source = "a"`, `connection_id = keccak256(zero12 || bridge_contract || inner_hash)`,
  Arbitrum chain ID `42161` on Mainnet / `421614` otherwise).
- `EthEventId` and `VoteEthDepositAction` / `l1ValidatorVoteBridgeDeposit`
  MessagePack & JSON wire codecs (`bridge-eth-event-wire-115`).
- `Bridge2` withdrawal request state mutation and 15-field schema metadata
  (`0x44d83f0`, `bridge-state-serializer-115`).

See `research/work-items/bridge-request-abi-all-tags-115/README.md` for
target-bound binary evidence and explicit non-claims.
