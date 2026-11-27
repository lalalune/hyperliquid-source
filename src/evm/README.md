# `evm` (Node #115)

Independently authored Rust reconstruction of the `evm` component
(`l1/src/evm/{evm_db,evm_state,hash,hyper_evm}.rs` and HyperEVM `revm-precompile`
routing) targeted strictly at Linux x86-64 node #115
(`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`).

Joins all six verified node #115 EVM micro-crates (`node115-evm-precompile-outcome-names`,
`node115-evm-tx-type-names`, `node115-read-precompile-result`, `node115-child-reserve-fold`,
`node115-sstore-warm`, `node115-transient-rollback-branches`) with:
- All 21 HyperEVM read precompiles (`0x0800..=0x0814`) and their exact node #115
  gas formula (`input.len() <= 2000`, `1000 + 33 * (input.len() + output.len())`),
  plus exact `0x0809` (`L1BlockNumber`, `0x38e3b40`) execution.
- All 7 scaled standard Ethereum precompiles (`0x01 /5`, `0x05..=0x09 /10`,
  `0x0a /40`, `0x46a0eb0`) with saturating output gas scaling (`0x2a6b6e6`) and
  activation predicate (`0x433dc40`).
- Mode-13 EIP-7623 intrinsic gas + floor admission (`0x5be2560`, `0x2b93030`).
- EVM DB checkpoint `LtHash` (`0x810` bytes, 1024 wrapping big-endian `u16` lanes
  + saturating `n_elements`/`n_bytes`), keyspaces (`Ea`, `Ec`, `Es`), and
  `lt_hashes.json` serialization (`0x38c2580`, `0x38c2690`, `0x3915d30`).

See `research/work-items/RE-011-node115-evm-crate-and-precompiles/README.md` for
target-bound binary evidence and explicit non-claims.
