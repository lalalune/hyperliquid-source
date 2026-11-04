# RE-002: which third-party crates and private forks does node115 build from?

- Target: node #115 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Claim status: observation (embedded source paths only)

## Finding

node115 is built from `/home/ubuntu/hl/code_Mainnet` with dependencies vendored
in-tree. Embedded panic/location paths name `z_vendor/<crate>/...` and
`z_forks/<fork>/...` rather than `~/.cargo/registry/.../<crate>-<version>`
directories, so most crate versions are not recorded in the binary.

`inventory.json` lists 131 vendored directories (18 carry a version in the
directory name, e.g. `http-0.2.12`, `ark-ff-0.5.0`, `rand-0.8.5`) and 8 private
fork directories:

`bincode-fork`, `hyper-fork`, `hyper-tls-fork`, `reth-chainspec`,
`reth-ethereum-forks`, `reth-rpc-eth-types`, `reth-rpc-server-types`,
`revm-precompile`.

Each entry keeps the source files observed under it.

## Reproduce

The inventory was produced by a regex over the raw node115 bytes for
`(z_vendor|z_forks)/<dir>/...rs`. The method and limits are in `inventory.json`.

## Limitations

- A crate whose code embeds no location path is invisible here.
- Most directories have no version. Establish versions by compiling candidate
  releases with rustc 1.95.0 and comparing functions against node115.
- No lockfile, build or equivalence claim.

Next question: for each fork, which upstream release is its base and what
changed (start with `bincode-fork` and `hyper-fork`, the largest path sets)?
