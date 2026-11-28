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

## Resolving the versioned source paths

The 18 directories with explicit versions name 36 Rust files. For the pinned node we found 190 distinct directory/file/line/column combinations with a matching filename slice and positive coordinates. All 36 files exist in the corresponding published crate archives, and all 190 positions fall on a character of the indicated source line. The [archive checksums](archive-checksums.json) are the SHA-256 values of the published .crate files from the [crates.io sparse index](https://index.crates.io/config.json). The [full comparison](source-coordinate-results.json) includes the six cross-version controls.

The reader resolves R_X86_64_RELATIVE entries whose storage lies in .data.rel.ro and whose addends name exact .rodata paths. At the pointer it checks the adjacent filename length and reads the two little-endian u32 coordinates. Repeated positions are counted once within a file. The search covers the absolute code_Mainnet prefix and relative z_vendor spelling for the paths in the historical inventory. The file/line/column layout is consistent with Rust source locations; it does not establish the runtime consumer of each record.

| Directory used for captured coordinates | Archive tested | Positions inside line / tested |
| --- | --- | ---: |
| hashbrown 0.15.2 | 0.16.1 | 16 / 26 |
| hashbrown 0.16.1 | 0.15.2 | 14 / 24 |
| secp256k1 0.29.0 | 0.30.0 | 0 / 1 |
| secp256k1 0.30.0 | 0.29.0 | 2 / 4 |
| socket2 0.4.10 | 0.5.7 | 1 / 1 |
| socket2 0.5.7 | 0.4.10 | 1 / 1 |

The two hashbrown archives both contain src/raw/mod.rs; changing releases disqualifies ten coordinates in each direction based on line length. Both socket2 alternatives fit the single recorded position from the other version. An in-range position alone does not prove identical source, local patches, the full Cargo graph, or membership in a particular lockfile. This result supplies exact candidate archives and records which competing versions this check can distinguish.

From this directory, provision the 18 public archives (3,903,659 compressed bytes total) and reproduce offline. No crate is built or executed.

```sh
cache=$(mktemp -d)
python3 -B published_sources.py --cache "$cache" --fetch > "$cache/first.json"
python3 -B published_sources.py --cache "$cache" > "$cache/replay.json"
diff -u source-coordinate-results.json "$cache/replay.json"
```
