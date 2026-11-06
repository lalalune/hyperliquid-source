# RE-002 · Node #115 secp256k1 generator multiplication and blinding

Component: foundation utilities, native dependency linkage. Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`. Registry baseline: `05bc2de303c05525b71e7e257426e741bc66a390`.

## Observations

This packet resolves concrete outgoing direct transfers in the secp256k1-sys windows listed in [roots.tsv](roots.tsv). The earlier [byte-window registry](../../byte-windows.json) establishes the source-window attribution and records the relocation masks. [linkage.tsv](linkage.tsv) connects those records to the actual linked instruction bytes and destinations.

| Reference root | Instruction VA | Transfer | Destination VA | Destination attribution |
| --- | --- | --- | --- | --- |
| `rustsecp256k1_v0_11_ecmult_gen_blind` | `0x6339718` | `call` | `0x6337f90` | `rustsecp256k1_v0_11_ecmult_gen` |
| `rustsecp256k1_v0_11_ecmult_gen` | `0x63384fd` | `call` | `0x6331980` | `rustsecp256k1_v0_11_gej_double` |
| `rustsecp256k1_v0_10_0_ecmult_gen_blind` | `0x632aef9` | `call` | `0x632a770` | `rustsecp256k1_v0_10_0_rfc6979_hmac_sha256_initialize` |

The denominator is **40 off-window direct transfer sites in 4 registered bodies**. 40 instruction sites have a four-byte displacement covered by a recorded source relocation. 38 sites have destination labels from an exact registered function start or an ELF PLT relocation. The remainder retain their addresses without a symbol claim.

## Reproduction

From the repository root with the target materialized, verify the full digest and decode the recorded ranges:

```sh
node=artifacts/node/115/hl-node
echo 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301  artifacts/node/115/hl-node' | sha256sum -c -
objdump -d -M intel --start-address=0x63234f0 --stop-address=0x63237eb "$node"
objdump -d -M intel --start-address=0x63393a0 --stop-address=0x63398b7 "$node"
objdump -d -M intel --start-address=0x6337f90 --stop-address=0x633939c "$node"
objdump -d -M intel --start-address=0x632ae70 --stop-address=0x632b1e5 "$node"
objdump -d -j .plt "$node"
readelf -rW "$node"
```

For each direct call or unconditional jump out of the window, add the signed displacement to the next instruction VA. Compare the reference bytes by reading the recorded source path at `source_offset + (site_va - root_va)`. The registry's relocation pointer identifies which source displacement was masked and the type and addend in the table. For a PLT entry, the RIP-relative jump identifies the GOT slot and `.rela.plt` identifies its dynamic symbol.

The local scan used Python 3.12.14, Capstone 5.0.9 and pyelftools 0.33. It verified the source and target body hashes, decoded each full root interval and checked the signed displacement independently of the disassembler. The negative control changes `e873e8ffff` to `e872e8ffff` at `0x6339718`, producing `0x6337f8f` instead of `0x6337f90`. The artifact was read only.

These are static instruction sites. Indirect calls, conditional branches, and runtime paths are outside the scope. Source attribution comes from the existing registry, with any ambiguities retained in the table. This packet does not change byte coverage or acceptance gates.
