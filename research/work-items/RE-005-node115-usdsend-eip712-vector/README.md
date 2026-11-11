# RE-005: close the node #115 UsdSend EIP-712 digest path

Partial progress for [#3912](https://github.com/lalalune/hyperliquid-source/issues/3912), component `action-wire`. This packet closes one mapped action's type-hash, domain-result, final-preimage and digest-helper chain. It leaves all component gates false.

## Target and references

- Base commit: `0781ce04826eeefd89fe336cb8ea073be0c1de30` (`main` at collection time).
- Target: Linux x86-64 node #115, `artifacts/node/115/hl-node`, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Addresses are ELF virtual addresses. FDEs are unwind extents; they are not asserted to be validated function boundaries.
- Existing open [#5398](https://github.com/lalalune/hyperliquid-source/pull/5398) records the `UsdSend` type declaration and type hash. Existing open [#5427](https://github.com/lalalune/hyperliquid-source/pull/5427) records `EIP712Domain` type-string fragments and leaves the final caller/hash chain unresolved. This packet adds the missing target-bound call relation for this one action.
- Existing [RE-009 permutation packet](../RE-009-sponge-permutation-115/CONTRACT.md) covers a separate 200-byte Keccak permutation body; it does not claim this action's preimage or digest.

## Observations

The authenticated `.rela.dyn` table binds these indirect-call slots to target VAs:

| Slot | Relocated target | Use in this packet |
|---|---:|---|
| `0x64ea890` | `0x43d2b20` | `UsdSend` message struct-hash path |
| `0x64ea898` | `0x43d3130` | `UsdSend` type-data builder |
| `0x64e2178` | `0x169e950` | EIP-712 domain typed-data path |
| `0x64e0140` | `0x169e350` | typed-data record constructor |
| `0x64e0148` | `0x5cda910` | sponge update call site |
| `0x64e0150` | `0x5cdad40` | sponge finalize call site |

The wrapper's FDE is `[0x44338b0, 0x4433c1b)`. It allocates and writes the 26-byte domain name `HyperliquidSignTransaction`, writes ASCII `1` for the version, calls the domain slot at `0x443399f`, then the `UsdSend` message-hash slot at `0x44339ee`. The latter slot has one call site in the target's full disassembly. At `0x44339f4` the wrapper branches on the returned tag: tag `1` is propagated through the short path; the other branch continues to final preimage construction and writes output tag `0`.

The wrapper passes three records to the byte-joining helper at `0x44e5db0`: the two-byte literal `0x1901`, followed by two 32-byte values from the domain-result and message-result paths. It then calls the `0x64e0148` update slot and `0x64e0150` finalize slot and writes a tag plus the 32-byte result. The call instructions and relocated targets are checked from original bytes; the complete selected FDE disassemblies are retained in `disassembly.txt`.

The `UsdSend` message-hash FDE is `[0x43d2b20, 0x43d312e)`. Its call to `0x64ea898` reaches the `UsdSend` type-data builder at `0x43d3130`, FDE `[0x43d3130, 0x43d342c)`. The message-hash path builds five 32-byte records (the type hash and four encoded fields) before the struct-hash helper and Keccak update/final calls. The mapped declaration is:

```text
HyperliquidTransaction:UsdSend(string hyperliquidChain,string destination,string amount,uint64 time)
```

The domain path begins in FDE `[0x169e950, 0x169f713)`, constructs the `EIP712Domain(` type text, hashes typed field records and uses the same constructor and sponge slots. Its wrapper output occupies the 32-byte input slot used in the final preimage. This packet identifies the output's role as the domain separator by the observed helper path and the final `0x1901 || bytes32 || bytes32` structure; it does not claim to recover the runtime values or outer input ABI.

## Synthetic verification vector

`vector.json` records all preimage parts and hashes for public synthetic data. It uses chain label `Testnet`, destination `0x00000000000000000000000000000000000000a1`, amount `1.25`, time `1700000000`, and domain values `HyperliquidSignTransaction`, version `1`, chain ID `1337`, zero verifying contract and zero salt. The `UsdSend` type hash is independently calculated and checked against the value in #5398. The domain type hash is calculated from the type string recorded in #5427.

The resulting final preimage is 66 bytes (`0x1901`, 32-byte domain separator, 32-byte `UsdSend` struct hash); its digest is:

```text
0x5f4ad47ff6a6f14e393ab0605191f836f96905dc62bdeaec47cd7c0f99d4e10b
```

The independent Keccak model passes the empty-string and `abc` known vectors. Changing the amount, domain chain ID or prefix changes the final digest. This is a synthetic EIP-712 vector derived from the recorded types and static call structure; it is not a runtime output comparison, signature, or proof of the actual production domain values.

## Reproduction and limits

From the repository root:

```sh
python3 tools/action_wire_usd_send_digest_115.py --out research/work-items/RE-005-node115-usdsend-eip712-vector
python3 -m unittest discover -s tests -p 'test_action_wire_usd_send_digest_115.py' -v
sha256sum -c research/work-items/RE-005-node115-usdsend-eip712-vector/MANIFEST.sha256
```

The collector authenticates the complete target digest, exact FDE extents, relative relocations, indirect/direct call destinations and data literals. Seven focused tests cover Keccak known vectors, the vector, target identity and corruption controls for a call, relocation, prefix and digest. Captured code is never executed or emulated. The actual domain inputs, outer action-object ABI, other action families, signatures, replay checks and full component gates remain open.

Recorded checks (`checks.json`): the focused seven-test module, `make verify`, `make catalogue-check` and `make reproduce` passed. `make doctor` exited 2 because GNU `objdump` and `readelf` are unavailable on this host; Apple LLVM objdump 21.0.0 produced the retained static disassembly. Full `make test` was not run because flat test discovery includes Unicorn emulation of captured instructions; that broader path was outside this static-only task. No captured binary was executed or emulated.

No progress gate is requested. Next question: recover the runtime producer and source values for this `UsdSend` wrapper, then compare a public live-protocol vector without private keys or signing.
