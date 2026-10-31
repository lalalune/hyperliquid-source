# bridge: the message a validator signs for a bridge request, from payload to EIP-712 digest (node #94)

This packet fixes every byte hashed for a bridge request, so a Rust signer or verifier can now be compared digest by digest: each of the eight payload arms is a standard ABI tuple, its Keccak hash is ABI paired with the Bridge2 contract address taken from a built in book, and that hash is the `connectionId` of an Agent struct with source `a`, signed under the `Exchange` domain with chain id 42161 or 421614.

- Component ID: `bridge` (path rule `l1/bridge_request.rs`)
- Target release and full SHA-256: `hl-node` #94,
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`
- Source commit / reference commit: repository `1f8c67c63ca4794c9689235471c60297f8a5c985`; `references/can1357-hl` used only as a lead
- Claim status: observation, with inferences labelled; no gate requested
- Scope included and excluded: included are the request builder `0x358ea60`, the payload hash `0x358de50` with all eight arms, the two set helpers `0x37db5d0` and `0x37db0d0`, the token builders `0x3c97de0`, `0x3c97a70`, `0x3c99df0`, `0x3c9a570`, `0x3c9f240`, `0x3c97be0`, the pair `0x3814080`, the digest wrapper `0x37f2940`, the typed hash `0x38eff30`, the Agent hash `0x13f13d0`, the concat `0x38139c0`, and the book builder `0x1405720` with its parse and insert helpers. This answers the next question of `research/work-items/bridge`, the rules of the finisher `0x1592160`. Excluded are the address lookup body `0x1405240` (bound in #163, a stub here), the contract file check `0x144a710` and reader `0x144e940` (stubs here, so no file format is claimed), signature recovery, and any execution of the binary.

## Reproduce

Run from the repository root. Standard library only. No external program is called and the binary is never executed.

```sh
python3 tools/bridge_signed_message.py --out research/work-items/bridge-signed-message-94
python3 -m unittest tests.test_bridge_signed_message
```

The tool checks the artifact SHA-256 first and fails on a mismatch. Function bounds come from `.eh_frame` through the shared parsers. Real bytes run in a small x86-64 interpreter in the tool. Regeneration took about 240 s here. Output depends only on the artifact.

## Evidence

Coordinates are virtual addresses. Files beside this record:

| file | content |
| --- | --- |
| `evidence.json` | function rows, the arm table, both callers, templates, book rows, contract file names, mutation counts |
| `vectors.tsv` | 66 requests: contract, payload hash, connection id and digest, for a Rust test |
| `worked_words.tsv` | the ABI words of one message per arm |
| `cases.tsv` | every case with its outcome and number of hash inputs |
| `mutations.tsv` | every mutant with its result and reason |

### The chain of hashes

Every hash input below was captured at the absorb call `0x4f59a10` during the real run, in this order, and compared with the specification byte by byte.

| step | input | result |
| --- | --- | --- |
| 1 | `abi.encode(arm tokens)` | payload hash |
| 2 | `abi.encode(address contract, bytes32 payload hash)` | connection id, stored at request `+0x18` |
| 3, 4, 5 | `Exchange`, `1`, `EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)` | three domain words |
| 6 | `abi.encode(type hash, name hash, version hash, chainId, address 0)` | domain separator |
| 7, 8 | `Agent(string source,bytes32 connectionId)`, `a` | two struct words |
| 9 | `abi.encode(type hash, source hash, connection id)` | Agent struct hash |
| 10 | bytes `19 01`, domain separator, Agent struct hash | the 32 byte digest |

### The payload arms

`0x358de50` jumps through the 8 row table at `0x58f650` on the byte at payload `+0`. Offsets are payload offsets.

| tag | entry | action text | tokens | fields |
| --- | --- | --- | --- | --- |
| 0 | `0x358de77` | `modify` + role name | string, address, bool, uint | role `+1`, active `+2`, validator `+3`, nonce `+0x18` |
| 1 | `0x358e2cc` | `changeDisputePeriodSeconds` | string, uint, uint | value `+8`, nonce `+0x10` |
| 2 | `0x358dfdb` | `changeBlockDurationMillis` | string, uint, uint | same |
| 3 | `0x358e11c` | `changeLockerThreshold` | string, uint, uint | same |
| 4 | `0x358dfca` | `updateValidatorSet` | string, uint, address[], address[], uint[] | set at `+8`, epoch at `+0x20` |
| 5 | `0x358e40d` | `requestWithdrawal` | string, address, address, uint, uint | account `+1`, destination `+0x15`, amount `+0x30`, nonce `+0x38` |
| 6 | `0x358e57a` | `unlock` | string, uint, address[], address[], uint[], uint | nonce `+8`, set at `+0x10`, epoch at `+0x28` |
| 7 | `0x358e260` | `invalidateWithdrawals` | string, bytes32[], uint | nonce `+8`, list at `+0x10` |

Role 0 prints `Locker`, role 1 `Finalizer`. The table entries are in `evidence.json`.

Set shape: root, height, length, then the epoch word. A set row is 0x30 bytes: power u64 at `+0`, hot address at `+8`, cold address at `+0x1c`. Nodes hold 11 rows, with parent `+0x210`, parent slot `+0x218`, length `+0x21a`, edges `+0x220`.

`0x37db0d0` walks the set from the last row to the first, so all three lists are in reverse tree order. The epoch is the fourth word of the set, widened to a 32 byte uint.

ABI text note: `0x1592160` sizes its word buffer from a byte count, so the capacity is 32 times larger than the words it holds. The output is not changed by this.

### Only two callers

`0x358ea60` is reached through slot `0x5775da8` from two sites in the whole text, each with an immediate tag: `0x374e916` in `0x374e620` writes tag 4 at `0x374e8ff`, and `0x374ed3d` in `0x374ec60` writes tag 5 at `0x374ed2b`. Arms 0, 1, 2, 3, 6 and 7 have no caller through this slot. In the first site the set can be empty: `0x374e8a0` writes root 0 and length 0.

### The request and the contract address

`0x358ea60` does this after the payload hash:

1. Format `Bridge2` + chain name with the template at `0x200e12`, and pack the text. `Bridge2Mainnet` becomes 16 bytes, the text then zeros.
2. Look up the 16 bytes in namespace 2 when the chain byte is 3, in namespace 3 for every other chain byte (`0x358eafa`: `cmp bpl,3; sete cl; xor ecx,3`).
3. If the lookup returns nothing, panic through slot `0x576e470` with location `l1/src/bridge_request.rs` line 83.
4. Run the pair hash, then write the request: `+0` capacity 1, `+8` pointer to one byte `a`, `+0x10` length 1, `+0x18` connection id, `+0x38` chain id as the low word of a 4 word integer, `+0x40` to `+0x58` zero.

The chain id is 42161 for chain byte 3 and 421614 otherwise.

### The book

`0x1405720` builds a two level map. A real run gives these rows, from the text pairs at `0x218509` to `0x2185bb`:

| namespace | name | address |
| --- | --- | --- |
| 2 | `Bridge2Mainnet` | `0x2Df1c51E09aECF9cacB7bc98cB1742757f163dF7` |
| 2 | `Usdc2Mainnet` | `0xaf88d065e77c8cC2239327C5EDb3A432268e5831` |
| 3 | `Bridge2Testnet` | `0x08cfc1B6b2dCF36A1480b99353A354AA8AC56f89` |
| 3 | `Usdc2Testnet` | `0x1baAbB04529D43a73232B713C0FE471f7c7334d5` |

The checksummed text is parsed to 20 bytes by `0x14ca560`. The builder then walks 11 namespaces, 0 to 10, and asks whether `<config dir>/contract_addresses/<name>.json` exists for each. The names, from the real format call: `0 Localhost`, `1 Mainnet`, `2 Arbitrum`, `3 ArbitrumTestnet`, `4 Optimism`, `5 Base`, `6 HlUnitTest`, `7 HlLocal`, `8 HlSandbox`, `9 HlTestnet`, `10 HlMainnet`. In `evidence.json`, `contract_files` keeps the order.

So namespace 2 is `Arbitrum` and namespace 3 is `ArbitrumTestnet`. Chain bytes 0 and 1 ask namespace 3 for `Bridge2Local` and `Bridge2Sandbox`, which have no built in row. Only `ArbitrumTestnet.json` can supply them. Two cases run this with a row placed by the lookup stub, and two more show the panic.

A contract file replaces the whole table of its namespace. With the file reader stubbed to return a table, a file for `Arbitrum` that lists only `Bridge2Mainnet` leaves no `Usdc2Mainnet` row. A file with no rows leaves an empty table. A file for a namespace with no built in table adds one. A reader error panics. The walk of the old rows at `0x1405c1c` searches the new table, but both outcomes continue, so a found or missing row changes nothing.

### Against the reference

These are differences with `l1/bridge_request.rs` and `base/cid.rs`, which are leads only.

| item | reference | bytes |
| --- | --- | --- |
| encoding | a custom tag byte stream | standard ABI head and tail words |
| final hash | one hash of the stream | three levels: payload, pair with the contract, Agent digest |
| tag 6 | `Reserved`, no action | `unlock` with a set, epoch and nonce |
| tag 4 | locker, finalizer and root lists, then nonce | epoch, then hot, cold and power lists |
| source tag | stored, role unclear | hashed as the Agent `source` string |
| namespace walk | 0 to 11 | 0 to 10 |

## Inferences

- Source `a`, the `Exchange` domain and the Agent type are the same phantom agent scheme as the signed L1 actions. Only the source byte and chain id differ. `0x37f2940` is shared with other callers, and a direct case with chain 1337 and source `b` matches.
- `hot` and `cold`, `power` and `epoch` come from the wording of the deposit and validator set packets. The bytes only show two address lists, a u64 list and a u64 word.
- The empty set at `0x374e8a0` looks like the case where the caller has no stored set, which fits #909. Nothing here shows when it happens.
- The six arms with no caller look left over from the bridge contract ABI. A caller through another route is not ruled out, because a body inlined elsewhere could reach the same text. The inlined chain id sites at `0x22af76e` and `0x3341cb9` are not read here.

## Implementation and comparison

Not yet implemented. A Rust version should reproduce `vectors.tsv` and `worked_words.tsv`. No Rust code or Cargo manifest is added.

## Results and limitations

| metric | value |
| --- | --- |
| Cases | 85 |
| Mismatches | 0 |
| Instructions stepped | 7,995,266 |
| Stepped / total: request builder `0x358ea60` | 122 / 137 |
| Stepped / total: payload hash `0x358de50` | 475 / 544 |
| Stepped / total: arm 4 hash `0x37db5d0` | 218 / 301 |
| Stepped / total: set adapter `0x37db0d0` | 167 / 267 |
| Stepped / total: arm 0 tokens `0x3c97de0` | 75 / 114 |
| Stepped / total: arms 1 to 3 tokens `0x3c97a70` | 64 / 94 |
| Stepped / total: arm 4 tokens `0x3c99df0` | 337 / 459 |
| Stepped / total: arm 5 tokens `0x3c9a570` | 74 / 104 |
| Stepped / total: arm 6 tokens `0x3c9f240` | 343 / 465 |
| Stepped / total: arm 7 tokens `0x3c97be0` | 68 / 110 |
| Stepped / total: address and hash pair `0x3814080` | 65 / 97 |
| Stepped / total: role name `0x365e370` | 11 / 11 |
| Stepped / total: chain name `0x1650530` | 18 / 22 |
| Stepped / total: digest wrapper `0x37f2940` | 25 / 117 |
| Stepped / total: typed hash `0x38eff30` | 129 / 165 |
| Stepped / total: Agent struct hash `0x13f13d0` | 163 / 224 |
| Stepped / total: byte concat `0x38139c0` | 68 / 98 |
| Stepped / total: contract book builder `0x1405720` | 384 / 854 |
| Stepped / total: name and address parse `0x14ca560` | 118 / 137 |
| Stepped / total: namespace insert `0x14cbd80` | 90 / 127 |
| Stepped / total: namespace map from pairs `0x14bf3a0` | 68 / 107 |
| Stepped / total: domain separator `0x1594080` | 442 / 685 |
| Stepped / total: ABI writer `0x1592160` | 95 / 146 |
| Stepped / total: ABI head size `0x1592460` | 37 / 46 |
| Stepped / total: ABI tail size `0x15924e0` | 44 / 70 |
| Stepped / total: token sort `0x158fb50` | 65 / 78 |
| Stepped / total: token iterator `0x158fc70` | 88 / 197 |
| Stepped / total: token writer `0x1591f20` | 135 / 151 |
| Stepped / total: Keccak absorb `0x4f59a10` | 192 / 266 |
| Stepped / total: Keccak squeeze `0x4f59e40` | 63 / 171 |
| Stepped / total: Keccak permutation `0x4f59480` | 354 / 354 |
| Mutants killed / survived / unreached | 912 / 164 / 467 |

Survivors are labelled by class in `mutations.tsv`, not proven one by one. Most are Vec and token list capacity words on the stack that this path never reads again, a squeeze length one byte longer than the 32 bytes the caller keeps, and bookkeeping in the book parse that fixed text cannot show. A survivor means these cases cannot tell, not that the instruction has no effect.

Limits:

- Rows are placed in a fixture tree in the order given, so nothing here shows which row field the tree sorts on. Only the reverse walk is shown.
- `0x1405240` is a stub that reads the book produced by the real builder. Its body and panic text are out of scope.
- The file check and reader are stubs. A stub table has one leaf, so the deep B-tree descents in `0x1405720` are the main unreached mutants there.
- Allocation failure and panic arms are not run. The error path in `0x37f2940`, with the five texts at `0x2602c0` to `0x26034c`, is not run. No input here reaches it.
- The domain separator `0x1594080` runs with this one domain shape only, and its other arms are not run.
- Keccak runs on real bytes for the cases. Mutants use the specification permutation for speed, so a mutant is never inside `0x4f59480`.
- Hash inputs match the specification, but the specification was corrected once, for the reverse row order, after reading output.

No gate is requested.

Next question: what do the inlined request sites at `0x22ae8a0` and `0x3341af0` sign, and do they reach any of the six arms with no caller?
