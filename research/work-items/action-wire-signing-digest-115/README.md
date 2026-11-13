# action-wire: reconstruct the node #115 user-signed action EIP-712 digest wrappers (38 of 40 actions)

With this packet the complete signing digest of 38 user-signed Hyperliquid actions in node #115 can be recomputed in plain Python from a field list: `digest = keccak256(0x1901 || domainSeparator(chainId) || keccak256(typeHash || word_1 || ... || word_n))`, with the fixed domain `EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)` = (`HyperliquidSignTransaction`, `1`, chain id, zero address), the chain label table (`Local`, `Sandbox`, `Testnet`, `Mainnet`), the per-action selector tables (governance category and vote, abstraction kind) and the exact record layout (which record byte feeds which signed field) of each wrapper. Every one of 2673 fuzzed records was run through the original wrapper bytes and the 32-byte result equals the independent Python digest (13 of them with the binary's own Keccak bodies running instead of a model).

- Component ID: `action-wire` (Action wire and signing: signing payloads and domains). Task text: "Recover tags, signing domains, replay checks and error precedence" - this packet recovers the signing domain and digest path; replay (nonce) checks and error precedence are not covered.
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (the tool refuses any other input before reading it).
- Source commit / reference commit: repository `main` when the packet was made. No reference source text was used; every name, number and offset below comes from the binary or from bytes the interpreter produced.
- Claim status:
  - Observation: the 40 (wrapper, hash function, builder) triples of the relocated slot table `0x64ea840..0x64eab28`, the record bytes each wrapper reads (logged during execution), the strings absorbed by the sponge, the digests produced by the original code.
  - Inference: that the 32-byte output is the EIP-712 digest of the action (it equals the independent reference for all cases, which makes the inference strong but it rests on the interpreter, see Limits); that the byte at the selector offset is an index into a label table.
  - Unresolved: the dyn-callback actions (below), the callers of the wrappers, the replay checks, which error the tag byte 1 carries.
- Scope included: 40 slot triples found structurally, 38 resolved; per resolved action the layout, selectors, encodeType, domain, final preimage and digest. Scope excluded: the ECDSA recovery that consumes the digest, nonce handling, the multi-sig envelope `SendMultiSig` (builder `0x3bca050`, a different table), callers.

## Reproduce

From the repository root, Python 3 standard library only (plus `tools/elf_index.py` and `tools/fde_extents.py`); no binutils, no subprocess; the binary is only read, never executed.

```
python3 tools/action_wire_signing_digest_115.py --out research/work-items/action-wire-signing-digest-115
python3 -m unittest tests.test_action_wire_signing_digest_115
```

One regeneration takes about 2.5 minutes and well under 1 GB; two regenerations into different folders (and under other hash seeds) give byte-identical files. Cases are run one at a time and only counters are kept. `MANIFEST.sha256` lists every file of this folder.

| File | Rows | Content |
| --- | ---: | --- |
| `layouts.tsv` | 196 | per action and field: record offset, type/kind, the raw (offset, width) reads that produced it |
| `actions.tsv` | 38 | per action: wrapper, chain-id offset, selector tables, zero-record step count, encodeType string |
| `selectors.tsv` | 176 | value -> label for every one-byte selector (chain, vote choice, proposal category, abstraction) |
| `updates.tsv` | 348 | per action: the byte strings the sponge absorbed for one sample record, in order, classified |
| `cases.tsv` | 2673 | one row per run: mode (`fast` or `real`), chain selector, chain id, digest, match |
| `callees.tsv` | 117 | the callees promoted from stubs to real bodies while learning (address, FDE size) |
| `labels.tsv` | 5 | the chain label table read from the image |
| `negatives.tsv` / `equivalent-mutants.tsv` | 39 / 4 | every negative control and the three equivalent byte edits with reasons |
| `summary.json`, `measure.json` | 1 | counts |

## Evidence

Coordinates are virtual addresses of the PIE image; `.text` file offset = VA - 0x1000 here, `.rodata` identity.

**The slot table.** `.rela.dyn` RELATIVE relocations fill the 8-byte slots `0x64ea840..0x64eab28` with code addresses. Every wrapper reaches its hash function and every hash function reaches its type builder through `call *slot(%rip)`. A fixed-pattern scan of `.text` for `ff 15 disp32` whose target is a table slot gives the call graph with no disassembler: for each builder slot exactly one caller (the message-hash function), that function is held by exactly one other table slot, and that slot has exactly one caller (the wrapper). 40 such triples exist; the first is the `CWithdraw` wrapper `0x442f740` -> hash `0x43ce420` -> builder `0x43cea10`; the `UsdSend` triple is `0x44338b0` -> `0x43d2b20` -> `0x43d3130`.

**What a wrapper does** (`UsdSend`, `0x44338b0..0x4433c1b`, read through the interpreter and checked against the strings it absorbs): allocate the 26-byte domain name and 1-byte version, build the domain record from the 32 record bytes at `+0x30` (little-endian chain id), call the domain digest `0x169e950` through slot `0x64e2178`, call the hash function through slot `0x64ea890`, join `0x1901 || domain || struct` with `0x44e5db0`, absorb it through the update slot `0x64e0148`, squeeze 32 bytes through the finalize slot `0x64e0150` and return the tag byte 0 plus the digest (tag 1 plus an error payload when the hash function fails).

**Layout probing.** The tool runs each wrapper on a zero record while logging the (offset, width) of every read of the record. Reads before the domain call are the chain id (always one 32-byte block), reads between value-constructor calls (`0x169f9c0`, slot `0x64e0138`) belong to successive signed fields. A string field reads its length at record offset `o+16` (the record holds `{cap, ptr, len}`), an address field reads 16+4 bytes, `uint64` 8, `bool` 1 and `bytes32` 2x16; a string-typed field that reads exactly one byte is a selector. The encodeType string is not typed in: it is the first absorbed string that starts with `HyperliquidTransaction:`, produced by the binary's own formatter. Selector labels are learned by running selector value 0, 1, 2, ... and taking the first absorbed string that changes, until the wrapper stops accepting values.

**Selector tables** (`selectors.tsv`): chain `0 Local, 1 Sandbox, 2 Testnet, 3 Mainnet` (identical to the table read statically from `0x648e198` / `0x458700`), vote choice `yes, no, abstain`, proposal category `accelerated, constitutional, ecosystem, electoral`, abstraction kinds as listed in the file.

**Resolved actions** (record offsets are in `layouts.tsv`):

| Action | Wrapper | Hash fn | Builder | Chain id offset | Fields in signed order |
| --- | --- | --- | --- | --- | --- |
| `CWithdraw` | `0x442f740` | `0x43ce420` | `0x43cea10` | `0x0` | hyperliquidChain:string, payloadMultiSigUser:address, outerSigner:address, wei:uint64, nonce:uint64 |
| `SendAsset` | `0x4430f50` | `0x43ceec0` | `0x43cf850` | `0x90` | hyperliquidChain:string, payloadMultiSigUser:address, outerSigner:address, destination:string, sourceDex:string, destinationDex:string, token:string, amount:string, fromSubAccount:string, nonce:uint64 |
| `GovPropose` | `0x442f3d0` | `0x43cfec0` | `0x43d0740` | `0x30` | hyperliquidChain:string, payloadMultiSigUser:address, outerSigner:address, title:string, description:string, category:string, nonce:uint64 |
| `CUserModify` | `0x4430500` | `0x43d1670` | `0x43d1c50` | `0x0` | hyperliquidChain:string, payloadMultiSigUser:address, outerSigner:address, extendLongTermStaking:bool, nonce:uint64 |
| `GovVote` | `0x4431640` | `0x43d1fd0` | `0x43d2680` | `0x0` | hyperliquidChain:string, id:bytes32, choice:string, nonce:uint64 |
| `UsdSend` | `0x44338b0` | `0x43d2b20` | `0x43d3130` | `0x30` | hyperliquidChain:string, destination:string, amount:string, time:uint64 |
| `ApproveAgent` | `0x442f060` | `0x43d3610` | `0x43d3c70` | `0x18` | hyperliquidChain:string, payloadMultiSigUser:address, outerSigner:address, agentAddress:address, agentName:string, nonce:uint64 |
| `TokenDelegate` | `0x44312d0` | `0x43d4360` | `0x43d4a40` | `0x0` | hyperliquidChain:string, payloadMultiSigUser:address, outerSigner:address, validator:address, wei:uint64, isUndelegate:bool, nonce:uint64 |
| `CDeposit` | `0x442e980` | `0x43d5340` | `0x43d5840` | `0x0` | hyperliquidChain:string, wei:uint64, nonce:uint64 |
| `SpotSend` | `0x4432400` | `0x43d5b60` | `0x43d6220` | `0x48` | hyperliquidChain:string, destination:string, token:string, amount:string, time:uint64 |
| `Withdraw` | `0x4430870` | `0x43d6b60` | `0x43d7170` | `0x30` | hyperliquidChain:string, destination:string, amount:string, time:uint64 |
| `CWithdraw` | `0x4435b50` | `0x43d7c40` | `0x43d8140` | `0x0` | hyperliquidChain:string, wei:uint64, nonce:uint64 |
| `LinkStakingUser` | `0x4435ec0` | `0x43d83c0` | `0x43d8a10` | `0x0` | hyperliquidChain:string, payloadMultiSigUser:address, outerSigner:address, user:address, isFinalize:bool, nonce:uint64 |
| `SendAsset` | `0x44331c0` | `0x43d9000` | `0x43d98a0` | `0x90` | hyperliquidChain:string, destination:string, sourceDex:string, destinationDex:string, token:string, amount:string, fromSubAccount:string, nonce:uint64 |
| `UsdClassTransfer` | `0x4436230` | `0x43da2a0` | `0x43da950` | `0x18` | hyperliquidChain:string, payloadMultiSigUser:address, outerSigner:address, amount:string, toPerp:bool, nonce:uint64 |
| `ApproveBuilderFee` | `0x44319b0` | `0x43dad60` | `0x43db410` | `0x18` | hyperliquidChain:string, payloadMultiSigUser:address, outerSigner:address, maxFeeRate:string, builder:address, nonce:uint64 |
| `GovPropose` | `0x44357e0` | `0x43db810` | `0x43dbfa0` | `0x30` | hyperliquidChain:string, title:string, description:string, category:string, nonce:uint64 |
| `UserDexAbstraction` | `0x4435470` | `0x4426e90` | `0x44274e0` | `0x0` | hyperliquidChain:string, payloadMultiSigUser:address, outerSigner:address, user:address, enabled:bool, nonce:uint64 |
| `UserSetAbstraction` | `0x4432770` | `0x44278e0` | `0x4427f40` | `0x0` | hyperliquidChain:string, payloadMultiSigUser:address, outerSigner:address, user:address, abstraction:string, nonce:uint64 |
| `UserPortfolioMargin` | `0x4433540` | `0x44297f0` | `0x4429e40` | `0x0` | hyperliquidChain:string, payloadMultiSigUser:address, outerSigner:address, user:address, enabled:bool, nonce:uint64 |
| `CUserModify` | `0x4436910` | `0x442a240` | `0x442a730` | `0x0` | hyperliquidChain:string, extendLongTermStaking:bool, nonce:uint64 |
| `ApproveAgent` | `0x442e610` | `0x442b240` | `0x442b7a0` | `0x18` | hyperliquidChain:string, agentAddress:address, agentName:string, nonce:uint64 |
| `ConvertToMultiSigUser` | `0x4431d20` | `0x442baa0` | `0x442c0d0` | `0x18` | hyperliquidChain:string, payloadMultiSigUser:address, outerSigner:address, signers:string, nonce:uint64 |
| `TokenDelegate` | `0x4434a00` | `0x442c450` | `0x442ca30` | `0x0` | hyperliquidChain:string, validator:address, wei:uint64, isUndelegate:bool, nonce:uint64 |
| `ConvertToMultiSigUser` | `0x442e2a0` | `0x443c780` | `0x443ccc0` | `0x18` | hyperliquidChain:string, signers:string, nonce:uint64 |
| `Withdraw` | `0x442ecf0` | `0x4503770` | `0x4503e70` | `0x30` | hyperliquidChain:string, payloadMultiSigUser:address, outerSigner:address, destination:string, amount:string, time:uint64 |
| `StakingLinkDisableTradingUser` | `0x442fab0` | `0x443d650` | `0x443db40` | `0x0` | hyperliquidChain:string, tradingUser:address, nonce:uint64 |
| `GovVote` | `0x442fe20` | `0x44ffa30` | `0x45001d0` | `0x0` | hyperliquidChain:string, payloadMultiSigUser:address, outerSigner:address, id:bytes32, choice:string, nonce:uint64 |
| `UsdClassTransfer` | `0x4430190` | `0x44377a0` | `0x4437d50` | `0x18` | hyperliquidChain:string, amount:string, toPerp:bool, nonce:uint64 |
| `LinkStakingUser` | `0x4430be0` | `0x4436d70` | `0x44372e0` | `0x0` | hyperliquidChain:string, user:address, isFinalize:bool, nonce:uint64 |
| `UserDexAbstraction` | `0x4432090` | `0x443a790` | `0x443ad00` | `0x0` | hyperliquidChain:string, user:address, enabled:bool, nonce:uint64 |
| `UserPortfolioMargin` | `0x4432ae0` | `0x443b950` | `0x443bec0` | `0x0` | hyperliquidChain:string, user:address, enabled:bool, nonce:uint64 |
| `UsdSend` | `0x4432e50` | `0x4500670` | `0x4500d70` | `0x30` | hyperliquidChain:string, payloadMultiSigUser:address, outerSigner:address, destination:string, amount:string, time:uint64 |
| `StakingLinkDisableTradingUser` | `0x4433c20` | `0x4438050` | `0x4438640` | `0x0` | hyperliquidChain:string, payloadMultiSigUser:address, outerSigner:address, tradingUser:address, nonce:uint64 |
| `CDeposit` | `0x4434320` | `0x4501a30` | `0x4502020` | `0x0` | hyperliquidChain:string, payloadMultiSigUser:address, outerSigner:address, wei:uint64, nonce:uint64 |
| `UserSetAbstraction` | `0x4434690` | `0x443b000` | `0x443b560` | `0x0` | hyperliquidChain:string, user:address, abstraction:string, nonce:uint64 |
| `SpotSend` | `0x4435100` | `0x4502910` | `0x45030d0` | `0x48` | hyperliquidChain:string, payloadMultiSigUser:address, outerSigner:address, destination:string, token:string, amount:string, time:uint64 |
| `ApproveBuilderFee` | `0x44365a0` | `0x44389c0` | `0x4438f80` | `0x18` | hyperliquidChain:string, maxFeeRate:string, builder:address, nonce:uint64 |

**Unresolved** (2):

- wrapper `0x4433f90` (hash function `0x4428520`, builder `0x44290c0`): probe-failed:Halt
- wrapper `0x4434d70` (hash function `0x44396b0`, builder `0x443a170`): probe-failed:Halt

The hash function of these two calls a trait object (`call *(%rax)` at `0x44289ca` in the first) with a vtable taken from the record; a zero record cannot supply one, so no layout was derived and no digest claim is made.

## Implementation and comparison

`tools/action_wire_signing_digest_115.py` has two parts. Part 1 is a copy of the offline x86-64 interpreter used by other packets (Image, decoder, Memory, Machine; instruction decoding and execution verified elsewhere); it was changed in one message string only. Part 2 is this packet: `Rig` serves the allocator slots (`0x64df480` alloc, `0x64df4a0` free, `0x64df580/588` realloc, `0x64df590` aligned alloc) and the libc `memcpy`/`memmove`/`memset` imports (found through `.dynsym`, GLOB_DAT) with small Python models, serves the Keccak update/finalize slots with a Python sponge in `fast` mode or runs the real bodies in `real` mode, and promotes every other callee that the byte path reaches to a real body (`learn`, 117 bodies, `callees.tsv`). `probe` derives the layout, `make_case` builds a record from random values (string lengths include 0, 1, 2, 19, 20, 42, 43, 64), `reference_digest` is the independent EIP-712 computation (own Keccak-256, original padding, tested on known vectors), and `case_matches` compares the two.

Runs: 2660 `fast` runs (70 per action) plus 13 `real` runs (every third action, the original sponge permutation executed, roughly 10^5 interpreted instructions per run against roughly 10^4 in `fast` mode) = **2673 cases, 2673 matching**. The `real` runs also check that the Python sponge used in `fast` mode is the same function as the binary's sponge on the absorbed data.

Negative controls (**39**, 36 detected, 3 equivalent): 15 wrong references (domain name, version, type string, chain id +1, wrong prefix, dropped or swapped fields, unhashed string, little-endian integer, no domain, retyped field, reversed label table), 7 wrong layouts (shifted string, chain id, selector and uint64 offsets, reversed address bytes, inverted bool, rotated selector labels), 12 single-byte corruptions of the original image (domain version byte, join record count, domain record offset, selector and time read offsets in the hash function, sponge rate immediate, the `0x1901` literal bytes, a domain-name literal byte, and the three equivalent edits below), 4 entry points outside a function (mid-function, the hash function alone, unmapped, past the image) and a wrong binary digest. Equivalent edits (`equivalent-mutants.tsv`): a larger domain-name allocation, a 33-byte squeeze length and a 225-byte state copy, each unchanged in output with the reason recorded; the last two are observed on the real sponge, not proven for all paths.

## Results and limitations

Metrics (`measure.json`, `summary.json`): cases 2673, matched 2673; real-sponge cases 13/13; negative controls 39, detected 36, equivalent 3; actions found 40, resolved 38.

Limits:
- The interpreter is a subset interpreter written for these bytes; allocator and libc routines are modelled, everything else on the path runs as original bytes. Agreement of the original bytes with an independent EIP-712 computation is strong evidence of the digest recipe but is not proof that the Rust compiler's source intent is recovered, and no Rust implementation is claimed.
- Layouts were derived from reads on a zero record; a field read only conditionally (for example behind a non-empty check on a pointer) would be missed, but a missed or misplaced field makes the digests differ, and none do.
- The wrappers' callers, the signature recovery, nonce replay checks and the error precedence between them are not covered. The `action-wire` gates need those paths too; no gate is requested.
- The domain `verifyingContract` is zero and the salt is absent in every wrapper; the chain id is whatever the record carries (little-endian 32 bytes).

Next question: the callers of the 40 wrappers (where the chain id at record offset `+0x30` and the selector bytes come from), the signature check that consumes the digest, and the nonce-set checks of tags 203/204/205 and 93/96/97 that decide the order of replay rejection against signature rejection.
