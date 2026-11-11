# action-wire: reconstruct the node #115 user-signed action typed-data struct builders (41 functions, 21 actions)

With this packet the EIP-712 signing structs of every user-signed Hyperliquid action in node #115 can be rebuilt from byte evidence: for all 41 builder functions the primary type name (`HyperliquidTransaction:<Action>`), the ordered field names and the field types (string, address, bool, uint32/uint64, bytes32, bytes), including the multi-sig variants that insert `payload_multi_sig_user` and `outer_signer` after `hyperliquidChain` and the `SendMultiSig` envelope that signs `multi_sig_action_hash`. From them the exact encodeType string and its keccak-256 type hash are fixed (`eip712.tsv`), and the failure behaviour of each builder (one 16-byte allocation, an allocation failure aborts before the constructor is reached) is pinned. The original machine code of each builder was run in an interpreter for the x86-64 subset it uses, 10,715 times under varied stack garbage, return-slot placement and allocation failures, and every run equals an independent reconstruction; 41/41 negative controls are detected.

- Component ID: `action-wire` (Action wire and signing: signing payloads). Task text: "Recover tags, signing domains, replay checks and error precedence" - this packet recovers the signing-domain structs. Replay checks (nonce handling) and error precedence are not covered.
- Target release and full SHA-256: Linux x86-64 node #115, `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (the tool refuses any other input before reading it).
- Source commit / reference commit: repository `0781ce048` (origin/main when the packet was made). No reference source text was used or copied; every name and number below comes from the binary.
- Claim status:
  - Observation: the 41 function extents, the pieces-slice relocations, every field-name literal (bytes, lengths, order), the record layout written to the stack, the type words and payloads handed to the struct constructor, the allocation sizes, call sequences and the stored result.
  - Inference: that the constructor argument is an EIP-712 struct definition and that type words 0/1/3/4/5/7 mean address/bytes/uintN/bool/string/bytesN (see Limits); the model of callees.
  - Unresolved: the callee bodies, the module that hashes and signs the structs, and the call sites of the 41 builders.
- Scope included: the 41 builder functions (FDE extents) found by their reference to the `HyperliquidTransaction:` format-pieces slice (`0x6475948`, one copy; `0x6488038`, 40 copies), the shared `&str` to `String` helper contract, the allocation-failure path and the cleanup loop.
- Scope excluded: the format helper, the constructor and the drop helpers (modelled by their arguments only), signing, hashing of message data, replay and nonce checks, the callers.

## Reproduce

From the repository root, Python 3 standard library only (plus `tools/elf_index.py` and `tools/fde_extents.py`), no binutils, no subprocess, the capture is never executed:

```
python3 tools/action_wire_typed_data_115.py --out research/work-items/action-wire-typed-data-structs-115
python3 -m unittest tests.test_action_wire_typed_data_115
```

The tool checks the SHA-256 first and rewrites the eight generated files (all but this README) listed in `MANIFEST.sha256`. A run takes about one minute and well under 1 GB; two runs into different folders, and runs under other hash seeds and time zones, give byte-identical files. Case outcomes are compared one at a time and only counters are kept.

| File | Rows | Content |
| --- | ---: | --- |
| `functions.tsv` | 41 | per builder: extent, pieces slot, action name, record flag byte, field count, steps, executed instructions |
| `fields.tsv` | 219 | per builder and field: name, type word, payload, solidity type |
| `eip712.tsv` | 41 | encodeType string and keccak-256 type hash |
| `literals.tsv` | 178 | per call to the string helper: literal address, length, name, call-order agreement |
| `cases-sample.tsv` | 328 | outcome of seeds 0 and 1 of every variant (the full run has 64 seeds) |
| `negatives.tsv` | 41 | every negative control and whether it was detected |
| `summary.json` | 1 object | counts, per-variant matches, type-word histogram, action names |
| `measure.json` | 1 object | `cases`, `negative_controls`, `negative_detected` |

## Evidence

Coordinates are virtual addresses of the PIE image (`.text` file offset = VA - 0x1000, `.rodata` identity).

**Finding the builders.** The string `HyperliquidTransaction:` (23 bytes, `.rodata` `0x7b97b8` and `0x7d053c`) is referenced only through two `&str` slots in `.data.rel.ro`, `0x6475948` and `0x6488038` (RELATIVE relocations; the slot is the first piece of a `format!("HyperliquidTransaction:{}", name)` argument block). A fixed-pattern scan for RIP-relative `lea` of these slot addresses inside `.text`, mapped to unwind extents, yields 41 functions: 1 for slot `0x6475948` (`0x3bca050`, 636 bytes) and 40 for `0x6488038` (`0x43cea10`..`0x4503e70`, 636 to 1,836 bytes each).

**What one builder does** (CDeposit, `0x43d5840`): `format` with the name record at `0x441511` (flag byte `0xc0`, length byte, bytes `CDeposit`) and the pieces slot; `alloc(0x10)`; copy of the 16 bytes `hyperliquidChain` from `0x455a90` into that buffer; the string helper on `wei` (3 bytes at `0x7d0575`) and `nonce` (5 bytes at `0x7d0578`); three 48-byte records (name String cap/ptr/len, type word, payload) assembled on the stack; the constructor called with (result slot, formatted name String, records, count 3); a zero tag byte and the 32 result bytes stored through the return pointer; a loop that, for each record, frees the name buffer (`dealloc(cap, 0)`) and drops the type (4 iterations counter, `cmp $1`). All 41 follow this layout; they differ only in literals, type words and record counts (3 to 12).

**Type words.** The record's type word is `0x8000000000000000 + k`: the histogram over the 219 records is k=0: 56, k=1: 2, k=3: 51, k=4: 12, k=5: 95, k=7: 3. Words 3 and 7 carry a payload (64 or 32 for k=3, 32 for k=7); for k=0, 1, 4 and 5 the payload slot is uninitialised stack padding, which is why the comparison zeroes it.

**Type hashes.** `eip712.tsv` lists the 41 encodeType strings, for example `HyperliquidTransaction:UsdSend(string hyperliquidChain,string destination,string amount,uint64 time)` (`0x43d3130`), and `HyperliquidTransaction:SendMultiSig(string hyperliquidChain,bytes32 multi_sig_action_hash,uint64 nonce)` (`0x3bca050`). The hash is Keccak-256 (original padding) implemented in the tool and checked against known vectors in the tests.

**Static cross-check.** Independently of the interpreter, a fixed-byte scan of each extent finds every `call` to the string helper (`0x41c5490`), the preceding RIP-relative `lea` and `mov $len,%edx`, and reads the literal from the image: 178/178 literal sites equal the names the interpreter saw, in the same order (41/41 functions also have the same multiset as the record table minus the first field).

## Implementation and comparison

`tools/action_wire_typed_data_115.py` has three parts: an x86-64 subset interpreter (push/pop, mov/lea/movabs, ALU and compare forms, movups/movaps, jcc/jmp, direct and GOT-indirect calls; any other opcode raises `Unsupported`); a pure reconstruction `reconstruct(spec, variant)` from the decoded tables (type name, fields, alloc size, string-helper order, record rows, result digest, cleanup events, return tag); and the comparison loop. Callees are modelled by arguments: the string helper copies the literal into a fresh buffer and fills a String; the format helper concatenates the prefix and the name record; the allocator returns a bump pointer (or null on demand); the constructor reads count records from memory and stores a SHA-256 digest of the normalised records (the real result is not modelled). A GOT slot reads back as its own address, which names the modelled callee.

Per builder, 4 variants x 64 seeds are run: `ok`, `ok-shifted` (return slot moved by 0x40), `alloc-fail-0` (the 16-byte allocation returns null, the function must stop at the allocation-failure call with no constructor call) and `alloc-fail-1` (no second allocation exists, so the result must equal the clean run). Seeds change the initial stack garbage and the callee-saved registers, which must be restored with `rsp` and `rax == return slot`. Totals: 41 x 256 = 10,496 runs, plus 178 literal-site checks and 41 call-order checks = 10,715 cases, 10,715 matching.

Negative controls (41, all detected): 13 wrong reconstructions (wrong prefix, wrong allocation size, missing allocation-error event, reversed fields, dropped last field, wrong integer width, bool read as string, wrong first field name, swapped literal order, wrong count, wrong hash, missing cleanup, wrong return tag) plus 2 on other structs; 20 single-byte corruptions of the original code (string length immediate, allocation size, record count, payload width immediate) in five functions; 6 out-of-range starts (mid-function, the string helper, unmapped, a rodata address, past the image, null).

## Results and limitations

Metrics (`measure.json`, `summary.json`): cases 10,715, matched 10,715; negative controls 41, detected 41; 41 functions, 21 distinct action names, 219 fields.

Limits:
- The interpreter is a subset interpreter with modelled callees; the real format, constructor and drop helpers were not executed or reconstructed, so the claim is about each builder's own behaviour and the data it passes on.
- The meaning of type words is inferred from field names and the order of a common ABI type enum (address, bytes, int, uint, bool, string, array, fixed bytes); `GovVote.id` is a 32-bit-payload k=7 word read here as `bytes32` and could be a different fixed-size type until the consumer of the records is recovered. Word k=2 does not occur.
- The signing domain object (`HyperliquidSignTransaction`, chain id, verifying contract) is not part of these builders; `hyperliquidChain`, `payload_multi_sig_user`, `outer_signer`, `nonce`/`time` are only names here.
- No gate is requested. The `action-wire` gates need the signing, replay and error-precedence paths too.

Next question: which function consumes these records (the callee at the constructor slot `0x64e0158`), and where do the 41 builders get selected per action, so the hashing of message data and the replay/nonce check can be recovered.
