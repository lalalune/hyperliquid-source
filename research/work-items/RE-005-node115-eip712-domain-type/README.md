# Node #115 EIP-712 domain type-string fragments

- Component: `action-wire` (RE-005), partial static research.
- Target: Linux x86-64 node #115, SHA-256
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base: `0781ce04826eeefd89fe336cb8ea073be0c1de30` (`origin/main`).
- Related scope: [issue #3912](https://github.com/lalalune/hyperliquid-source/issues/3912).
- Claim status: instruction and byte observations below; interpretation is
  deliberately limited. No component gate is requested.

## Bounded question

Which EIP-712 domain type-string fragments are visibly emitted by one #115
unwind-described code range? This supplements the open action-typed-data
packet (#5398), whose limits explicitly exclude the signing domain object.
It does not close #3912's first step (a complete action preimage and digest
chain).

## Observations

The retained `fde.tsv` row places the range at
`[0x169e950, 0x169f713)` in ELF virtual addresses, `.text`, size 3,523 bytes.
An FDE is an unwind-described range; this packet does **not** claim that the
range is a validated function boundary or that it covers every split/cold
part.

`domain-fde.objdump` preserves the complete Intel-syntax disassembly captured
from the range. Selected instruction/data anchors:

| Address | Byte-backed observation |
| --- | --- |
| `0x169e988`, `0x169e997` | `movabs` immediates are stored at output offsets that spell `EIP712Domain(`; the initial capacity is 13 bytes. |
| `0x169ea54`, `0x169ea62` | Stored immediates spell `string name`. |
| `0x169ec15`, `0x169ec24` | Stored immediates spell `string version`. |
| `0x169edf1`, `0x169ee00` | Stored immediates spell `uint256 chainId`. |
| `0x169eee0`, `0x169eeed` | RIP-relative loads from `0x47b802` and `0x47b7f9`; target bytes at `0x47b7f9` start `address verifyingContract`. The instructions copy 25 bytes to the output. |
| `0x169efc4`, `0x169efd2` | Stored immediates spell `bytes32 salt`. |
| `0x169f07c` | Stores `)` at the current output index. |

The code tests byte `[r15+0x58]` before the `verifyingContract` fragment and
byte `[r15+0x6d]` before the `salt` fragment. These are observed conditions;
the input object's field names, ABI, caller and values are not recovered here.
Repeated indirect calls target slots `0x64e0148`, `0x64df508` (called with
length `0xe0`), and `0x64e0150` (called with output length `0x20`). Their
runtime bindings and semantics are not established, so this packet does not
label them as a type constructor, serializer or hash function.

## Reproduce

The captured binary is data only and was not executed. From the repository
root, first run `make verify` to check pinned inputs, then:

```sh
python3 tools/fde_extents.py --release 115 --output-dir work/domain-fde-replay
rg '^0x169e950\b' work/domain-fde-replay/node-115-fde.tsv
python3 research/work-items/RE-005-node115-eip712-domain-type/collect.py
python3 -m unittest tests.test_node115_eip712_domain_type -v
objdump -d --x86-asm-syntax=intel \
  --start-address=0x169e950 --stop-address=0x169f713 \
  artifacts/node/115/hl-node
```

The stored disassembly was produced on macOS with Apple LLVM objdump 21.0.0.
The extent decoder output binds to the target digest. A different disassembler
may format the transcript differently; verify the instruction bytes and
addresses, not textual formatting. The exact range row and full transcript
are retained in this packet. The collector checks the pinned target digest,
unique FDE range, selected code bytes and rodata literal. Four focused tests
cover a positive replay, wrong-target digest, code-byte corruption and rodata
corruption. This is an evidence checker, not an instruction semantic analyzer.

## Limits and next question

This does not establish which action selects the domain, domain values, final
type hash, chain separation, digest algorithm, signature verification,
replay/nonce checks, or caller/callee closure. It is not a complete signing
preimage and no Rust implementation or behavior vector is claimed. Next:
trace the callers and close one action's domain inputs through its verified
message-data digest, without using private keys.
