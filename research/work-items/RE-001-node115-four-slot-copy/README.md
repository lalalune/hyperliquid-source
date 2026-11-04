# RE-001: four-slot-back copy in node #115

- Component: function map; the owning subsystem and source name are unresolved.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`; no external reference source is used.
- Bounded question: what does the complete leaf at `0x50b4950` do to the state and return byte?

**Answer.** Given valid nonaliasing state and storage, let `n` be the unsigned 64-bit word at state+0x30 and `base` the pointer at state+0x28. If `4 <= n <= 1023`, it copies the 32 bytes at `base + 32*(n-4)` to `base + 32*n`, writes `n+1` at state+0x30, and returns AL=0. Otherwise it returns AL=0x2d without loading the base pointer or writing memory. Failure writes only AL: the remaining RAX bits must not be interpreted as zero. This describes raw operations, not an identified original API, data type, protocol, or error meaning.

## Evidence and reasoning

All addresses are original ELF virtual addresses. The unique FDE covers `0x50b4950..0x50b498a` (file offset `0x50b3950`), FDE VA/offset `0xf4eb80`, CIE VA/offset `0xca6ed8` (`zR`, no LSDA). The body SHA-256 is `745039b56f68ed673f28a26354add48e3ca6b593130f226c8a4b737df16096f5`. Six following INT3 bytes end at the next aligned entry. The unique FDE, complete decoded paths with two returns, and following padding support this bounded entry/extent, not a general assertion that all FDEs define functions.

Packet counts: 58 bytes; 16 instructions; 0 callees; 0 direct rel32 candidates; 6 padding bytes.

`records.json` contains every instruction address, original bytes, and decoding in execution order. The unsigned comparison tests `(n-4) mod 2^64 <= 0x3fb`; this holds exactly for `4..1023`. The taken `ja` reaches the failure return. On success the shift scales the index by 32; the two 16-byte loads at offsets -0x80 and -0x70 precede both stores at offsets +0x10 and +0, followed by the index write and zero return. Under the stated validity assumptions this is a 32-byte copy from four slots back. The input state word is readable; the storage ranges are readable/writable and address arithmetic is valid, and neither storage range aliases the state words. The two slots themselves are disjoint. Faults, invalid pointers, unusual aliasing, and concurrency are excluded.

There are no calls, tail calls or indirect dispatch in the body, hence no callee behavior or extent to resolve. A complete bytewise scan of `.text` `[0x1419300,0x63f0a00)` for `e8` and `e9` rel32 encodings targeting the entry found no candidates. This scan includes non-instruction bytes, and cannot identify indirect callers or prove instruction boundaries. A `R_X86_64_RELATIVE` relocation at slot `0x649f2b8` has addend `0x50b4950`; its presence supports a possible indirect reference but proves neither actual dispatch nor a caller's identity. No source Location or first-party ownership is established.

## Novelty

Before analysis, these commands returned no matches (exit status 1):

```sh
rg -i -n '50b4950|84625744' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

The body has no callees whose behavior requires a separate novelty search. These local title lists are not a complete global claim registry.

## Reproduction and controls

From the repository root on Linux with Python 3.10+ (observed Python 3.13.5), using the authenticated artifact as static input:

```sh
python3 tools/node115_four_slot_copy.py --out research/work-items/RE-001-node115-four-slot-copy/
python3 -m unittest tests.test_node115_four_slot_copy -v
python3 research/work-items/RE-001-node115-four-slot-copy/verify.py
make verify
make catalogue-check
```

The generator checks the full target digest before output, parses ELF sections and unwind records with repository Python modules, validates each exact instruction encoding and branch, checks the relocation, and regenerates `records.json` byte-identically. It uses no disassembler or target execution. The packet verifier checks a fixed file whitelist and SHA-256 manifest. Tests include wrong public digest, changed instruction, shifted FDE, changed relocation target, synthetic direct-call target discrimination, boundary vectors and README counts. The small independent model expresses the rule; its vectors derive from the decoded bounds and are not differential node execution.

No implementation build, byte comparison or normalization is claimed. No whole-node equivalence, component gate, original function name, reachable caller, runtime ABI beyond the observed registers, production error semantics or application ownership is established. CIE/FDE and relocation are static metadata, not runtime observations; no captured executable, network or chain operation is run. Next, identify the owner and consumers of the relocation table and validate its surrounding dispatch context before assigning a higher-level meaning.
