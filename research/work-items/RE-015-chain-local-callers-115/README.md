# RE-015: direct callers of the node #115 chain-name serializer copy

- Component: `constants`; bounded RE-015 caller census.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source/reference revision: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no inferred reference source was read or copied.
- Claim status: **observation** — direct `E8 rel32` calls to three previously reconstructed serializer entries, raw bytes, and the unique containing `.eh_frame` FDE for each caller site. **Inference / unresolved** — source names, owning structs, map-key literals, indirect callers, tail calls, and domain meaning.
- Bounded question: where are the direct relative-call sites for the three chain-name serializer copies, and which unwind ranges contain those sites?
- Scope: the file-backed `.text` section of the pinned node #115 artifact. This is a call-site census only; it does not claim that FDEs are complete function boundaries or establish caller ownership.

## Reproduce

From the repository root, with Python 3.10+ and the pinned artifact present:

```sh
python3 tools/re015_chain_local_callers_115.py --out research/work-items/RE-015-chain-local-callers-115
python3 -m unittest tests.test_re015_chain_local_callers_115
python3 research/work-items/RE-015-chain-local-callers-115/verify.py
```

The analysis reads the target file, parses ELF sections and `.eh_frame`, and scans `.text` bytes for `E8` plus signed rel32 destinations. It executes no captured code, starts no process, and accesses no network. Apple LLVM objdump 21.0.0 was used only to confirm that the candidate encodings are decoded as `callq` instructions; all candidates were covered by these focused disassemblies:

```sh
objdump -d -w --start-address=0x2406120 --stop-address=0x241351c artifacts/node/115/hl-node
objdump -d -w --start-address=0x2d3c1b0 --stop-address=0x2d404dc artifacts/node/115/hl-node
objdump -d -w --start-address=0x44b0670 --stop-address=0x44d185c artifacts/node/115/hl-node
objdump -d -w --start-address=0x53809d0 --stop-address=0x5380d94 artifacts/node/115/hl-node
objdump -d -w --start-address=0x53c6080 --stop-address=0x53cc190 artifacts/node/115/hl-node
objdump -d -w --start-address=0x591f180 --stop-address=0x5937bec artifacts/node/115/hl-node
```

The producer fails closed on a target digest mismatch, ambiguous `.text`, any changed call-site census, or a site that does not have exactly one containing FDE. Output is deterministic JSON. `records.json` preserves each site, five instruction bytes, and FDE start/end VAs.

## Evidence and results

All addresses are original ELF virtual addresses. The producer checked the complete file-backed `.text` range and found 52 direct calls: 17 to `0x2674b80`, 17 to `0x467f2d0`, and 18 to `0x57c1de0`. For each byte-scan candidate, signed displacement calculation resolves to the stated entry; focused GNU objdump output decodes all 52 sites as `callq` to that entry. Every site falls in exactly one recorded FDE. The records include the original instruction bytes and containing FDE boundaries.

The three entries are the chain-name serializer copies listed in the existing RE-015 chain-codec packet. The census does not identify the calling source routines or prove that the three groups correspond to three particular structs. In particular, it does not locate a map-key literal; that question remains open. A byte scan alone can match an `E8` byte inside another instruction, which is why the separate disassembly check is part of the evidence. Indirect calls, tail jumps, code outside file-backed `.text`, and functions without FDEs are not covered by this direct-call claim.

No Rust implementation, source equivalence, build, or component gate is claimed. This packet advances one caller-reference question for the `constants` work; the `constants` gate remains false. No progress gate is requested.

Next question: identify the key strings and serialization contexts at the containing call sites, while keeping FDE ranges separate from validated source-function boundaries.
