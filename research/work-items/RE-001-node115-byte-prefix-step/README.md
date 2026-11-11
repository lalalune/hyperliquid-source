# RE-001: node #115 byte-prefix step at `0x5434bb0`

- Component: serialization/foundation, RE-001 function binding. Base revision `05bc2de303c05525b71e7e257426e741bc66a390`; no external source revision or original function name is asserted. New material is independently authored under the repository's MIT license.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Question: given the cursor and count at input offsets `+0x10` and `+0x18`, what does this complete leaf write to its output for an empty input or the next byte?
- Answer: if count is zero it leaves the input unchanged, writes output byte 0 as zero and writes the runtime address corresponding to ELF VA `0x64b0270` at output `+8`; its output bytes 1 and 2 come from incoming register values. Otherwise it consumes exactly one byte, advances the cursor and decrements count. For byte `0xc0` it writes only output byte 0 as 9. For every other byte it writes 2 at byte 0, the pair in the table below at bytes 1 and 2, and that same address at `+8`. These statements assume valid readable input and writable, non-overlapping input/output storage, a valid stack/return address, and normal execution. The meaning of the pair and descriptor is not established.

| Input byte | Output byte 1 | Output byte 2 |
| --- | --- | --- |
| `00..7f` | `00` | byte |
| `80..8f` | `80` | byte & `0f` |
| `90..9f` | `90` | byte & `0f` |
| `a0..bf` | `a0` | byte & `1f` |
| `c1..df` | byte | byte & `1f` |
| `e0..ff` | `e0` | byte |

## Observations and extent

Original ELF virtual addresses are used throughout. The complete FDE is `0x5434bb0..0x5434c2f`, file offset `0x5433bb0`, FDE VA/file offset `0xf7dfbc`, CIE `0xca6ed8` (`zR`, no LSDA). Body SHA-256: `4a021dbd4e8c12f7758be77760ec0e777966aaf3de048ed2fbda0f3e27c1e4ec`. A `cc` byte separates the body from the next code. The FDE, contiguous instruction walk, local branch destinations, returns and padding support this extent; FDEs alone do not prove all function boundaries. Raw FDE/CIE and instruction bytes are retained in `records.json`.

Packet counts: 127 bytes; 49 instructions; 0 callees; 4 direct rel32 candidates; 1 padding bytes.

The walk tests the count first, branching directly to the empty return preparation. On nonempty input it reads `[cursor]`, advances and stores the cursor and remaining count, then tests the byte's high bit. The unsigned comparisons against `df`, `90`, `a0` and `c0`, and masks `0f` and `1f`, select the table entries. The `c0` equality path stores 9 and returns immediately; all other paths meet the shared stores at `0x5434c1a`. The empty path zeroes EAX but does not initialize EDX or ESI before those shared stores: byte 1 receives the incoming DL, and byte 2 the low byte of the incoming input-pointer register. The RIP-relative LEA resolves to ELF VA `0x64b0270` (plus the runtime load bias); it is stored as a pointer, and the data there is not interpreted or dereferenced by this leaf. All instructions are decoded as exact byte forms, with relative branch destinations checked against instruction starts; no call or indirect dispatch occurs, so there are no callee identities or extents to bind.

The complete `.text` bytewise `e8`/`e9` rel32 scan over `[0x1419300,0x63f0a00)` finds the call candidates `0x534f9b1`, `0x534fb6b`, `0x534ff57`, `0x5350475`. Their original bytes are in the JSON. This conservative scan may include unaligned coincidences and omits indirect calls; it does not prove reachability or complete caller behavior. The descriptor's source, contents and meaning are unresolved.

## Reproduction and novelty

Python 3.10+ standard library; no objdump dependency. From repository root, with the pinned artifact materialized:

```sh
python3 tools/node115_byte_prefix_step.py --out research/work-items/RE-001-node115-byte-prefix-step/
python3 -m unittest tests.test_node115_byte_prefix_step -v
python3 research/work-items/RE-001-node115-byte-prefix-step/verify.py
make verify
make catalogue-check
```

The producer authenticates the complete binary before output, validates ELF geometry and FDE/CIE, decodes the entire body strictly, checks the descriptor displacement and branch targets, checks padding and scans the whole `.text` section. There are no normalization masks. JSON contains semantic records and original bytes; the manifest verifier accepts only the listed packet files. Inspection used GNU objdump 2.44 for a focused independent view; regeneration and tests do not use it. Python 3.13.5 on Linux was used for the checks. No target binary, emulator, network or external state was executed or accessed.

Before selection, both searches below returned no matches (exit status 1); no callee behavior is bound:

```sh
rg -i '5434bb0' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
rg -i '88296368' research/ ../open_prs.txt ../merged_prs.txt ../closed_unmerged_prs.txt
```

## Controls, non-claims and next step

The focused tests check byte-identical regeneration, table boundary vectors, README counts and fail-closed controls for the public digest, a body byte, the FDE start, an actual caller displacement and the descriptor displacement. The standalone model represents the pointer by its ELF VA and describes only definite output writes and is not a target execution oracle. The empty path's other written bytes depend on incoming registers; `0xc0` leaves all other output bytes untouched. Invalid pointers, aliasing, exceptions, original source and types, complete codec or wire format, first-party ownership, caller effects, runtime behavior, a source build, binary equivalence and component-gate completion are not established. No gate is changed. Next, identify the descriptor and follow a caller's handling of the output before assigning protocol meaning to these byte ranges.
