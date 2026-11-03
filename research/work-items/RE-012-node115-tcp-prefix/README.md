# RE-012: node115 TCP prefix length, marker and local read outcomes

- Component: transport; RE-001 range validation supports this bounded RE-012 wire-path finding.
- Target: Linux x86-64 node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
- Reference implementation: none. No inferred or unlicensed source was used.
- Question: what prefix does the measured sender append before its payload, and what width, byte order, marker comparison and limit boundary does the measured reader use?
- Claim: static observations and their local arithmetic consequences only. No Rust implementation, full transport recovery, runtime compatibility or progress gate is claimed.

## Scope and original evidence

| Role | FDE half-open ELF VA range | Bytes | Instructions |
| --- | --- | ---: | ---: |
| Prefix read poll | `0x2b780d0..0x2b782d5` | 517 | 139 |
| Reader continuation | `0x2b788e0..0x2b79e2e` | 5,454 | 1,001 |
| Sender continuation | `0x2b7a290..0x2b7b523` | 4,755 | 914 |

The export denominator is **three complete FDE ranges, 10,726 bytes and 2,054 instructions**. It is not a denominator of understood, reconstructed or matching bytes. Only the selected prefix paths below are interpreted. The rest of each async body remains outside the semantic claim.

`records.json` contains file offsets, complete body hashes, original FDE/CIE bytes, LSDA identities, every direct-E8 and RIP-slot call in the three bodies, and the actual dynamic relocations of those RIP slots. GNU readelf independently confirms the FDE extents. The three raw objdump exports cover every byte of each range without normalization. `frames.txt` and `relocations.txt` preserve the selected native exports.

Relocated source Locations bind `net_utils/src/tcp/read.rs:35:13` at `0x644afc0` and `net_utils/src/tcp/write.rs:34:17` at `0x644b020`. Three actual LEA instructions in the measured reader/sender reference them. Path pointers, lengths and line/column fields are checked. These are diagnostic ownership observations, not recovered original function names or complete source files.

## Sender: five bytes precede the selected payload

At `0x2b7a6b5`, R13 is copied to RAX and shifted right by 32. Only a zero upper word branches to `0x2b7a702`; the other path calls the opaque error helper at `0x2a02640`. This accepts local payload counts through `0xffffffff`, not arbitrary u64 counts silently truncated to u32.

The accepted path allocates `R13+5`. At `0x2b7a72d`, `BSWAP R13D` precedes a DWORD store at the output start. On this little-endian target that writes the original accepted count in big-endian order. At `0x2b7a758`, R15B is stored separately at byte 4; the constructed length becomes five.

The next sequence reloads the retained payload pointer/count, checks the remaining capacity after subtracting five, and passes destination-plus-five, payload pointer and payload count to the call through `0x64df508`. That slot names the dynamic symbol `memcpy` in the authenticated ELF; its native relocation is retained. The final constructed length is five plus payload count. Thus the constructed length field describes the selected payload, excluding the prefix.

This does not determine how the upstream compression/selection path produced R15B or the selected payload. Its helper through `0x64e7798 -> 0x47855c0` remains open.

## Reader: raw marker retention, equality-to-one and an inclusive limit

The prefix poll zeroes its five-byte buffer at object `+0x50`, points the read descriptor at that buffer, and stores a span of five. On its local successful completion path at `0x2b78225`, it loads the first DWORD and applies `BSWAP ECX`. It loads byte `+0x54` with zero extension. Its output stores a zero DWORD at `+0`, the decoded count at `+4`, and the raw byte widened to a qword at `+8`.

The measured reader calls this poll at `0x2b78c42` and `0x2b78ec4`; these are the two calls **inside this measured reader**, not a whole-binary caller census. The first ready path zero-extends the count into R14. At `0x2b7903f`, it compares the reader's qword limit at `+0x28` with that count; `JAE` takes the accepted path. Equality is accepted. This is a configured local limit, not a discovered global maximum.

At `0x2b791c6`, `CMP BPL,1` followed by `SETE` stores the selected boolean. This is equality to one, **not** conversion of every nonzero raw byte to true. The preceding poll preserves the raw marker. No invalid-marker rejection is established at these instructions; values other than one produce false at this comparison. The nominal marker meaning and the complete subsequent decompression path remain unresolved.

## Poll outcomes and remaining boundaries

Both four-entry signed-relative poll dispatch tables are retained, and each target is a native instruction start inside the prefix poll. At the opaque provider call `0x5cdfa50`, an odd low return bit leads to output discriminator 2 and stored poll state 3. It does not execute the prefix-decode stores. The other path inspects RDX, and the completed span reaches the decode stores. A nonzero error value is passed to `0x2a026d0`. No progress while a span remains constructs an error using the literal `early eof` and the relocated helper at `0x64e0750`, then takes the error conversion path. The error outcome uses discriminator 1.

These are observed numeric states and branches. Provider ABI/type names, real socket behavior, scheduling, cancellation, unwind cleanup and inactive output bytes are not reconstructed. Allocation and error-helper semantics remain boundaries. No captured node, instruction emulator, socket, service, chain or signing operation is used.

## Reproduce and controls

Observed environment: Ubuntu 24.04 under WSL, Python 3.12.3 and GNU binutils 2.42. The full repository suite also uses Capstone 5.0.7, as pinned in `.github/workflows/verify.yml`; the packet collector itself uses only Python's standard library, existing repository parsers and GNU binutils.

From the repository root, after the standard pinned-input setup and the CI analysis dependencies:

```sh
python3 research/work-items/RE-012-node115-tcp-prefix/collect.py --check
python3 -m unittest discover -s tests -p test_node115_tcp_prefix.py -v
(cd research/work-items/RE-012-node115-tcp-prefix && sha256sum -c MANIFEST.sha256)
make doctor verify test catalogue-check
make reproduce
```

The collector authenticates the complete capture before creating output. GNU tools read a private byte-identical, non-executable snapshot. Tool versions are retained in `tool-versions.json`; outputs use UTF-8/LF and sanitized artifact paths. The Python collector and GNU tools independently validate ranges, instruction bytes and relocation records. There is no byte-comparison mask or compiled candidate.

Four focused tests passed locally. Actual immediate counterfactuals change the extracted span 5 to 4, upper-word shift 32 to 31, and marker comparison 1 to 2 before the relation validator refuses them. The changed marker would select raw 2 instead of raw 1; the changed shift would refuse `0xffffffff`. Additional controls change real endian/register offsets, output stores, the receive-limit branch, sender prefix/capacity fields and payload-copy operands. Wrong/truncated captures refuse before output creation. These are static operand/predicate controls, not differential execution or tests of an invented node.

Full repository check commands and exact-head results accompany the PR. All component acceptance gates stay false. Next: recover the provider/read-buffer contract and the marker-selected payload transformation before implementing an interoperable Rust frame codec.
