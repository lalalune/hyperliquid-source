# RE-002: node #115 cached-word selector and two initializer callers

- Component: build-provenance / runtime-dispatch preparation.
- Target: node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source revision: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Question: is the byte inserted into two source-associated hash-adapter contexts a fixed build tag, or the result of a runtime word-dependent selection?
- Observation: both selected callers invoke the same relocated helper and preserve its AL result into context-relative `+0x6b`. The helper chooses tags 1..4 through repeated reads of a relocated cache pointer and optional calls to a refresh helper.
- Inference: this is a runtime backend/platform-like selector; concrete CPU/ISA bit names and downstream hash behavior are not established here.
- No global build flag, unconditional ISA baseline, reconstructed Rust or component gate is resolved.

## Prior work and bounded scope

PR #875 performs an FDE-bounded ISA census over #94/#115/visor. Its same-function CPUID test explicitly leaves cross-function/runtime dispatch unclosed. This packet adds one concrete #115 cache-word selector and two complete calling contexts, rather than redoing that census or interpreting vector instruction presence as an unconditional build requirement. It neither reviews/changes #875 nor resolves all paths in its next question. The main provenance field remains unknown.

| Role | Actual FDE range, original ELF VA, half-open | Bytes | Native instructions |
| --- | --- | ---: | ---: |
| runtime byte selector | `0x160bee0..0x160bf68` | 136 | 46 |
| caller 0 | `0x38d2920..0x38d2af8` | 472 | 100 |
| caller 1 | `0x38d2b00..0x38d2cd8` | 472 | 100 |

Denominator: **three complete bodies, 1,080 bytes / 246 native instructions**. The small selector and both full callers are one contribution. Independent GNU readelf ranges, complete native exports, file offsets/body hashes and original FDE/CIE bytes are retained. No normalized match, Rust build or target-equivalence claim is made.

The callers' source association is the actual relocated Location `0x646e9a8 -> 0x44ada0`, length15, `l1/src/utils.rs:28:43`. This is not a recovered original function name. Both source-associated worker bodies have an early provider call and test raw word **0x8000000000000004** before entering the initializer route. The provider/serialization format, public error type and alternative route remain unclosed.

## Runtime word and stable-cache theorem

The selector loads slot `0x64dfa60` into RBX, then reads a qword through it. The slot's RELATIVE addend binds a runtime cache address; on-disk relocation bytes and NOBITS initialization are not treated as a captured runtime cache value. Zero cache reads call through relocated slot `0x64dfa68`. The refresh helper's implementation and effects remain unknown.

For a **stable, nonzero** u64 cache word M across all reads, no refresh call is reached and the measured control flow gives:

```
if (M & (1<<19)) != 0 and (M & (1<<25)) != 0: tag = 4
elif (M & (1<<15)) != 0:                       tag = 3
else:                                        tag = 1 + ((M >> 10) & 1)
```

Actual operands are TEST EAX,0x80000; TEST ECX,0x2000000; TEST **CX** followed by JS; and SHR EAX,10 / AND EAX,1 / INC AL. The 16-bit sign test selects bit15, not the sign of the full qword or EAX. The last expression only depends on low dword bit10. Thus the four bit predicates completely determine the result for every stable nonzero raw u64 word, and unrelated bits cannot affect it. The conjunction's tag4 takes priority over bit15/tag3 and bit10.

There are **four** cold refresh call sites. Each cold arm rejoins the same predicate chain, with two duplicated tag assignments. Both ordinary RET sites are checked. Conditional on normal refresh returns and valid ABI/memory, even changing cache values can only produce tags 1,2,3,4: the return paths either assign AL3/AL4 or compute one masked bit plus1. The piecewise formula above is **not** claimed for concurrently changing cache reads or an inconsistent refresh result; cache synchronization, initialization validity and termination are unproved.

The selected FDE contains no direct CPUID instruction. A called refresh helper may use CPUID or another mechanism, and none of its feature-bit meanings is inferred from that absence. Names such as SSE/AVX/AVX-512 are deliberately not assigned to these bits or tags. This selected runtime relation does not determine the binary's unconditional instruction baseline.

## Caller byte propagation

Both callers use the following same relative instruction positions:

- `+0x61`: indirect call through `0x64df488 -> 0x160bee0` on the raw marker-equal route.
- Between that call and `+0xe6`: zero/vector/immediate context stores preserve AL; no intervening call or RAX write occurs in the retained native sequence.
- `+0xe6`: store AL at **RSP+0xcb**.
- `+0xf8`: pass **RSP+0x60** as context base to the call through `0x64df510`.
- `+0x109`: pass that same context base to the call through `0x64df518`.

The byte's relative offset is `0xcb-0x60 = 0x6b`. It is a runtime-selected input to these opaque consumers, rather than a fixed immediate in these two initializers. The source buffers, initialization constants, direct provider targets, calls, source/vtable/data LEAs and cleanup slots are retained in the authenticated spec. Ten distinct relevant relocations are checked, including cache/refresh and selector/update/finalize slots.

The 32-byte initialization IV is a research lead for a BLAKE3-like context, not a proof of a concrete cryptographic algorithm or Rust layout. Update/finalize bodies, SIMD kernels, data serialization, digest correctness, helper error behavior and all callers remain outside this packet. No claim is made that different tags produce equivalent output, that the byte cannot affect a digest, or that any hardware supports a particular ISA.

## Reproduce and actual counterfactuals

macOS arm64; Python 3.12.14; GNU readelf/objdump 2.47.20260726. From repository root with materialized captures and native GNU tools on PATH:

```sh
python3 -B tools/runtime_tag_static.py --output work/runtime-tag-check
# Compare generated files with this packet except README/spec/manifest.
python3 -B -m unittest discover -s tests -p test_runtime_tag_static.py -v
make doctor verify test catalogue-check
make reproduce
(cd research/work-items/RE-002-node115-runtime-tag && shasum -a 256 -c MANIFEST.sha256)
```

The producer authenticates the complete capture and spec before parsing/output/native calls. Native tools receive private byte-identical snapshots; full byte coverage, counts and every recorded call/RIP/control instruction start are checked. Raw text is unnormalized UTF-8/LF. Public generation rejects same-size modified, truncated and wrong-release captures before output creation.

Six focused tests cover native regeneration, all16 relevant bit classes plus every unrelated bit, and four actual operand counterfactuals:

- First mask bit19 ->bit18 changes M=(1<<19)|(1<<25) from tag4 to1.
- Second mask bit25 ->bit24 changes that same M from4 to1.
- SHR10 ->SHR11 changes M=1<<10 from2 to1.
- Hot JS ->JNS changes M=1<<15 from3 to1 under the stable nonzero-cache condition.

Each changed extracted relation is demonstrated before evidence validation rejects it. Controls additionally alter all13 branch displacements, cold duplicated tests/assignments, both RET paths, actual caller byte/context displacements, direct/RIP calls, source metadata, real relocation addends and all three FDE extents. These bit equations are not an emulator, target run or actual hardware-feature query.

Before: main has no selected #115 packet connecting this mask-dependent byte selector to these full source-associated initializers. After: this concrete runtime dependency and its limitations can be independently reproduced, helping keep runtime dispatch separate from unconditional build-feature inference. Artifacts/source pins and all component gates stay unchanged; new code/docs are independently authored under root MIT. No inferred unlicensed source is copied. No captured binary/emulator, hardware detection, live service, wallet, signing, chain action, hosted CI or reconstructed equivalence is claimed.

Next question: close the refresh helper and one downstream byte consumer before assigning CPU feature names, concurrency guarantees or algorithm/ISA equivalence.

Observed local validation: **six focused tests passed in 9.532s**.
`make doctor verify test catalogue-check` passed **437 tests in 162.294s**;
`make reproduce` passed. Packet manifest and staged whitespace checks passed.
No hosted-CI result is claimed.
