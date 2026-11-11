# RE-001: node #115 byte-prefix leaf caller output handling

- Component: `foundation` / serialization boundary; one bounded caller-flow packet.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source/reference revision: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no inferred source was read or copied.
- Claim status: **observation** — four direct calls to `0x5434bb0` in one containing FDE, each call's register setup, tag test, branch, constant store, and the shared non-tag-9 output copy. **Inference / unresolved** — source names and meanings of the constants.
- Bounded question: how does one #115 caller consume the output of the existing byte-prefix leaf?
- Scope: four call sites in `[0x534f7a0,0x5350b9a)`, their immediate output handling, and the common copy block. No whole-function semantic reconstruction or caller-of-caller analysis.

## Reproduce

From repository root with Python 3.10+ and the pinned artifact materialized:

```sh
python3 tools/re001_byte_prefix_caller_output_115.py --out research/work-items/RE-001-node115-byte-prefix-caller-output
python3 -m unittest tests.test_re001_byte_prefix_caller_output_115
python3 research/work-items/RE-001-node115-byte-prefix-caller-output/verify.py
PATH="/opt/homebrew/opt/binutils/bin:$PATH" objdump -d -w --start-address=0x534f7a0 --stop-address=0x5350b9a artifacts/node/115/hl-node
```

Observed tools: Python 3.14.3 and GNU objdump 2.47.20260726. The producer hashes the complete artifact before parsing, scans the complete `.text` for direct `E8 rel32` references to the leaf, checks the recorded bytes and FDE containment, and writes deterministic JSON. It does not execute the capture or make network requests.

## Evidence and results

All coordinates are original ELF virtual addresses. The complete direct-call scan finds exactly four references to `0x5434bb0`, at `0x534f9b1`, `0x534fb6b`, `0x534ff57`, and `0x5350475`; all lie in FDE `[0x534f7a0,0x5350b9a)`. Each call passes a local output at `rsp` in `rdi` and the state pointer in `r14` via `rsi`. Each caller then compares output byte 0 with 9.

When the byte equals 9, the four sites write a 64-bit constant to `[rbx]` and branch to the shared return path:

| Call site | Stored value |
| --- | ---: |
| `0x534f9b1` | `99` (`0x63`) |
| `0x534fb6b` | `133` (`0x85`) |
| `0x534ff57` | `60` (`0x3c`) |
| `0x5350475` | `38` (`0x26`) |

When byte 0 is not 9, each call reaches `0x535048c`, which copies 32 bytes from the local output at `rsp` to `[rbx+8..rbx+0x28)`. The earlier byte-prefix packet records the leaf's local behavior: the nonempty `0xc0` input yields byte 0 equal to 9, while other byte-prefix classes use different tags. Combined, these packets establish how this one FDE consumes that tag locally, without assigning protocol or source-level meaning to the constants.

The FDE is one unwind-described range, not asserted to be a validated source function. No Rust implementation, whole-call-graph claim, component gate, target execution or runtime reachability is claimed. Next question: bind the surrounding input branches that select these four call sites to the owning source-level operation without inferring names from this FDE alone.
