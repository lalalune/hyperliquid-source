# RE-015: node #115 Spot/Mark codec caller and map-key bytes

- Component: `constants`; bounded RE-015 caller/prefix census.
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Source/reference revision: repository `0781ce04826eeefd89fe336cb8ea073be0c1de30`; no inferred reference source was read or copied.
- Claim status: **observation** — one direct relative call to each of three serializer entries, exact call and prefix-store bytes, and each call's unique containing FDE. **Inference / unresolved** — source function names, struct identity, the array's second element, and higher-level domain meaning.
- Bounded question: which caller sites invoke the three Spot/Mark/ExternalPerp name serializer copies, and what MessagePack prefix do they write before each call?
- Scope: these three direct call targets and their containing FDE ranges in file-backed `.text`. No full call graph or source ownership is claimed.

## Reproduce

From the repository root, with Python 3.10+ and the pinned artifact present:

```sh
python3 tools/re015_spot_mark_callers_115.py --out research/work-items/RE-015-spot-mark-callers-115
python3 -m unittest tests.test_re015_spot_mark_callers_115
python3 research/work-items/RE-015-spot-mark-callers-115/verify.py
```

The producer checks the artifact digest, parses ELF sections and `.eh_frame`, scans all `.text` bytes for `E8 rel32` references to the three expected entries, and checks the call and four prefix-store instruction encodings at each site. Python 3.14.3 and GNU objdump 2.47.20260726 were used. On macOS, the Homebrew binutils directory was first on `PATH`; the focused independent disassembly commands were:

```sh
PATH="/opt/homebrew/opt/binutils/bin:$PATH" objdump -d -w --start-address=0x25d67dc --stop-address=0x25d6865 artifacts/node/115/hl-node
PATH="/opt/homebrew/opt/binutils/bin:$PATH" objdump -d -w --start-address=0x367123c --stop-address=0x36712c5 artifacts/node/115/hl-node
PATH="/opt/homebrew/opt/binutils/bin:$PATH" objdump -d -w --start-address=0x50bc2dc --stop-address=0x50bc365 artifacts/node/115/hl-node
```

The commands decode all three call instructions and the four preceding prefix stores in their respective FDEs. The producer starts no process, executes no captured code, and makes no network requests. `records.json` is deterministic.

## Evidence and results

All addresses are original ELF virtual addresses. The byte scan found exactly one direct call per serializer copy:

| Serializer entry | Call site | Containing FDE | Bytes written before the call |
| --- | --- | --- | --- |
| `0x22e3810` | `0x25d6860` | `0x25d67b0..0x25d6a43` | `81 a1 70 92` |
| `0x3d4d420` | `0x36712c0` | `0x3671210..0x36714a3` | `81 a1 70 92` |
| `0x5361090` | `0x50bc360` | `0x50bc2b0..0x50bc543` | `81 a1 70 92` |

The four store instructions append those bytes in order to the same vector: `0x81` (fixmap with one entry), `0xa1` (fixstr length one), `0x70` (ASCII `p`), and `0x92` (fixarray with two elements). The call to the name serializer follows the prefix. The direct observed conclusion is that each call appears after a one-entry map prefix with key `p`, followed by an array-of-two marker. This does not identify the caller's source struct or the other array element. One FDE contains each call site, but an FDE range is not by itself a proven source-function boundary.

The complete component gate remains false; no Rust implementation or source equivalence is claimed. No progress gate is requested.

Next question: identify the second array element and the exact source-side owner, using additional #115 evidence rather than FDE ownership alone.
