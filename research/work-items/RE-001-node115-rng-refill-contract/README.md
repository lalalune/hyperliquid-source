# RE-001: node 115 caller-bound RNG refill contract

Partial progress for [#3906](https://github.com/lalalune/hyperliquid-source/issues/3906).
This connects the previously recorded buffer selection to the actual direct
refill routine and derives its in-function four-block fallback state contract.
It leaves every full-component gate false.

## Target and prior boundary

Base: `7ff06a0973b5b8c79bde0b229c9bb2eabf8b29a6`. Original node #115 ELF:
105,896,032 bytes, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
All coordinates below are ELF virtual addresses.

`RE-012-rng-buffer-selection-115` / [#2799](https://github.com/lalalune/hyperliquid-source/pull/2799)
already owns the cursor, allowance and refill-selection evidence. It explicitly
leaves the real refill/CPU-dispatch implementation unresolved. This packet uses
that caller as a prerequisite and follows its selected direct edge into
`0x5bba800..0x5bbb030`; it does not reimplement the caller's selection API or
claim entropy/reseed equivalence. Open #4156 studies different RocksDB LCG
consumers and is not this refill routine.

## Observed caller and dispatch contract

At the selected caller window `0x150139d..0x1501409`, the exhausted buffer has
64 u32 positions. On the direct-refill branch, RDI is object+0x120, ESI is 6,
and RDX is object+0x10. The slot at `0x64e0980` resolves to `0x5bba800`.
After normal return the caller resets its cursor, reads the first output word,
and stores cursor 1. The 0x100-byte output occupies object+0x10..0x110;
the core state begins at +0x120, so these caller ranges do not overlap.

The refill loads a feature-cache pointer through `0x64dfa60 -> 0x6500098`.
An empty cache calls `0x64dfa68 -> 0x5cadd50` while preserving the three
arguments. In priority order, observed mask tests route to these tail targets:

| Observed bit/mask | Alternative target |
|---|---|
| bit 15 (`test ax, ax; js`) | `0x5bbb630` |
| `0x4000` | `0x5bbb030` |
| `0x400` | `0x5bb9a60` |
| `0x200` | `0x5bba120` |

Only when none of those alternatives is selected does execution enter the
fallback at `0x5bba86e`. These are mask/target observations, not inferred CPU
feature names. The feature provider and alternative implementations are outside
the behavioral scope of this packet.

## Derived fallback state transformation

The fallback loads eight u32 key words from input+0x00..0x20 and four tail words
from +0x20..0x30. The first two tail words form a little-endian u64 counter;
the last two are preserved. It prepares four independent blocks with counters
`counter + j (mod 2^64)`, for j=0,1,2,3. The constant vector at `0x4519c0`
is the 16 bytes `expand 32-byte k`.

For each block, let A be the four constant words, B/C the two key vectors and
D the counter/tail vector. The observed add/xor/rotate operation is, lane-wise:

```text
A += B; D = rotate_left(D xor A, 16)
C += D; B = rotate_left(B xor C, 12)
A += B; D = rotate_left(D xor A,  8)
C += D; B = rotate_left(B xor C,  7)
```

Additions wrap at 32 bits. The first operation is followed by the observed
word permutations B=[1,2,3,0], C=[2,3,0,1], D=[3,0,1,2]. The same operation
then runs on those diagonals; inverse permutations restore the original lane
order. The loop decrements ESI at `0x5bbadf5` and returns to `0x5bba970` while
nonzero. Thus the selected caller's ESI=6 supplies six double rounds, or twelve
rounds, to this path. This derivation comes from the instruction schedule;
neither a symbol name nor an assumed upstream library implementation is used.

At the end, each block adds its original A/B/C/D vectors back. Sixteen
consecutive 16-byte stores publish four 64-byte blocks to output+0..0x100.
The u64 counter advances by four with native wraparound; the vector store at
`0x5bbae90` writes input+0x20 while preserving the last two tail words. The
eight key words are not written on this fallback path. Stack spills are local.
The generic zero-round shortcut exists in the retained function but is outside
the caller-bound six-double-round interpretation.

## Reproduction and limits

`records.json` retains two windows, **2,204 bytes / 456 instructions**: the
caller slice and the complete refill FDE. The enclosing FDE decode and exact
bytes authenticate boundaries; they do not prove the unexamined transitive
providers or runtime equivalence. The documented mathematical interpretation
is a manual static dataflow derivation, not execution of captured instructions.

Use an existing Python environment with Capstone **5.0.7** and a hydrated
artifact (observed Python **3.14.7**):

```sh
python3 research/work-items/RE-001-node115-rng-refill-contract/verify.py
```

Expected: 2 windows, 2,204 bytes, 456 instructions, 54 explicit facts and 13
rejected semantic corruptions. `verification.json` retains the observed result.
`--target PATH` accepts another copy only with the pinned digest. The verifier
reuses the existing registry-row-labels ELF/FDE helper and downloads nothing.
Controls change the caller state/round arguments, CPU mask/provider, rotations,
permutations, feed-forward, counter advance, stores and constants. Controls run
the fact checks without digest/window rejection, so a changed whole-file hash
alone does not count as detecting the alteration.

Valid aligned native state and a disjoint writable output are premises. The
packet does not establish TLS initialization, reseeding, entropy quality,
cryptographic security, CPU-provider correctness, accelerated-path equivalence
or concurrent behavior. No native target code was executed or emulated. New
interpretation/tooling is independently authored; imported rights are unchanged.
