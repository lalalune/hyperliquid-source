# RE-001: node #115 nonce-associated strict ordering across a ring split

- Component: l1 nonce-container foundation; bounded post-provider invariant mapping.
- Target: node #115, 105,896,032 bytes, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Base/source revision: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Question: do the measured source-associated paths check strict unsigned order across both contiguous parts of a wrapped buffer, including their boundary?
- Observation/proof: conditional on a normal provider result and valid ring metadata/memory, every logical neighboring u64 pair is compared with unsigned **JB**. Both an equal pair and a decreasing pair select the shared invariant-failure path, including a pair crossing the wrap.
- No full decoder/nonce-admission/anti-replay policy, vulnerability, Rust implementation or component completion is claimed.

## Full measured scope

Original ELF virtual addresses, actual FDE ranges, half-open:

| Body | Start..end | Bytes | Native instructions |
| --- | --- | ---: | ---: |
| 0 | `0x2923c30..0x2923d91` | 353 | 99 |
| 1 | `0x2923da0..0x2923ee1` | 321 | 92 |
| 2 | `0x4227d30..0x4227e81` | 337 | 98 |
| 3 | `0x4227e90..0x4227fd1` | 321 | 92 |
| 4 | `0x5b07c50..0x5b07db1` | 353 | 99 |

Denominator: **five full bodies, 1,685 bytes / 480 native instructions**. All five are included in this one packet, not split into separate contributions. `records.json` retains their file offsets, complete body hashes and original FDE/CIE bytes; `frames.txt` independently confirms the ranges with GNU readelf. Full native exports cover every byte starting at each actual FDE entry. No normalization, reconstructed Rust build or machine-code equivalence is claimed.

All five actual source LEAs name Location `0x6483ff8`, whose relocation points at `l1/src/nonce_set.rs:141:13` (path at `0x4424eb`, 19 bytes). The failure path also loads a data anchor at `0x7c958c` beginning with **`nonce invariant`**, then calls through slot `0x64df6b8`, followed by UD2. The helper ABI and complete diagnostic formatting are unclosed; in particular its raw ESI 31 is **not** interpreted as the length of that 15-byte prefix. Adjacent pool bytes are not concatenated into an invented diagnostic.

The authenticated `spec.json` records ten direct calls, all selected RIP bindings and the three relevant relocated slots (Location, failure helper and cleanup helper). Every binding is checked against actual instructions and independently validated as a native instruction start. All provider functions and complete failure/cleanup/unwind behavior remain unmeasured.

## Provider and raw metadata boundary

The five bodies have distinct input providers:

| Body | Direct provider |
| --- | --- |
| 0 | `0x17ca720` |
| 1 | `0x1e29f50` |
| 2 | `0x2f44ba0` |
| 3 | `0x3fc6b20` |
| 4 | `0x47c1ba0` |

Bodies 0/2/4 observe a raw provider status 1 route, copy 32 bytes and propagate an outer raw status 1. The other provider route reaches metadata checking and normally writes status 0 plus four qwords. Bodies 1/3 instead test a raw word with NEG/JNO: the signed-minimum bit pattern is propagated with a second word; the other route enters metadata checking and normally copies four qwords directly. These ABI variants are recorded separately, not conflated into one recovered Result layout. The original decoder format, error type and success completeness remain unknown.

For the ordering theorem, name the four observed metadata words **capacity C, buffer P, head H and count N** by their pointer arithmetic roles. This is a conditional raw layout model, not a complete Rust VecDeque ABI recovery. Assume:

```
0 <= N <= C
0 <= H < C             # or H=0 if C=0
8*C <= ISIZE_MAX
P names valid nonwrapping storage for C u64 words
providers return normally with the observed ABI
```

The code does not establish all these conditions itself; malformed metadata is **not claimed safely rejected**. Empty N branches directly to the normal metadata stores without element comparisons. No provider error route is claimed to perform the ordering checks.

## Two spans and all neighboring pairs

The native arithmetic first reduces a head by one capacity when head >=capacity. Under the stated valid-head assumption, this leaves H unchanged. It forms:

```
A = C-H
first span  = [H, min(C,H+N))
second span = [0, max(0,N-A))
```

The second span's byte length is selected as zero when N<=A. Otherwise the positive excess is multiplied by eight. Relevant native SHL/LEA operands, source loads and normal-output metadata stores are preserved in the full body hashes. Pointer safety and no-overflow here rely on the stated valid layout/storage assumptions, not an independent allocator proof.

For nonempty contents the first span is nonempty. The first comparison loop starts at its second element, loads `[cursor-8]`, compares with `[cursor]`, advances cursor by eight with LEA (which preserves flags), and uses unsigned **JB**. At its end, the cursor is stepped back to the first span's last element. The second loop compares that retained element with the first element of the second span, updates the previous pointer, then walks the rest of the second span. Thus it includes the wrap boundary instead of treating the spans as independently sorted lists.

| Body | First-span JB | Boundary / second-span JB |
| --- | --- | --- |
| 0 | `0x2923d30` | `0x2923d52` |
| 1 | `0x2923e80` | `0x2923ea2` |
| 2 | `0x4227e20` | `0x4227e42` |
| 3 | `0x4227f70` | `0x4227f92` |
| 4 | `0x5b07d50` | `0x5b07d72` |

Each first loop continues at JB-site minus16; each second loop at JB-site minus18. Both comparison failures converge on the same body-local source-associated failure block; the first has an explicit short JMP to the second loop's fallthrough. Both destinations are checked, not merely the conditional opcodes.

For arbitrary valid C/H/N, let first-span length be m=min(N,C-H) and second-span length be n=N-m. If N>0, the first loop checks m-1 pairs, and the second checks n pairs (one boundary plus n-1 internal pairs when n>0). Total is `(m-1)+n=N-1`, exactly the neighbors of logical sequence `P[(H+i) mod C]`. Empty/singleton contents have no pairs. Since both actual predicates are unsigned strict less-than, this proves the local ordering condition over the complete raw u64 value domain. It does not prove that arbitrary external bytes reach this layout or that all callers enforce any larger nonce policy.

## Reproduce and counterfactuals

macOS arm64; Python 3.12.14; GNU readelf/objdump 2.47.20260726. From repository root with materialized captures and native GNU tools on PATH:

```sh
python3 -B tools/nonce_ordering_static.py --output work/nonce-ordering-check
# Compare generated files with this packet except README/spec/manifest.
python3 -B -m unittest discover -s tests -p test_nonce_ordering_static.py -v
make doctor verify test catalogue-check
make reproduce
(cd research/work-items/RE-001-node115-nonce-ordering && shasum -a 256 -c MANIFEST.sha256)
```

The producer authenticates the complete capture and spec before parsing, output or native calls. Native tools receive private byte-identical snapshots. Complete byte coverage, native counts and instruction-start bindings are checked. Exports are UTF-8/LF and unnormalized. Modified, truncated and wrong-release inputs fail the public gate before output creation.

Six focused tests regenerate the retained packet, enumerate pair-index obligations for every head/count up to capacity16, and compare the two-span relation with independent logical-index enumeration for all contents over a small four-value alphabet up to capacity4. These finite controls exercise the all-domain proof above; they are not a substitute for it or target execution.

Actual operand counterfactuals are tested on **both loops of all five bodies**:

- JB (0x72) ->JBE (0x76) lets an equal pair through. Physical `[4,4]`, head0/count2 exercises the first loop; head1/count2 exercises the cross-wrap loop.
- JB ->JL (0x7c) changes strictness over the unsigned sign boundary: logical `[2^63-1,2^63]` passes the actual unsigned predicate and fails the changed signed predicate, in either span arrangement.

Each extracted comparison demonstrably changes before evidence validation rejects it. Additional controls alter actual loop backedges/failure convergence, comparison/load/advance operands, every provider/unwind direct call and selected RIP displacement, metadata-associated code, source metadata, the diagnostic anchor, real relocation addends and all five FDE extents. Static pair obligations are mathematical relations, not an instruction emulator or a captured-node run.

Before: main has no #115 packet tying these five source-associated provider paths to a strict logical-ring invariant. After: the normal-path ordering relation, raw metadata/ABI differences, native branches and known unknowns are independently reproducible. All capture bytes, imported source/pins and progress gates are preserved; new tooling/docs are independently authored under root MIT. No inferred unlicensed source was copied. No captured binary/emulator, real nonce submission, live API/network, wallet, signing, chain action, Rust reconstruction, hosted CI, protocol security or runtime equivalence is claimed.

Next question: close one provider and its caller before assigning a public input encoding or connecting this local invariant to nonce admission/window semantics.

Observed local validation: **six focused tests passed in 18.592s**. After
clarifying the metadata-assumption wording, an initial full run caught a stale
`records.json` description (one equality failure); the packet was regenerated.
The final `make doctor verify test catalogue-check` passed **437 tests in
171.146s**, including all six focused tests with the final retained records.
`make reproduce` passed. Manifest and staged whitespace checks passed.
No hosted-CI result is claimed.
