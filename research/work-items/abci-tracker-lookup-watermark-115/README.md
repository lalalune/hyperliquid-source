# abci: reconstruct node #115 hash signature tracker prior lookup and watermark bodies

This packet makes four more bodies of `l1/src/abci/hash_signature_tracker.rs` reconstructable as
executable Python: the two prior-hash lookups `0x2BAFCE0` / `0x2BAFF80` that the record path
(`RE-017-hash-signature-record-115`) calls first, and the two watermark / cutoff bodies
`0x27605D0` / `0x27604D0` that it calls last. `lookup()` and `watermark()` in
`tools/tracker_lookup_watermark_115.py` reproduce what each body returns, stores and passes to its
callees. The real bytes of all four bodies are run with every callee stubbed, and the
reconstructions agree with them on all 18,722 cases (0 mismatches). All 44 conditional-jump flips
of the four bodies and 11 deliberately wrong reconstructions are caught, 55 of 55 negative
controls.

- Component ID: `abci` (block execution and state; the tracker holds signed state-hash votes)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: `0781ce04826eeefd89fe336cb8ea073be0c1de30` (workspace base).
  No `references/can1357-hl` source was consulted; every claim comes from #115 bytes.
- Claim status: observation (control flow, constants, memory offsets, stores and callee arguments of
  the four bodies, executed from bytes); inference (role names such as "ring", "map", "probe",
  "collect", "seal marker"); unresolved (what the five callees compute, see Limits)
- Scope included: complete FDEs `[0x2BAFCE0,0x2BAFF7A)`, `[0x2BAFF80,0x2BB021A)`,
  `[0x27605D0,0x27606CD)`, `[0x27604D0,0x27605CD)` (173, 173, 60 and 60 instructions). Scope
  excluded: callee bodies, the `0x5afa7f0` copies.
- Gate request: none. All component gates stay false.

## Reproduce

Run from the repository root with the LFS target materialized (no binutils needed; the binary is
read, never executed):

```sh
printf '%s  %s\n' a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301 artifacts/node/115/hl-node | sha256sum -c -
python3 tools/tracker_lookup_watermark_115.py --out research/work-items/abci-tracker-lookup-watermark-115
python3 -m unittest tests.test_tracker_lookup_watermark_115
```

The tool takes about 25 s and peaks near 470 MB. Its output is byte-identical across runs. It
checks the target digest first and stops on a mismatch. The ELF, FDE and instruction decoding come
from `tools/decimal_scaled_u64.py` (the shared #115 evaluator); no objdump or readelf output is
parsed. The excerpts below were read once with `objdump -d -M intel` for the reader only and are not
inputs to any generated file.

## Evidence

Coordinates are link-time ELF virtual addresses. Files in this folder (all generated):

| file | content |
| --- | --- |
| `calls.tsv` | every direct and slot call of the four bodies, in byte order |
| `cases.tsv` | 564 representative cases (one per distinct outcome class), each with its real outcome |
| `mutants.tsv` | all 44 conditional-jump flips and the case that kills each |
| `summary.json` | per-body FDE, instruction counts, reached instructions, outcome counts, result digests, wrong-model catch counts |
| `measure.json` | `cases`, `negative_controls`, `negative_detected` |

### Prior lookup (`0x2BAFCE0`, twin `0x2BAFF80`)

Arguments: `rdi` out, `rsi` tracker, `rdx` height, `rcx` pointer to a 32-byte hash. The result is
either the niche word `0x8000000000000000` stored at `out` ("no prior") or a collector call whose
output is left in `out`. The twin differs from the first body only in jump displacements, the memcmp
slot displacement and the collector (`0x236FF70` instead of `0x236E750`); both give identical
digests over all 8,721 cases.

```
2bafd09: mov r12,[rsi+0x18] ; neg rax ; jno 2bafd67      tracker+0x18 == 0x8000.. selects the map form
2bafd30: call 0x1d65b20 (out,[tracker+0x20],[tracker+0x28],&height) ; cmp dword [out],1 ; je none
2bafd70: call 0x24c9200 (tracker+0x18,&height) ; test al,1 ; jne none ; cmp rdx,[tracker+0x30] ; jae none
2bafd87: idx = rdx+[tracker+0x28]; idx -= (idx>=cap ? cap : 0); entry = [tracker+0x20] + idx*80 + 8
2bafdab: rax=[entry+0x18] ; test ; je none ; cmp rax,1 ; jne iterate
2bafdc2: cmp [entry],0x8000.. ; jne probe ; root=[entry+8] ; test ; je iterate ; depth=[entry+0x10]
2bafe21: memcmp(hash,node+0x2c0+32*i,32) per key, count nk=u16[node+0x42a]; equal -> none
2bafe74: node = [node + pos*8 + 0x430] ; sub depth,1 ; jb iterate
2bafe87: call 0x24c6b60 (entry,hash) ; test rax,rax ; je none
2bafe91: build the nine-word iterator and call the collector
```

Observed behaviour, reproduced by `lookup()`:

1. Entry location. If `tracker+0x18` is `0x8000000000000000` the entry comes from a map search:
   a null root `[tracker+0x20]` gives "no prior", the search callee `0x1D65B20` receives (root,
   `[tracker+0x28]`, address of the height) and a result tag of 1 gives "no prior"; otherwise the entry
   is `node + slot*72 + 0x60` with `node` at `out+8` and `slot` at `out+0x18`. Any other value of
   `tracker+0x18` is the capacity of a ring: callee `0x24C9200` is asked for the index of the
   height; error bit 0 or an index `>= [tracker+0x30]` gives "no prior"; otherwise the slot is
   `(index + head) - (cap if index+head >= cap)` with head at `tracker+0x28`, entry
   `[tracker+0x20] + slot*80 + 8`.
2. Count gate. The word at `entry+0x18` is 0: "no prior"; 1: one extra test; anything else: go to
   the iterator.
3. Single-element test. If `[entry]` is `0x8000000000000000` and `[entry+8]` is non-null, `entry`
   is a hash set (nodes with a u16 length at `+0x42A`, 32-byte keys from `+0x2C0`, child pointers
   from `+0x430`) of depth `[entry+0x10]`. Each node is scanned in key order with memcmp of
   (hash, key): the scan stops at the first key that does not compare below the hash; an equal key
   gives "no prior" (the hash is already in the set); otherwise the child at that position is
   entered, and with depth 0 the scan result is "not found" and the iterator is built. A null root
   skips the scan. If `[entry]` is anything else the entry is a deque and callee `0x24C6B60`
   (entry, hash) decides: zero gives "no prior", non-zero builds the iterator.
4. Iterator. Nine words are stored for the collector: for the set form
   `(root!=0, 0, root, depth, root!=0, 0, root, depth, root!=0 ? count : 0)`; for the deque form
   (`[entry]` capacity, `[entry+8]` buffer, `[entry+0x10]` head, `[entry+0x18]` length, 96-byte
   elements) the head is reduced by the capacity once if `head >= cap`, the first run is
   `head..min(head+len, cap)`, a wrapped second run is `len - (cap-head)` long, and the
   comparison `len > cap-head` is unsigned, so a head still `>= cap` after the reduction (heads
   `5`, `7`, `9` with capacity 4 in the cases) never wraps and ends at `head+len`.

### Watermark and cutoff (`0x27605D0`, twin `0x27604D0`)

Arguments: `rdi` tracker, `rsi` height `h`, `rdx` opaque (passed through), `rcx` object.

```
27605e4: mov rax,[rdi+0x80] ; cmp rsi,rax ; cmova rax,rsi ; mov [rdi+0x80],rax     unsigned running maximum
27605fc: mov eax,[rip+..flag] ; test eax,eax ; jne 276068d                          trace/log block, then rejoin
2760622: call 0x2daf740 (rsp+8, tracker+0x60, h, obj+0x60, Location)
2760627: cmp rbx,[r12+0x10] ; jne ; mov word [r14+0x90],1                          seal marker word := 1 when h == obj+0x10
276063a: sub rbx,0xc350 ; cmovb rbx,0                                              cutoff = h - 50000, saturating
2760661: call helper (rsp+8, tracker, cutoff, rdx, 0)  [rsp] = Location             0x28ac490 / twin 0x28aced0
276067b: if [rsp+8] != 0 : slot 0x64df4a0 (ptr [rsp+0x10], count*8, 0)               release of the returned descriptor
```

`watermark()` reproduces the maximum, the marker word write, the saturating cutoff, the exact
argument words of the locate and helper calls (the output buffer is `rsp+8` of the body frame, which
the cases record as `entry rsp - 0x40`), the optional trace call when the global flag word is
non-zero, and the release call with the byte count `8 * count`. Both bodies reach all 60 of their
instructions. The twins give identical digests over all 640 cases.

## Implementation and comparison

`tools/tracker_lookup_watermark_115.py` (729 lines) runs each body in the shared evaluator with a
logging stub per callee (search, ring index, probe, collector, memcmp, locate, helper, release,
trace) and compares `("ret", out word or maximum, flag/marker, ordered callee log)` with the
Python reconstructions. Cases are generated, run and compared one at a time; only counts and
digests are kept.

- Lookup cases (8,721 per body): 57 tracker shapes (ring with capacity 3/4, head 0/2/3, length
  0/1/3, indexes 0..3, an error index; map with null/non-null root, found/not found, slot 0/2) times
  141 `entry` shapes (8,037 pairs, 8,721 cases once the probe result 0/1 is added for single deque elements): zero counts, set entries with null root, depth-0 leaves with every key relation
  (`<`, `=`, `>`, empty, two- and three-key mixes, first differing byte 0 and 31), depth-1 inner nodes
  over leaves, a depth-2 walk, and 73 deque shapes (an empty one and capacity 4/8, head 0/1/3/4/7/9, length
  1/2/3/4/8/9).
- Watermark cases (640 per body): height `0, 1, 49999, 50000, 50001, 2^40, 2^63, 2^64-1` times
  previous maximum `0, 5, 50000, 2^63, 2^64-1`, marker match, trace flag, descriptor count 0/3,
  prior marker 0/0x201.
- Negative controls (55, all detected): 11 wrong reconstructions (`map_skips_null_root`,
  `ring_skips_bound`, `single_skips_filter`, `equal_continues`, `signed_max`, `mark_always`,
  `wrap_cutoff`, `cutoff_off_by_one`, `cutoff_from_max`, `no_release`, `bytes_not_words`) and
  44 byte corruptions that flip each conditional jump of the four bodies; each flip is run on the
  per-outcome sample and must change a result (44 killed, 0 survived, 0 unreached).
- `tests/test_tracker_lookup_watermark_115.py` (17 tests, about 37 s) covers the gates, ring wrap,
  set hit versus miss, deque head beyond capacity, twin equality, the unsigned maximum, saturating
  cutoff, release byte count, the wrong models, a corrupted digest, an out-of-range and a
  mid-function start, flipped jumps, a corrupted `0xC350` immediate, an unknown callee, and exact
  regeneration of the committed files.

No Rust implementation is claimed here and nothing is compared against a source build.

## Results and limitations

- cases: 18,722 (8,721 + 8,721 lookup, 640 + 640 watermark); mismatches: 0.
- negative controls: 55, detected 55.
- Callees are stubs. `0x1D65B20`, `0x24C9200`, `0x24C6B60`, `0x236E750`/`0x236FF70`,
  `0x2DAF740`, `0x28AC490`/`0x28ACED0` and the trace slot `0x64DF9F0` are modelled only by the
  arguments they receive and by a case-chosen result; what the map search, ring index, deque
  probe, collector, locate call and cutoff helper compute is unresolved.
- The meaning of "prior" (the stored vote hashes of an earlier signer for the same height) and the
  seal marker is inferred from the record path packet; the bytes only show the word writes.
- Only normal returns are modelled. Memory not written by a case is unknown to the evaluator and
  stops a run, so layouts outside the cases (deeper sets, other entry sizes) are unobserved.
- The `0x5afa7f0` / `0x5afadd0` copies of the record path are not covered.

Next question: what does the insert body `0x28AEAC0` (twin `0x28B2F10`) do with the 54-byte record
when the key already exists, and which entry layout does it write that this lookup later reads?
