# RE-010: MessagePack Content map / seq visitors behind the TagOrContent key reader (node #115)

With this packet, the `Content` collection step of node #115's MessagePack
deserializer can be rebuilt as code: how a msgpack map or array that is not the
tag is turned into `Content::Map(Vec<(Content, Content)>)` or
`Content::Seq(Vec<Content>)`. That covers the size-hint clamp, the allocation,
the per-element remaining-count write-back, the Option::None and Result::Err
niches, growth, the Err cleanup order and every landing pad. These are the map
and array callees that the previous TagOrContent key-reader packet left stubbed:

- `visit_map` 0x21e0380 / 0x3b68660 / 0x57af090 (1,191 B each), called at key reader +0x13f;
- `visit_seq` 0x21e1c10 / 0x3b69610 / 0x57af540 (666 B each), called at key reader +0x203.

The reconstruction is the pure `Model` class in
`tools/re010_content_map_seq_visitors_115.py`. The tool runs the original bytes of
all six bodies over 3,147 map cases and 2,263 seq cases with the callees
scripted. The binary is never executed. The result is 0 mismatches in every copy, and
64/64 wrong models and corrupted images are rejected.

- Component ID: `action-dispatch` (RE-010, transaction handler dispatch)
- Target release and full SHA-256: Linux x86-64 node #115 `artifacts/node/115/hl-node`,
  SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`
- Source commit / reference commit: main `7ff06a097`. `references/can1357-hl` was not used.
- Claim status:
  - Observation, proved by running the original bytes against the reconstruction:
    control flow, constants, call arguments, result bytes, access write-back,
    heap contents, LSDA call sites and landing pads.
  - Inference: the serde names (`ContentVisitor::visit_map` / `visit_seq`,
    `Content::Map` 0x15, `Content::Seq` 0x14, `MapAccess` / `SeqAccess`,
    `RawVec::grow_one`, `handle_alloc_error`, `size_hint::cautious`).
- Scope included: the full bodies of the six functions above and their LSDA
  call-site tables, plus the check that key reader copies 0x1a7e1a0, 0x30fb4f0 and
  0x48cd3a0 call them at +0x13f / +0x203.
- Scope excluded: callee bodies, all stubbed by contract:
  - the generic value reader (anchor 0x17fb290; each copy has its own target, see `call_sites.tsv`);
  - the allocator, `handle_alloc_error`, `RawVec` grow, free, the Content / pair / Vec drops.
  - Other RE-001 packets (`skiplist-holder`, `owner-tail-phases`, `skiplist-rep-factory`,
    `tagged-value-drop-aa810`) list some of these functions only as caller rows of a
    shared callee (`_Unwind_Resume` or a drop). They do not decode the bodies.

## Reproduce

```
python3 tools/re010_content_map_seq_visitors_115.py --out research/work-items/RE-010-content-map-seq-visitors-115
python3 -m unittest tests.test_re010_content_map_seq_visitors_115
cd research/work-items/RE-010-content-map-seq-visitors-115 && sha256sum -c MANIFEST.sha256
```

The tool and tests use only the Python 3 standard library and the shared
`tools/elf_index.py` and `tools/fde_extents.py` parsers. They call no external
program and never execute the binary. The tool checks the input SHA-256 first.
Generation takes about 240 s; most of it is the 5 inputs with more than
0x4000 pairs / 0x8000 items, which are the only way to reach the grow call.

Two generations produced byte-identical output: one with `PYTHONHASHSEED=0`, `TZ=UTC`,
the other with `PYTHONHASHSEED=12345`, `TZ=Asia/Seoul`.

## Evidence

All numbers and tables are produced by the tool from ELF bytes:
- section headers via `elf_index`;
- FDE and LSDA via `fde_extents` and the uleb call-site table;
- `.rela.plt` JUMP_SLOT relocations (to confirm `_Unwind_Resume`);
- fixed-pattern instruction decoding.

| file | content |
|---|---|
| `functions.tsv` | per kind and copy: FDE extent, LSDA, caller site, instruction and call counts, frame size |
| `call_sites.tsv` | every call site by offset, its role, each copy's target, and landing pad and action |
| `lsda.tsv` | the call-site tables (the same in all copies of a kind) |
| `coverage.tsv` | every instruction of both anchor copies, whether it was covered, and the taken and not-taken edges |
| `cases.tsv` | every case (base and unwind): outcome, result bytes, callee sequence, access state after the call, heap block digests |
| `mutants.tsv` | 30 wrong models and 34 corrupted images, with the number of cases each one changes |
| `summary.json` | totals and outcome classes |

### Interface (observed)

The call is `rdi` = out `Result<Content, rmp::Error>` (0x28 B) and `rsi` = the access
`{ de: *mut Deserializer, left: u32 }` (+0, +8). The value reader is called with
`rdi` = a 0x28-byte frame slot and `rsi` = `de`. The map body tests its result with a
dword compare to 1 at +0; the seq body tests the byte at +0 for non-zero. The element
`Content` is the 32 bytes at +8 of that result.

### Behaviour (reconstructed and proved)

- **Size hint.** `left == 0` returns at once with `Vec { cap 0, ptr 8, len 0 }`, no
  allocation. Otherwise the capacity is `min(left, 0x4000)` for maps (64-byte
  pairs) and `min(left, 0x8000)` for seqs (32-byte items): the first allocation is
  at most 1 MiB in both. A null allocation calls `handle_alloc_error(8, size)`,
  whose call site has no landing pad.
- **Loop.** Exactly `left` rounds unless stopped. Before each round the remaining
  count after this element (`left - k - 1`) is written to access +8, and then the
  reader runs (map: key, then value, with the same count).
- **Stops.**
  - Reader `Err`: its 32-byte error (result +8..+0x28) becomes `Err`. For a map
    value error the already read key is dropped first (`drop_content` on the frame slot).
  - Tag 0x16 (Option::None niche) in the first read of a round ends the loop with `Ok`.
    A map value with tag 0x16 is stored as a value, not a stop.
  - Map only: key tag 0x17 is the `Result<Option<(K, V)>>::Err` niche. The value is
    still read, then `Err` is returned with key bytes 8..32 followed by value bytes
    0..8. Neither half is dropped. A seq item with tag 0x17 is stored.
- **Growth.** When `len == cap` before a push the grow call gets `&vec` (frame +8);
  the pending element is pushed after it returns.
- **Err cleanup.** Every collected element is dropped in order (map: key then value
  of each pair), then the buffer is freed with `(ptr, cap * size, 0)` if `cap != 0`.
- **Ok result.** Tag 0x15 (Map) or 0x14 (Seq) at +8, then cap/ptr/len at
  +0x10/+0x18/+0x20. Bytes +9..+0x10 are padding copied from the frame: the map
  copies key bytes 9..16 of the last pair that reached its value read, the seq copies
  the first 7 bytes of the last reader result. With `left == 0` it is uninitialised
  frame. The model predicts these bytes exactly.
- **Landing pads.** A key or seq read that unwinds drops the Vec. A map value read
  that unwinds drops the key, then the Vec. A grow call that unwinds drops the
  pending element (map: the whole pair), then the Vec. A drop in the Err cleanup that
  unwinds drops the remaining halves and elements (map: whole pairs), frees and
  resumes. A second unwind inside any pad drop reaches a terminate pad. The free calls
  and `handle_alloc_error` sit in LSDA ranges without a pad; the allocation call is
  outside every range.

## Implementation and comparison

The `Model` class is a pure reconstruction of both bodies. It reads nothing from the
binary.

The `Machine` interprets the original instructions of each copy with contract stubs:
- a value reader scripted per call (Ok with a chosen tag, or Err) whose result bytes
  are a deterministic pattern of the call ordinal;
- an allocator with a failure switch and a grow stub that doubles the capacity
  (minimum 4) into a fresh heap block;
- drops and free that record their arguments and the bytes they would drop.

Every callee call of every base case is also made to unwind once, and every later
call in the resulting pad once more.

- map 0x21e0380: 3,147 cases, 0 mismatches, 247/248 instructions, 10/12 conditional jumps both ways.
- map 0x3b68660: 3,147 cases, 0 mismatches, 247/248 instructions, 10/12 conditional jumps both ways.
- map 0x57af090: 3,147 cases, 0 mismatches, 247/248 instructions, 10/12 conditional jumps both ways.
- seq 0x21e1c10: 2,263 cases, 0 mismatches, 158/159 instructions, 8/10 conditional jumps both ways.
- seq 0x3b69610: 2,263 cases, 0 mismatches, 158/159 instructions, 8/10 conditional jumps both ways.
- seq 0x57af540: 2,263 cases, 0 mismatches, 158/159 instructions, 8/10 conditional jumps both ways.
- map: 34/34 rejected (16 wrong models, 18 image mutants).
- seq: 30/30 rejected (14 wrong models, 16 image mutants).

## Results and limitations

- **Uncovered in the map anchor:** 0x7c `nop`, 0x3bb `j` one way, 0x47e `j` one way. The `nop` is alignment padding before the loop head, which is always jumped over. The two one-way jumps are the `cap != 0` tests before `free` in the Err cleanup and in the unwind pad: both are only reached after the allocation, so cap >= 1 and the skip-free edge is unreachable. Inverting either test is still rejected (`mutants.tsv`).
- **Uncovered in the seq anchor:** 0x6f `nop`, 0x1ff `j` one way, 0x25e `j` one way. The `nop` is alignment padding before the loop head, which is always jumped over. The two one-way jumps are the `cap != 0` tests before `free` in the Err cleanup and in the unwind pad: both are only reached after the allocation, so cap >= 1 and the skip-free edge is unreachable. Inverting either test is still rejected (`mutants.tsv`).
- **Callee contracts.** Callee bodies are stubbed. The reader result layout and the
  grow contract are taken from how these functions read them. They are not proved here.
- **Huge inputs.** Growth is only reachable with more than 0x4000 pairs / 0x8000
  items. Those 5 cases per kind are run in full but not unwound at every call; only
  the grow call (and the drop inside its pad) is unwound.
- **Names.** Serde names are inferences from the layout and discriminants; Content
  0x14 Seq / 0x15 Map / 0x16 None niche match serde's `Content` declaration order.
- **Unreachable niche.** Whether the generic reader can ever return key tag 0x17 is not
  examined. The path exists in the bytes and leaks the value if taken.
- No component gate is advanced by this packet.
