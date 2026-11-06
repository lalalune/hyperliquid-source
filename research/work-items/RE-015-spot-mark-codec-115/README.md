# RE-015: reconstruct the node #115 Spot/Mark/ExternalPerp name codec (msgpack writer and exact-name visitors)

This packet makes the three-name enum `Spot`, `Mark`, `ExternalPerp` (tags 0..2) of node #115 rebuildable as executable code in both directions. Before it, the names appeared in the capture only as scattered immediates and string-pool entries. Three monomorphized serializer copies write exactly one msgpack fixstr (`0xa4` + `Spot`/`Mark`, or `0xac` + `ExternalPerp`) into a `Vec<u8>` with two capacity checks, and they send every tag byte other than 0 and 1 to the `ExternalPerp` arm. Three visitor copies accept only a complete, case-sensitive, exact-length match. For any other input they pass the input and a three-entry name pool to an unknown-variant error callee. Interpreting the original machine code byte by byte, the reconstruction agrees on all 1,335 serializer cases and all 15,486 visitor cases. Each of the nine deliberately wrong reconstructions is caught.

- Component ID: `constants` (Global configuration); task `RE-015`. The packet uses the RE-001 unwind index (`tools/fde_extents.py`) and the shared section parser (`tools/elf_index.py`).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (`artifacts/node/115/hl-node`).
- Source commit / reference commit: repository `05bc2de303c05525b71e7e257426e741bc66a390`. No inferred reference source was read or copied, and no file in the repository contains `ExternalPerp`. #94 material is not used.
- Claim status:
  - **Observation:** FDE extents, decoded instruction bytes, immediates, length gates, RELATIVE relocations, and the interpreted results of the original bytes on the listed inputs.
  - **Inference:** the serde/rmp roles (a `Serialize` that writes a unit variant name as a msgpack string, and a field-identifier `visit_str`), the meaning of the result words, and that the error callees build `unknown_variant` errors. What the enum means in the domain (for example a price or oracle source kind) is a guess from the names and is not claimed.
  - **Unresolved:** the callers of the six bodies, the internals of the grow and error callees, and which structures own each copy.
- Scope:
  - Included: six complete bodies, with every byte of each FDE extent decoded and only `int3` fill after the last instruction. These are the serializers `0x22e3810`, `0x3d4d420`, `0x5361090`, the tagged visitors `0x22e20d0`, `0x3d47cb0`, `0x535bee0`, and their three variant-name pools `0x642d150`, `0x6479be0`, `0x64a7c68`.
  - Excluded: the callee bodies `0x231e050`/`0x43bd910`/`0x5963a10` (Vec growth) and `0x17fbba0`/`0x2f7fef0`/`0x47d2d80` (error construction), all callers, and any progress gate.
  - The six entries and three pools appear in no file under `research/work-items` and in no open PR file list at the time of writing.
  - The ASCII immediate `ExternalPerp` occurs in `.text` only inside these six FDEs: the `External` qword occurs exactly six times, once per body.

## Reproduce

Run from the repository root on Linux x86-64 with Python 3.12.3. Only the standard library is needed, plus `tools/elf_index.py` and `tools/fde_extents.py`.

- The producer checks the full SHA-256 of the input before it parses anything.
- It never executes the capture, starts no process and makes no network access. It interprets the selected machine code in Python.
- Its output contains no time, randomness, absolute path or unordered-dict iteration.

```sh
python3 tools/re015_spot_mark_codec_115.py --out research/work-items/RE-015-spot-mark-codec-115
python3 -m unittest tests.test_re015_spot_mark_codec_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

Determinism check (two independent outputs, different hash seed and time zone):

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/re015_spot_mark_codec_115.py --out <tmp-dir-one>
PYTHONHASHSEED=91 TZ=Pacific/Honolulu python3 tools/re015_spot_mark_codec_115.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
```

The producer writes exactly the eleven generated files below. `README.md` and `MANIFEST.sha256` are maintained separately. A full run takes about 10 s.

The producer exits non-zero and writes nothing if any of these holds:
- the digest differs;
- an entry is not an FDE start;
- any byte in a body falls outside the supported instruction subset;
- a call reaches an unmodelled target, or a call's arguments differ from the expected ones;
- a store leaves scratch memory;
- a visitor loads a pool other than the three listed;
- a pool slot lacks a RELATIVE relocation;
- any case disagrees with the reconstruction;
- any negative control is not caught.

| Generated evidence | Contents |
| --- | --- |
| `functions.tsv` | 6 bodies: role, entry, FDE end, size, decoded instruction count and bytes (equal to the FDE size), LSDA, body SHA-256, direct callees |
| `instructions.tsv` | 486 decoded instructions (VA, length, raw bytes, operation, branch/call target) |
| `serializer-arms.tsv` | per serializer, every tag compare, reserve bound, marker store, name-bytes store and result-word load, in body order |
| `visitor-literals.tsv` | per visitor, the length gates, name immediates and result-word stores |
| `variant-refs.tsv` | the rip-relative `lea` in each visitor's error arm, the pool it loads, and the `mov r8d, 3` count |
| `variant-pool.tsv` | 9 rows: the three `&[&str; 3]` pools, slot VA, `.rela.dyn` file offset of the RELATIVE relocation, string VA, length, text |
| `serializer-cases.tsv` | 1,335 cases: serializer × (tags 0..2 × length {0,1,7,64} × spare capacity 0..15, plus tags 3..255 at capacity 64); appended bytes, grow calls (`length+additional`), final length, result word, arm, verdict |
| `visitor-cases.tsv` | 5,162 inputs × 3 visitors: outcome per copy, reconstruction, verdict |
| `paths.tsv` | per body, the number of inputs ending after each interpreted step count and outcome (path classes) |
| `negative-controls.tsv` | nine wrong reconstructions and how many cases each fails |
| `summary.json` | totals, callee lists, pools and pass flags |

## Evidence

Coordinates are linked virtual addresses (VA). Section membership and file offsets come from `elf_index.sections`, with SHT_NOBITS sections excluded. Body extents come from `fde_extents.fde_extents`. None of the six FDEs has an LSDA.

**Serializers** (`0x22e3810`, `0x3d4d420`, `0x5361090`). Each is 519 bytes and 131 instructions. All three have the same shape and differ only in their grow callee. Human-readable excerpt of `0x22e3810` (GNU objdump 2.42, not used by the tool):

```
22e3817: movzx ecx,BYTE PTR [rsi]   ; tag byte
22e381a: test ecx,ecx ; je  Spot arm
22e381e: cmp  ecx,0x1 ; jne ExternalPerp arm   ; every other byte
22e3823: mov rcx,[rdx] ; mov rsi,[rdx+0x10] ; cmp rcx,rsi ; je grow(len,1)
22e3837: mov BYTE PTR [rdi+rsi*1],0xa4            ; fixstr length 4
22e3842: sub rcx,rsi ; cmp rcx,0x3 ; jbe grow(len,4)
22e384f: mov DWORD PTR [rdi+rsi*1],0x6b72614d     ; "Mark"
22e38a9: mov BYTE PTR [rdi+rsi*1],0xac            ; fixstr length 12
22e38b4: sub rcx,rsi ; cmp rcx,0xb ; jbe grow(len,12)
22e38c1: movabs rcx,0x6c616e7265747845 ; mov [..],rcx ; mov DWORD [..+8],0x70726550   ; "External" "Perp"
22e38db: mov [rdx+0x10],rsi ; movabs rcx,0x8000000000000004 ; mov [rax],rcx ; ret
```

- **Tag selection.** There is no jump table: tag selection is a two-compare chain on the tag byte. Tag 0 selects `Spot`, tag 1 selects `Mark`, and every other byte value falls through to `ExternalPerp`. The tool drives all 253 out-of-range byte values through each copy, and each writes `ExternalPerp`.
- **Growth calls.** Every growth call passes `(vec, len, additional, 1, 1)`. `additional` is 1 before the marker when `cap == len`. After the marker it is 4 or 12 when the remaining capacity is `<= 3` or `<= 11`, that is, strictly less than the name length.
- **Result.** Every path stores the word `0x8000000000000004` to `[rdi]`, and no path returns an error. The reserve slow paths (six per copy) call the grow callee and jump back to reload `ptr`/`len`.

**Tagged visitors** (`0x22e20d0`, `0x3d47cb0`, `0x535bee0`; 110 bytes and 31 instructions each):

```
22e20d0: cmp rdx,0x4 ; jne len12
22e20d6: cmp DWORD PTR [rsi],0x746f7053 ; je Spot      ; "Spot"
22e20de: cmp DWORD PTR [rsi],0x6b72614d ; jne error    ; "Mark"
22e20e6: mov WORD PTR [rdi],0x109 ; mov rax,rdi ; ret
22e20ef: cmp rdx,0xc ; jne error
22e20f5: movabs rax,"External" ; xor rax,[rsi] ; mov ecx,[rsi+8] ; xor rcx,"Perp" ; or rcx,rax ; jne error
22e2111: mov WORD PTR [rdi],0x209 ; ret
22e211a: mov WORD PTR [rdi],0x9 ; ret
22e2123: push rbx ; lea rcx,[pool] ; mov r8d,0x3 ; mov rbx,rdi ; call error ; mov rax,rbx ; pop rbx ; ret
```

- **Length gates.** Length 4 is tested first, then length 12. Any other length goes straight to the error arm.
- **Success.** Success stores the word `0x09 | tag << 8` at `[rdi]` and returns `rdi`.
- **Failure.** Failure calls the copy's error callee with `(out, ptr, len, pool, 3)` and returns `out`. The tool checks all five arguments on every rejecting case.

**Variant pools** (`0x642d150`, `0x6479be0`, `0x64a7c68`). Each pool is three `(ptr, len)` slots, one pool per visitor copy, and each slot pointer is a `.rela.dyn` R_X86_64_RELATIVE addend read by the tool.
- The texts are `Spot`, `Mark`, `ExternalPerp` in tag order, so the error-path name list has the same order as the success tags.
- The `Spot` (`0x45a114`) and `Mark` (`0x459ec4`) strings are shared by all three pools, but each pool points at its own `ExternalPerp` copy (`0x5eac46`, `0x7bd36c`, `0x924bf9`).

**Interpreter.**
- The interpreter is a fixed x86-64 subset decoder and machine contained in the tool itself, so the packet stands alone.
- The tool decodes every byte of each body. ZF and CF are enough for every conditional branch present (`je`, `jne`, `jbe`).
- Writes go only to scratch memory above the image. Reads below it come from file-backed sections.
- Calls go only to the identified grow/error callees, modelled as stubs. The grow stub sets `cap = max(2·cap, len+additional, 8)`, and the error stub returns a sentinel. After a call, the interpreter overwrites the caller-saved registers, so the bodies cannot depend on their old values.

`paths.tsv` gives the path classes, and they match the source structure:
- **Visitors:** six classes each. Success needs 7, 9 or 13 steps (`Spot`, `Mark`, `ExternalPerp`). Errors end after 12, 14 or 18 steps (wrong length, a 4-byte mismatch, a 12-byte mismatch).
- **Serializers:** seven classes each, combining the three arms with no growth call, one call, or (for `ExternalPerp` only) two calls.

## Implementation and comparison

The reconstruction lives in `tools/re015_spot_mark_codec_115.py` as pure functions. There is no Rust implementation yet.

- `recon_tag_name(tag)` returns `Spot` for 0, `Mark` for 1 and `ExternalPerp` for any other byte.
- `recon_serialize(tag, cap, len)` appends `0xa0 | len(name)` followed by the name. It reserves 1 when `cap == len`, then reserves `len(name)` when `cap - len < len(name)`, and returns `0x8000000000000004`.
- `recon_classify(text)` returns the index of `text` in `NAMES` only for an exact, full-length, case-sensitive match. `recon_visitor_tagged` wraps it in the observed output word.

Comparison inputs:
- **Serializer:** 3 copies × (3 tags × 4 starting lengths × 16 spare capacities + 253 out-of-range tag bytes) = 1,335 cases. Each case compares the appended bytes, the exact sequence of growth calls `(len, additional)`, the final length and the result word.
- **Visitors:** 5,162 distinct inputs × 3 copies = 15,486 cases. The inputs are:
  - the empty string and every prefix of each name;
  - each name plus one byte, plus a doubled last byte, and plus a NUL;
  - each name in lower and in upper case;
  - every single-byte substitution of every position with all 256 values;
  - cross-name half splices and concatenations;
  - `A` repeated 0..16 times.

Result: 1,335/1,335 serializer cases and 15,486/15,486 visitor cases match.

Negative controls (`negative-controls.tsv`). Each count must be above 0, or the producer fails:

| Wrong reconstruction | Failing cases |
| --- | --- |
| serializer without the second (name-length) reserve | 249 / 1,335 |
| serializer reserving when spare equals the name length | 36 / 1,335 |
| serializer using a str8 marker (`0xd9 len`) | 1,335 / 1,335 |
| serializer mapping out-of-range tags to `Spot` (range-checked table) | 759 / 1,335 |
| visitor accepting a name prefix | 45 / 15,486 |
| visitor folding case | 72 / 15,486 |
| visitor with `Spot` and `Mark` swapped | 6 / 15,486 |
| visitor checking only the first qword of `ExternalPerp` | 3,060 / 15,486 |
| visitor without the length gate (4-byte prefix of a longer input) | 30 / 15,486 |

The unit test also mutates the target bytes and checks that each change is detected:
- the `Spot` immediate at `0x22e20d8`: the name is now rejected;
- the tag compare at `0x22e3820`: the `Mark` tag now writes `ExternalPerp`;
- the reserve bound at `0x22e3848`: the growth sequence changes;
- a `ud2` at a body entry: rejected as an unsupported instruction.

It also checks that each of these is rejected: an unmodelled call, an error call that loads a different pool, an out-of-scratch store, and a wrong input digest.

## Results and limitations

- All 6 selected bodies are fully decoded: 486 instructions, with decoded bytes equal to FDE bytes.
- 1,335/1,335 serializer cases and 15,486/15,486 visitor cases match the reconstruction.
- 9/9 negative controls are caught.
- The callees are stubs, not reconstructions. The growth policy inside the grow callees and the error value are outside the claim; only the callees' arguments and how the bodies use their results are compared.
- The out-of-range tag behaviour (bytes 3..255 write `ExternalPerp`) describes the compiled code. A valid Rust value of the enum never has those tags.
- The serde/rmp role names and any domain meaning of `Spot`/`Mark`/`ExternalPerp` are inferences. No caller was traced.
- No progress gate is requested. This packet covers one enum codec, not the `constants` component.

Next question: which struct serializers call the three serializer copies, and under which map-key literal do they write this field?
