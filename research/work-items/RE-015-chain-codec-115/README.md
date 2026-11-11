# RE-015: reconstruct the node #115 chain-name codec (msgpack writer and exact-name visitors)

The four-name chain enum of node #115 (`Local`, `Sandbox`, `Testnet`, `Mainnet`, tags 0..3) can now be rebuilt as executable code in both directions: three monomorphized serializer copies write exactly one msgpack fixstr (`0xa5` + `Local` or `0xa7` + a 7-byte name) into a `Vec<u8>` with two capacity checks, and five visitor copies accept only a complete, case-sensitive, exact-length match and otherwise hand the input and a four-entry name table to an unknown-variant error callee. The reconstruction agrees with the original machine code, interpreted byte by byte, on all 360 serializer cases and all 33,375 visitor cases, and seven deliberately wrong reconstructions are each caught.

- Component ID: `constants` (Global configuration); task `RE-015`, using the RE-001 unwind index (`tools/fde_extents.py`) and the shared section parser (`tools/elf_index.py`).
- Target release and full SHA-256: Linux x86-64 node #115, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (`artifacts/node/115/hl-node`).
- Source commit / reference commit: repository `05bc2de303c05525b71e7e257426e741bc66a390`. No inferred reference source was read or copied for this packet; #94 material is not used.
- Claim status: **observation** — FDE extents, decoded instruction bytes, jump-table entries, immediates, RELATIVE relocations and the interpreted results of the original bytes on the listed inputs. **Inference** — the serde/rmp roles (`Serialize` writing a unit variant name as a msgpack string, field-identifier `visit_str`/`visit_bytes`), the meaning of the result words, and that the error callees build `unknown_variant` errors. **Unresolved** — callers of the eight bodies, the grow and error callees' internals, and which configuration structures own each copy.
- Scope included and excluded: included are eight complete bodies (every byte of each FDE extent is decoded; trailing bytes are only `int3` fill): serializers `0x2674b80`, `0x467f2d0`, `0x57c1de0`; tagged visitors `0x14be010`, `0x2690cd0`, `0x4682610`; result visitors `0x2690d70`, `0x46826b0`; their three jump tables and three variant-name tables. Excluded: the already-published classifier `0x14be0b0` (RE-015 replica bucket packet) and the apply writer `0x564cce0` (RE-005 rmp signable tag writers), the callee bodies `0x231e050`/`0x43bd910`/`0x5963a10` (Vec growth) and `0x14a1970`/`0x17fbba0`/`0x2cf1360`/`0x2f7fef0`/`0x45a8fe0` (error construction), all callers, and any progress gate.

## Reproduce

From the repository root on Linux x86-64 with Python 3.12.3 (standard library only plus `tools/elf_index.py` and `tools/fde_extents.py`). The producer checks the full SHA-256 of the input before parsing anything, never executes the capture, starts no process and makes no network access. It interprets the selected machine code in Python; output contains no time, randomness, absolute path or unordered-dict iteration.

```sh
python3 tools/re015_chain_codec_115.py --out research/work-items/RE-015-chain-codec-115
python3 -m unittest tests.test_re015_chain_codec_115
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
```

Determinism check (two independent outputs, different hash seed and time zone):

```sh
PYTHONHASHSEED=7 TZ=UTC python3 tools/re015_chain_codec_115.py --out <tmp-dir-one>
PYTHONHASHSEED=91 TZ=Pacific/Honolulu python3 tools/re015_chain_codec_115.py --out <tmp-dir-two>
diff -r <tmp-dir-one> <tmp-dir-two>
```

The producer writes exactly the ten generated files below; `README.md` and `MANIFEST.sha256` are maintained separately. It exits non-zero, writing nothing, if the digest differs, an entry is not an FDE start, any byte in a body falls outside the supported instruction subset, a call reaches an unmodelled target, a store leaves scratch memory, a variant slot lacks a RELATIVE relocation, any case disagrees with the reconstruction, or any negative control is not caught. A full run takes about 22 s.

| Generated evidence | Contents |
| --- | --- |
| `functions.tsv` | 8 bodies: role, entry, FDE end, size, decoded instruction count and bytes (equal to the FDE size), LSDA, body SHA-256, direct callees |
| `instructions.tsv` | 771 decoded instructions (VA, length, raw bytes, operation, branch/call target) |
| `jump-table.tsv` | 12 rows: each serializer's rel32 table entry per tag, arm VA, fixstr marker store and marker byte |
| `variant-refs.tsv` | the rip-relative `lea` in each visitor's error arm and the table it loads |
| `variant-table.tsv` | 12 rows: the three `&[&str]` tables, slot VA, `.rela.dyn` file offset of the RELATIVE relocation, string VA, length, text |
| `serializer-cases.tsv` | 360 cases: serializer × tag 0..3 × length {0,1,13} × spare capacity 0..9; appended bytes, grow calls (`length+additional`), final length, result word, verdict |
| `visitor-cases.tsv` | 6,675 inputs × 5 visitors: outcome per copy, reconstruction, verdict |
| `paths.tsv` | per visitor, the number of inputs ending after each interpreted step count and status (path classes) |
| `negative-controls.tsv` | seven wrong reconstructions and how many cases each fails |
| `summary.json` | totals, callee lists, table bases and pass flags |

## Evidence

Coordinates are linked virtual addresses (VA). `.text` file offset = VA − `0x1000`; `.rodata` file offset = VA; `.data.rel.ro` file offset = VA − `0x2000`. Section membership comes from `elf_index.sections` with SHT_NOBITS sections excluded. Body extents come from `fde_extents.fde_extents`; none of the eight FDEs has an LSDA.

**Serializers** (`0x2674b80`, `0x467f2d0`, `0x57c1de0`; 689 bytes and 169 instructions each, same shape, different jump table, grow callee and string immediates' locations). Human-readable excerpt of `0x2674b80` (GNU objdump 2.42, not used by the tool):

```
2674b87: movzx ecx,BYTE PTR [rsi]          ; tag byte
2674b8a: lea   rsi,[rip+...]               ; table 0x5f2960
2674b91: movsxd rcx,DWORD PTR [rsi+rcx*4]
2674b95: add   rcx,rsi ; jmp rcx
2674b9a: mov rcx,[rdx] ; mov rsi,[rdx+0x10] ; cmp rcx,rsi ; je grow(len,1)
2674bae: mov BYTE PTR [rdi+rsi*1],0xa5     ; fixstr length 5
2674bb9: sub rcx,rsi ; cmp rcx,0x4 ; jbe grow(len,5)
2674bc6: mov BYTE [..+4],0x6c ; mov DWORD [..],0x61636f4c   ; "Local"
2674c94: mov [rdx+0x10],rsi ; movabs rcx,0x8000000000000004 ; mov [rax],rcx ; ret
```

The tool decodes the jump-table entries from `.rodata` bytes: tag 0 → `Local` arm, 1 → `Sandbox`, 2 → `Testnet`, 3 → `Mainnet` in all three copies (`jump-table.tsv`). The marker byte stored first in each arm is `0xa5` (tag 0) or `0xa7` (tags 1–3). The 7-byte names are written as two overlapping dword immediates at +0 and +3. There is no range check on the tag byte; the table has four meaningful entries and the producer only drives tags 0..3. Every growth call passes `(vec, len, additional, 1, 1)`: `additional` is 1 before the marker when `cap == len`, then 5 or 7 when the remaining capacity after the marker is `<= 4` or `<= 6`, that is, strictly less than the name length. Every path stores the word `0x8000000000000004` to `[rdi]`, and no path returns an error.

**Tagged visitors** (`0x14be010`, `0x2690cd0`, `0x4682610`; 150 bytes, 48 instructions). Length 7 is tested first, then length 5; any other length goes straight to the error arm. Length 5 requires `dword[0] == 'Loca'` and `byte[4] == 'l'`; length 7 tries `Sandbox`, `Testnet`, `Mainnet` in that order with `dword[0]` and `dword[3]` xor-compares. Success stores the word `0x09 | tag << 8` at `[rdi]`. Failure calls the copy's error callee with `(out, ptr, len, table, 4)`.

**Result visitors** (`0x2690d70`, `0x46826b0`; 172 bytes, 60 instructions) apply the same checks but store `byte[0] = 0`, `byte[1] = tag` on success. On failure they call the error callee with `(ptr, len, table, 4)` and store its return value at `+8` and `byte[0] = 1`.

**Variant tables** (`0x63f8748`, `0x6437328`, `0x64915a8`): each is four `(ptr, len)` slots. The pointer of each slot is a `.rela.dyn` R_X86_64_RELATIVE addend, read by the tool. The texts read from those addends are `Local`, `Sandbox`, `Testnet`, `Mainnet` in tag order, so the error-path name list has the same order as the success tags. The table `0x63f8748` was already listed as chain descriptors in the RE-015 replica bucket packet; this packet adds the relocation file offsets and the visitor that loads it.

**Interpreter.** The tool decodes every byte of each body. The subset covers REX/0x66 prefixes, ModRM/SIB/rip-relative addressing, add/sub/cmp/xor/or/and/test, mov forms, movzx, movsxd, lea, inc, Jcc/jmp rel8/rel32, indirect jmp, call rel32, push/pop and ret. The interpreter tracks ZF and CF, which is enough for every conditional branch present (`je`, `jne`, `jbe`). It writes only to scratch memory above the image. Reads below it come from file-backed sections. Calls go only to the identified grow/error callees, which are modelled as stubs: growth sets `cap = max(2·cap, len+additional, 8)`, and errors return a sentinel. After a call, the interpreter overwrites caller-saved registers, so the body cannot depend on their old values. The step counts in `paths.tsv` give 7 path classes per tagged visitor and per result visitor. These match the source structure: a wrong length, a failure at each comparison, and four success arms.

## Implementation and comparison

The reconstruction lives in `tools/re015_chain_codec_115.py` as pure functions. It has no Rust implementation yet.

- `recon_serialize(tag, cap, len)` appends `0xa0 | len(name)` followed by the name. It reserves 1 when `cap == len`, then reserves `len(name)` when `cap - len < len(name)`, and returns `0x8000000000000004`.
- `recon_classify(text)` returns the index of `text` in `NAMES` only for an exact, full-length, case-sensitive match. `recon_visitor_tagged` and `recon_visitor_result` wrap it in the two observed output shapes.

Comparison inputs:

- **Serializer:** 3 copies × 4 tags × 3 starting lengths × 10 spare capacities = 360 cases. Each case compares the appended bytes, the exact sequence of growth calls `(len, additional)`, the final length and the result word.
- **Visitors:** 6,675 distinct inputs × 5 copies = 33,375 cases. The inputs are the empty string, every prefix of each name, each name plus one byte, a doubled last byte, lower and upper case, every single-byte substitution of every position with all 256 values, and cross-name splices at offsets 3 and 4. The splices exercise the overlapping dword checks.

Result: 360/360 and 33,375/33,375 cases match.

Negative controls (`negative-controls.tsv`; each must be > 0 or the producer fails):

| Wrong reconstruction | Failing cases |
| --- | --- |
| serializer without the second (name-length) reserve | 243 / 360 |
| serializer reserving when spare equals the name length | 45 / 360 |
| serializer using a str8 marker (`0xd9 len`) | 360 / 360 |
| visitor accepting a name prefix | 35 / 33,375 |
| visitor folding case | 150 / 33,375 |
| visitor with tags 1 and 2 swapped | 10 / 33,375 |
| visitor checking only the first four bytes and length | 12,765 / 33,375 |

The unit test also mutates the target bytes and checks that each change is detected:

- the `Loca` immediate at `0x2690cdd` (the name is now rejected)
- the serializer jump-table entries for tags 1 and 2 (the wrong name is written)
- the reserve bound at `0x2674c7a` (the growth sequence changes)
- a `ud2` at a body entry (rejected as an unsupported instruction)

It also checks that an unmodelled call, an out-of-scratch store and a wrong input digest are each rejected.

## Results and limitations

- 8/8 selected bodies are fully decoded (771 instructions, decoded bytes equal FDE bytes).
- 360/360 serializer cases and 33,375/33,375 visitor cases match the reconstruction.
- 7/7 negative controls are caught.
- The callees are stubs, not reconstructions. The growth policy inside `0x231e050`-family callees and the error value are outside the claim; only their arguments and the bodies' use of their results are compared.
- The input domain of the serializers is tags 0..3. Bytes outside that range index past the four-entry table, and their behavior is not claimed.
- The serde/rmp role names are inferences from the observed shapes. No caller was traced, so which configuration fields serialize or parse through each copy remains unresolved.
- No progress gate is requested; this covers one enum codec, not the `constants` component.

Next question: which callers reach the three serializer copies, and do their enclosing struct serializers write the chain name as a map value under a fixed key literal that can be recovered from the same bytes?
