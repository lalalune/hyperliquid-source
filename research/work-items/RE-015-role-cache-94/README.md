# RE-015: trace the name-gated user-role cache and role writer in node 94

This packet identifies how a configuration-name gate follows role lookup and cache updates, and establishes the distinct cache-miss and five role tags plus their candidate writer descriptors and nested field keys.

- Component ID: `constants` / RE-015, with an explicitly bounded downstream user-role path.
- Target release and full SHA-256: Linux x86-64 node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: repository `e5c9b6436876b2a4a39daef813171f9879317699`; unlicensed reference tree `999556f6e0a474b8312db96ec3149e1c44e97c23`, used only for comparison of previously investigated labels and defaults.
- Claim status: static byte observations and explicitly identified inferences; external helper effects, runtime behavior and some inter-function connections remain unresolved.
- Scope included and excluded: fifteen selected FDE ranges, their local control flow, selected exception entries, configuration gate, cache structures and separate five-arm writer; no complete node, AWS-name inventory, compiler reconstruction, #115 or visor comparison, networking or captured-binary execution.

## Reproduce

From the repository root on Linux x86-64, with the node artifact and the shared `tools/elf_index.py` and `tools/fde_extents.py` present. The captured input is checked for both its full SHA-256 and byte length before any parsing; all generated evidence is built from ELF bytes using Python's standard library. The generator reads the binary as data; it does not execute it or invoke other programs. This run used Python 3.12.3. Numeric code addresses are linked ELF virtual addresses (VAs); file offsets, FDE record VAs, LSDA VAs, relocation-record file offsets and LSDA entry file offsets are separately labeled in the TSV files.

```sh
python3 tools/config_role_cache94.py --out research/work-items/RE-015-role-cache-94
python3 -m unittest tests.test_config_role_cache94
python3 tools/artifacts.py verify
python3 tools/catalogue.py --check
python3 tools/reproduce.py
(cd research/work-items/RE-015-role-cache-94 && sha256sum -c MANIFEST.sha256)
PYTHONHASHSEED=7 TZ=UTC python3 tools/config_role_cache94.py --out work/role-cache-a
PYTHONHASHSEED=983 TZ=Pacific/Honolulu python3 tools/config_role_cache94.py --out work/role-cache-b
diff -r work/role-cache-a work/role-cache-b
for f in work/role-cache-a/*; do
  cmp "$f" "research/work-items/RE-015-role-cache-94/${f##*/}"
done
```

Use empty directories for the last two runs and compare each generated file to the namesakes beside this README. The generated TSV/JSON files are the raw reproducible records; `MANIFEST.sha256` covers them and this README, but not itself. No binutils output is parsed. The instruction-length decoder is deliberately scoped to these byte-locked ranges; it is not a general x86 disassembler or a function census. FDE starts and ends are unwind ranges, not automatically the complete source functions. Local direct branch targets are checked against decoded instruction starts, while indirect branches and external calls are retained as boundaries.

## Evidence

### Entry, configuration and ownership boundaries

`handoffs.tsv` records thirteen short instructions in previously inventoried caller bodies, solely to locate the new path. The pointer and explicit length at `0x27e537a` and `0x27e5386` select all 20 bytes of `user_role_cache_peek` at VA/file offset `0x3f3adf`; the pointer and length at `0x27e55a3` and `0x27e55be` select all 22 bytes of `user_role_cache_update` at `0x3f3af3`. These strings are adjacent without a terminating separator. The selected call sites invoke peek `0x27d5ac0` and update wrapper `0x258ac60`. Tag 5 at `0x27e5412` separates the miss arm from a preexisting freshness path; a hit is not shown to bypass that freshness path.

On the miss arm, a vtable reference `0x56c4018` and its `+0x18` RELATIVE relocation resolve to `0x27f7530`; another at `0x56c44f0` resolves similarly to `0x27f93b0`, which calls role wrapper `0x25869c0` at `0x27f9400`. These short caller observations and relocation slots are context only; the already inventoried caller FDEs are not selected or claimed here. The exact freshness policy and full async/polling behavior are outside this packet.

After its selection call, wrapper `0x25869c0` copies the tag and associated bytes before a gate. It adds two binary64 values and compares their sum to the file-backed value `3.0` at VA/file offset `0x20aab8`. Equal, lower and unordered comparisons bypass the gate. When the sum is greater, RELATIVE slot `0x576e928` resolves to the global cell `0x577b288`; the wrapper checks its word at `+0x50`, then reads byte `+0x48` after the local once path if needed. For a byte no greater than 31, `bt` tests mask `0x803c6000`, selecting bytes 13, 14, 18, 19, 20, 21 and 31. Only those cases reach the second cell state at `0x577ab98`. Update wrapper `0x258ac60` uses the same threshold, bound and mask after its update call. The gate is not shown to change the returned role or the cache mutation; the values' meaning and units and the external once helper's effects are unresolved.

A human-readable excerpt of the selected gate (GNU objdump 2.42, Intel syntax) is shown for inspection; `contracts.tsv` contains the exact reproducible bytes and no generator parses this text:

```text
2586a45: 83 f8 1f             cmp eax, 0x1f
2586a48: 77 14                ja  0x2586a5e
2586a4a: b9 00 60 3c 80       mov ecx, 0x803c6000
2586a4f: 0f a3 c1             bt  ecx, eax
2586a52: 73 0a                jae 0x2586a5e
```

The existing constants and AWS-parser packets associate `NvTestnet` and the failed-parse default with byte 32. This packet independently preserves its complete nine-byte descriptor at `0x2180ff` through relocation `0x5668488`; assuming that previously established byte is present in the global cell, this gate bypasses the second cell because 32 exceeds 31. The reference tree suggests the same default, but is not treated as evidence of runtime state. Neither the prior 76-entry table nor the previously owned parser FDEs are reproduced as new findings.

### Role selection and the cache

The selected entry and helper ranges and their full bytes, FDE record VAs and body digests are in `functions.tsv` and `instructions.tsv`; `layout.tsv` decodes the referenced offsets and sizes directly from the selected instruction bytes. The labels below are analytical names, not recovered Rust symbols. `0x27cfdd0` searches a 20-byte key in the following local precedence, with all sixteen synthetic hit combinations in `role-cases.tsv`:

| Search order | Container coordinates relative to the selector's base | Match tag | Observed payload |
| --- | --- | ---: | --- |
| first map | pointer `+0x4720`, count `+0x4738` | 2 | copies 20 bytes |
| ordered tree | root `+0x18c0` | 3 | no copied map payload established |
| second map | pointer `+0x4800`, count `+0x4818` | 4 | copies 20 bytes |
| third map | pointer `+0x1730`, count `+0x1748` | 1 | no copied map payload established |
| no match | no later source | 0 | no copied map payload established |

The common output stores the tag at result `+0x10` and a 20-byte payload area beginning at `+0x11`. Stores of that area do not by themselves prove that the payload was initialized for the non-map outcomes. `cfg.tsv` checks the selected match arms' local reachability and shows why a later container is not searched after an earlier match, under normal call returns.

Peek `0x27d5ac0` and update `0x27d2d90` use the same cache at object `+0x570` and lock at `+0x568`. The lookup helper `0x1f854e0` compares the full 20-byte key and returns a null pointer on a miss; peek turns that into tag 5. A hit copies the 48-byte record, whose tag is at `+0x14`, and no local relink is observed on this lookup path. Tag 5 is therefore a cache sentinel at these sites; it is neither the role-selection no-match tag 0 nor an established valid input to the role writer.

Update calls `0x1f851b0` while holding the local lock. For an existing key it swaps in the 48-byte record, returns the prior record and relinks the node. For a new key with available capacity it allocates `0x58` bytes, inserts an index entry and links the node. At capacity it removes the index entry for the sentinel's predecessor, reuses and relinks that node, and inserts its new index entry. New-key paths return tag 5, including the reuse path. The input-derived 64-bit value loaded before the insertion is incremented with saturation at `2^64-1` and placed in the new record; a write back to its source is not observed. `cache-cases.tsv` is a synthetic front-to-tail model with positive capacity as a research precondition, not proof that the target rejects capacity zero.

The selected index removal `0x2047aa0` computes a 16-bit neighbor distance. At distance at most 15, its local path writes marker `0xff` and increments a counter, with a separate counter-overflow boundary. Above 15 it writes `0x80` without that increment; the mirrored control-byte write is also recorded. `marker-cases.tsv` varies the assumed distance and counter, not actual hash-table reachability. Index insertion is `0x2047c80`. Allocation failure and failure to find the selected tail reach separate external call boundaries.

### Independent writer and exception paths

Writer `0x2a287e0` indexes the five signed 32-bit jump-table entries at `0x41f33c` using its input tag. Each arm passes a relocated descriptor with the type string `UserRole`; `role-descriptors.tsv` records the pointer, length, ordinal and full variant spelling:

| Input tag / descriptor ordinal | Variant | Additional local data-key path |
| ---: | --- | --- |
| 0 | `missing` | none observed |
| 1 | `user` | none observed |
| 2 | `agent` | call at `0x2a289cb` |
| 3 | `vault` | none observed |
| 4 | `subAccount` | call at `0x2a28925` |

All five arms select the full four-byte key `role`. Only arms 2 and 4 reach the four-byte key `data` and their respective helpers, according to the bounded CFG. The `agent` path is `0x29fb8b0` to `0x2a28cf0`, whose field call supplies `user` at `0x209ebc`, length 4. The `subAccount` path is `0x2a04fb0` to `0x2a28bc0`, whose field call supplies `master` at `0x41fb8e`, length 6. `writer-keys.tsv` includes the exact bytes, lengths, references and file offsets. The nested helper returns select a normal continuation on zero and a local cleanup path on nonzero. These are field and control-flow observations; the external field helper and final wire encoding have not been closed.

All five writer arms call the newly selected common field helper `0x29fbd30`. It loads the variant length from descriptor `+0x18` at `0x29fbddd` and the pointer from `+0x10` at `0x29fbdf3`, consistent with the relocated slices in `role-descriptors.tsv`. On the normal path it passes a destination, that pointer and length to the indirect byte helper at `0x29fbe1f`, then reaches the separate object helper `0x2a39f40`. The latter helper and the bytes helper remain external boundaries. A negative variant length or failed variant allocation reaches an external failure helper followed by `ud2` if it returns; its protected call at `0x29fbdeb` has landing `0x29fbf2c`, which frees the earlier temporary when applicable and resumes unwinding.

The selector's 0–4 tags agree with these writer ordinals. It is a useful reconstruction hypothesis that each selector tag corresponds to the same writer variant, but the complete selector-to-writer transport has not been established independently. The `writer_descriptor_if_tag_reused` column makes this condition explicit. Rejecting tag 5 in the research model defines its analysis domain and does not assert the target's response to an invalid tag.

`lsda.tsv` preserves all 55 parsed call-site entries for the selected FDEs. `failure-routes.tsv` selects fourteen call-site/landing pairs, including selector hashes, cache lookup and insertion, the five writer arms, both nested data paths and the common field helper failure. The selected cache landing pads perform local lock-release instructions before the external unwind continuation. The nested writer field-call landing pads reach local cleanup and then the unwind continuation; their cleanup-failure entries remain recorded separately. Normal-return CFG reachability does not model exception propagation or the behavior of the called helpers.

## Implementation and comparison

Independent Rust implementation: not yet implemented. Cargo dependency lock, compiler/linker settings, two-build reproducibility, captured-execution fixtures and target implementation comparison: not yet implemented or measured. No raw or normalized binary comparison has been attempted; no masks, matched-window denominator, vtable closure or whole-ELF equivalence are claimed. The shared ELF and FDE parsers supply section and unwind metadata; the packet-specific decoder, relocation checks, selected byte contracts, LSDA extraction and synthetic models provide the bounded evidence described above. Inferred source labels remain hypotheses.

## Results and limitations

`summary.json` reports 15 selected FDE ranges totaling 9,038 bytes; 2,079 linear instruction records; 195 direct branches; 156 calls or indirect transfers; 343 exact instruction contracts; 19 decoded layout fields; 28 selected RELATIVE relocations; 55 LSDA call-site entries; 34 local CFG propositions; and 14 selected exception call sites. The models cover 16 role-hit combinations, 3 cache actions, 36 name-gate combinations and 18 assumed-distance/counter cases. They are mathematical controls on the stated interpretation, not node executions. The focused suite contains 35 tests with negative controls for digest, code, FDE, branch boundary, relocation, label, key, name gate, descriptor and landing corruption; all passed with zero skips in the stated environment.

The evidence does not close the preexisting caller's freshness path, all allocator/hash/time/format helpers, dynamic type transport to the writer, the cache's full lifetime or all role outputs. The configuration component remains at 0/4 gates; no full-scope gate is requested. The available local repository and PR snapshot were checked for selected-address ownership, but no live upstream refresh was performed under the no-network constraint. The next question is whether the caller transports the selected tag and payload unchanged into this writer after freshness handling, using coordinated evidence for the already inventoried boundary.
