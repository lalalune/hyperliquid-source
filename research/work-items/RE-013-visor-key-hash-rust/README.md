# Visor seeded key + FF value reconstruction

RE-013 closes the complete arithmetic dependency used by the existing Visor lookup proof: two seed words and arbitrary input bytes produce one 64-bit value after exactly one additional FF byte. This is the pre-code evidence freeze for a proposed real `src/visor-key-hash` crate. Production Rust is absent at this freeze and requires the separate review gate in [CONTRACT.md](CONTRACT.md). No implementation, target execution or component-completion claim is made yet.

The only target is Visor SHA-256 `89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`, 8,305,392 bytes. Addresses are linked ELF VAs, with exclusive ends. Source base is `56c0ec672bd8fdcfaa80f2db700a61e6240b3663`.

| Complete FDE extent | Role | Bytes / native rows |
| --- | --- | --- |
| `0x626760..0x6268c0` | Seed initialization, two feed calls, final value | 352 / 90 |
| `0x628d00..0x628ed7` | Complete call-free feed | 471 / 141 |
| `0x5d3220..0x5d3361` | Lookup context, selected seed and result use | 321 / 94 |
| `0x5b9070..0x5b92a6` | Selected literal/call context | 566 / 125 |

The value theorem covers 823 bytes / 231 rows. The remaining 887 bytes / 219 rows are complete native context, not a new table or whole-caller theorem. [PROOF.md](PROOF.md) derives seed lane order, every feed path, bounded little-endian reads, wrapping arithmetic, final length-byte projection and the shortened last round's XOR cancellation. Its memory/stack premises are explicit. The graph's two calls both target the retained feed; it has no allocator or imported dependency.

[PR #1009](https://github.com/lalalune/hyperliquid-source/pull/1009) established the lookup's ordinary 0/1 return bound while leaving this hash opaque. [PR #988](https://github.com/lalalune/hyperliquid-source/pull/988) supplied selected CLI context. Their exact main-base packet identities are pinned in [BASIS-PINS.json](BASIS-PINS.json). The self-contained ELF coordinate parser credits the independently authored MIT child-args parser in its source header; that packet is not an import or replay dependency. No unlicensed inferred source or existing hash-library implementation supplies the oracle.

The actual author pre-code run passed 36 rejection controls and regenerated all 13 retained native/corpus files byte-identically in a second output tree. [PRECODE-VALIDATION.json](PRECODE-VALIDATION.json) retains each rejection and regeneration stdout/stderr; [PRECODE-RUN.json](PRECODE-RUN.json) records commands and the interpreter. The controls comprise two whole-image identity checks, 27 operand/literal checks below whole-image/body hashes, three decoded FDE field checks with raw FDE identity rebound, two RELA structural checks and two native-export partition checks. These test evidence binding, not the semantics of a mutated executable.

[corpus.py](corpus.py) independently constructs 12,724 deduplicated expected values across 264 seed pairs using whole-message mathematical decomposition. The corpus covers every one-byte input under ten seeds, individual seed/message bits, block/tail and length-byte rollover boundaries, and opaque NUL/FF/invalid UTF-8 inputs. Its 9,520 quotient/remainder checks, 224 packing basis bits and 66 cancellation vectors supplement the manual general proof. These are mathematical expectations, never observed target outputs. Opaque input IDs and provenance are separate; the later Rust client receives no expectations or semantic labels. [VALIDATION-PLAN.md](VALIDATION-PLAN.md) specifies the future source freeze, actual dependency-free Cargo builds and compiling semantic mutants.

Run from the repository root with the authenticated capture and credited main-base inputs materialized:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 research/work-items/RE-013-visor-key-hash-rust/verify.py --require-source-absent --out /tmp/hl-key-hash-precode-replay
```

The output directory must not exist. This command requires production source absence. After a separately approved implementation exists, omit `--require-source-absent` to replay only the static/corpus evidence; that does not verify future Rust. Defaults use installed GNU binutils under `/opt/homebrew/opt/binutils/bin` and LLVM `/usr/bin/objdump`. Complete dual exports, raw FDE/CIE records, all-RELA overlap summaries and provider identities are in `observed/`; inputs, expectations and provenance are separate compressed files in `frozen/`.

All binary observations have one project provenance. GNU and LLVM are independent decoders of that same capture, not independent source organizations. Native execution, generic streaming behavior, source-library identity, cryptographic strength, seed generation, table membership, cache consistency, control mirroring below capacity 16, growth and probe reachability remain outside this result. No byte-coverage, catalogue or component gate is changed. New code and documentation are MIT; the captured artifact retains its original rights.
