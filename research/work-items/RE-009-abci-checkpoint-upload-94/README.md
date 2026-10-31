# RE-009: what does the node #94 abci checkpoint thread body run after the checkpoint file exists?

- Component ID: storage / state roots (reference labels `node/abci_checkpoint.rs`, `base/fu.rs`, `base/shell.rs`, used as leads only).
- Target release and full SHA-256: Linux x86-64 hl-node #94, `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
- Source commit / reference commit: branch cut from `1f8c67c`; reference submodule as pinned there.
- Claim status: observation for every pin, table and census row below; inference where marked; unresolved items are listed under Results and limitations.
- Scope included: closure `0x432fc10`, its sleep_retry monomorph `0x13c96c0`, compress worker `0x14503b0`, upload helper `0x1404d90`, and the small callees needed to read them (`0x14050e0`, `0x144cca0`, trampoline `0x433a9a0`).
- Scope excluded: the code that builds the closure (spawner), the checkpoint serialization, the shell runner, the quoting rules, and any #115 or visor claim.

## Reproduce

From the repository root on Linux, with Python 3 standard library only. The tool runs no external program and does not execute the binary.

```
python3 tools/artifacts.py verify
python3 tools/abci_checkpoint_upload.py --out research/work-items/RE-009-abci-checkpoint-upload-94
python3 -m unittest tests.test_abci_checkpoint_upload
```

The tool checks the input SHA-256 first and fails on any other file. It writes `abci-checkpoint-upload.json` and `abci-checkpoint-pins.tsv`; both hashes are in `MANIFEST.sha256`. Runtime is about 20 s.

## Evidence

Addresses are virtual addresses. Function bounds come from `tools/fde_extents.py`, sections from `tools/elf_index.py`, relocations from `.rela.dyn` with `struct`. All 84 instruction facts are fixed byte pins in `abci-checkpoint-pins.tsv`; 42 of them also resolve a relative operand from their own bytes.

| Function | Start | Bytes |
| --- | --- | --- |
| closure | `0x432fc10` | 565 |
| retry | `0x13c96c0` | 870 |
| worker | `0x14503b0` | 1105 |
| mv helper | `0x1404d90` | 343 |
| config string getter | `0x14050e0` | 349 |
| remove old output | `0x144cca0` | 749 |
| trampoline | `0x433a9a0` | 456 |

Call chain, closed by census over `.text` and `.rela.dyn`:

- `0x14503b0` has 2 direct callers, `0x13c9716` and `0x13c98ef`, both in `0x13c96c0`.
- `0x13c96c0` has 1 direct caller, `0x432fc69`, in the closure.
- The closure is reached only through RELATIVE slot `0x5776630`, used once, at `0x433aa1a` in `0x433a9a0`.
- `0x433a9a0` has one RELATIVE row, `0x571cae0`, the call slot of the vtable at `0x571cac8` (size 0x50, align 8). The closure payload starts at box offset 0x28.
- `0x1404d90` is bound by one slot, `0x576efd8`, and that slot has one use, `0x432fc97`.

The census is a raw byte scan for `e8`/`e9`, `ff15`/`ff25`, RIP `mov` and RIP `lea`, plus RELATIVE addends. A byte scan can over-count and misses other pointer forms, such as an address computed in pieces. It found exactly these rows, and no RIP `lea` of the five chain functions.

Closure steps:

1. The payload holds a destination `String` at +0x00 and a source `&str` at +0x18. Pins `0x432fc20`, `0x432fc24`, `0x432fc89`, `0x432fc8d`.
2. It stores two option bytes, 0 then 1 (`0x432fc32`), and calls `0x13c96c0` with label `zip_inner_retry` (15 bytes) and no sleep list (`0x432fc66`).
3. Err unwraps at `node/src/abci_checkpoint.rs:26:26`.
4. It passes the returned path and the destination to `0x1404d90`. Err unwraps at `node/src/abci_checkpoint.rs:27:55`.
5. It stores 1 at `0x57883f1` under the lock at `0x57883f0`.

Retry: one attempt, then one attempt after each default sleep. The table at `0x216dd8` is 0.001, 0.05 and 1.0 seconds, so 4 attempts when all fail. Option bytes are reloaded for each attempt (`0x13c98ce`, `0x13c98d1`). Exhaustion text decodes to `sleep_retry retried {} for sleep times {} last err {}`.

Worker, for input path `p`:

- A path of 4 or more bytes ending in `.lz4` returns Err `zip_inner: {}` before any file action (`0x14503d1`, `0x14503d7`).
- The output path is `p` followed by `.lz4`.
- `0x144cca0` removes an existing output: an exists test, then `unlink` through import slot `0x576f690`. It runs on every attempt.
- Input and output each pass through `0x4ecc3d0`; Err gives `zip_inner {}: {}`.
- The command template decodes to `lz4 -q -9 {} {} {}`, with arguments option text, input, output (`0x14505f9`, `0x145060b`, `0x1450624`).
- Option byte 1 selects `--rm` or an empty string (`0x1450462`, `0x145046a`). The closure sets it, giving `lz4 -q -9 --rm <in> <in>.lz4`. An empty option would leave two spaces.
- Option byte 0 sets the flag byte beside the command (`0x14506c9`). The closure leaves it clear.

Upload helper `0x1404d90(a, b)`:

- `0x14050e0` reads an optional string at config offset 0x1a8 (tag), 0x1b0 (pointer), 0x1b8 (length), from global slot `0x576eb70`.
- None returns Ok and runs nothing (`0x1404dc4`).
- Some joins the words `aws`, `s3`, `mv`, `a`, `b` through `0x1455c00` and runs them with `0x13c9080`, label `shell::wait_retry`, no sleep list, flag byte clear.

Related rodata, not bound to any function here: the template at `0x1e1ad7` decodes to `{}/hyperliquid/abci_checkpoints/{}/{}.lz4`.

Inferences, kept apart from the observations:

- The chain compresses a checkpoint file and moves the result to object storage. This rests on the command words and the rodata template, not on an observed spawn site.
- `0x4ecc3d0` is shell quoting from `shlex`. The crate string `shlex-1.3.0` is in the binary and the callee handles quote bytes, but the crate entry was not proved.
- The option at config +0x1a8 is the reference's `s3_bucket`. Only the offset is observed.
- `--rm` removes the input after a successful compress. That is lz4 tool behavior, outside this binary.

Against the reference, read as a lead:

- `node/abci_checkpoint.rs` models `zip_inner_retry` as a file name suffix with a temporary file, `File::create`, `sync_all` and `fs::rename`. In the bytes it is only the retry label, and the output name is `.lz4`.
- `base/fu.rs` puts a newline before `last err`. Byte 0x0a in that template is a literal length, so the rendered text has a space there.

## Implementation and comparison

not yet implemented. No Rust path, build or binary comparison exists for this scope.

## Results and limitations

- 84 of 84 pins match; 42 of 42 relative operands resolve to the expected target.
- 6 of 6 templates, 7 of 7 texts, 2 of 2 Location rows and 8 of 8 slot bindings match.
- 31 unit tests pass, including one negative control per pin plus one per relative operand.
- Analysis of the listed functions was limited to the pinned facts; the census covered all of `.text` and `.rela.dyn`.

Unresolved:

- The spawn site and where source and destination come from. That code is outside this packet, so the destination shape stays an inference.
- Any reader of `0x57883f1`.
- The first thread step at `0x433a9f1` (slot `0x57733a8`).
- The exact word quoting in `0x1455c00`.
- What a failed unwrap does to the rest of the node.

Next question: which call builds this closure, and do its source and destination match the rodata template at `0x1e1ad7`?
