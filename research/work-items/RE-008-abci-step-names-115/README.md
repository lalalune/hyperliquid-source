# RE-008: node #115 block-step names and the one host that formats them

- Component ID: abci. Question: which byte slices does the #115 block-step name writer emit for tags 0 to 5, which instruction loads that writer, and what does that host select and format with the same tag byte?
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues the merged #94 packet (#1995, `4ec5b4c79`), which the 115-only migration removed; every address here is new #115 evidence.
- Claim status: the jump tables, slices, relocations, constants and instruction windows are observations. The block-step reading of the names, the meaning of the f64 values, and the rendered text of the format template are inferences.
- Scope included: writer FDE `0x41c9f80..0x41ca014` (148 bytes) and the data it reads; host FDE `0x4da7e20..0x4da81a5` from entry to the format call at `0x4da7ff1`. Scope excluded: the writer target `0x167fa70`, the format routine `0x141e3a0`, the init routine `0x5c87d50`, the host after `0x4da7ff7`, the host's `[rdi+0x20] == 7` branch, and every producer of the tag byte. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/abci_step_names_115.py --check
python3 -m unittest tests.test_abci_step_names_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The two `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence: name writer

`0x41c9f80` keeps `rsi` (the formatter) in `rax`, zero-extends the tag byte at `[rdi]`, and jumps through the relative table at `0x7c6438`. Each of six 21-byte arms loads a slice into `rsi`, its length into `edx`, the formatter into `rdi`, and tail-jumps through `[0x64df720]`. That slot is `R_X86_64_RELATIVE` addend `0x167fa70`.

| Tag | Arm | Slice VA | Length | Bytes |
| --- | --- | --- | --- | --- |
| 0 | `0x41c9f96` | `0x7c6fce` | 21 | `RecoveredSignerToUser` |
| 1 | `0x41c9fea` | `0x7c6fe3` | 10 | `BeginBlock` |
| 2 | `0x41c9fc0` | `0x7c6fed` | 20 | `DeliverSignedActions` |
| 3 | `0x41c9fd5` | `0x4599d8` | 8 | `EndBlock` |
| 4 | `0x41c9fab` | `0x7c7001` | 6 | `Commit` |
| 5 | `0x41c9fff` | `0x7c7007` | 13 | `RespHashCheck` |

Tags 0, 1, 2, 4 and 5 are one contiguous run at `0x7c6fce` with no NUL between names. `EndBlock` is a separate slice followed by a NUL. Table entries 6 and 7 target `0x41cad7b` and `0x41cae11`, outside the FDE; the byte is not compared with 6 here.

Compared with #94: the function has the same size (148 bytes), the same arm layout and the same tag order. Tag 0 changed from `RecoverUsers` (12 bytes) to `RecoveredSignerToUser` (21 bytes); tags 1 to 5 have the same bytes.

## Evidence: the one host

One `R_X86_64_RELATIVE` relocation has addend `0x41c9f80`; it writes slot `0x64ea680`. In the encodings `48/4c 8b`, `48/4c 8d` with a RIP modrm, `ff 15` and `ff 25`, exactly one instruction names that slot: `0x4da7fd1` (`mov rax, [rip+...]`), inside FDE `0x4da7e20..0x4da81a5`.

The host reads the same tag byte through `rsi` twice. First, at `0x4da7e67` it indexes the relative table `0x915300` and loads one f64 into `xmm0`:

| Tag | Arm | f64 VA | Value |
| --- | --- | --- | --- |
| 0 | `0x4da7edd` | see below | 0.15 or 0.08 |
| 1 | `0x4da7f0a` | `0x459cc0` | 0.03 |
| 2 | `0x4da7ec3` | `0x4598a0` | 0.32 |
| 3 | `0x4da7ed0` | `0x459038` | 0.05 |
| 4 | `0x4da7e7a` | `0x458e48` | 0.01 |
| 5 | `0x4da7e7a` | `0x458e48` | 0.01 |

Host table entries 6 and 7 target `0x4daadcb` and `0x4daaeea`, outside the host FDE.

Tag 0 loads the global through GOT slot `0x64e0918` (relocation addend `0x64f06c0`; the RE-015 db-root packet reads `+0x18` of the same object). If the dword at `+0x50` is nonzero, the host calls `[0x64df9f0]` (addend `0x5c87d50`) with `rdi = global+0x50`, `esi = 1`, and closure data at `0x6411220`/`0x6411248`, then continues. It then takes the byte at `+0x48`, subtracts 10, and if the result is below 23 loads `0x917580[byte-10]`; otherwise it uses `0.08` from `0x4593a0`. The 23-entry table holds `0.15` at indexes 0, 9-16 and 22, and `0.08` at the other 13 indexes.

After selection, the value is stored at `[rsp+0x38]`, divided by `10.0` (`0x4593e8`) and compared with `+inf` (`0x459010`). If the quotient equals `+inf` or is unordered, the stored result at `[rsp+0x8]` is `0.0`; otherwise it is the quotient.

Second, at `0x4da7f90..0x4da7ff1` the host builds three format arguments and calls `[0x64df6e8]` (addend `0x141e3a0`) with the template at `0x440e47`:

| Argument | Value | Callback |
| --- | --- | --- |
| 0 | stack `&str` to `seq_task` (8 bytes at `0x459820`) | `0x5616320` |
| 1 | `0x649cc90`: relocated pointer to `l1` (`0x9172e5`), length 2 | `0x5616320` |
| 2 | incoming `rsi` (the tag byte) | `0x41c9f80` (loaded from `0x64ea680`) |

`0x5616320` (FDE `0x5616320..0x5616333`) moves the `(ptr, len)` pair at `[rdi]` into `rsi`/`rdx` and tail-jumps through the same writer slot `0x64df720`. The template bytes are `c0 01 2f c0 01 2f c0 00`. Inference: three arguments separated by `/`, so the rendered text is `seq_task/l1/<step name>`.

Counts: writer 6 arms, 6/6 table targets inside the FDE, 2 later entries outside; 1 pointer relocation; 1 pointer load in the stated encodings; host 6 tag arms (tags 4 and 5 share one), 2 later entries outside. These are not counts of every block-step string in the file.

## Implementation and comparison

No Rust is added. The tool re-derives every address above from instruction bytes and relocations and pins the exact host instruction windows. Negative controls in `tests/test_abci_step_names_115.py` change one name byte, the `EndBlock` terminator, the `Commit` length immediate, one writer table entry, one host table entry, one host constant displacement, the template displacement, and add a second load of the pointer slot in padding. Each change fails the check (11 tests pass on the real image).

## Results and limitations

No progress gate is requested. Unknown: who produces the tag byte, what the host does with the `seq_task/l1/<step>` string and the per-step value after `0x4da7ff7`, the units of the f64 values (seconds is a guess, not shown), what the byte at global `+0x48` means and why only tag 0 depends on it, and what `0x5c87d50` initializes.

Next question: which callers of `0x4da7e20` pass each tag byte, and where the formatted `seq_task/l1/<step>` string and the scaled value go after `0x4da7ff7`.
