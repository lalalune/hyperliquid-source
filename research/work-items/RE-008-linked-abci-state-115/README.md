# RE-008: node #115 linked abci state step after the snapshot label (32nd stage)

- Component ID: abci. Question: #5970 found that after the engine step `0x5a08720` chooses its snapshot label it calls `0x5485f80`, whose strings include `linked abci state`. It left open what that call does with the label and the box, and what it returns.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). This continues merged #5925 and #5970 and imports helpers from `tools/freeze_snapshot_115.py`.
- Claim status: instruction bytes, string bytes, relocations, Location records, FDE extents and the direct-call census are observations. "Path", "hard link", "log line", "height" and "label" are inferred labels from the strings, templates and call shapes. The binary was not executed.
- Scope included: the label choice at `0x5a0884a..0x5a08883`; all of `0x5485f80` up to its unwrap panic; the string and template references in `0x38d8240`, `0x5942870` and `0x38d7f20`. Scope excluded: the bodies of `0x4e45a30`, `0x1505a50`, `0x38d7f20` beyond its template, the logger `0x5c9b830`, and `0x5a046f0`. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/linked_abci_state_115.py --check
python3 -m unittest tests.test_linked_abci_state_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the label argument

At `0x5a08853..0x5a08874` the step loads `freeze` (`0x93a687`) into `rax` and `periodic` (`0x458f30`) into `rdx`, then `test r13b, r13b` / `cmovne rdx, rax`. The length is `lea rcx, [rax*2+6]` with `rax = r13b ^ 1`: 6 for `freeze`, 8 for `periodic`. It then calls `0x5485f80` with `rdi = rsp` (output) and `rsi = r12`. That is the only direct call of `0x5485f80`.

## Evidence 2: what `0x5485f80` does, in call order

The label is kept at `rsp+0x160`/`+0x168`. `[[rsi]+0x28]` is loaded at `0x5485faa` and kept at `rsp+0xe8`; #5925 read box `+0x28` as the height.

1. `0x38d8240` through slot `0x64e4f30`, with the height. It reads the wall clock (`0x1629690`) and formats template `0x448b77` (argument, `/data/`, argument) with `periodic_abci_state_statuses` (`0x7a1586`, 28 bytes), then template `0x440e47` (argument `/` argument `/` argument).
2. `0x5942870` with `abci_state` (`0x929ae3`, 10 bytes). It formats template `0x44f615` (argument, `/hyperliquid_data/`, argument) and `0x43d024` (argument `.` argument) with `rmp` (`0x9382b9`) or `json` (`0x459f60`).
3. `0x4e45a30` with `edx = 1` and a three-pointer block `{rsi holder, rsp+0xc0, rsp+0x20}`. Its 0x38-byte result is copied out at `0x5486050..0x5486089` and returned through `rdi` at `0x548629b..0x54862cd`.
4. `0x1505a50` through slot `0x64e09e0`, with Location `l1/src/abci/state.rs:201:9`. A non-zero result branches to `0x548632e`: `Result::unwrap()` on an `Err` value, Location `state.rs:201:32`.
5. `0x38d7f20` through slot `0x64e4f38`, with the step-1 path (`rsp+0x28`/`+0x30`) and the step-2 path (`rsp+0xd8`/`+0xe0`). `0x38d7f20` formats `utils_hard_link_and_replace/{}` (`0x439e43`). If it returns a box, `0x5485f80` calls the box's first vtable entry (`0x54860d4..0x54860da`) and goes on: the error is dropped, not returned or logged.
6. The logger `0x5c9b830` through slot `0x64e0ae8` with template `0x448ef9`: `{} WARN >>> {} @@ {} @@ [desc: {}] @ [periodic_fln: {}] @ [fln: {}] @ [height: {}]`. The argument block at `rsp+0xf0..0x108` binds `desc` to the label, `periodic_fln` to the step-1 path (`rbp = rsp+0x20`), `fln` to the step-2 path (`rbx = rsp+0xd0`) and `height` to `rsp+0xe8`. The first argument is a time formatted with `%Y-%m-%dT%H:%M:%S%.3fZ` (`0x929aed`, 0x16 bytes). The third is a 0x23-byte slice at `0x929b03`, whose bytes are `linked abci state` followed by `assertion failed: `.

Inference: each labelled snapshot hard-links the current `hyperliquid_data/abci_state.{rmp|json}` file into a `data/periodic_abci_state_statuses/...` path, logs one WARN line naming both paths, the label and the height, and ignores a failed link.

## Implementation and comparison

The tool pins 40 instruction byte runs, 23 RIP-relative or rel32 references, 8 relocations, 6 strings, 6 templates, 2 Location records and 5 function memberships, and recomputes the direct-call census of `0x5485f80`. Tests mutate one byte at a time in a copy of the image and expect rejection (8 mutation tests). The helpers come from the merged `tools/freeze_snapshot_115.py`.

## Results and limitations

- Result: the label only reaches the log line (`desc`); it does not choose a path in `0x5485f80`. The hard-link error is dropped; the `state.rs:201` call panics on error.
- Limits: the bodies of `0x4e45a30` (references runtime messages such as `closure claimed permanent executor`), `0x1505a50` and `0x38d7f20` are not mapped, so what step 4 does and how the link replaces an existing file are not claimed. The `{}/{}/{}` arguments of step 1 and the `rmp`/`json` choice of step 2 are not mapped. Why the third log argument spans `assertion failed: ` is not explained. `0x5a046f0`, called after the periodic-folder path in `0x5a08720`, references no strings in its extent `0x5a046f0..0x5a04e3c` and is not mapped.
- Next lead: the `{}/{}/{}` arguments of `0x38d8240` (the date and height parts of the periodic path).
