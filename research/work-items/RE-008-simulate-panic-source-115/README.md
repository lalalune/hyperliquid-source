# RE-008: node #115 Exchange and Locus deserialisers behind the abci box (stage 87)

- Component ID: abci. Question: stage 86 (#6091) named three stack builders (`0x199ce60`, `0x32caf70`, `0x49da420`) as the place to look for the source of the simulate-panic stop fields (layout-A box `+0x39a8`/`+0x39b0`, #6090), and found the selector byte `+0xb9a` written once at `0x2fc32ad` in `0x2fc21d0`. This packet says what those functions are.
- Target: node #115 `artifacts/node/115/hl-node`, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `a8616af94` (origin/main at packet time). Continues open PRs #6090 and #6091.
- Claim status: instruction bytes, relocations, string bytes and call censuses are observations. "rmp-serde visitor", "field visitor", "boxed", "Locus" and "Exchange" as type names are labels read from the `expected` strings and the vendored `rmp-serde` Location paths. The binary was not executed.

## Reproduce

```
python3 tools/simulate_panic_source_115.py --check
python3 -m unittest tests.test_simulate_panic_source_115
```

The tool reads the ELF only. The five `*.objdump.txt` files are review copies (GNU objdump 2.42); the tool does not read them.

## Evidence 1: the three builders deserialise `Exchange`

- Each of `0x199ce60`, `0x32caf70` and `0x49da420` (FDEs of 0x59a6 bytes each) loads its own `expected` record: `0x641f220`, `0x6464800`, `0x6499c28` (`lea rdx` at `0x199d76b`, `0x32cb87b`, `0x49dad2b`). Each record relocates to `0x457700` = `struct Exchange with 59 elements` with length 32. Two more records point at the same string (`0x64222d8`, `0x647d590`); their users are not mapped here.
- On success `0x199ce60` copies 0x27a8 bytes to the out pointer saved at `rsp+0xf8` (`0x199ea85 mov edx, 0x27a8`; `0x199ea8a mov rdi, [rsp+0xf8]`). Inference: `Exchange` is 0x27a8 bytes in this build.
- `0x199e478 movaps [rsp+0x39b0], xmm0` is a stack slot. The stage 86 lead matched this stack offset, not box `+0x39a8`.

## Evidence 2: the callers box the value under the key `exchange`

- Direct calls: `0x199ce60` from `0x1b45512`, `0x1b4587b`; `0x32caf70` from `0x3266b02`, `0x3266e6b`; `0x49da420` from `0x4bad4c2`, `0x4bad82b` (each pair in one 0x1477-byte function).
- In `0x1b44f30` the call follows a key compare with `movabs rcx, 0x65676e6168637865` (`exchange`, `0x1b454db`). The result is copied into a new allocation of 0x27a8 bytes (`0x1b450f1 mov edi, 0x27a8`, alloc slot `0x64df480`, then memcpy).
- Result: the deserialised `Exchange` lives behind a pointer. It cannot be the inline source of box `+0x39a8`.

## Evidence 3: `0x2fc21d0` deserialises `Locus`, including the selector byte

- `0x2fc2201 lea rdx` loads record `0x6464530`, which relocates to `0x794eba` = `struct Locus with 16 elements`, length 29.
- The output is `rbx = rdi` (`0x2fc21f0`). The success block ends with stores to `+0xb90` (qword), `+0xb98`, `+0xb99` and `+0xb9a` (bytes, `0x2fc328b`..`0x2fc32ad`).
- The `+0xb9a` value is the element byte saved at `0x2fc288d` (`mov [rsp+0x7], cl`) after the element decode.
- The function has one direct caller, `0x332dd91`.
- Inference: the selector byte is a deserialised `Locus` field. The freeze assertion text `self.locus.context.height()` (#5925) and the overlap with the #6027 slot-0 field group fit a box that starts with `Locus`; this packet does not prove the placement.

## Results and limitations

- Result: the stage 86 lead functions are `Exchange` visitors whose output is boxed; they are not the source of the stop fields. The selector byte comes from `Locus` deserialisation.
- Limits: the writer of box `+0x39a8`/`+0x39b0` is still not found; the users of the other two `Exchange` records (`0x64222d8`, `0x647d590`) are not mapped; the meaning of selector values 2 and 3 and the opposite bit-0 polarity of the stop checks (#6091) are not mapped; where `Locus` sits in the box is an inference.
- Next lead: the users of `0x64222d8` and `0x647d590`, and the caller `0x332dd91` of the `Locus` visitor, to find the struct that contains both `Locus` and the stop pair.
