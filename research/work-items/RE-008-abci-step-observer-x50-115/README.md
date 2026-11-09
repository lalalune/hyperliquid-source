# RE-008: node #115 shared value observer `0x1547530` (third stage): who sets and who reads the ×50 flag

- Component ID: abci. Question: the second stage (open PR #5839) left two byte stores to the ×50 flag `+0x25c` untraced (`0x47832e9`, `0x47849a8`), did not say what the five observers with the flag set measure, and did not list who reads the flag.
- Target release and full SHA-256: node #115 `artifacts/node/115/hl-node`, `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301` (checked against `provenance/artifacts.json` by the tool).
- Source commit: `0781ce048` (origin/main at packet time). This continues open PRs #5045 (first stage, observer entry) and #5839 (second stage, window and constructor `0x1548bb0`). It does not depend on their files.
- Claim status: instruction bytes, offsets, constants, relocations, template bytes and the censuses are observations. "Closure", "factory", "builder", "name" and "record" are inferred labels from the calling pattern and layout. Reading the template byte `0xc0` as an argument slot is inferred (each site passes exactly two `(value, formatter)` pairs to the format slot). The binary was not executed.
- Scope included: the closure methods `0x47832b0` and `0x4784980` and their vtable `0x6497668`; the vtable's only reference in the builder `0x4784750`; the builder's reference census; the five flag-setting call sites (template, format call, constructor call, `xmm0`, `esi`); the census of byte reads and byte stores of `+0x25c` in `.text`; the two reads. Scope excluded: what the builder's caller `0x567bb70..0x567bc40` configures, the inner factories, what `0x1546570` does with the record, the formatter functions, and the meaning of `+0x0`/`+0x8` that the five sites also write. No gate changes.

## Reproduce

From the repository root, Python 3.12.3:

```
python3 tools/abci_step_observer_x50_115.py --check
python3 -m unittest tests.test_abci_step_observer_x50_115
```

The tool reads the ELF. It does not execute the captured binary and does not start objdump or readelf. The four `*.objdump.txt` files beside this record were made with GNU objdump 2.42 (`objdump -d -M intel --start-address=... --stop-address=...`) for review only; the tool does not read them.

## Evidence 1: the two untraced stores clear the flag in a boxed closure

Both stores write **0**, not 1.

- `0x6497668` is a Rust `dyn` vtable: `R_X86_64_RELATIVE` drop `0x47837f0` at `+0x0`, size `0x10` and align `8` as raw qwords at `+0x8`/`+0x10`, then `0x47832b0` at `+0x18` (`call_once`) and `0x4784980` at both `+0x20` (`call_mut`) and `+0x28` (`call`).
- `call_once` `0x47832b0` (FDE `0x47832b0..0x4783383`): keeps the output pointer (`mov r14, rdi`), loads the closure's `(data, vtable)` pair from `[rsi]`/`[rsi+8]`, calls the inner vtable slot `+0x28` (`call [r15+0x28]` at `0x47832e5`), writes `byte [r14+0x25c] = 0` at `0x47832e9`, then drops the inner box through its vtable (`[r15]`, `[r15+8]`/`[r15+0x10]` size/align to the free slot).
- `call` `0x4784980` (FDE `0x4784980..0x47849b8`): same without the drop: `call [rcx+0x28]` at `0x47849a5`, `byte [rbx+0x25c] = 0` at `0x47849a8`, returns the output.
- So the closure wraps another boxed observer factory: it builds the observer with the inner factory and then forces the ×50 flag off.
- The vtable has one reference in `.text`: `lea rax, [rip+...]` at `0x4784830` in `0x4784750` (FDE `0x4784750..0x4784978`). No relocation and no E8/E9 names it. That function moves its input's `(data, vtable)` pair (`[rbx]`, `[rbx+8]`) into a new 16-byte box (`mov edi, 0x10`), stores the box at output `+0x0` and the vtable at output `+0x8`. Inference: it is a builder conversion that replaces a configured factory with the flag-clearing wrapper.
- `0x4784750` itself has no direct callers; its only relocation is the slot `0x64eb1c0`, and the only `FF 15`/`FF 25` through that slot is `0x567bbac` (FDE `0x567bb70..0x567bc40`). What that caller configures is not traced.

With these two, the census of byte stores to `+0x25c` from #5839 is fully attributed: `0x1548e0a` (constructor), `0x47832e9` and `0x47849a8` (wrapper) write 0; the five sites below write 1.

## Evidence 2: the five ×50 observers profile lock waits

Each of the five sites formats a name with the format slot `0x64df6e8` (`R_X86_64_RELATIVE` to `0x141e3a0`), passes the result's pointer (`mov rdx, r12`) and length (`rcx`) to the constructor slot `0x64e1020`, passes `esi = 0` (`xor esi, esi`, the `+0x25d` byte in #5839), and then writes `+0x25c = 1`. The template is a `lea rsi` before the format call:

| Flag store | Function (FDE) | Template | Template bytes | `xmm0` |
| --- | --- | --- | --- | --- |
| `0x16eeeca` | `0x16eee50..0x16eef3f` | `0x44c834` | `0f` `profiled_mutex/` `c0 09` `/compute/` `c0 00` | `1.0` (`0x4592b0`) |
| `0x250347a` | `0x2503400..0x25034ef` | `0x44c834` | same | `1.0` |
| `0x47716da` | `0x4771660..0x477174f` | `0x44c834` | same | `1.0` |
| `0x477292d` | `0x4772530..0x47729e3` | `0x432e2d` | `11` `profiled_rw_lock/` `c0 01` `/` `c0 00` | `[rsp+0x58]` |
| `0x5ab257a` | `0x5ab2500..0x5ab25ef` | `0x44c834` | same | `1.0` |

The length bytes match the literals exactly (`0x0f` = 15 = `profiled_mutex/`, `0x09` = `/compute/`, `0x11` = 17 = `profiled_rw_lock/`, `0x01` = `/`). Inference: the observer names are `profiled_mutex/{}/compute/{}` (four sites) and `profiled_rw_lock/{}/{}` (one site), so the ×50 flag is set only on observers of lock profiling. The other 30 constructed observers keep the constructor's 0.

## Evidence 3: the flag has two readers, both in the observer

The census of byte reads of `+0x25c` in `.text` (`80 /7`, `0F B6`, `F6 /0`, `8A`, `38`, `3A`, `84`, mod=10, disp32, optional REX) finds 2, both inside the observer FDE `0x1547530..0x1548ba3`:

1. `0x15475b1` `cmp byte [rbx+0x25c], 1`: when 1, the u64 weight in `r14` is multiplied by 50 (`mov ecx, 0x32`; `mul rcx`); on overflow (`jo` at `0x15475cb`) `0x1548a0b` sets it to `u64::MAX` and rejoins at `0x15475dc`. This is the multiply #5045 described; the same shape is documented for node #94 in `RE-001-bucket-guard-94`.
2. `0x15486e6` `movzx r15d, byte [rbx+0x25c]`: the flag is copied unchanged (no instruction in `0x15486ee..0x1548873` writes `r15`; the two calls between preserve it) to `byte [rsp+0x17c]` at `0x1548873`, the end of a stack record whose base `rsp` is passed in `rdx`, with `rsi = state + 0x98`, to slot `0x64e0f80` (`R_X86_64_RELATIVE` to `0x1546570`) at `0x15488a3`. Inference: the exported window record carries the flag, so a reader can tell a ×50-weighted series apart.

## Implementation and comparison

No Rust is added. The tool re-derives every address above from instruction bytes, the FDE index, relocations and template bytes. Negative controls in `tests/test_abci_step_observer_x50_115.py` change the closure's cleared value (0 to 1), the inner vtable slot (`+0x28` to `+0x20`), the vtable `call` relocation addend, one template byte, the `1.0` constant, the multiply factor (50 to 51), the record offset (`+0x17c` to `+0x17d`), and an `r15` write between the read and the record store, and add an extra flag read, an extra flag store and an extra vtable `lea` in the int3 padding after the observer. Each change fails the check (14 tests pass on the real image, none skipped).

## Results and limitations

Counts: 8 of 8 byte stores to `+0x25c` attributed (3 write 0, 5 write 1); 2 byte reads, both in the observer; 1 `.text` reference to the wrapper vtable; 1 slot call to its builder; 5 of 5 flag-setting sites with a template (4 `profiled_mutex`, 1 `profiled_rw_lock`). Denominators: the encodings listed above with disp32 `0x25c` in `.text`; E8/E9 rel32, FF15/FF25 rip-relative and 7-byte rip-relative `lea` in `.text`, plus `R_X86_64_RELATIVE` addends. No progress gate is requested.

Unknown: what the builder's caller configures (which observers get the flag-clearing wrapper), the inner factories, how `0x1546570` uses the record and the flag, the formatter functions (the `{}` values), the source of `xmm0` and of `+0x8` at the `rw_lock` site, and the meaning of `+0x0`/`+0x8`.

Next question: the record sink `0x1546570`, which receives each finished window with the flag.
