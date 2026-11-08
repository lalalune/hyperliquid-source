# RE-001: register setup at abstraction-kind visitor calls

- Component/task: `constants`, bounded RE-001 cross-reference and call-site dataflow.
- Target: Linux x86-64 node #115, SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
- Bounded question: what explicit register values reach the seven direct calls to the five abstraction-kind visitors recorded in the companion census?
- Result: each call has three explicit argument registers (`rdi`, `rsi`, `rdx`). The three tagged-word visitor copies share the observed setup `rdi=r15`, `rsi=mem[rsp+0x08]`, `rdx=mem[rsp+0x10]`. The two `Result<u8, E>` visitor copies use stack-relative output and input slots; their exact offsets are recorded per call in `records.json`.
- Claim status: machine-code observations only. Stack offsets are not source-level field names, types, or struct layouts. No caller names, input meanings, or Rust signatures are inferred.

## Reproduce

With the pinned artifact materialized, Python 3.10+ and GNU objdump on `PATH`:

```sh
export PATH="/opt/homebrew/opt/binutils/bin:$PATH"
python3 research/work-items/RE-001-node115-abstraction-call-arguments/collect.py
python3 -m unittest tests.test_re001_node115_abstraction_call_arguments
python3 research/work-items/RE-001-node115-abstraction-call-arguments/verify.py
```

The evidence was collected with GNU objdump 2.47.20260726. The collector checks the full target digest and exact containing FDE for each call, asks objdump to decode from each FDE start through the call, and verifies the producer instruction bytes, call destination, conditional branch bytes and absence of an intervening write to the three argument registers. The captured binary is disassembled only; it is never executed.

## Observations

All addresses are ELF virtual addresses. `mem[rsp+N]` denotes a load from the caller's current stack pointer at the recorded producer instruction. The explicit call path is conditional at four sites: the recorded direct call is reached after the fallthrough of the `je` at `0x1debaaf` and `0x3f7f8bf`, and the taken edge of the `jne` at `0x1e22074` and `0x3fbb224`. These are control-flow observations, not decoded value meanings.

| Visitor entries | Sites | Register setup at call boundary |
| --- | --- | --- |
| `0x23c65f0`, `0x3bdd720`, `0x4d6b5d0` | `0x1c0ef86`, `0x3164176`, `0x48d2956` | `rdi=r15`; `rsi=mem[rsp+0x08]`; `rdx=mem[rsp+0x10]` |
| `0x23c6720` | `0x1debabf`, `0x1e22089` | `rdi=rsp+0x18` / `rsp+0x10`; `rsi=mem[rsp+0x08]` / `mem[rsp+0x28]`; `rdx=mem[rsp+0x10]` / `mem[rsp+0x30]` |
| `0x3bdd5e0` | `0x3f7f8cf`, `0x3fbb239` | Same two per-site stack-slot setups as the preceding row |

No Rust implementation, component gate or completion percentage is claimed. Indirect calls, tail jumps, other argument registers, stack layout ownership, and all behavior outside these call boundaries remain unexamined.
