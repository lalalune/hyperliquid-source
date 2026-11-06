# RE-012: map node115 Once callback publication and poison wake

Linux x86-64 node #115 SHA-256 a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301.
Base 05bc2de303c05525b71e7e257426e741bc66a390.

The std census identifies 0x5c87d50 as the futex Once call. This
packet follows its initialization callback, terminal state publication
and exceptional cleanup. The selected caller at 0x1500b41 passes
force 1 and invokes the body via RELATIVE slot 0x64df9f0 at 0x1500b60.

The body decodes low state bits with mask 3 and tests waiters with
mask 4. In force mode low states 2 and 3 can acquire state 1,
preserving bit 2. The callback receives a stack record with a zero
dword and a byte reporting whether the acquired state was 2.
In non-force mode the four relative offsets at 0x947eac dispatch
low state 0 to return, 1 to wait, 2 to the diagnostic, and 3 to the
acquisition exchange. The non-force callback receives zero in the
prior-poison byte. Both modes call through the supplied table +0x20.

A waiter adds bit 2 with a compare-exchange when it is absent. The
wait rechecks the full observed value and passes it as the expected
word to syscall 202 with operation 0x89 and mask 0xffffffff. A
negative result with errno 4 goes back to that word check. The
normal callback continuation exchanges the dword from the stack
record into the state word. If the replaced word had bit 2 set,
syscall 202 with operation 0x81 wakes up to 0x7fffffff on that word.

The exceptional continuation at 0x5c87f3c exchanges state 2, applies
the same waiter-bit wake test, and calls _Unwind_Resume. The retained
FDE and LSDA location record this context. Callback internals, LSDA
action tables, scheduling and panic-runtime equivalence remain
outside the static scope. Qualification reads bytes only.

The retained 2 full FDEs cover 831 bytes and 220 instructions. GNU, LLVM and Capstone byte partitions agree and GNU readelf confirms the extents. The verifier rejected 13 instruction/data windows, 1 RELATIVE addends, 2 import writers and two identity controls. Collector and verifier scaffolding are adapted from the MIT Build ID packet.

From the repository root with authenticated artifacts and pinned tools, use fresh output paths.

```sh
python3 -B research/work-items/RE-012-once-futex-publish-115/collect.py --out work/once-futex-publish-fresh
python3 -B research/work-items/RE-012-once-futex-publish-115/verify.py --out work/once-futex-publish-check-fresh.json
```
