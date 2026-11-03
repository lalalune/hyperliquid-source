# RE-001: map node #115 group-sum getter 0x5eeb670 with its nested group sum 0x5f6abb0

## Bounded question

Immediately before the rdx-arg getters mapped by #2263, the binary
holds a getter that reads its object from the fourth argument
(rcx), not from rdi or rdx: what does getter 0x5eeb670 return, and
what does its callee 0x5f6abb0 sum? This packet pins the whole
behavior end to end, not lone-window fragments: the getter whole
plus the whole 251-byte sum, with the sum's five-argument callee
left by contract and every census-confirmed caller of both
windows.

## Windows

- Getter: 0x5eeb670..0x5eeb691 (33 bytes), FDE at .eh_frame offset
  0x35705c, length 0x18, CIE 0 (no LSDA). Ends at the `ret` at
  0x5eeb690; the `int3` padding from 0x5eeb691 is excluded.
- Group sum: 0x5f6abb0..0x5f6acab (251 bytes), FDE at .eh_frame
  offset 0x35dc8c, length 0x48, CIE 0 (no LSDA). Ends at the `ret`
  at 0x5f6ac8b; the `nopl` at 0x5f6ac8c and the `int3` padding from
  0x5f6acab are excluded, while the cold blocks at 0x5f6ac90
  (index <= 7 arm) and 0x5f6aca7 (total == 0 arm) belong to the
  function and are included.
- Artifact: work/hl-node-115.bin, SHA-256
  a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301,
  matching provenance/artifacts.json entry artifacts/node/115/hl-node.

## How the excerpts were produced

From the repository root:

```
objdump -d --start-address=0x5eeb670 --stop-address=0x5eeb691 work/hl-node-115.bin
objdump -d --start-address=0x5f6abb0 --stop-address=0x5f6acab work/hl-node-115.bin
```

The excerpt files are that output verbatim, whole-function. Both
windows start with `endbr64`; every mnemonic in the excerpts is
genuine objdump output from the target binary, not a placeholder,
and verify.py checks sampled instructions byte-for-byte against a
fresh objdump run and the raw binary. Instruction-level detail
lives only in the verbatim excerpts; records.json carries semantic
records, not a per-instruction list.

## Semantics (literal)

### Getter 0x5eeb670

Arguments (outer, out, obj) in (rdi, rsi, rcx). The outer object
in rdi is IGNORED (never read). The sum's object is the fourth
argument in rcx, not rdi or rdx:

```
*out = 0 if obj is null else group_sum(obj)
return 1
```

The null arm stores the zeroed eax; the non-null arm moves rcx to
rdi and calls 0x5f6abb0, then stores its return. The return value
is 1 unconditionally on both arms.

### Group sum 0x5f6abb0

```
total = arithmetic_shift_right([obj + 0x108] - [obj + 0x100], 4)
        + [obj + 0x70]
if total == 0: return 0
sum = 0
for i in 0..total-1:
    if i <= 7: desc = [obj + 0xf8] + i * 16
    else:      desc = [obj + 0x100] + i * 16 - 0x80
    count = [desc]
    for j in 0..count-1:
        item = [desc + 0x08] + j * 80
        sum += callee([[obj + 0x10] + 0x8c0], obj + 0x1040,
                      [obj + 0x10] + 0x40, [item + 0x28],
                      obj + 0x1118)
return sum
```

Notes, all literal from the disassembly:

- The descriptor threshold is the constant 7, while the total
  adds the value at +0x70. The packet does NOT assume that value
  equals 8; it models both literally, and the model tests cover
  the index-8 boundary with field70 = 8 and a 16-byte vector span
  as one concrete instance.
- A group with count 0 contributes nothing: the count test at
  0x5f6ac1f jumps straight to the index increment.
- The callee 0x5f415c0 is by contract only (its internals were
  not read); its return is added to the running sum, and its
  arguments are exactly as listed. The binary re-reads
  [obj + 0x10] for every item, so the model re-reads it per item
  too.
- The sum has no null check anywhere and no stack canary; a null
  object or a dangling descriptor pointer would fault, which the
  model states as a guard rather than a binary arm.
- The getter's object is the only caller of the sum file-wide,
  and the sum is the only caller of 0x5f415c0 file-wide (see
  census.py output in the verification below).

## Census (whole-file scan)

- Getter 0x5eeb670: no direct calls, no tail jumps, no qword
  hits, no RELATIVE addends anywhere in the file — the
  virtual-getter shape, as in #2228/#2229/#2263.
- Sum 0x5f6abb0: exactly 1 direct call, at 0x5eeb682 inside the
  getter; no tail jumps, qword hits or RELATIVE addends.
- Callee 0x5f415c0: exactly 1 direct call, at 0x5f6ac5c inside
  the sum; nothing else.

## Model and tests

tools/group_sum_getter_115.py implements `group_sum(obj, callee)`
and `getter(outer, out, obj, callee)` with the state shapes
documented in the module docstring; the callee is an injectable
callable because 0x5f415c0 is by contract. tests/
test_group_sum_getter_115.py covers the zero total, the exact
callee arguments, zero-count groups, the index-8 inline/vector
boundary, vector groups past index 8, the negative-total model
guard, and both getter arms.

## Verification

```
python3 research/work-items/RE-001-group-sum-getter-115/verify.py
python3 tests/test_group_sum_getter_115.py
```

verify.py checks the binary digest, the packet manifest, verbatim
excerpt regeneration from a fresh objdump run, sampled + 3 extra
gate instructions byte-for-byte against the raw binary, the FDE
records, the census, the call-site raw bytes, and the model tests.
`make doctor` fails on missing providers (pre-existing, stated
honestly); pytest is not installed, so the pytest-style test file
runs under plain python3 via its `__main__` runner (stated
honestly in the PR body).

## Unknowns (kept separate from observations)

- Names/meanings of the outer object, the summed object, and the
  fields at +0x10/+0x70/+0xf8/+0x100/+0x108/+0x1040/+0x1118.
- What the by-contract callee 0x5f415c0 computes from its five
  arguments.
- Why the descriptor threshold is the constant 7 while the group
  total adds the value at +0x70.
- Internals of any caller of the getter beyond its (absent) call
  sites: the getter has no callers file-wide.
