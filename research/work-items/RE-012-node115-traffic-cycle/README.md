# RE-012: node115 traffic-recorder async timing and snapshot handoff

Component: transport. Target Linux x86-64 node #115, 105896032 bytes,
SHA-256 `a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`.
Base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`. Independently authored
static analysis; no inferred source was copied.

Question: where does the traffic-recorder-associated poll continuation delay,
suspend and hand a locked global snapshot to its consumer? This resolves a
bounded scheduling/data-handoff unknown, not traffic-accounting semantics.

## Measured observations

One complete FDE `[0x4781880,0x4781f09)` is exported: 1673 bytes /353
instructions. Python unwind parsing and GNU readelf independently agree;
GNU instruction bytes cover the whole range contiguously. The relocated
Location at `0x6497448` binds the actual LEA at `0x478193f` to
`net_utils/src/tcp/traffic_recorder.rs:64:47`. This diagnostic association does
not establish an original function name or a public Rust ABI.

- Outer state byte `object+0x148` selects initial tag0 or resumed tag3. Other
  values route to diagnostic failure. Two four-entry relative jump tables at
  `0x7e1b00` and `0x7e1b10` dispatch nested state bytes at +0x140/+0x138;
  all eight entries name measured instruction boundaries, retained in records.
- Initial entry at `0x4781d17` writes two binary64 values30.0 to +0xb0/+0xb8
  and loads another30.0 for +0xc0. The backing16-byte and8-byte constants
  are retained and checked. Thus this initial path requests a30-second value;
  this is not a claim about wall-clock precision or every later interval.
- At `0x47818d6`, +0xb0 is copied to +0xb8 and compared with binary64 zero.
  JNE followed by JNP makes either signed zero bypass the sleep path to
  `0x4781c3b`; unordered (NaN) does not take that bypass. The nonzero path
  writes +0xc0 and converts binary64 into the seconds/nanoseconds argument
  pair before the relocated construction call at `0x4781b40`. The detailed
  rounding and invalid-duration behavior is not reconstructed here.
- The poll at `0x4781bed` receives the nested object at +0xc8 and the saved
  incoming RSI context. A nonzero AL result branches to `0x4781d47`: it
  writes3 to all three state bytes(+0x138/+0x140/+0x148), returns AL=1, and
  does not reach the later global snapshot path in that invocation. Pending
  is an inferred async label for this concrete suspension/return pattern.
- The zero-delay bypass and completed nested cleanup converge before global
  work. A locked CMPXCHG at `0x4781c51` attempts0→1 at `0x64fdc20`.
  The nonzero-global initializer and failed-acquire helpers are distinct
  unresolved paths. Once acquired, global table fields at +8/+0x10/+0x20
  relative to this lock feed a local iterator and direct helper `0x477d440`.
- A second CMPXCHG at `0x4781cb7` attempts1→0 BEFORE handing the result to
  direct consumer `0x476f920` at `0x4781d12`. The failed-release path first
  calls its helper and rejoins. The local normal-return ordering is therefore
  snapshot helper, unlock attempt, consumer, reset/restart. No guarantee of
  atomic whole-system snapshots, helper success or progress is inferred.
- Unwinding cleanup writes outer state2 before `_Unwind_Resume`. Raw call
  targets and all measured RIP-call relocation records remain in records;
  their presence does not establish helper closure.

## Reproduction and controls

Linux Python3.12.3 /GNU binutils2.42; no target execution or emulation:

```sh
python3 research/work-items/RE-012-node115-traffic-cycle/collect.py --output work/traffic-cycle --check
python3 -m unittest discover -s tests -p test_node115_traffic_cycle.py -v
```

The collector authenticates the entire immutable target before native tools,
creates a private non-executable copy, checks complete FDE/CIE/body exports,
relocations, data and instruction boundaries. Tests regenerate retained bytes,
reject wrong artifact identity before output, and flip each claim anchor in a
private bytearray to ensure structural observations reject corrupted code.
They do not execute original or altered instructions or prove runtime behavior.

All component gates remain false. No Rust reconstruction, captured-node run,
network, chain, external command, full traffic counters, helper body closure,
compiled comparison or whole-node equivalence is claimed. Exported bytes are
an evidence denominator, not recovered implementation coverage. Next: measure
snapshot/consumer helper ownership and the post-consumer delay update path.
