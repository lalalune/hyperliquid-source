# RE-012: Node115 command declaration and owned-validator producer

## Question and identity

Which local command/argument records does the current startup factory create,
and which actual owned validator callbacks are attached before parsing?
Target: Linux x86-64 Node115, SHA256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
105,896,032 bytes. Source base: `8fd8db680ec4bfef40996e5616bce3d5156d0b86`.
All addresses are ELF virtual addresses before load bias. New analysis/code is
independently authored under root MIT. Captured bytes retain upstream rights.
No unlicensed inferred source, captured execution or emulation was used.

## Observations

The complete factory `[0x564e1a0,0x56544a9)` is 25,353 bytes. It constructs
14 command names using exact-length heap writes, including overlapping SIMD
stores, and registers 24 local Arg-like records through RELATIVE slot
`0x64e1cf0 -> 0x1638840`. `records.json` joins their pointer/length/flag writes
to 20 actual validator-vtable bindings and all 60 method relocation writers.
The 4 presence flags have no such validator candidate in their local assembly.

The 24 registrations have 14 raw flags `0x425`, 6 `0x424`, and 4 `0x404`.
All have global bit 8 clear. The shared registration helper tests bit 1 and
appends those 14 names to the required-name vector; this is producer-side
required-name evidence, not proof of the entire parser's rejection behavior.
The field/layout interpretation is credited to PR2034's immutable CONTRACT.
The construction-order parent association is a static inference supported by
the retained constructor/copy/append call sites; it is not a recovered Rust ABI.

| Command | Local arguments, in registration order |
| --- | --- |
| translate-abci-state | in-fln, out-fln |
| send-signed-action | action |
| delegate | validator, wei, undelegate |
| staking-deposit / staking-withdrawal | wei |
| send-slack-alert | msg |
| check-reachability | abci-state-fln |
| compute-referrer-states | abci-state-fln, out-fln |
| compute-l4-snapshots | abci-state-fln, out-fln, include-users, include-trigger-orders |
| change-validator-profile | abci-state-fln, node-ip, name, description, unjailed, disable-delegations, commission-bps, signer |

run-non-validator, run-validator, print-address and approve-non-expiring-agent
have no local registrations in this table. Both run constructors separately
call the opaque common-options helper at `0x5656bf0`; its options are not counted
as absent or reconstructed here. Each selected command receives the five-byte
version literal `0.1.0`. This is embedded data, not build/source authentication.

Twenty validator pairs have observed allocation qwords (1,1) and vtable
headers (0,0,1). Twelve bind the previously described owned-string callback
`0x564e0f0`; those callback semantics remain credited context. Four bind
`0x56544b0` (wei three times, commission-bps once). The remaining callbacks are
`0x56546c0` (node-ip), `0x56547d0` (disable-delegations), `0x5654920`
(validator), and `0x5654a90` (signer). Their five 5-byte once adapters are
complete tail jumps to these actual targets. Exact vtables, writes and FDEs
are in spec/records; shared callback addresses do not identify source types.

The numeric callback accepts optional leading '+' and nonempty decimal digits
under checked u64 arithmetic. Its short (<17 digits) path only checks digits;
the long path checks multiply/add overflow. Empty input and lone '+'/'-' take
error boundaries; overflow still classifies the currently loaded byte. The
Boolean callback admits only exact lowercase true/false. Both callbacks return
a Result-unit-like MIN64 first word on success, not the parsed numeric/Boolean
payload; the later command extractor parses values independently.

The IP callback requires length <=15, calls `0x167ccb0`, then requires both
its low return bit and exhausted input. The accepted IP grammar is not closed.
The validator/signer callbacks use slot `0x64e0b88` and regard result byte 1 as
error; address grammar and dynamic formatting remain opaque. Their distinct
error-object formatting/drop paths are retained, not assumed interchangeable.
Each normal result frees the original owned input when its capacity is nonzero.

Primary retained ranges total 27,208 bytes (factory + five callbacks + five
once adapters). Four shared context helpers total 2,768 bytes; register-argument
and optional-vector cleanup were already interpreted in PR2034. Native records
separate these roles. Complete GNU/Capstone address-and-byte comparisons retain
original stdout, with no operand/byte masks. LSDA call-site ranges and landing
pads are decoded; type/action chains and arbitrary callee unwinding are not.
These denominators measure selected static evidence, not implementation credit.

## Relation to existing work

[PR2034](https://github.com/lalalune/hyperliquid-source/pull/2034), immutable head
`d675d68d872ed8402c21845b610ca2abd619e4bf`, establishes root builder/config,
selected-command consumption, helper layouts and the fourteen command spellings.
It explicitly excludes this factory. Those findings and its Clap correspondence
are credited, not re-claimed. Exact vendored Clap version/patches stay unknown.
[PR2476](https://github.com/lalalune/hyperliquid-source/pull/2476) covers the separate
output constructor; its handed-off source was not changed or tested here.
Live factory/address/callback searches and PR2034 discussion were inspected;
only the bot comment was present. Searches are bounded, not an exhaustive census
of every open changed file. Repeat live overlap checks before submission.

## Reproduce and controls

From repository root, with authenticated retained inputs:

```sh
python3 -B tools/node115_cli_command_factory.py --out work/cli-factory-replay
python3 -B -m unittest discover -s tests -p test_node115_cli_command_factory.py -v
python3 -B research/work-items/RE-012-node115-cli-command-factory/verify.py
python3 -B research/work-items/RE-012-node115-cli-command-factory/verify.py --native-output work/cli-factory-native
```

The collector uses only Python's standard library and existing ELF/FDE readers.
It validates the complete input digest before collecting. Mutation tests attack
copied actual target name pointers/lengths, flags, registration displacement,
vtable header, actual and duplicate RELA writers, FDE extent, LSDA encoding and
callback body. Pure field readers permit isolated corruption controls; the
public collector never bypasses target authentication. No instruction evaluator
or target executable is invoked. The initial FF15-prefix failure and corrected
source are retained in the operator logs; no test/assertion was removed.

Native evidence used GNU objdump 2.47 and an installed Capstone distribution
whose metadata says 5.0.9 but actual binding is 5.0.7/core(5,0,1280). Tool identity,
options, original output hashes and full address/byte rows are retained. Capstone
is an observed crosscheck, not a new dependency of the collector or tests.
Mandatory repository-check outcomes and exact submitted head belong in the PR's
validation table; do not infer all-green from the focused controls.

## Limits / next question

This closes a bounded declaration-to-validator producer gap, not the whole CLI.
Full common-options factory, parser/default/help behavior, address/IP grammar,
formatter/allocator/drop closure, caller aliases and callee exceptions remain
open. No Rust reconstruction/build, source-byte identity, integrated node,
network compatibility or execution acceptance is claimed. All 0/92 gates remain
unchanged. No compiled byte window is registered. Next: bind parser consumption
of these constructed constraints and defaults while preserving the producer /
consumer distinction and the existing output-configuration boundary.
