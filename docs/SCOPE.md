# Scope and acceptance

## Target artifacts

The sole node implementation target is Linux x86-64 **hl-node #115**, SHA-256
`a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301`,
the newest authenticated capture retained here. Before claiming current-network
support, authenticate the chosen current release and validate its protocol;
the newest retained capture is not necessarily the latest published binary.

Retired-release binaries, unvalidated implementations and dedicated tools are
not part of the active tree. They remain in Git history. Reuse is accepted only
through a new #115-bound record; it never transfers completion credit by name.

The captured **visor**, SHA-256
`89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31`,
is a separate supervisor executable. Its version is not inferred from the
node release number. Preserve its signature and establish its own inventory.

The binaries and signatures are in artifacts/; provenance/artifacts.json is
the identity authority. `make verify` authenticates the retained inputs.

## Included work

Recover an independently authored, buildable Rust implementation and the
build provenance needed to compare it with captured code and behavior. Cover
node startup, transport/gossip, consensus, block execution, order matching,
clearinghouses/risk, assets/quantities, fees, vaults, bridge, staking, HyperEVM,
APIs, persistence, serialization and dependencies. A supervisor is optional;
visor analysis is permitted only when it resolves a demonstrated #115 delivery blocker.
[The component map](COMPONENTS.md) partitions the currently visible source
paths. It is a work allocation map; cross-component calls still need recovery.
Its 23 node work areas are inherited planning scopes, not a validated #115
function inventory. All component gates remain false after the target change.

A final node claim requires matching the complete target ELF and its loadable
segments, code/data, symbol/relocation relationships, exception metadata and
observable behavior under stated conditions. Source builds must reproduce
without binary byte transplantation. Exact matches in isolated functions do
not establish whole-program equivalence or safety.

## References and supporting work

The pinned hyperliquid-dex repositories provide public interfaces, packaging,
examples, contracts and data tools. They do not supply the private native node
source. Public Solidity contracts and companion services have their own
scope and licensing; their availability earns no native reconstruction credit.
The order_book_server README explicitly disclaims core-team authorship.

## Source-built network node

The delivery goal is a fully open-source Linux/amd64 Docker image containing a
node built from source that connects to the chosen network, synchronizes and
validates state, persists it, and resumes correctly after restart. A TCP
connection alone does not establish a working node. Record the network, protocol
version, source commit, image digest, commands and observed results.

These delivery checks are separate from the four component reconstruction
gates. A functional release must pass the checks below; it must not claim exact
binary identity until the existing whole-ELF gates are also satisfied.

| Required area | Work needed | Current acceptance |
| --- | --- | --- |
| First-party node implementation | Complete the 23 baseline component scopes and their cross-component calls, state layouts and errors | Open: see the generated component gates in PROGRESS.md |
| Private forks and unassigned code | Identify code beyond the source-path taxonomy; recover private changes to codecs, networking, EVM and other dependencies | Open: module ownership and complete dependency graph unmeasured |
| Public dependencies and system libraries | Reuse licensed sources; establish exact source revisions, local patches, build flags and runtime libraries | Open: observed version strings and selected dependency windows are not a complete source lock |
| Data and executable integration | Recover constants, vtables, relocations, initialization, unwinding, ABI and persistent/wire formats | Open: selected `.text` comparisons do not cover these regions |
| Source and license closure | Account for every runtime component and license; no required proprietary node/visor download or copied unlicensed reference code | Open: independent fragments exist, full closure not established |
| Integrated executable | Build the actual node with pinned manifests, lockfiles, compiler and linker; exercise startup, configuration and clean shutdown | Open: no integrated node build accepted |
| Docker delivery | Build a pinned Linux/amd64 image from source, run the node as an unprivileged user with persistent data and health reporting | Open: `.devcontainer` supplies analysis tools only; no node runtime image accepted |
| Network compatibility | Validate the chosen network's discovery, handshake, framing, signatures and protocol version; handle disconnect/reconnect | Open: captured #115 evidence does not establish current-network compatibility |
| Synchronization and validation | Bootstrap from documented genesis/checkpoint inputs; verify blocks, consensus and state roots, reject corrupt inputs, catch up and resume after restart | Open: no end-to-end node acceptance run |
| APIs and operations | Serve the required APIs from synchronized state; verify persistence, resource limits and observable failure behavior | Open: no integrated acceptance run |
| Supervisor delivery | Supply an open-source lifecycle/update mechanism if needed; document direct container startup when the captured visor is unnecessary | Open: investigate visor only for a demonstrated #115 delivery blocker; direct startup may suffice |

Public contracts, SDKs, block importers, historical-data tools and order-book
consumers are supporting sources, not missing native-node implementations. Do
not assign them reconstruction percentages or include them in the 23-component
node denominator. Public dependency code does not need to be reinvented;
unavailable private changes and the target-specific integration still need work.

The next integration path is startup/configuration, transport and wire codecs,
peer discovery/handshake, storage/bootstrap, consensus/block validation, then
state replay and APIs. Existing bounded implementations must be joined only
after their calling conventions, data layouts and error behavior are established.
Do not create a placeholder node or container to satisfy a checklist.

## Execution boundaries

Live validator operation, mainnet/testnet traffic, signing/broadcasting chain
actions, importing private keys, and running the captured node or visor are
outside this preparation task. Differential execution requires a separately
approved, isolated offline harness. Static parsing, disassembly and Ghidra
analysis of the selected binaries are within research scope.

Do not download full chain datasets or start paid/requester-pays sync as a
setup step. Capture a small, licensed/sanitized fixture only when a concrete
question needs it. Do not relabel historical evidence as validated #115 functionality.

## How completion is counted

`research/progress.json` holds four acceptance gates per component: mapped,
built, behavior and identity. `docs/PROGRESS.md` derives the percent as accepted
gates divided by four. All are initially false. This measures reviewed
milestones, not engineering effort, lines of code or guessed correctness.
A partial packet may be valuable while its component gate remains false.

Record raw-equal bodies, normalized-only bodies, unmatched bodies and total
validated windows separately when a comparator exists. State exactly which
operands a normalization masks. Never count an address match, a source path,
a literal, an unwinding entry, an assembly-only patch or a test that merely
mirrors new code as proof of reconstructed Rust equivalence.
