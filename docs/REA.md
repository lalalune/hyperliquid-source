# REA configuration

The project uses [morluto/rea](https://github.com/morluto/rea), pinned to
`rea-agents` **6.8.0** in package.json and package-lock.json. The selected native
provider is **Ghidra**; target paths are in config/rea.json and hashes remain
authoritative in provenance/artifacts.json.

## Install and inspect

```sh
nvm install                      # .nvmrc selects Node 24.22.1
make rea-install                 # npm ci; package lifecycle scripts disabled
make rea-doctor                  # local provider/target checks; no target execution
make rea-smoke                   # pinned CLI + both node identities; no Ghidra needed
make rea-mcp-check               # owned stdio handshake and Ghidra availability check
make rea-native-smoke            # native visor entrypoint, explicitly reduced analysis
python3 tools/rea.py --version
python3 tools/rea.py target 94    # verified input and provider for MCP open_binary
```

The launcher selects a supported installed Node rather than inheriting an
incompatible shell default. REA 6.8.0 declares `^22.23.4 || ^24.22.1 || >=26.12.1`.
Use `REA_NODE=/absolute/path/to/node` to choose explicitly; an incompatible
explicit override fails rather than silently switching runtimes. No global
Node default is changed.

`make rea-install` restores the exact package lock. To create a deliberate
lockfile update, use npm under a supported runtime, review the diff, update the
version pin and validate the integration. Do not use unpinned `@latest` here.
The Python-only research workflow does not require npm installation.

## Native provider environment

Set `GHIDRA_INSTALL_DIR` to an existing standard Ghidra installation and
`JAVA_HOME` to a compatible full JDK. Explicit values are preserved. The
launcher can discover the previously installed Ghidra under
`~/.local/share/rea-tools/ghidra_*_PUBLIC` and Java on PATH.
For the macOS `/usr/bin/java` launcher, discovery uses `/usr/libexec/java_home`.
A Java 8 nested JRE is normalized to its enclosing JDK. Automatic discovery
requires both `bin/java` and `bin/javac`; explicit `JAVA_HOME` still wins.
The x86-64 targets do not need the sBPF extension.

```sh
export GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra
export JAVA_HOME=/absolute/path/to/jdk
make rea-doctor
make rea-mcp
```

`make rea-mcp-check` starts an owned local server, verifies its protocol/package
identity and Ghidra availability, then stops it without opening a target.
`make rea-mcp` runs a stdio MCP server until stopped; do not launch a second
server manually while expecting it to share an existing server's target state.
Configuration does not install Ghidra, Java, Hopper or IDA.
The devcontainer still needs a supported Node and native provider installed
before these optional REA commands; its build has not been verified.

## Agent registration

The current Codex host already has a working `rea` registration at version
6.8.0, with Ghidra 12.1.4 and Java 21.0.10. It uses its existing supported Node
24.22.1 runtime. That registration and unrelated user settings are preserved.
The repository launcher and the existing server use the same REA version.
Registration validation uses the environment from the MCP registration; a raw
shell invocation that omits its Ghidra/Java variables is not the same check.
A doctor run from the project-local package can list the global registration
as "stale" because the install paths differ. Its scoped Ghidra `healthy` result
and the live server identity are checked independently; do not rewrite the
working user registration merely to make those installation paths identical.
Missing unrelated providers in `informational_checks` are outside this profile.

For a new machine, review the official setup plan before changing its user
configuration or installed skill:

```sh
python3 tools/rea.py setup --client codex --dry-run --format json
# After reviewing the plan and authorizing its exact scope:
python3 tools/rea.py setup --client codex --yes
```

Setup writes the selected client's registration and bundled skill. Restart or
reconnect that client after a changed registration. Existing connected tools
should be used directly; repeated setup is not a substitute for a failed
provider operation. See the project's CONTRIBUTING.md and the installed
reverse-engineer-anything skill for permission and recovery boundaries.

## Verified target workflow

With the connected REA tools, use `open_binary` with an absolute path and
`provider_id: "ghidra"`; obtain the path and verify its hash with
`python3 tools/rea.py target 94`. Keep #94, #115 and visor sessions separate.

1. Start with a focused question and an artifact identity check.
2. Inspect a bounded function, instructions or xrefs. The first native query
   triggers Ghidra auto-analysis; this can be expensive for these large binaries.
3. Retain complete Evidence records, provider/profile identity, limitations and
   original bytes. Pseudocode and inferred function boundaries are not source.
4. Export needed evidence and call `close_binary` when done. This releases the
   provider's temporary project. Persist a snapshot only with its matching
   artifact/provider/profile; do not reuse a mismatched snapshot.

For lightweight, target-free static inspection:

```sh
python3 tools/rea.py inspect-rust-binary artifacts/node/94/hl-node --format json \
  > work/rea-node94-rust.json
```

The native setup smoke check uses the captured visor's entrypoint through a source-file-offset
selector and Ghidra's decompiler. It does not execute the visor or node. Evidence belongs
under research/rea/; reusable work packets belong under research/work-items/.
No reconstruction completion credit is awarded for tool configuration.

The [integration verification packet](../research/rea/setup-20261028/README.md)
contains the successful native result, handshake and preserved failures.

## Large-binary analysis profiles

The default Ghidra analysis attempt on the captured visor exceeded the default
330-second startup budget. The original error bundle is retained under
research/rea/setup-20261028/. This is not a successful full-binary analysis.

The explicit `native-smoke` profile disables `Decompiler Switch Analysis` and
`Decompiler Parameter ID`, as supported by REA's timeout remediation. It is
only for verifying the native pipeline quickly; its reduced coverage must be
preserved in every derived claim. The default profile and existing Codex
registration are unchanged. Select it explicitly for a new server or CLI run:

```sh
python3 tools/rea.py --profile native-smoke mcp
```

For full analysis, keep the default analyzer set. On a timeout, inspect the
retained error and cleanup state before retrying. Increase
`ghidra.startup_timeout_ms` with REA's runtime settings, or use the documented
`REA_GHIDRA_STARTUP_TIMEOUT_MS` launch variable, and provide a correspondingly
longer client deadline. A larger response buffer does not solve an analysis
timeout. Do not silently reuse reduced-profile snapshots as full-profile evidence.

## Address coordinates

Ghidra can rebase a PIE image (the captured visor was loaded at base
`0x100000`). An ELF virtual address is therefore not automatically a Ghidra
analysis address. For decompilation, use an explicit `file-offset:0x...`
selector derived from the authenticated file, or choose a provider-observed
address. The native smoke check resolves the ELF entry to its file offset
before calling `procedure_pseudo_code`. Other instruction/xref tools require
an observed analysis address; do not add a guessed load base.
