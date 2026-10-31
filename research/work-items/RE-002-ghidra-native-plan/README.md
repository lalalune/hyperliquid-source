# RE-002: executable native-shell Ghidra import plans

- Component: foundation / analysis-tool provenance. No progress gate requested.
- Base/source context: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Node #94 identity: `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`, 91,774,280 bytes.
- Claim: actual CLI/shell observations, with an inert local launcher fixture.
- No binary instruction, Rust implementation, function-boundary or provider-equivalence claim.

## Failure and cause

`python tools/ghidra_plan.py --release 94` authenticates the retained capture
and exits 0, but on Windows it prints a POSIX-quoted command naming the Unix
`analyzeHeadless` launcher. Pasting that command into PowerShell fails before
the launcher sees its arguments. A normal installation path containing a space
reproduces a parser error and exit 1. Both conventional distribution launcher
names are present in the fixture, so discovery already succeeds: this is not
the missing `.bat` discovery addressed by PR #331, nor GHIDRA_INSTALL_DIR
selection in #206. #690/#720 change manifest lookup, not command rendering.

## Implementation and regression

On Windows emit an explicitly labeled PowerShell plan with the call operator,
literal quoting (including apostrophes), and `analyzeHeadless.bat`. On POSIX
retain the original `mkdir -p` / `shlex.join` command bytes. Select no new
provider, install nothing, and keep release authentication and existing-project
refusal before plan output. A missing selected native launcher refuses output.

`tests/test_ghidra_plan_shell.py` executes the generated native-host plan against
an independently authored argument-recording marker. It checks the complete
argument vector, space/apostrophe paths and directory creation; the purported
capture path does not even exist in that unit fixture. Other controls cover
POSIX parsing, Windows launcher/quoting and missing native launcher refusal.

Windows Python 3.10 focused command: 4 pass, 0 fail, 0 skip, using the normal
approved execution path. The initial default-sandbox attempt was 3 pass/1 fail
because PowerShell could not access execution-policy registry state. No policy
or protection was changed; the same command passed through formal tool approval.
That environment failure is not attributed to the planner.

## Actual CLI controls

`before.json` and `after.json` retain the actual CLI output and exact selected
artifact identity; only the local workspace prefix is redacted. The before CLI
exits 0 but its PowerShell plan exits 1 without reaching the marker. After the
change, the generated plan reaches the marker and exits 0 under both Windows
PowerShell 5 and PowerShell 7. The marker only prints its arguments. The node
path is an inert argument, never an executable command. Installation discovery,
Ghidra itself, Java and analysis of a capture are not qualified by these controls.

Commands from the repository root:

```text
python -X utf8 -m unittest discover -s tests -p test_ghidra_plan_shell.py -v
python -X utf8 tools/ghidra_plan.py --release 94
make doctor
make verify test catalogue-check
```

For the actual CLI control, GHIDRA_HOME points only to a disposable fixture
directory with both launcher names; it is not a real installation or a global
setting. The full required commands must be checked at the submitted final head;
the focused tests above do not imply their success. Source hashes are in
after.json, and packet bytes are locked by MANIFEST.sha256.

## Limits and next question

No real native Ghidra/Rust build, captured node/visor execution, live chain,
provider/model call, signing, registration, deployment or full Windows repository
verification. POSIX execution is checked by the native-host unit on Linux;
native Windows shell execution is separate. Existing installation-discovery
gaps in #206/#331 remain those PRs' scope. No inferred unlicensed source was
copied. A real configured-provider static import is a separate, explicitly
bounded provider qualification, not something this planner invokes.
