# RE-000: resolve REA JAVA_HOME to the full JDK

- Component: deterministic offline REA launcher setup, `tools/rea.py`.
- Base: `1f8c67c63ca4794c9689235471c60297f8a5c985`.
- Requirement: docs/REA.md requires a full JDK for the native provider and
  preserves explicit JAVA_HOME. Automatic discovery must identify that JDK
  root when PATH selects the macOS system Java launcher or a nested Java 8 JRE.
- Target context: launcher setup precedes selection of node94/node115/visor.
  Default node94 remains bound to SHA-256
  `3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f`.
  No captured target is executed or changed; no target semantics are claimed.

## Reproduced defect

With JAVA_HOME unset on a real macOS host, `environment()` found `/usr/bin/java`
then inferred its parent-of-parent `/usr` as JAVA_HOME. macOS supplies that
executable as a platform launcher, while `/usr/libexec/java_home` reports the
actual registered JDK root. A second real case using the installed Java 8
`<jdk>/jre/bin/java` advertised `<jdk>/jre` instead of the enclosing full JDK.

The same two native regression methods failed on the base implementation:
`test_system_launcher_uses_registered_jdk_root` and
`test_real_nested_jre_uses_enclosing_jdk`. The first observed `/usr`; the second
observed `<native-jdk>/jre`. Neither matches the native registered full JDK.
These are real platform-resolver/filesystem tests, not a fake JVM or mocked
provider. Original failing output is retained outside the contribution; local
installation paths are not published here.

## Change

`find_java_home()` uses the macOS resolver only when the selected executable
resolves to `/usr/bin/java`. A directly selected JDK keeps its own location.
A Java 8 nested JRE is normalized to its parent when that parent has javac.
Discovery accepts a full JDK layout with both bin/java and bin/javac. Missing,
failed, timed-out or unusable macOS resolution leaves automatic JAVA_HOME
unset rather than inventing `/usr`. An explicit JAVA_HOME bypasses discovery.

The resolver is bounded by a five-second timeout. It queries only the JDK
location, without dumping arbitrary JVM system properties. No JDK/package is
installed and no system configuration is changed.

## Reproduction and validation

Host: macOS 26.4 arm64, Python 3.12.14. Native installed Java observed during
reproduction: OpenJDK/Corretto 1.8.0_402. That version is used to establish
location discovery only; native Ghidra/REA provider compatibility is not claimed.
A compatible full JDK remains the operator's provider prerequisite.

From the repository root:

```sh
python3 -B tests/test_rea_java_home.py NativeJavaHomeTests
python3 -B tests/test_rea_java_home.py
python3 -B -m unittest discover -s tests -p test_rea_launcher.py -v
make doctor verify test catalogue-check
```

Before the fix, the first command reports **2 native failures**. After the fix,
all **8** new tests pass, including those same two native cases. The other six
methods use temporary filesystem-shape fixtures and controlled resolver outcomes
to check direct/nested JDKs, path spaces, failure/timeout/missing resolver,
absolute/full-JDK validation, explicit configuration and missing Java. They do
not pretend to compile or run those fixture files. The **5 existing launcher
tests** also pass. `make doctor verify test catalogue-check` passes: **439 tests**
in 142.168 seconds, with artifact/signature/import/pin and catalogue checks.

Native tests skip when macOS or a registered full JDK/nested JRE is unavailable;
the deterministic controls still run. No captured program, model-backed feature,
Ghidra analysis or full native provider workflow was executed. No hosted-CI
success is claimed. `make reproduce` is not required for this environment-only
change: no inventory, literal interpretation, catalogue or progress input changes.

## Limits

Discovery validates the JDK filesystem layout; provider-specific Java version
compatibility and arbitrary custom launcher scripts are outside this fix.
Explicit user configuration remains authoritative. Imports, signatures, captures,
pins and all component gates are preserved. No new dependencies are introduced.
