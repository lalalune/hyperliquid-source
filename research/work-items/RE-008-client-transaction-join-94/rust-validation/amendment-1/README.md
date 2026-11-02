# Pre-build source amendment 1

The original SOURCE-FREEZE.json remains byte-identical, as do its original
production module, driver.rs, build.py and SOURCE-PROOF.md. No Rust compilation
was attempted under that freeze. The amended public integration test is the
only changed crate file; its exact original bytes are retained here and in the
private session archive. The three unified diffs identify every change.

Independent peer review found two qualification gaps. First, the original client
observed original-block Weak liveness and returned bytes without directly
comparing the returned block's pointer. The immutable PROTOCOL.md requires that
identity. driver_amended.rs now checks Weak::as_ptr against Arc::as_ptr for every
successful result, rejecting a wrong identity before publishing any output.
The observation frame and every original expected byte remain unchanged. The
new eleventh integration test additionally checks the newly constructed-rows
branch's exact opaque-block pointer and post-drop liveness. The existing supplied
rows test already checks that branch's pointer. No production logic changes.

Second, the old build harness removed its first clean build before repeating at
the same path and retained only artifact identities. build_amended.py archives
both baseline and repeat rlib/client bytes immediately after linking and before
value execution or directory removal. Content-addressed gzip references are
written to receipts/compiled-artifacts.json as an append-only sequence and also
bound to each observation. If repeat bytes differ, both actual byte streams
remain available even when the run fails. These compiled archives are distinct
from raw command stdout/stderr. Mutant build trees remain in scratch; their
binaries are not duplicated into these baseline/repeat archives.

SOURCE-FREEZE-2.json admits the amended test, driver and harness while retaining
and checking the original freeze, original harness and reconstructed original
source graph. Run build_amended.py with the new source-freeze hash after the
separate parent source/build gate. build.py and driver.rs remain historical
originals. SOURCE-PROOF.md's ten-test count and original entrypoints describe the
first freeze; this amendment supersedes only those source-phase details.

The production module, 17 mutation definitions, original 49 pre-code inputs,
361 input/expected cases and native premises are unchanged. This is a pre-build
review correction, not a concealed compilation failure or an alteration of the
independent expected corpus. Actual compilation outcomes remain unobserved at
the amendment freeze. Formatting is recorded separately in FORMAT.json.
