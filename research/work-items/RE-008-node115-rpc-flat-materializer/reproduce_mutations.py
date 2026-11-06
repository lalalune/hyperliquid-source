"""Fixed twelve-release mutation replay, called only by pinned reproduce.py.

This file does not run on import. Metadata supplies pinned literal edits and
witness data, never commands. Only the actual dependency-free package is copied.
Compilation and authored-code execution require explicit caller options.
"""
import json
import os
from pathlib import Path

SOURCE_PINS = {
    "Cargo.toml": "c936a44663b7c0289a8dfffba5cd3cb457204d4a54c3457a57c11bcf3542d0ca",
    "Cargo.lock": "e40ce88aad1cd1958b5fbb70728e88cc8ea1bf4f5c6ad2bf741ea61df894881c",
    "src/lib.rs": "8da06fda6977268c7495b3387272aacbaa3eb35bb1ce72026ac317a8db4a4d9f",
    "src/bin/driver.rs": "2b046ee9f26290bd08f10577ae9647a02b4ae4438f663d783dbffa528c06a36f",
}
METADATA_PINS = {
    "AUTHORING.json": "b793d157c77f17dbe8a55577f943ae7cf55d6825e757141ee9bcf53f4863f93c",
    "EXACT-EDITS.json": "f4920e20c53c32bcc7686f89de8b89791fd39c3565774c2313bb9d2e2927a499",
    "WITNESS-BINDINGS.json": "9e7478338044367db2b174eb2943b3398e61e48a7676a25db805d6da3ff98e3d",
}
IDS = tuple(f"M{i:02d}" for i in range(1, 13))


def by_id(rows, field):
    result = {row[field]: row for row in rows}
    if len(rows) != 12 or set(result) != set(IDS):
        raise ValueError("mutation IDs must be exactly M01..M12")
    return result


def audit_ancestors(package):
    """Check both lexical and physical Cargo discovery paths."""
    inspected = []
    for location in (package.absolute(), package.resolve()):
        for parent in (location, *location.parents):
            for name in (".cargo/config", ".cargo/config.toml"):
                candidate = parent / name
                if candidate.exists() or candidate.is_symlink():
                    raise ValueError("Cargo ancestor configuration present: " + str(candidate))
                inspected.append(str(candidate))
            manifest = parent / "Cargo.toml"
            if parent != location and (manifest.exists() or manifest.is_symlink()):
                raise ValueError("ancestor Cargo manifest present: " + str(manifest))
    return sorted(set(inspected))


def run(session, args):
    cargo = session.admit_executable(args.cargo, args.cargo_sha256)
    rustc = session.admit_executable(args.rustc, args.rustc_sha256)
    if cargo.parent != rustc.parent:
        raise ValueError("cargo and rustc must be direct files in one admitted toolchain bin")
    toolchain = cargo.parent.parent
    if not (toolchain / "lib").is_dir():
        raise ValueError("toolchain lib directory missing")
    # These caller-supplied executable hashes are not a transitive SDK/toolchain
    # attestation. Retain version identities; review the installed toolchain too.
    versions = {}
    for name, path, flag in (("cargo", cargo, "--version"), ("rustc", rustc, "-vV")):
        record = session.command("mutation-" + name + "-version", [str(path), flag])
        session.require_exit(record, 0)
        versions[name] = record
    if not Path(versions["rustc"]["stdout_path"]).read_text("utf-8").startswith("rustc 1.95.0 "):
        raise ValueError("this replay requires Rust 1.95.0")

    source = args.repo / "src/node115-rpc-flat-materializer"
    baseline = {name: session.pin(source / name, digest) for name, digest in SOURCE_PINS.items()}
    metadata = {}
    for name, digest in METADATA_PINS.items():
        raw = session.pin(session.packet / "mutations" / name, digest)
        session.write(session.out / "mutation-admission" / name, raw)
        metadata[name] = json.loads(raw)
    authoring = by_id(metadata["AUTHORING.json"]["mutations"], "id")
    edits = by_id(metadata["EXACT-EDITS.json"]["mutations"], "id")
    witnesses = by_id(metadata["WITNESS-BINDINGS.json"]["mappings"], "mutation_id")
    if metadata["EXACT-EDITS.json"]["baseline_sha256"] != SOURCE_PINS["src/lib.rs"]:
        raise ValueError("literal-edit baseline mismatch")

    expected_lines = dict(line.split(b"\t", 1) for line in
                          (session.data / "expected.tsv").read_bytes().splitlines())
    reports = []
    for ident in IDS:
        item, change, witness = authoring[ident], edits[ident], witnesses[ident]
        patch = session.pin(session.packet / "mutations" / ident / "lib.patch", item["patch_sha256"])
        session.write(session.out / "mutation-admission" / ident / "lib.patch", patch)
        modified = baseline["src/lib.rs"].decode("utf-8")
        for edit in change["changes"]:
            if type(edit["count"]) is not int or edit["count"] < 1 or not edit["old"]:
                raise ValueError("invalid admitted literal-edit count")
            if modified.count(edit["old"]) != edit["count"]:
                raise ValueError("literal coordinate mismatch: " + ident)
            modified = modified.replace(edit["old"], edit["new"])
        modified = modified.encode("utf-8")
        if session.sha(modified) != item["source_sha256"]:
            raise ValueError("mutated source identity mismatch: " + ident)
        if witness["canonical_id"] != item["primary_canonical_witness"]:
            raise ValueError("witness binding mismatch")
        expected_line = witness["expected_output"].encode("ascii")
        expected_id = witness["canonical_id"].encode("ascii")
        if expected_line != expected_id + b"\t" + expected_lines[expected_id] + b"\n":
            raise ValueError("frozen witness does not match full expected stream")

        package = session.out / "variants" / ident / "package"
        for name, raw in baseline.items():
            session.write(package / name, modified if name == "src/lib.rs" else raw)
        # README is intentionally not needed to build this package; its later
        # editorial history cannot alter these four admitted build inputs.
        config_checks = audit_ancestors(package)
        target = session.out / "variants" / ident / "target"
        cargo_home = session.out / "variants" / ident / "cargo-home"
        cargo_home.mkdir()
        env = session.clean_env()
        env.update({
            "CARGO_HOME": str(cargo_home), "CARGO_NET_OFFLINE": "true",
            "CARGO_INCREMENTAL": "0", "CARGO_BUILD_JOBS": "2",
            "CARGO_TARGET_DIR": str(target), "RUSTC": str(rustc),
        })
        # Encoded flags preserve paths with spaces and cover lexical/canonical
        # spellings. The installed compiler/linker remains caller-admitted.
        roots = sorted({str(session.out.absolute()), str(session.out.resolve())})
        flags = [f"--remap-path-prefix={root}=<REPRODUCTION>" for root in roots]
        flags += ["-C", "target-cpu=generic"]
        env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(flags)
        build = session.command("build-" + ident, [
            str(cargo), "build", "--offline", "--locked", "--release",
            "--lib", "--bin", "node115-rpc-flat-driver",
            "--manifest-path", str(package / "Cargo.toml"),
            "--target-dir", str(target),
        ], cwd=package, env=env)
        session.require_exit(build, 0)
        for name, raw in baseline.items():
            actual = (package / name).read_bytes()
            if actual != (modified if name == "src/lib.rs" else raw):
                raise ValueError("build changed a pinned package input")
        binary = target / "release/node115-rpc-flat-driver"
        binary_hash = session.file_identity(binary)["sha256"]
        result, child, comparison = session.driver(
            "mutant-" + ident, binary, binary_hash)
        if child["process_status"] != "completed" or child["returncode"] != 0:
            raise ValueError("mutant process failure is inconclusive: " + ident)
        if (comparison["returncode"] != 1 or result["classification"] != "semantic_mismatch"
                or result.get("records") != 13957):
            raise ValueError("mutant is not a complete semantic detection: " + ident)
        found = [row for row in result["semantic_mismatches"] if row["id"] == witness["canonical_id"]]
        if len(found) != 1 or found[0]["expected_fields"] != witness["expected_output"].rstrip("\n").split("\t"):
            raise ValueError("named manual witness not distinguished: " + ident)
        report = {
            "id": ident, "profile": "release", "source_sha256": item["source_sha256"],
            "patch_sha256": item["patch_sha256"], "binary_sha256": binary_hash,
            "build": build, "child": child, "comparison": comparison,
            "records": result["records"], "semantic_mismatch_count": result["semantic_mismatch_count"],
            "manual_witness": found[0], "ancestor_config_absences": config_checks,
        }
        session.json(session.out / "mutation-results" / (ident + ".json"), report)
        reports.append(report)
    for name, digest in SOURCE_PINS.items():
        session.pin(source / name, digest)
    session.pin(cargo, args.cargo_sha256)
    session.pin(rustc, args.rustc_sha256)
    return {
        "profile": "release", "variants": len(reports), "results": reports,
        "tool_versions": versions,
        "limits": [
            "A new twelve-release replay, not a restatement of the historical twenty-four-profile run.",
            "Only successful builds and completed, well-formed outputs with the named semantic witness count.",
            "Compiler executables are hash-bound; installed compiler libraries, linker and SDK are caller-reviewed dependencies.",
            "No captured execution, native lifetime/ABI equivalence, or allocation-failure oracle.",
            "Compiled artifacts remain under the caller's output directory and may contain local build paths.",
        ],
    }

