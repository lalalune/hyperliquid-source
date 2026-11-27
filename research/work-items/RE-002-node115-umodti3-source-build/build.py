#!/usr/bin/env python3
"""Provision Rust release sources, then independently rebuild a Linux arithmetic leaf."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

TARGET = "x86_64-unknown-linux-gnu"
SYMBOL = "__umodti3"
# rust-src distribution tarball hashes, not prebuilt target library hashes.
RELEASES = {
    "1.95.0": ("59807616e1fa2540724bfbac14d7976d7e4a3860",
               "67b09138c8db96afc4bbfc69ea771ac9a091fd777698acb43f6dfd9fb7dea363"),
    "1.94.1": ("e408947bfd200af42db322daf0fadfe7e26d3bd1",
               "cb3756156fe6d2d6cedad327c94ad3721b612c4cd20dfb226d7543250788b66c"),
}
MANIFEST = """[package]
name = "umodti3-source-probe"
version = "0.0.0"
edition = "2021"
publish = false
[lib]
path = "src/lib.rs"
[profile.release]
opt-level = 3
codegen-units = 256
debug = 0
debug-assertions = false
overflow-checks = false
lto = false
incremental = false
"""
PROBE = "#![no_std]\npub fn remainder(value: u128, divisor: u128) -> u128 { value % divisor }\n"
BUILD_STD = "-Zbuild-std=core,compiler_builtins"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def capture(args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs)


def sources(cache, scratch, version, provision):
    filename = f"rust-src-{version}.tar.xz"
    archive = cache / filename
    wanted = RELEASES[version][1]
    if provision and not archive.exists():
        with urllib.request.urlopen(f"https://static.rust-lang.org/dist/{filename}", timeout=60) as response:
            data = response.read()
        require(digest(data) == wanted, f"unexpected digest for {filename}")
        with tempfile.NamedTemporaryFile(dir=cache, delete=False) as tmp:
            tmp.write(data)
        Path(tmp.name).replace(archive)
    # Authenticate the same bytes passed to the extractor, including on offline replays.
    with archive.open("rb") as stream:
        require(hashlib.file_digest(stream, "sha256").hexdigest() == wanted, f"unexpected digest for {filename}")
        stream.seek(0)
        with tarfile.open(fileobj=stream, mode="r:xz") as tar:
            tar.extractall(scratch, filter="data")
    return scratch / f"rust-src-{version}/rust-src/lib/rustlib/src/rust/library"


def tools_for_release(version):
    cargo, rustc = [capture(["rustup", "which", "--toolchain", version, tool]).strip()
                    for tool in ("cargo", "rustc")]
    rust_version = capture([rustc, "-vV"])
    fields = dict(line.split(": ", 1) for line in rust_version.splitlines() if ": " in line)
    require(fields["release"] == version and fields["commit-hash"] == RELEASES[version][0],
            f"incorrect rustc for {version}")
    cargo_version = capture([cargo, "-V"]).strip()
    require(cargo_version.startswith(f"cargo {version} "), f"incorrect cargo for {version}")
    return cargo, rustc, rust_version.strip(), cargo_version


def cargo_job(work, cache, library, version, provision):
    (work / "src").mkdir(parents=True)
    (work / "src/lib.rs").write_text(PROBE)
    (work / "Cargo.toml").write_text(MANIFEST)
    cargo, rustc, compiler, cargo_version = tools_for_release(version)
    env = {key: os.environ[key] for key in ("PATH", "HOME", "TMPDIR", "SYSTEMROOT") if key in os.environ}
    env.update(
        LC_ALL="C", CARGO_HOME=str(cache / "cargo"), CARGO_INCREMENTAL="0",
        RUSTC=rustc, RUSTC_BOOTSTRAP="1", __CARGO_TESTS_ONLY_SRC_ROOT=str(library),
    )
    # Use unit-separated flags so spaces in the chosen temporary directory stay in a single argument.
    env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(
        [f"--remap-path-prefix={work}=/build/probe", f"--remap-path-prefix={library}=/build/rust-library"])
    capture([cargo, "generate-lockfile", "--offline"], cwd=work, env=env)
    if provision:
        subprocess.run([cargo, "fetch", "--locked", "--target", TARGET, BUILD_STD], cwd=work, env=env, check=True)
        return
    output = capture([cargo, "build", "--locked", "--offline", "--release", "--target", TARGET,
                      BUILD_STD, "--message-format=json"], cwd=work, env=env)
    products = [json.loads(line) for line in output.splitlines()]
    builtin, = [p for p in products if p["reason"] == "compiler-artifact"
                and p["target"]["name"] == "compiler_builtins"]
    require(builtin["fresh"] is False and Path(builtin["manifest_path"]).is_relative_to(library),
            "compiler_builtins was not freshly compiled from the authenticated release source")
    archive, = [Path(path) for path in builtin["filenames"] if path.endswith(".rlib")]
    return archive, compiler, cargo_version


def binutils(directory):
    result = {}
    for name in ("nm", "ar", "objdump", "objcopy"):
        candidates = [str(directory / name)] if directory else [shutil.which("g" + name), shutil.which(name)]
        for path in filter(None, candidates):
            version = subprocess.run([path, "--version"], capture_output=True, text=True)
            lines = version.stdout.splitlines()
            if version.returncode == 0 and lines and "GNU" in lines[0]:
                result[name] = path
                break
        else:
            raise ValueError(f"missing GNU {name}; supply --binutils-dir")
    return result


def symbol_bytes(archive, tools, work):
    symbols = capture([tools["nm"], "-A", "-S", "--defined-only", archive])
    row, = [line.split() for line in symbols.splitlines() if line.split() and line.split()[-1] == SYMBOL]
    label, hex_size, binding, _ = row
    _, member, hex_offset = label.rsplit(":", 2)
    require(int(hex_offset, 16) == 0 and binding in {"W", "T"}, "unexpected public symbol definition")
    members = capture([tools["ar"], "t", archive]).splitlines()
    require(members.count(member) == 1, "ambiguous object in archive")
    obj = work / "selected.o"
    obj.write_bytes(subprocess.check_output([tools["ar"], "p", archive, member]))
    raw = obj.read_bytes()
    require(raw[:6] == b"\x7fELF\x02\x01" and raw[16:20] == bytes.fromhex("01003e00"),
            "expected a little-endian x86-64 relocatable ELF")
    rows = capture([tools["objdump"], "-t", obj]).splitlines()
    sym, = [line.split() for line in rows if line.split() and line.split()[-1] == SYMBOL]
    section = f".text.{SYMBOL}"
    require("F" in sym and int(sym[0], 16) == 0 and section in sym
            and int(sym[sym.index(section) + 1], 16) == int(hex_size, 16),
            "ELF symbol is not a whole zero-offset function")
    relocations = capture([tools["objdump"], "-r", "-j", section, obj])
    require("RELOCATION RECORDS FOR" not in relocations, "function has relocation fields")
    body_file = work / "selected.bin"
    subprocess.run([tools["objcopy"], "--dump-section", f"{section}={body_file}", obj], check=True)
    body = body_file.read_bytes()
    require(len(body) == int(hex_size, 16) > 0, "symbol does not occupy its exact section")
    return dict(archive=archive.name, archive_sha256=digest(archive.read_bytes()), member=member,
                member_sha256=digest(raw), symbol=SYMBOL, section=section, symbol_offset=0,
                length=len(body), function_sha256=digest(body), relocations_in_section=0), body


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["provision", "run"])
    parser.add_argument("--cache", required=True, type=Path, help="dedicated source archives and Cargo registry")
    parser.add_argument("--output", type=Path, help="new directory for the three generated evidence files")
    parser.add_argument("--binutils-dir", type=Path, help="directory containing GNU ar, nm, objdump, objcopy")
    args = parser.parse_args()
    provision = args.action == "provision"
    if not provision and (args.output is None or args.output.exists()):
        parser.error("run requires an unused --output directory")
    cache = args.cache.resolve()
    if provision:
        cache.mkdir(parents=True, exist_ok=True)
    tools = {} if provision else binutils(args.binutils_dir)
    builds, bodies = [], []
    with tempfile.TemporaryDirectory(prefix="umodti3-build-") as temp:
        root = Path(temp).resolve()
        for version in RELEASES:
            library = sources(cache, root, version, provision)
            labels = ["fetch"] if provision else (["build-a", "build-b"] if version == "1.95.0" else ["control"])
            for label in labels:
                work = root / f"{version}-{label}"
                result = cargo_job(work, cache, library, version, provision)
                if provision:
                    continue
                archive, compiler, cargo_version = result
                row, body = symbol_bytes(archive, tools, work)
                row.update(label=label, rust_release=version, rustc_commit=RELEASES[version][0],
                           rustc_verbose=compiler, cargo_version=cargo_version)
                builds.append(row)
                bodies.append(body)
    if provision:
        return
    require(bodies[0] == bodies[1], "repeat source builds produced differing function bodies")
    for field in ("member_sha256", "archive_sha256"):
        require(builds[0][field] == builds[1][field], f"repeat source builds differed at {field}")
    require(bodies[0] != bodies[2], "toolchain/version control did not discriminate")
    for row, body in zip(builds, bodies):
        row["aligned_mismatches"] = sum(a != b for a, b in zip(bodies[0], body))
        row["length_difference"] = len(body) - len(bodies[0])
    evidence = dict(target=TARGET, host=f"{platform.system()} {platform.machine()}", symbol=SYMBOL,
                    binutils_versions={name: capture([path, "--version"]).splitlines()[0] for name, path in tools.items()},
                    source_archives={v: value[1] for v, value in RELEASES.items()}, builds=builds)
    args.output.mkdir(parents=True)
    (args.output / "build-results.json").write_text(json.dumps(evidence, indent=2) + "\n")
    (args.output / "umodti3.bin").write_bytes(bodies[0])
    (args.output / "control-1.94.1.bin").write_bytes(bodies[2])


if __name__ == "__main__":
    main()
