"""Check loader dependency and version-node closure without executing ELF files."""
from hashlib import sha256
from io import BytesIO
import lzma
from pathlib import Path
import re
import subprocess as sp
import sys
import tarfile
from tempfile import TemporaryDirectory

TARGET_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
SIGNER = "F6ECB3762474EDA9D21B7022871920D1991BC93C"
CACHE, KEYRING = (Path(p).resolve() for p in sys.argv[1:3])
TARGET = Path("artifacts/node/115/hl-node")
assert sha256(TARGET.read_bytes()).hexdigest() == TARGET_SHA


def readelf(path, options):
    return sp.check_output(["readelf", options, str(path)], text=True)


def dynamic(path):
    output = readelf(path, "-dW")
    return (set(re.findall(r"\(NEEDED\).*?\[([^]]+)\]", output)),
            re.findall(r"\(SONAME\).*?\[([^]]+)\]", output))


def versions(path):
    definitions = set()
    needs = {}
    kind = owner = None
    for line in readelf(path, "-VW").splitlines():
        if line.startswith("Version "):
            kind = line.split()[1]
        if kind == "definition":
            name = re.search(r"\bName:\s+(\S+)", line)
            if name:
                definitions.add(name[1])
        if kind == "needs":
            file = re.search(r"\bFile:\s+(\S+)", line)
            if file:
                owner = file[1]
            name = re.search(r"\bName:\s+(\S+)", line)
            if name:
                assert owner is not None
                needs.setdefault(owner, set()).add(name[1])
    return definitions, needs


def release_packages(suite):
    release = CACHE / f"{suite}.InRelease"
    status = sp.check_output(["gpgv", "--keyring", str(KEYRING), "--status-fd", "1", str(release)], text=True)
    assert any(line.startswith(f"[GNUPG:] VALIDSIG {SIGNER} ") for line in status.splitlines())
    data = (CACHE / f"{suite}.Packages.xz").read_bytes()
    signed = release.read_text()
    assert f"\nCodename: {suite}\n" in signed
    expected = re.search(r"^ ([a-f0-9]{64}) +([0-9]+) main/binary-amd64/Packages\.xz$",
                         signed.split("SHA256:\n", 1)[1], re.M)
    assert sha256(data).hexdigest() == expected[1] and len(data) == int(expected[2])
    return lzma.decompress(data).decode().split("\n\n")


def extract(suite, package, cached_suffix, sonames, stanzas, scratch):
    row, = (r for r in stanzas if r.startswith(f"Package: {package}\n"))
    fields = dict(line.split(": ", 1) for line in row.splitlines() if ": " in line and not line.startswith(" "))
    deb = CACHE / f"{suite}{cached_suffix}"
    assert sha256(deb.read_bytes()).hexdigest() == fields["SHA256"]
    print(suite, package, fields["Version"], fields["SHA256"])
    member, = [line for line in sp.check_output(["ar", "t", str(deb)], text=True).splitlines()
               if line.startswith("data.tar.")]
    content = sp.check_output(["ar", "p", str(deb), member])
    if member.endswith(".zst"):
        content = sp.check_output(["zstd", "-dc"], input=content)
    with tarfile.open(fileobj=BytesIO(content), mode="r:*") as archive:
        result = {}
        for name in sonames:
            candidates = [item for item in archive.getmembers()
                          if Path(item.name).name == name and (item.isfile() or item.issym())]
            regular = [item for item in candidates if item.isfile()]
            if regular:
                item, = regular
            else:
                link, = candidates
                assert not link.linkname.startswith("/") and "/" not in link.linkname
                resolved = Path(link.name).parent / link.linkname
                item, = [member for member in archive.getmembers() if Path(member.name) == resolved]
            assert item.isfile()
            dst = scratch / name
            dst.write_bytes(archive.extractfile(item).read())
            assert dynamic(dst)[1] == [name]
            result[name] = dst
        return result


def missing_names(graph, providers):
    return {name: sorted(deps - providers) for name, deps in graph.items() if deps - providers}


def missing_versions(requests, props):
    return {name: sorted(req - props[name][0]) for name, req in requests.items()
            if req - props[name][0]}


root_dynamic, _ = dynamic(TARGET)
_, root_versions = versions(TARGET)
assert root_versions.keys() == root_dynamic
print("node #115", TARGET_SHA)
suite_properties = {}
for suite, ssl_package, expected_root_gap in [("jammy", "libssl3", {"GLIBC_2.38", "GLIBC_2.39"}), ("noble", "libssl3t64", set())]:
    with TemporaryDirectory() as tmp:
        signed = release_packages(suite)
        print("verified archive signature", suite, SIGNER)
        providers = {}
        for package, suffix, names in [
            ("libc6", ".libc6.deb", ("libc.so.6", "libm.so.6", "ld-linux-x86-64.so.2")),
            ("libgcc-s1", ".libgcc.deb", ("libgcc_s.so.1",)),
            ("libstdc++6", ".libstdcxx.deb", ("libstdc++.so.6",)),
            (ssl_package, ".deb", ("libssl.so.3", "libcrypto.so.3")),
        ]:
            providers.update(extract(suite, package, suffix, names, signed, Path(tmp)))
        assert providers.keys() == root_dynamic
        graph = {name: dynamic(path)[0] for name, path in providers.items()}
        props = {name: versions(path) for name, path in providers.items()}
        suite_properties[suite] = props
        assert not missing_names(graph, providers.keys())
        print("internal provider edges", sum(map(len, graph.values())))
        for source, dependencies in sorted(graph.items()):
            _, requests = props[source]
            assert requests.keys() <= dependencies
            for dep in sorted(dependencies):
                required = requests.get(dep, set())
                absent = sorted(required - props[dep][0])
                assert not absent, (suite, source, dep, absent)
                print(source, "->", dep, f"{len(required)} required version nodes")
        gaps = missing_versions(root_versions, props)
        assert gaps == ({"libc.so.6": sorted(expected_root_gap)} if expected_root_gap else {})
        print("target root version gaps", gaps)
        # A candidate without the loader cannot satisfy the recorded dependency graph.
        incomplete = providers.keys() - {"ld-linux-x86-64.so.2"}
        missing = missing_names(graph, incomplete)
        assert missing and all(values == ["ld-linux-x86-64.so.2"] for values in missing.values())
        print("missing-interpreter control rejected", sorted(missing))

noble_cpp_requests = suite_properties["noble"]["libstdc++.so.6"][1]
cross_suite_gap = missing_versions(noble_cpp_requests, suite_properties["jammy"])
assert cross_suite_gap
print("Noble libstdc++ against Jammy provider set", cross_suite_gap)
