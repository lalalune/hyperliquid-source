"""Build and check the ordinary timeout-parent extension to retained fingerprints."""

from argparse import ArgumentParser
from importlib.util import module_from_spec, spec_from_file_location
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

PACKET = Path(__file__).resolve().parent
LINK = "3049035108cc416a3cb83fc6c8b8361fafd7f984"
PARENT = "3f1a007af8a16d5a9d3c3d185aa7ac88d1aaab72"
LINK_PACKET = "RE-017-node115-retained-decoded-fingerprint"
PARENT_PACKET = "RE-017-node115-replay-decoded-parent-link"


def require(condition, text):
    if not condition:
        raise ValueError(text)


def materialize(repo, scratch, commit, packet, names):
    folder = scratch / packet
    folder.mkdir()
    for name in names:
        path = f"{commit}:research/work-items/{packet}/{name}"
        (folder / name).write_bytes(subprocess.check_output(["git", "show", path], cwd=repo))
    return folder


def load(path, name):
    spec = spec_from_file_location(name, path)
    result = module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def prepare(repo, scratch):
    parents = materialize(repo, scratch, PARENT, PARENT_PACKET, ("anchors.tsv", "verify.py"))
    subprocess.run([sys.executable, "-B", parents / "verify.py", "--repo", str(repo)], check=True)
    sources = materialize(repo, scratch, LINK, LINK_PACKET, ("oracle.py", "probe.rs", "verify.py"))
    sys.path.insert(0, str(sources))
    old = load(sources / "verify.py", "existing_retained_verifier")
    oracle = load(sources / "oracle.py", "independent_variant_zero_oracle")
    subprocess.run(["git", "apply", "--recount", str(PACKET / "timeout-parent.patch")], cwd=sources, check=True)
    old.native(repo, scratch)
    return old.build(repo, scratch), oracle


def test(scratch, probe, oracle):
    artifacts, bytes_zero, digest_zero = oracle.fixture()
    left = scratch / "left.bin"
    right = scratch / "right.bin"

    def run(previous, following):
        left.write_bytes(previous)
        right.write_bytes(following)
        return json.loads(subprocess.check_output([probe, left, right]))

    direct = run(artifacts["previous.bin"], artifacts["next.bin"])
    require(direct["link_matches"] and direct["previous_variant_zero"] == bytes_zero.hex()
            and direct["expected_predecessor"] == digest_zero.hex(), "direct-quorum fixture regression")

    def certificate(fields, hash_byte):
        return b"".join(map(oracle.compact, fields)) + bytes([hash_byte] * 32) + b"\0"

    identity_inputs = (44, 38, 40)
    timeout, embedded_round, optional_round = identity_inputs
    embedded = certificate((5, 39, embedded_round, 4, 5), 0x61)
    optional = certificate((5, 40, optional_round, 4, 5), 0x62)
    prefix = bytes([0x33] * 20) + b"\0\0\x07"  # no header digests, epoch + 7 ns
    common = prefix + b"\x01" + oracle.compact(timeout) + embedded + b"\0"

    def next_wire(identity, predecessor):
        body = oracle.header(bytes([0x31] * 20), [], 0, 9, (5, 40, identity, 4, 5), predecessor)
        return oracle.wire(body)

    fingerprints = []
    for label, tail, incorrect_round in (
        ("embedded-only", b"\0", embedded_round),
        ("optional-quorum", b"\1" + optional, optional_round),
    ):
        body = common + tail
        expected = b"\0" + body
        independent = oracle.keccak.new(digest_bits=256, data=oracle.DOMAIN + expected).digest()
        fingerprints.append(independent)
        response = run(oracle.wire(body), next_wire(timeout + 1, independent))
        require(response["link_matches"] and response["expected_identity"] == 45
                and response["previous_variant_zero"] == expected.hex()
                and response["observed_predecessor"] == independent.hex(), f"wrong {label} projection")
        print(f"{label} wire_sha256={hashlib.sha256(oracle.wire(body)).hexdigest()} {json.dumps(response)}")
        wrong = run(oracle.wire(body), next_wire(incorrect_round + 1, independent))
        require(not wrong["link_matches"] and wrong["expected_predecessor"] == wrong["observed_predecessor"]
                and wrong["observed_identity"] == incorrect_round + 1, "used quorum round as timeout successor")
        print(f"rejected {label} quorum round {incorrect_round} as timeout successor basis")

    require(fingerprints[0] != fingerprints[1], "optional quorum did not enter canonical digest")
    missing_optional = run(oracle.wire(common + b"\1" + optional), next_wire(45, fingerprints[0]))
    require(not missing_optional["link_matches"] and missing_optional["expected_identity"] == 45,
            "retained fingerprint accepted a digest omitting its optional certificate")
    print("verified original direct fixture, both timeout branches and independent identity/fingerprint controls")


if __name__ == "__main__":
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    args = parser.parse_args()
    with TemporaryDirectory() as folder:
        scratch = Path(folder)
        probe, oracle = prepare(args.repo.resolve(), scratch)
        test(scratch, probe, oracle)
