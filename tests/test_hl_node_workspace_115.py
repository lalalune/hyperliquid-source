from __future__ import annotations

import pathlib
import tomllib
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
HL_NODE_DIR = REPO_ROOT / "src" / "hl-node"
CARGO_TOML = HL_NODE_DIR / "Cargo.toml"
CARGO_LOCK = HL_NODE_DIR / "Cargo.lock"
DOCKERFILE = HL_NODE_DIR / "Dockerfile"
CLI_RS = HL_NODE_DIR / "src" / "cli.rs"

EXPECTED_SUBCOMMANDS = [
    "run-non-validator",
    "run-validator",
    "print-address",
    "approve-non-expiring-agent",
    "translate-abci-state",
    "send-signed-action",
    "delegate",
    "staking-deposit",
    "staking-withdrawal",
    "send-slack-alert",
    "check-reachability",
    "compute-referrer-states",
    "compute-l4-snapshots",
    "change-validator-profile",
]


class TestHlNodeWorkspace115(unittest.TestCase):
    def test_cargo_manifest_is_offline_zero_external_deps_with_overflow_checks(self) -> None:
        manifest = tomllib.loads(CARGO_TOML.read_text(encoding="utf-8"))
        self.assertIn("workspace", manifest)
        self.assertEqual(manifest["package"]["name"], "hl-node")

        deps = manifest["dependencies"]
        self.assertGreaterEqual(len(deps), 24)
        for name, spec in deps.items():
            self.assertIsInstance(spec, dict, f"dependency {name} must be a path table")
            self.assertIn("path", spec, f"dependency {name} must be a local path dependency")
            self.assertNotIn("version", spec, f"dependency {name} must not pull crates.io")
            dep_dir = (HL_NODE_DIR / spec["path"]).resolve()
            self.assertTrue((dep_dir / "Cargo.toml").is_file(), f"missing dep manifest {dep_dir}")

        release = manifest["profile"]["release"]
        self.assertTrue(release["overflow-checks"])
        self.assertEqual(release["opt-level"], 3)
        self.assertEqual(release["panic"], "unwind")

    def test_cargo_lock_has_zero_external_sources(self) -> None:
        lock = tomllib.loads(CARGO_LOCK.read_text(encoding="utf-8"))
        packages = lock.get("package", [])
        self.assertGreaterEqual(len(packages), 200)
        for pkg in packages:
            self.assertNotIn(
                "source",
                pkg,
                f"package {pkg.get('name')} must not reference an external registry/git source",
            )

    def test_dockerfile_is_pinned_linux_amd64_source_build_and_unprivileged(self) -> None:
        text = DOCKERFILE.read_text(encoding="utf-8")
        self.assertIn("FROM --platform=linux/amd64 rust:1.95.0-bookworm AS builder", text)
        self.assertIn("FROM --platform=linux/amd64 ubuntu:24.04 AS runtime", text)
        self.assertIn("--offline", text)
        self.assertIn("--locked", text)
        self.assertIn("--release", text)
        self.assertIn("USER \"${USERNAME}\"", text)
        self.assertIn("VOLUME [\"/home/hluser/hl/data\"]", text)
        self.assertIn("HEALTHCHECK", text)
        self.assertIn("ENTRYPOINT [\"/usr/local/bin/hl-node\"]", text)
        # Never download proprietary binaries in Dockerfile
        for forbidden in ("curl ", "wget ", "binaries.hyperliquid", "hyperliquid-dex"):
            self.assertNotIn(forbidden, text)

    def test_cli_covers_all_14_node115_subcommands(self) -> None:
        text = CLI_RS.read_text(encoding="utf-8")
        for sub in EXPECTED_SUBCOMMANDS:
            self.assertIn(f'"{sub}"', text, f"missing node #115 subcommand {sub}")
        self.assertIn("serve-eth-rpc", text)
        self.assertIn("serve-evm-rpc", text)


if __name__ == "__main__":
    unittest.main()
