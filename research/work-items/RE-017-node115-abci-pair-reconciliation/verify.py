"""Rerun the authenticated #115 export binding and paired receipt controls."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from reconcile import RAW_KIND, TARGET, reconcile


def write(path, rows, origin, **overrides):
    data = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows).encode()
    path.with_suffix(".jsonl").write_bytes(data)
    values = {
        "network": "fixture-mainnet",
        "target_sha256": TARGET,
        "digest_kind": RAW_KIND,
        "data": path.with_suffix(".jsonl").name,
        "data_sha256": hashlib.sha256(data).hexdigest(),
        "origin": origin,
    }
    path.write_text(json.dumps(values | overrides))


def main():
    repo = Path.cwd()
    subprocess.run(
        [sys.executable, "-B", "tools/abci_hashes_log_115.py", "--check"],
        cwd=repo,
        check=True,
    )
    print(f"PASS: writer authenticated against node #115 SHA-256 {TARGET}")
    h = 1191310000
    roots = ["0x" + "12" * 32, "0x" + "34" * 32]
    raw = [
        {"height": h + i, "abci_digest": word, "exchange_abci_hash": []}
        for i, word in enumerate(roots)
    ]
    observed = [
        {"height": h + i, "abci_digest": word, "stage": stage}
        for i, (word, stage) in enumerate(zip(roots, ("restored", "replayed")))
    ]
    with tempfile.TemporaryDirectory() as directory:
        reference = Path(directory) / "reference.json"
        observation = Path(directory) / "observation.json"

        def run():
            return [row["status"] for row in reconcile(
                h, "fixture-mainnet", reference, observation
            )["results"]]

        write(reference, raw, "synthetic source reference")
        write(observation, observed, "synthetic source replay")
        assert run() == ["match", "match"]
        write(observation, [observed[0], observed[1] | {"abci_digest": roots[0]}], "replay")
        assert run() == ["match", "mismatch"]
        write(observation, observed[:1], "replay")
        assert run() == ["match", "missing_observation"]
        write(observation, observed, "replay")
        write(reference, raw[:1], "reference")
        assert run() == ["match", "missing_reference"]
        print("PASS: two matched heights, independent H+1 mismatch and both missing-row branches")

        outcomes = [
            (raw, {"digest_kind": "linked_l1"}, "digest kind"),
            (raw, {"network": "other"}, "capture network"),
            (raw, {"target_sha256": "0" * 64}, "capture target"),
            (raw, {"data_sha256": "0" * 64}, "data SHA-256"),
            (raw, {"origin": "replay"}, "distinct captures"),
            (raw + [raw[1]], {}, "duplicate capture row"),
            ([raw[0], raw[1] | {"abci_digest": "0x00"}], {}, "raw 32-byte"),
        ]
        for rows, kwargs, expected in outcomes:
            origin = kwargs.pop("origin", "reference")
            write(reference, rows, origin, **kwargs)
            try:
                run()
            except ValueError as error:
                assert expected in str(error), (expected, error)
            else:
                raise AssertionError(expected)
        write(reference, raw, "reference")
        write(observation, [observed[0] | {"stage": "replayed"}, observed[1]], "replay")
        try:
            run()
        except ValueError as error:
            assert "unexpected offline stage" in str(error)
        else:
            raise AssertionError("swapped stage")
        print("PASS: target, network, raw-kind, artifact digest, origin, duplicate, width and stage controls")


if __name__ == "__main__":
    main()
