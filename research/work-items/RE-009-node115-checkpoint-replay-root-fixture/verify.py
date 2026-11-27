#!/usr/bin/env python3
"""Offline verifier for RE-009-node115-checkpoint-replay-root-fixture.

Connects all four reviewed node #115 pilot contracts into one synthetic,
SHA-256-hashed offline fixture:
  - qcp-first-replay-key (RE-017-node115-replay-key-source)
  - qcp-expected-root-provenance (RE-009-node115-expected-root-provenance)
  - qcp-root-selector (RE-009-node115-root-digest-selector)
  - qcp-root-cell-writer (RE-009-node115-root-digest-cell-writer)

Does not execute any captured binary and does not advance full component gates.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET_DIR = Path(__file__).resolve().parent
FIXTURE_PATH = PACKET_DIR / "fixture.json"

TARGET_REL = "artifacts/node/115/hl-node"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
VOTE_HEIGHT_LIMIT = 0x0CCCCCCCCCCCCCCC

PREREQUISITE_PACKETS = [
    ("qcp-first-replay-key", "research/work-items/RE-017-node115-replay-key-source"),
    ("qcp-expected-root-provenance", "research/work-items/RE-009-node115-expected-root-provenance"),
    ("qcp-root-selector", "research/work-items/RE-009-node115-root-digest-selector"),
    ("qcp-root-cell-writer", "research/work-items/RE-009-node115-root-digest-cell-writer"),
]


def canonical_sha256(obj) -> str:
    payload = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def verify_target(target_path: Path) -> None:
    digest = hashlib.sha256(target_path.read_bytes()).hexdigest()
    if digest != TARGET_SHA256:
        raise ValueError(f"target sha256 mismatch: {digest} != {TARGET_SHA256}")


def verify_prerequisites(root: Path) -> dict:
    manifests = {}
    for qid, rel in PREREQUISITE_PACKETS:
        pdir = root / rel
        manifest_path = pdir / "MANIFEST.sha256"
        if not manifest_path.is_file():
            raise ValueError(f"missing prerequisite manifest for {qid}: {rel}")
        checked = 0
        for line in manifest_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            expected_hex, filename = line.split(None, 1)
            filename = filename.lstrip("*")
            actual_hex = hashlib.sha256((pdir / filename).read_bytes()).hexdigest()
            if actual_hex != expected_hex:
                raise ValueError(f"prerequisite {qid} manifest mismatch on {filename}")
            checked += 1
        manifests[qid] = {"packet": rel, "manifest_entries": checked}
    return manifests


def select_root_impl_model(cell_words: list[int], fallback_r13: int, fallback_rdi: int, fallback_rdx: int) -> tuple[int, list[int], int]:
    words = list(cell_words)
    fallbacks = 0

    def next_word() -> int:
        nonlocal fallbacks
        if words[0] == 0:
            fallbacks += 1
            words[0] = fallback_r13 | fallback_rdi
            words[1] = fallback_rdx | fallback_r13
            words[2] = fallback_rdx | fallback_rdi
            return fallback_r13
        return words[0]

    w0 = next_word()
    if (w0 >> 19) & 1:
        w1 = next_word()
        if (w1 >> 25) & 1:
            return 4, words, fallbacks
    w2 = next_word()
    if (w2 >> 15) & 1:
        return 3, words, fallbacks
    w3 = next_word()
    return 1 + ((w3 >> 10) & 1), words, fallbacks


def simulate_fixture(inputs: dict) -> dict:
    # 1. Checkpoint restore (qcp-first-replay-key)
    ckpt = inputs["checkpoint"]
    if ckpt["persisted_height"] != ckpt["requested_height"]:
        raise ValueError("checkpoint height mismatch")
    height = ckpt["persisted_height"]
    round_num = ckpt["persisted_round"]
    loader_seq = min(ckpt["persisted_seq"] + 1, (1 << 64) - 1)
    copied_round = round_num

    # 2. First replay block H -> H+1 (0x54838d3..0x54838f1) + local root selector (0x160bee0 / 0x5cadd50)
    b1 = inputs["first_replay_block"]
    if not (b1["new_round"] > b1["prev_round"] and b1["prev_round"] == round_num):
        raise ValueError("block 1 round continuity violated")
    if b1["expected_loader_seq"] != loader_seq or b1["expected_copied_round"] != copied_round:
        raise ValueError("block 1 loader seq/round mismatch")
    height = min(height + 1, (1 << 64) - 1)
    round_num = b1["new_round"]

    sel_in = inputs["root_selector_input"]
    selector_byte, post_cell, fallback_calls = select_root_impl_model(
        sel_in["initial_cell_words"],
        sel_in["fallback_r13"],
        sel_in["fallback_rdi"],
        sel_in["fallback_rdx"],
    )
    local_history = {height: b1["synthetic_local_root_hex"]}

    # 3. Second block: external 0xdd votes -> two-gate support -> drain -> compare (qcp-expected-root-provenance)
    b2 = inputs["vote_replay_block"]
    if not (b2["new_round"] > b2["prev_round"] and b2["prev_round"] == round_num):
        raise ValueError("block 2 round continuity violated")
    height = min(height + 1, (1 << 64) - 1)
    round_num = b2["new_round"]

    sup = inputs["support_context"]
    weights_32 = sup["weights_32"]
    total_weight = sum(weights_32.values())
    eligible_20 = set(sup["eligible_20"])
    fraction_20 = float(sup["fraction_20"])
    stored_total_20 = int(sup["stored_total_20"])
    registry = inputs["registry"]

    selected_by_height = {}
    candidates = {}
    pending = set()

    for vote in b2["external_votes"]:
        if vote["provenance"] != "external_action_0xdd_synthetic":
            raise ValueError("expected-root vote missing explicit external provenance")
        vh = vote["height"]
        if vh >= VOTE_HEIGHT_LIMIT:
            continue
        vd = vote["digest_hex"]
        if vh in selected_by_height and selected_by_height[vh] != vd:
            continue
        cand = candidates.setdefault((vh, vd), {"k32": set(), "k20": set()})

        def supports_now(c) -> bool:
            sel_w = sum(weights_32[k] for k in c["k32"] if k in weights_32)
            if 3 * sel_w <= 2 * total_weight:
                return False
            if fraction_20 == 0.0:
                return True
            matched = sum(1 for k in c["k20"] if k in eligible_20)
            return float(matched) > fraction_20 * float(stored_total_20)

        before = (vh in selected_by_height) or supports_now(cand)
        if vote.get("voter_32_eligible"):
            cand["k32"].add(vote["voter_32"])
        if vote.get("voter_20_eligible"):
            cand["k20"].add(vote["voter_20"])
        if not before and supports_now(cand):
            selected_by_height[vh] = vd
            pending.add(vh)

    drained = []
    for th in b2["timer_eligible_heights"]:
        if th in pending and th in selected_by_height:
            sel_d = selected_by_height[th]
            k32s = candidates[(th, sel_d)]["k32"]
            members = sorted({registry[k] for k in k32s if k in registry})
            if members:
                drained.append({"height": th, "digest_hex": sel_d, "members": members})
            pending.remove(th)

    sink_pairs = [[r["height"], r["digest_hex"]] for r in drained]
    comparisons = []
    for r in drained:
        local = local_history.get(r["height"])
        if local is None:
            status = "missing_local"
        elif local == r["digest_hex"]:
            status = "equal"
        else:
            status = "mismatch"
        comparisons.append({
            "height": r["height"],
            "incoming": r["digest_hex"],
            "local": local,
            "status": status,
        })
        if status == "mismatch":
            break

    return {
        "restored_height": ckpt["persisted_height"],
        "first_replay_height": ckpt["persisted_height"] + 1,
        "post_block2_height": height,
        "selector_byte": selector_byte,
        "post_selector_cell": post_cell,
        "fallback_calls": fallback_calls,
        "sink_pairs": sink_pairs,
        "comparisons": comparisons,
    }


def build_fixture() -> dict:
    local_root_h1 = "5a" * 32
    inputs = {
        "checkpoint": {
            "provenance": "synthetic_offline_checkpoint_fixture",
            "requested_height": 1_000_000,
            "persisted_height": 1_000_000,
            "persisted_round": 1_000_050,
            "persisted_seq": 9,
            "completion_marker": "CHECKPOINT_COMPLETE",
        },
        "first_replay_block": {
            "provenance": "synthetic_offline_replay_block_h_plus_1",
            "prev_round": 1_000_050,
            "new_round": 1_000_051,
            "expected_loader_seq": 10,
            "expected_copied_round": 1_000_050,
            "synthetic_local_root_hex": local_root_h1,
            "local_root_provenance": "local_post_comparison_ctx_0x400",
        },
        "root_selector_input": {
            "provenance": "synthetic_offline_selector_cell_0x6500098",
            "initial_cell_words": [0, 0, 0],
            "fallback_r13": (1 << 19) | (1 << 25),
            "fallback_rdi": 0,
            "fallback_rdx": 0,
        },
        "support_context": {
            "provenance": "synthetic_offline_support_context",
            "weights_32": {"11" * 32: 40, "22" * 32: 35, "33" * 32: 25},
            "fraction_20": 0.5,
            "eligible_20": ["a1" * 20, "b2" * 20, "c3" * 20],
            "stored_total_20": 3,
        },
        "registry": {
            "11" * 32: "a1" * 20,
            "22" * 32: "b2" * 20,
            "33" * 32: "c3" * 20,
        },
        "vote_replay_block": {
            "provenance": "synthetic_offline_replay_block_with_external_0xdd_votes",
            "prev_round": 1_000_051,
            "new_round": 1_000_052,
            "timer_eligible_heights": [1_000_001],
            "external_votes": [
                {
                    "provenance": "external_action_0xdd_synthetic",
                    "action_tag": "0xdd",
                    "height": 1_000_001,
                    "digest_hex": local_root_h1,
                    "voter_32": "11" * 32,
                    "voter_32_eligible": True,
                    "voter_20": "a1" * 20,
                    "voter_20_eligible": True,
                },
                {
                    "provenance": "external_action_0xdd_synthetic",
                    "action_tag": "0xdd",
                    "height": 1_000_001,
                    "digest_hex": local_root_h1,
                    "voter_32": "22" * 32,
                    "voter_32_eligible": True,
                    "voter_20": "b2" * 20,
                    "voter_20_eligible": True,
                },
            ],
        },
    }
    input_hashes = {name: canonical_sha256(val) for name, val in inputs.items()}
    expected = simulate_fixture(inputs)
    return {
        "schema_version": 1,
        "target": {"path": TARGET_REL, "sha256": TARGET_SHA256},
        "prerequisites": [q for q, _ in PREREQUISITE_PACKETS],
        "inputs": inputs,
        "input_sha256": input_hashes,
        "expected_observation": expected,
        "unresolved_boundaries": [
            "ECDSA signature recovery internals behind slot 0x64e0ad8",
            "Timer delay duration population at tracker+0x88 and alternate flat timer route 0x57f1690",
            "CPUID feature bit semantics and concurrent access to .bss cell 0x6500098",
            "Live-chain canonical root authority, captured binary execution, and full storage/abci component gates",
        ],
    }


def verify_fixture_doc(doc: dict) -> dict:
    if doc["target"]["path"] != TARGET_REL or doc["target"]["sha256"] != TARGET_SHA256:
        raise ValueError("fixture target binding mismatch")
    for name, val in doc["inputs"].items():
        actual = canonical_sha256(val)
        if doc["input_sha256"].get(name) != actual:
            raise ValueError(f"input hash mismatch for {name}: {actual} != {doc['input_sha256'].get(name)}")
    actual_obs = simulate_fixture(doc["inputs"])
    if actual_obs != doc["expected_observation"]:
        raise ValueError(f"observed fixture result mismatch: {actual_obs} != {doc['expected_observation']}")
    return actual_obs


def run_negative_controls(doc: dict) -> int:
    def clone():
        return json.loads(json.dumps(doc))

    rejected = 0

    # 1. Corrupted input hash must fail authentication
    c1 = clone()
    c1["inputs"]["checkpoint"]["persisted_round"] += 1
    try:
        verify_fixture_doc(c1)
        raise AssertionError("corrupted input hash passed")
    except ValueError:
        rejected += 1

    # 2. Single-bit altered external digest produces mismatch (not equal)
    c2 = clone()
    bad_digest = "5a" * 31 + "5b"
    for v in c2["inputs"]["vote_replay_block"]["external_votes"]:
        v["digest_hex"] = bad_digest
    obs2 = simulate_fixture(c2["inputs"])
    if obs2["comparisons"][0]["status"] != "mismatch":
        raise AssertionError("single-bit flip did not produce mismatch")
    rejected += 1

    # 3. Pre-quorum vote only (40/100 weight, 1/3 count) must not drain any row
    c3 = clone()
    c3["inputs"]["vote_replay_block"]["external_votes"] = c3["inputs"]["vote_replay_block"]["external_votes"][:1]
    obs3 = simulate_fixture(c3["inputs"])
    if obs3["comparisons"] != []:
        raise AssertionError("pre-quorum vote unexpectedly drained")
    rejected += 1

    # 4. Missing external provenance label must be rejected
    c4 = clone()
    c4["inputs"]["vote_replay_block"]["external_votes"][0]["provenance"] = "local_post_comparison_ctx_0x400"
    try:
        simulate_fixture(c4["inputs"])
        raise AssertionError("local provenance conflation passed")
    except ValueError:
        rejected += 1

    # 5. Non-advancing round must be rejected
    c5 = clone()
    c5["inputs"]["first_replay_block"]["new_round"] = c5["inputs"]["first_replay_block"]["prev_round"]
    try:
        simulate_fixture(c5["inputs"])
        raise AssertionError("non-advancing round passed")
    except ValueError:
        rejected += 1

    return rejected


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=ROOT / TARGET_REL)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    verify_target(args.target)
    prereqs = verify_prerequisites(ROOT)
    doc = build_fixture() if args.write or not FIXTURE_PATH.is_file() else json.loads(FIXTURE_PATH.read_text())
    obs = verify_fixture_doc(doc)
    if args.write:
        FIXTURE_PATH.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    rejected = run_negative_controls(doc)
    print(
        f"RE-009-node115-checkpoint-replay-root-fixture verified: "
        f"{len(prereqs)}/4 prerequisite manifests valid, "
        f"{len(doc['input_sha256'])} hashed synthetic inputs, "
        f"selector={obs['selector_byte']}, comparison={obs['comparisons'][0]['status']}, "
        f"{rejected}/{rejected} negative controls verified."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
