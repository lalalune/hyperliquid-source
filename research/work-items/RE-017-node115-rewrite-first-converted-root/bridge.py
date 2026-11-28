"""Carry the selected local-startup pair rewrite into first-conversion checks."""

import hashlib
from struct import unpack_from


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(manifest, digest, scratch, startup, rewrite_local, sequence, wire_case, kit, cursor,
        decoder, compare_case, hash_bytes, helper):
    begin = kit["begin"]
    spec = begin.pinned_json(manifest, digest)
    external = (wire_case.ROLES - {"wire"}) | {"height", "records", "compact_image"}
    require(set(spec) == external, "wrong local startup fixture roles")
    height = begin.u64(spec["height"], "checkpoint height")
    require(height < (1 << 64) - 1, "no representable H+1 fixture")

    def artifact(role):
        item = spec[role]
        require(isinstance(item, dict) and set(item) == {"path", "sha256"}, f"invalid {role} declaration")
        return (manifest.parent / item["path"]).resolve(), item["sha256"]

    checkpoint, checkpoint_sha = artifact("checkpoint_rmp")
    fields = startup.read_checkpoint(checkpoint, checkpoint_sha, height)
    stored = kit["messagepack"].project_rmp(checkpoint, checkpoint_sha, height, kit["normalizer"])
    compact, image_sha = artifact("compact_image")
    image = compact.read_bytes()
    material = rewrite_local(image, image_sha, height)
    context_round = unpack_from("<Q", image, 0x30)[0]
    tag = unpack_from("<I", image, 0x10e8)[0]
    freeze = None if tag == 0 else unpack_from("<Q", image, 0x10f0)[0]
    require(material.original_pair == (fields["hardfork_version"], fields["hardfork_round"]),
            "compact original hardfork differs from named checkpoint")
    require(context_round == stored["round"], "compact Context round differs from checkpoint")
    require(freeze == fields["scheduled_freeze"], "compact freeze option differs from named checkpoint")

    archive, archive_sha = artifact("archive")
    block = begin.pinned_json(archive, archive_sha)["abci_block"]
    pair = tuple(begin.u64(block["hardfork"][key], key) for key in ("version", "round"))
    require(pair == material.replay_pair, "archive hardfork pair differs from materialized replay pair")
    sequence_input = {"height": height, "restored_round": context_round, "ordered_pair": material.replay_pair}
    for role in wire_case.ROLES - {"wire"}:
        path, sha = artifact(role)
        sequence_input[role] = {"path": str(path), "sha256": sha}
    require(isinstance(spec["records"], list), "expected ordered records")
    sequence_input["records"] = []
    for record in spec["records"]:
        require(isinstance(record, dict) and set(record) == {"path", "sha256", "prepared_count"},
                "invalid replay record declaration")
        sequence_input["records"].append({**record, "path": str((manifest.parent / record["path"]).resolve())})
    adapter = wire_case.save_json(scratch, "startup-aware-sequence.json", sequence_input)
    compared = sequence(scratch / adapter["path"], adapter["sha256"], scratch,
                        wire_case, kit, cursor, decoder, compare_case, helper)

    tree = kit["tree"]
    reference_sha, reference = tree.read_export(*artifact("reference_h_plus_one"), height + 1)
    require(reference_sha == tree.digest(helper, reference), "H+1 reference digest mismatch")
    subtree = tree.at_path(reference, (0, 0, 1))
    require(tuple(item[0] for item in subtree) == (0, 1), "invalid hardfork subtree order")
    expected = [bytes.fromhex(hash_bytes(helper, tree, word.to_bytes(8, "little"))[2:])
                for word in material.replay_pair]
    matches = {key: subtree[index][1] == expected[index]
               for index, key in enumerate(("version", "round"))}
    return {
        "original_hardfork_pair": material.original_pair,
        "materialized_replay_pair": material.replay_pair,
        "restored_context_round": context_round,
        "scheduled_freeze_height": freeze,
        "rewritten": material.rewritten,
        "materialized_image_sha256": hashlib.sha256(material.image).hexdigest(),
        "successor_hardfork": matches,
        "selected_checks_pass": compared["selected_root_comparison"]["selected_checks_pass"]
        and all(matches.values()),
        **compared,
    }
