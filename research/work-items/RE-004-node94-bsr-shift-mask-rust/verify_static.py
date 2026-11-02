"""Reach structural predicates with corrupted in-memory bytes, never run them."""
import json
from oracle import PACKET, TARGET, admit, structure, require


def check():
    frozen = json.loads((PACKET / "frozen/ORACLE-FREEZE.json").read_text())
    current = admit()
    require(current == frozen["static_facts"], "Static evidence changed")
    facts = current["structure"]
    locations = {"body_mask": facts["body_file_offset"] + 0x35,
                 "fde_extent": facts["frames"][0]["file_offset"] + 12,
                 "cie_encoding": facts["cie_file_offset"] + 15,
                 "padding": facts["padding_file_offset"] + 5}
    locations.update({"call_" + caller["call_va"]: caller["call_file_offset"] + 1
                      for caller in facts["callers"]})
    data = TARGET.read_bytes()
    rejected = {}
    for label, offset in locations.items():
        changed = bytearray(data)
        changed[offset] ^= 1
        try:
            found = structure(changed)
            require(found == facts, "Structural record changed")
        except ValueError as error:
            rejected[label] = str(error)
        else:
            raise ValueError("Accepted corruption: " + label)
    return {"target_sha256": current["target_sha256"], "body_bytes": 66,
            "callers_checked": 2, "structural_controls_rejected": rejected,
            "whole_digest_gate_bypassed_for_controls": True,
            "captured_binary_executed": False}


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
