"""Digest and complete structural checks with downstream corruption controls."""
import hashlib
import json
import oracle


def check():
    original = oracle.prior.TARGET.read_bytes()
    facts = oracle.admit()
    frozen = json.loads((oracle.PACKET / "frozen/ORACLE-FREEZE.json").read_text())
    oracle.require(facts == frozen["static_facts"], "Frozen static facts changed")
    secs, offset = oracle.mapping(original)
    eh = next(s for s in secs if s["name"] == ".eh_frame")["address"]
    cases = {
        "unsigned_first_threshold": 0x55716a7,
        "unsigned_second_threshold": 0x55716cb,
        "third_path_header_width": 0x55716e1,
        "first_path_payload_load": 0x55716be,
        "third_path_payload_offset": 0x55716d5,
        "last_return": 0x5571709,
        "padding": 0x557170a,
        "fde_extent": eh + 0x2d14c4 + 12,
        "cie_encoding": eh + 17,
        "caller_edge": 0x5573e2c,
        "caller_body_beyond_excerpt": 0x55739f1,
    }
    controls = {}
    for label, address in cases.items():
        changed = bytearray(original)
        changed[offset(address, 1)] ^= 1
        try:
            oracle.structure(changed)  # Bypass only full-target SHA, not structure.
        except ValueError as error:
            controls[label] = {"va": hex(address), "rejected": str(error)}
        else:
            raise ValueError(f"Structural corruption was accepted: {label}")
    altered = bytearray(original)
    altered[-1] ^= 1
    oracle.require(hashlib.sha256(altered).hexdigest() != oracle.prior.SHA256, "Identity control failed")
    return {"target_sha256": oracle.prior.SHA256, "leaf_instructions": len(facts["leaf"]),
            "caller_instructions": len(facts["caller"]), "structural_controls": controls,
            "identity_digest_changed": True, "captured_execution": False}


if __name__ == "__main__":
    print(json.dumps(check(), indent=2))
