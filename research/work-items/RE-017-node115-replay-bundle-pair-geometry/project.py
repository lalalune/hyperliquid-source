"""Keep archive signed-bundle counts separate from nested action counts."""

from dataclasses import dataclass

U64_MAX = 2**64 - 1


@dataclass(frozen=True)
class BundleCounts:
    header_bundles: int
    payload_descriptors: int
    nested_signed_actions: int

    @property
    def aligned(self) -> bool:
        return self.header_bundles == self.payload_descriptors


def project_bundle_counts(block: dict, payload_descriptors: int) -> BundleCounts:
    """Compare the archive header with an independently acquired descriptor count."""
    if type(payload_descriptors) is not int or not 0 <= payload_descriptors <= U64_MAX:
        raise ValueError("payload descriptor count must be a u64")
    bundles = block.get("signed_action_bundles")
    if not isinstance(bundles, list):
        raise ValueError("signed_action_bundles must be an array")
    action_count = 0
    for index, entry in enumerate(bundles):
        if not isinstance(entry, list) or len(entry) != 2 or not isinstance(entry[1], dict):
            raise ValueError(f"bundle {index} must be a two-element array with an object payload")
        actions = entry[1].get("signed_actions")
        if not isinstance(actions, list):
            raise ValueError(f"bundle {index} signed_actions must be an array")
        action_count += len(actions)
    return BundleCounts(len(bundles), payload_descriptors, action_count)
