"""Holds any aliases for deprecated functions or classes."""
import warnings
from typing import Iterable, List

from policyglass.policy_shard import PolicyShard, dedupe_policy_shards


def delineate_intersecting_shards(shards: Iterable[PolicyShard], check_reverse: bool = True) -> List["PolicyShard"]:
    """Alias dedupe_policy_shards.

    Parameters:
        shards: The shards to deduplicate.
        check_reverse: Whether you want to check these shards in reverse as well (only disabled when calling itself).
    """
    warnings.warn(
        "delineate_intersecting_shards is deprecated and will be removed in v1. "
        "Please use dedupe_policy_shards instead",
        DeprecationWarning,
    )
    return dedupe_policy_shards(shards=shards)
