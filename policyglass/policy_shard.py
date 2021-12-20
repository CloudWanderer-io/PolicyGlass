"""PolicyShards are a simplified representation of policies."""

import json
from typing import Any, Dict, FrozenSet, List, Optional

from pydantic import BaseModel

from .action import Action
from .condition import Condition
from .effective_arp import EffectiveARP
from .principal import Principal
from .resource import Resource


def dedupe_policy_shards(shards: List["PolicyShard"]) -> List["PolicyShard"]:
    """Dedupe policy shards that are subsets of each other.

    Parameters:
        shards: The shards to deduplicate.
    """
    deduped_shards: List[PolicyShard] = []
    for undeduped_shard in shards:
        if any(undeduped_shard.issubset(deduped_shard) for deduped_shard in deduped_shards):
            continue

        deduped_shards.append(undeduped_shard)

    return deduped_shards


def policy_shards_effect(shards: List["PolicyShard"]) -> List["PolicyShard"]:
    """Calculate the effect of merging allow and deny shards together.

    Parameters:
        shards: The shards to caclulate the effect of.
    """
    allow_shards = [shard for shard in shards if shard.effect == "Allow"]
    deny_shards = [shard for shard in shards if shard.effect == "Deny"]

    # This code is ugly because DIFFERENCE takes in a single shard and yields a list of them.
    merged_allow_shards = []
    for allow_shard in allow_shards:
        allow_candidates = [allow_shard]
        for deny_shard in deny_shards:
            result = []
            for allow_candidate in allow_candidates:
                result.extend(allow_candidate.difference(deny_shard))
            allow_candidates = result
        if allow_candidates:
            merged_allow_shards.extend(allow_candidates)
    return merged_allow_shards


def policy_shards_to_json(shards: List["PolicyShard"], exclude_defaults=False, **kwargs) -> str:
    """Convert a list of :class:`awspolicy.policy_shard.PolicyShard` objects to JSON.

    Parameters:
        shards: The list of shards to convert.
        exclude_defaults: Whether to exclude default values (e.g. empty lists) from the output.
        **kwargs: keyword arguments passed on to :func:`json.dumps`
    """
    return json.dumps([json.loads(shard.json(exclude_defaults=exclude_defaults)) for shard in shards], **kwargs)


class PolicyShard(BaseModel):
    """A PolicyShard is part of a policy broken down in such a way that it can be deduplicated and collapsed."""

    effect: str
    effective_action: EffectiveARP[Action]
    effective_resource: EffectiveARP[Resource]
    effective_principal: EffectiveARP[Principal]
    conditions: FrozenSet[Condition]
    not_conditions: FrozenSet[Condition]

    def __init__(
        self,
        effect: str,
        effective_action: EffectiveARP[Action],
        effective_resource: EffectiveARP[Resource],
        effective_principal: EffectiveARP[Principal],
        conditions: Optional[FrozenSet[Condition]] = None,
        not_conditions: Optional[FrozenSet[Condition]] = None,
    ) -> None:
        super().__init__(
            effect=effect,
            effective_action=effective_action,
            effective_resource=effective_resource,
            effective_principal=effective_principal,
            conditions=conditions or frozenset(),
            not_conditions=not_conditions or frozenset(),
        )

    def union(self, other: object) -> List["PolicyShard"]:
        """Combine this object with another object of the same type.

        Parameters:
            other: The object to combine with this one.

        Raises:
            ValueError: If ``other`` is not the same type as this object.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot union {self.__class__.__name__} with {other.__class__.__name__}")
        if not self.conditions == other.conditions:
            return [self, other]

        return [
            self.__class__(
                effect=self.effect,
                effective_action=effective_action,
                effective_resource=effective_resource,
                effective_principal=effective_principal,
                conditions=self.conditions,
            )
            for effective_action in self.effective_action.union(other.effective_action)
            for effective_resource in self.effective_resource.union(other.effective_resource)
            for effective_principal in self.effective_principal.union(other.effective_principal)
        ]

    def difference(self, other: object) -> List["PolicyShard"]:
        """Calculate the difference between this and another object of the same type.

        Effectively subtracts the inclusions of ``other`` from ``self``.
        This is useful when applying denies (``other``) to allows (``self``).

        Parameters:
            other: The object to subtract from this one.

        Raises:
            ValueError: If ``other`` is not the same type as this object.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot diff {self.__class__.__name__} with {other.__class__.__name__}")

        intersection_action = self.effective_action.intersection(other.effective_action)
        intersection_resource = self.effective_resource.intersection(other.effective_resource)
        intersection_principal = self.effective_principal.intersection(other.effective_principal)

        if not intersection_action or not intersection_resource or not intersection_principal:
            # Shards do not overlap
            return [self]

        effective_actions = self.effective_action.difference(other.effective_action)
        effective_resources = self.effective_resource.difference(other.effective_resource)
        effective_principals = self.effective_principal.difference(other.effective_principal)

        if not effective_actions and not effective_resources and not effective_principals:
            # Shards overlap wholly
            return []

        result = [
            self.__class__(
                effect=self.effect,
                effective_action=effective_action,
                effective_resource=effective_resource,
                effective_principal=effective_principal,
                conditions=self.conditions,
                not_conditions=self.not_conditions,
            )
            for effective_action in effective_actions or [self.effective_action]
            for effective_resource in effective_resources or [self.effective_resource]
            for effective_principal in effective_principals or [self.effective_principal]
        ]

        if self.conditions != other.conditions:
            # If the conditions differ return the intersection of the two shards back into the result.
            # This results in an uncomplicated difference (already in the result) with a conditional intersection.
            result.append(
                self.__class__(
                    effect=self.effect,
                    effective_action=intersection_action,
                    effective_resource=intersection_resource,
                    effective_principal=intersection_principal,
                    conditions=self.conditions,
                    not_conditions=other.conditions,
                )
            )
        return result

    def issubset(self, other: object) -> bool:
        """Whether this object contains all the elements of another object (i.e. is a subset of the other object).

        Parameters:
            other: The object to determine if our object contains.

        Raises:
            ValueError: If the other object is not of the same type as this object.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot compare {self.__class__.__name__} and {other.__class__.__name__}")

        return (
            self.effective_action.issubset(other.effective_action)
            and self.effective_resource.issubset(other.effective_resource)
            and self.effective_principal.issubset(other.effective_principal)
            and self.conditions == other.conditions
            and self.not_conditions == other.not_conditions
            and self.effect == other.effect
        )

    def dict(self, *args, **kwargs) -> Dict[str, Any]:
        """Convert instance to dict representation of it.

        Parameters:
            *args: Arguments to Pydantic dict method.
            **kwargs: Arguments to Pydantic dict method.

        Overridden from BaseModel so that when converting conditions to dict they don't suffer from being unhashable
        when placed in a set.
        """
        result = {}
        for attribute_name, attribute_value in self:
            if hasattr(attribute_value, "dict"):
                result[attribute_name] = attribute_value.dict(*args, **kwargs)
            elif isinstance(attribute_value, (set, frozenset)):
                value = list(attribute_value)
                if not kwargs.get("exclude_defaults") or value != []:
                    result[attribute_name] = value

        return result

    @property
    def explain(self) -> str:
        """Return a plain English representation of the policy shard.

        Example:
            Simple PolicyShard explain.

                >>> from policyglass import Policy
                >>> policy = Policy(**{"Statement": [{"Effect": "Allow", "Action": "s3:*"}]})
                >>> print([shard.explain for shard in policy.policy_shards])
                ['Allow action s3:* on resource * with principal AWS *']
        """
        result = f"{self.effect} action {self.effective_action.inclusion} "
        if self.effective_action.exclusions:
            result += f"(except for {', '.join(self.effective_action.exclusions)}) "
        result += f"on resource {self.effective_resource.inclusion} "
        if self.effective_resource.exclusions:
            result += f"(except for {', '.join(self.effective_resource.exclusions)}) "
        result += f"with principal {self.effective_principal.inclusion} "
        if self.effective_principal.exclusions:
            principal_exclusions = ", ".join([str(principal) for principal in self.effective_principal.exclusions])
            result += f"(except principals {principal_exclusions}). "
        if self.conditions:
            conditions = " and ".join([str(condition) for condition in self.conditions])
            result += f"Provided conditions {conditions} are met. "
        if self.not_conditions:
            not_conditions = " and ".join([str(condition) for condition in self.not_conditions])
            result += f"Unless conditions {not_conditions} are met. "
        return result.strip()

    def __repr__(self) -> str:
        """Return an instantiable representation of this object."""
        return (
            f"{self.__class__.__name__}(effect='{self.effect}', "
            f"effective_action={self.effective_action}, "
            f"effective_resource={self.effective_resource}, "
            f"effective_principal={self.effective_principal}, "
            f"conditions={self.conditions}, "
            f"not_conditions={self.not_conditions})"
        )

    def __str__(self) -> str:
        """Return a stringy representation of this object."""
        return repr(self)

    def __eq__(self, other: object) -> bool:
        """Determine whether this object and another object are equal.

        Parameters:
            other: The object to compare this one to.

        Raises:
            ValueError: When the object we are compared with is not of the same type.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot compare {self.__class__.__name__} and {other.__class__.__name__}")
        return (
            self.effective_action == other.effective_action
            and self.effective_resource == other.effective_resource
            and self.effective_principal == other.effective_principal
            and self.conditions == other.conditions
        )
