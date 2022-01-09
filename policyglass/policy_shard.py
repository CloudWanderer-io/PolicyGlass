"""PolicyShards are a simplified representation of policies."""

import json
from typing import Any, DefaultDict, Dict, Iterable, Iterator, List, Optional, Tuple

from pydantic import BaseModel

from .action import Action, EffectiveAction
from .condition import EffectiveCondition
from .effective_arp import EffectiveARP
from .principal import EffectivePrincipal, Principal
from .resource import EffectiveResource, Resource


def dedupe_policy_shard_subsets(shards: Iterable["PolicyShard"], check_reverse: bool = True) -> List["PolicyShard"]:
    """Dedupe policy shards that are subsets of each other.

    Parameters:
        shards: The shards to deduplicate.
        check_reverse: Whether you want to check these shards in reverse as well (only disabled when alling itself).
    """
    deduped_shards: List[PolicyShard] = []
    removed_shards: List[PolicyShard] = []
    sorted_shards = shards

    # Sorting by effective resource means that PolicyShards with larger resources will have any subsets
    # folded into them first, improving readability. We only do this whenn check_reverse is true otherwise
    # we won't respect the reverse order.
    if check_reverse:
        sorted_shards = sorted(shards, key=lambda x: x.effective_resource, reverse=True)

    for undeduped_shard in sorted_shards:
        if any(undeduped_shard.issubset(deduped_shard) for deduped_shard in deduped_shards):
            removed_shards.append(undeduped_shard)
            continue

        deduped_shards.append(undeduped_shard)

    if check_reverse:
        deduped_shards = dedupe_policy_shard_subsets(reversed(deduped_shards), False)
    if removed_shards:
        deduped_shards = dedupe_policy_shard_subsets(deduped_shards)
    return deduped_shards


def dedupe_policy_shards(shards: Iterable["PolicyShard"], check_reverse: bool = True) -> List["PolicyShard"]:
    """Dedupe policy shards that are subsets of each other and remove intersections.

    Parameters:
        shards: The shards to deduplicate.
        check_reverse: Whether you want to check these shards in reverse as well (only disabled when calling itself).
    """
    deduped_shards: List[PolicyShard] = []
    difference_shards: List[PolicyShard] = []
    removed_shards: List[PolicyShard] = []
    for undeduped_shard in shards:
        difference_buffer = []
        removed_buffer = []

        for deduped_shard in deduped_shards:
            if undeduped_shard.issubset(deduped_shard):
                removed_buffer.append(undeduped_shard)
                break
            if deduped_shard.issubset(undeduped_shard):
                break

            # The difference of Shard A (undeduped_shard) and Shard B (deduped_shard) will not be identical to
            # shard A if shard B's ARPs are a superset of Shard A's except for a condition.
            # If this difference is smaller than Shard A and not also a subset of shard B (by virtue of having
            # differing conditions) then this difference should be added to the dedupe list *instead* of
            # shard A because shard B covers the intersection with fewer conditions.

            if undeduped_shard.effect != deduped_shard.effect or not deduped_shard.intersection(undeduped_shard):
                continue
            differences = undeduped_shard.difference(deduped_shard, dedupe_result=False)
            if differences and differences != [undeduped_shard]:
                for difference in differences:
                    if difference < undeduped_shard and not difference.intersection(deduped_shard):
                        difference_buffer.append(difference)

        if removed_buffer:
            removed_shards.extend(removed_buffer)
            continue
        if difference_buffer:
            difference_shards.extend(difference_buffer)
            continue
        deduped_shards.append(undeduped_shard)

    deduped_shards = deduped_shards + difference_shards
    if check_reverse:
        deduped_shards = dedupe_policy_shards(reversed(deduped_shards), False)
    if removed_shards or difference_shards:
        deduped_shards = dedupe_policy_shards(deduped_shards)
    return deduped_shards


def policy_shards_effect(shards: List["PolicyShard"]) -> List["PolicyShard"]:
    """Calculate the effect of merging allow and deny shards together.

    Example:
        How to get the effective permissions of a policy as :class:`~policyglass.policy_shard.PolicyShard` objects.

            >>> from policyglass import Policy, policy_shards_effect, explain_policy_shards
            >>> policy = Policy(
            ...     **{
            ...         "Version": "2012-10-17",
            ...         "Statement": [
            ...             {
            ...                 "Effect": "Allow",
            ...                 "Action": ["s3:*"],
            ...                 "Resource": "*",
            ...             },
            ...             {
            ...                 "Effect": "Deny",
            ...                 "Action": ["s3:Get*"],
            ...                 "Resource": "*",
            ...             },
            ...         ],
            ...     }
            ... )
            >>> policy_shards = policy.policy_shards
            >>> policy_shards_effect(policy_shards)
            [PolicyShard(effect='Allow',
                effective_action=EffectiveAction(inclusion=Action('s3:*'),
                    exclusions=frozenset({Action('s3:Get*')})),
                effective_resource=EffectiveResource(inclusion=Resource('*'),
                    exclusions=frozenset()),
                effective_principal=EffectivePrincipal(inclusion=Principal(type='AWS', value='*'),
                    exclusions=frozenset()),
                effective_condition=EffectiveCondition(inclusions=frozenset(),
                    exclusions=frozenset()))]

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
    return dedupe_policy_shards(merged_allow_shards)


def policy_shards_to_json(shards: List["PolicyShard"], exclude_defaults=False, **kwargs) -> str:
    """Convert a list of :class:`~policyglass.policy_shard.PolicyShard` objects to JSON.

    Example:
        How to get the effective permissions of a policy as json.

            >>> from policyglass import Policy, policy_shards_effect, policy_shards_to_json
            >>> policy = Policy(
            ...     **{
            ...         "Version": "2012-10-17",
            ...         "Statement": [
            ...             {
            ...                 "Effect": "Allow",
            ...                 "Action": ["s3:*"],
            ...                 "Resource": "*",
            ...             },
            ...             {
            ...                 "Effect": "Deny",
            ...                 "Action": ["s3:Get*"],
            ...                 "Resource": "*",
            ...             },
            ...         ],
            ...     }
            ... )
            >>> policy_shards = policy.policy_shards
            >>> output = policy_shards_to_json(
            ...     policy_shards_effect(policy_shards),
            ...     indent=2,
            ...     exclude_defaults=True
            ... )
            >>> print(output)
            [
                {
                    "effective_action": {
                        "inclusion": "s3:*",
                        "exclusions": [
                            "s3:Get*"
                        ]
                    },
                    "effective_resource": {
                        "inclusion": "*"
                    },
                    "effective_principal": {
                        "inclusion": {
                            "type": "AWS",
                            "value": "*"
                        }
                    }
                }
            ]

    Parameters:
        shards: The list of shards to convert.
        exclude_defaults: Whether to exclude default values (e.g. empty lists) from the output.
        **kwargs: keyword arguments passed on to :func:`json.dumps`
    """
    return json.dumps([json.loads(shard.json(exclude_defaults=exclude_defaults)) for shard in shards], **kwargs)


def explain_policy_shards(shards: List["PolicyShard"], language: str = "en") -> List[str]:
    """Return a list of string explanations for a given list of PolicyShards.

    Example:
        How to get the effective permissions of a policy as a plain English explanation.

            >>> from policyglass import Policy, policy_shards_effect, explain_policy_shards
            >>> policy = Policy(
            ...     **{
            ...         "Version": "2012-10-17",
            ...         "Statement": [
            ...             {
            ...                 "Effect": "Allow",
            ...                 "Action": ["s3:*"],
            ...                 "Resource": "*",
            ...             },
            ...             {
            ...                 "Effect": "Deny",
            ...                 "Action": ["s3:Get*"],
            ...                 "Resource": "*",
            ...             },
            ...         ],
            ...     }
            ... )
            >>> explain_policy_shards(policy_shards_effect(policy.policy_shards))
            ['Allow action s3:* (except for s3:Get*) on resource * with principal AWS *.']

    Parameters:
        shards: The PolicyShards to explain.
        language: The language of the explanation

    Raises:
        NotImplementedError: When an unsupported language is requested.
    """
    if language != "en":
        raise NotImplementedError(f"Language '{language}' is not supported.")
    return [shard.explain for shard in shards]


class PolicyShard(BaseModel):
    """A PolicyShard is part of a policy broken down in such a way that it can be deduplicated and collapsed."""

    effect: str
    effective_action: EffectiveARP[Action]
    effective_resource: EffectiveARP[Resource]
    effective_principal: EffectiveARP[Principal]
    effective_condition: EffectiveCondition

    def __init__(
        self,
        effect: str,
        effective_action: EffectiveARP[Action],
        effective_resource: EffectiveARP[Resource],
        effective_principal: EffectiveARP[Principal],
        effective_condition: EffectiveCondition = None,
    ) -> None:
        """Initialize a PolicyShard object.

        Parameters:
            effect: `'Allow'` or `'Deny'`
            effective_action: The EffectiveAction that this PolicyShard allows or denies
            effective_resource: The EffectiveResource that this PolicyShard allows or denies
            effective_principal: The EffectivePrincipal that this PolicyShard allows or denies
            effective_condition: The EffectiveCondition that needs to be met for this PolicyShard to apply
        """
        super().__init__(
            effect=effect,
            effective_action=effective_action,
            effective_resource=effective_resource,
            effective_principal=effective_principal,
            effective_condition=effective_condition or EffectiveCondition(frozenset(), frozenset()),
        )

    class Config:
        """Pydantic Config."""

        json_encoders = {
            EffectiveAction: lambda v: v.dict() if v else None,
            EffectiveResource: lambda v: v.dict() if v else None,
            EffectivePrincipal: lambda v: v.dict() if v else None,
        }

    def union(self, other: object) -> List["PolicyShard"]:
        """Combine this object with another object of the same type.

        Parameters:
            other: The object to combine with this one.

        Raises:
            ValueError: If ``other`` is not the same type as this object.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot union {self.__class__.__name__} with {other.__class__.__name__}")
        if not other.issubset(self) and not self.issubset(other):
            return [self, other]
        if self.effective_condition != other.effective_condition:
            if other.issubset(self):
                return [self]
            if self.issubset(other):
                return [other]
            return [self, other]

        return [
            self.__class__(
                effect=self.effect,
                effective_action=effective_action,
                effective_resource=effective_resource,
                effective_principal=effective_principal,
                effective_condition=self.effective_condition,
            )
            for effective_action in self.effective_action.union(other.effective_action)
            for effective_resource in self.effective_resource.union(other.effective_resource)
            for effective_principal in self.effective_principal.union(other.effective_principal)
        ]

    def difference(self, other: object, dedupe_result: bool = True) -> List["PolicyShard"]:
        """Calculate the difference between this and another object of the same type.

        Effectively subtracts the inclusions of ``other`` from ``self``.
        This is useful when applying denies (``other``) to allows (``self``).

        Parameters:
            other:
                The object to subtract from this one.
            dedupe_result:
                Whether to deduplicate the resulting PolicyShards or not.
                Setting this to ``False`` will lead to many duplicates.

        Raises:
            ValueError: If ``other`` is not the same type as this object.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot diff {self.__class__.__name__} with {other.__class__.__name__}")
        if self.effect == "Deny" and other.effect == "Allow":
            # I don't know what it means to calculate the difference between a deny and an allow.
            # Difference between an Allow and Deny makes sense, as that is the effective permission.
            # But subtracting an Allow from a Deny is nonsensical.
            raise ValueError("Cannot calculate deny.difference(allow).")

        if not self.intersection(other):
            # Shards do not intersect
            return [self]

        result = self._decompose_difference(other)

        if other.effective_condition and self.effective_condition != other.effective_condition:
            # If the other has a condition and it's not identical to self's, then there is difference
            # such that self's conditions apply and other's conditions do not.
            # i.e. we need to add another PolicyShard that is ALL the ARP differences
            # If self is Allow and other is Deny we must add the deny's conditions as exclusions.
            # These exclusions will probably be reversed by the __init__ of EffectiveCondition.
            effective_condition = self.effective_condition
            if self.effect != other.effect:
                effective_condition = self.effective_condition.union(other.effective_condition.reverse)
            result.append(
                self.__class__(
                    effect=self.effect,
                    effective_action=self.effective_action,
                    effective_resource=self.effective_resource,
                    effective_principal=self.effective_principal,
                    effective_condition=effective_condition,
                )
            )
        if dedupe_result:
            return dedupe_policy_shard_subsets(result)
        return result

    def _decompose_difference(self, other: "PolicyShard") -> List["PolicyShard"]:
        """Decompose self and recompose with all possible ARP differences/intersections with other.

        Parameters:
            other: The other PolicyShard to recompose this one with.
        """
        intersection = self.intersection(other)
        if not intersection:
            return []
        difference_actions = self.effective_action.difference(other.effective_action)
        difference_resources = self.effective_resource.difference(other.effective_resource)
        difference_principals = self.effective_principal.difference(other.effective_principal)

        result = []
        result += self._decompose_difference_arps_with_combined_conditions(
            other, intersection, difference_actions, difference_resources, difference_principals
        )
        result += self._decompose_difference_arps_with_self_conditions(
            difference_actions, difference_resources, difference_principals
        )
        return result

    def _decompose_difference_arps_with_combined_conditions(
        self,
        other: "PolicyShard",
        intersection: "PolicyShard",
        difference_actions: List[EffectiveARP[Action]],
        difference_resources: List[EffectiveARP[Resource]],
        difference_principals: List[EffectiveARP[Principal]],
    ) -> List["PolicyShard"]:
        """Return a PolicyShard centred around each intersection_<ARP> passed in.

        If there is an EffectiveAction in intersection.effective_actions for example,
        that means there is an action which both ``self`` and ``other`` cover.
        Therefore we need to cover the scenario for that EffectiveAction with combined conditions.

        Parameters:
            other: The PolicyShard we're generating the difference against
            intersection: The Policyshard representing the intersection between self and other
            difference_actions: The diference between self's and other's effective_actions
            difference_resources: The diference between self's and other's effective_resources
            difference_principals: The diference between self's and other's effective_principals
        """
        if self.effect != other.effect:
            effective_condition = self.effective_condition.union(other.effective_condition.reverse)
        else:
            effective_condition = self.effective_condition
        result = []
        result.extend(
            [
                self.__class__(
                    effect=self.effect,
                    effective_action=difference_action,
                    effective_resource=intersection.effective_resource,
                    effective_principal=intersection.effective_principal,
                    effective_condition=effective_condition,
                )
                for difference_action in difference_actions
            ]
        )
        result.extend(
            [
                self.__class__(
                    effect=self.effect,
                    effective_action=intersection.effective_action,
                    effective_resource=difference_resource,
                    effective_principal=intersection.effective_principal,
                    effective_condition=effective_condition,
                )
                for difference_resource in difference_resources
            ]
        )
        result.extend(
            [
                self.__class__(
                    effect=self.effect,
                    effective_action=intersection.effective_action,
                    effective_resource=intersection.effective_resource,
                    effective_principal=difference_principal,
                    effective_condition=effective_condition,
                )
                for difference_principal in difference_principals
            ]
        )
        return result

    def _decompose_difference_arps_with_self_conditions(
        self,
        difference_actions: List[EffectiveARP[Action]],
        difference_resources: List[EffectiveARP[Resource]],
        difference_principals: List[EffectiveARP[Principal]],
    ) -> List["PolicyShard"]:
        """Return a PolicyShard centred around each difference_<ARP> passed in.

        If there is a EffectiveAction in difference_actions for example,
        that means there is an action which ``self`` covers that ``other`` does not.
        Therefore we need to cover the scenario for that EffectiveAction with JUST self.conditions.

        Parameters:
            difference_actions: The diference between self's and other's effective_actions
            difference_resources: The diference between self's and other's effective_resources
            difference_principals: The diference between self's and other's effective_principals
        """
        result = []
        result.extend(
            [
                self.__class__(
                    effect=self.effect,
                    effective_action=action,
                    effective_resource=self.effective_resource,
                    effective_principal=self.effective_principal,
                    effective_condition=self.effective_condition,
                )
                for action in difference_actions
            ]
        )

        result.extend(
            [
                self.__class__(
                    effect=self.effect,
                    effective_action=self.effective_action,
                    effective_resource=resource,
                    effective_principal=self.effective_principal,
                    effective_condition=self.effective_condition,
                )
                for resource in difference_resources
            ]
        )

        result.extend(
            [
                self.__class__(
                    effect=self.effect,
                    effective_action=self.effective_action,
                    effective_resource=self.effective_resource,
                    effective_principal=principal,
                    effective_condition=self.effective_condition,
                )
                for principal in difference_principals
            ]
        )
        return result

    def intersection(self, other: object) -> Optional["PolicyShard"]:
        """Calculate the intersection between this object and another object of the same type.

        Parameters:
            other: The object to intersect with this one.

        Raises:
            ValueError: if ``other`` is not the same type as this object.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot intersect {self.__class__.__name__} with {other.__class__.__name__}")
        if self.effect == "Deny" and other.effect == "Allow":
            # I don't know what it means to calculate the intersection between a deny and an allow.
            # Intersection between an Allow and Deny makes sense, as that is what is denied.
            # But adding an Allow to a Deny is nonsensical.
            raise ValueError("Cannot calculate deny.intersection(allow).")
        intersection_action = self.effective_action.intersection(other.effective_action)
        intersection_resource = self.effective_resource.intersection(other.effective_resource)
        intersection_principal = self.effective_principal.intersection(other.effective_principal)

        if not intersection_action or not intersection_resource or not intersection_principal:
            return None
        if self.effect == other.effect:
            if (
                self.effective_condition.inclusions
                and other.effective_condition.inclusions
                and not self.effective_condition.inclusions.intersection(other.effective_condition.inclusions)
            ):
                return None
            if (
                self.effective_condition.exclusions
                and other.effective_condition.exclusions
                and not self.effective_condition.exclusions.intersection(other.effective_condition.exclusions)
            ):
                return None

        # intersection conditions/not_conditions cannot be a proper subset of self's as if they were they would include
        # scenarios not originally included by self.
        intersection_conditions = self.effective_condition.inclusions.intersection(other.effective_condition.inclusions)
        if intersection_conditions < self.effective_condition.inclusions:
            intersection_conditions = self.effective_condition.inclusions
        intersection_not_conditions = self.effective_condition.exclusions.intersection(
            other.effective_condition.exclusions
        )
        if intersection_not_conditions < self.effective_condition.exclusions:
            intersection_not_conditions = self.effective_condition.exclusions

        return self.__class__(
            effect=self.effect,
            effective_action=intersection_action,
            effective_resource=intersection_resource,
            effective_principal=intersection_principal,
            effective_condition=EffectiveCondition(
                inclusions=intersection_conditions, exclusions=intersection_not_conditions
            ),
        )

    def issubset(self, other: object) -> bool:
        """Whether this object contains all the elements of another object (i.e. is a subset of the other object).

        Conditions:
            If both PolicyShards have conditions but are otherwise identical, self will be a subset of other if the
            other's conditions are are a subset of self's as this means that self is more restrictive and therefore
            carves out a subset of possiblilites in comparison with other.

        Parameters:
            other: The object to determine if our object contains.

        Raises:
            ValueError: If the other object is not of the same type as this object.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot compare {self.__class__.__name__} and {other.__class__.__name__}")
        if (
            self.effective_condition.inclusions
            and other.effective_condition.inclusions
            and not other.effective_condition.inclusions.issubset(self.effective_condition.inclusions)
        ):
            return False
        if (
            self.effective_condition.exclusions
            and other.effective_condition.exclusions
            and not other.effective_condition.exclusions.issubset(self.effective_condition.exclusions)
        ):
            return False
        if not self.effective_condition.inclusions and other.effective_condition.inclusions:
            return False
        if not self.effective_condition.exclusions and other.effective_condition.exclusions:
            return False
        return (
            self.effective_action.issubset(other.effective_action)
            and self.effective_resource.issubset(other.effective_resource)
            and self.effective_principal.issubset(other.effective_principal)
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
                value = attribute_value.dict(*args, **kwargs)
                if not kwargs.get("exclude_defaults") or value:
                    result[attribute_name] = value
            elif isinstance(attribute_value, (set, frozenset)):
                value = list(attribute_value)
                if not kwargs.get("exclude_defaults") or value:
                    result[attribute_name] = value

        return result

    def _iter(self, *args, **kwargs) -> Iterator[Tuple[str, Any]]:  # type: ignore[override]
        for key, value in self.dict(*args, **kwargs).items():
            yield key, value

    @property
    def explain(self) -> str:
        """Return a plain English representation of the policy shard.

        Example:
            Simple PolicyShard explain.

                >>> from policyglass import Policy
                >>> policy = Policy(**{"Statement": [{"Effect": "Allow", "Action": "s3:*"}]})
                >>> print([shard.explain for shard in policy.policy_shards])
                ['Allow action s3:* on resource * with principal AWS *.']
        """
        explain_elements: Dict[str, str] = DefaultDict(str)

        explain_elements["arp_explain"] = f"{self.effect} action {self.effective_action.inclusion} "
        if self.effective_action.exclusions:
            explain_elements["arp_explain"] += f"(except for {', '.join(self.effective_action.exclusions)}) "
        explain_elements["arp_explain"] += f"on resource {self.effective_resource.inclusion} "
        if self.effective_resource.exclusions:
            explain_elements["arp_explain"] += f"(except for {', '.join(self.effective_resource.exclusions)}) "
        explain_elements["arp_explain"] += f"with principal {self.effective_principal.inclusion} "
        if self.effective_principal.exclusions:
            principal_exclusions = ", ".join([str(principal) for principal in self.effective_principal.exclusions])
            explain_elements["arp_explain"] += f"(except principals {principal_exclusions}) "

        if self.effective_condition.inclusions:
            condition_inclusions = " and ".join(
                sorted([str(condition) for condition in self.effective_condition.inclusions])
            )
            explain_elements["condition_inclusion_explain"] = f"Provided conditions {condition_inclusions} are met"
        if self.effective_condition.exclusions:
            condition_exclusions = " and ".join(
                sorted([str(condition) for condition in self.effective_condition.exclusions])
            )
            explain_elements["condition_exclusion_explain"] = f"Unless conditions {condition_exclusions} are met"

        return ". ".join(element.strip() for element in explain_elements.values() if element) + "."

    def __repr__(self) -> str:
        """Return an instantiable representation of this object."""
        return (
            f"{self.__class__.__name__}(effect='{self.effect}', "
            f"effective_action={self.effective_action}, "
            f"effective_resource={self.effective_resource}, "
            f"effective_principal={self.effective_principal}, "
            f"effective_condition={self.effective_condition})"
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
            and self.effective_condition == other.effective_condition
        )

    def __lt__(self, other: object) -> bool:
        """Whether this object is a proper subset of another object.

        Parameters:
            other: The object to determine if our object is a proper subset of.

        Raises:
            ValueError: If the other object is not of the same type as this object.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot compare {self.__class__.__name__} and {other.__class__.__name__}")
        return self.issubset(other) and self != other

    def __gt__(self, other: object) -> bool:
        """Whether another object is a proper subset of this object.

        Parameters:
            other: The object to determine to check if it is a subset of our object.

        Raises:
            ValueError: If the other object is not of the same type as this object.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot compare {self.__class__.__name__} and {other.__class__.__name__}")
        return other.issubset(self) and self != other
