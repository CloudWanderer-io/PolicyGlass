"""PolicyShards are a simplified representation of policies."""

from typing import Any, Dict, FrozenSet, List, Optional

from pydantic import BaseModel

from .action import Action
from .condition import Condition
from .effective_arp import EffectiveARP
from .principal import Principal
from .resource import Resource


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
                    not_conditions=other.conditions,
                )
            )
        return result

    def dict(self, *args, **kwargs) -> Dict[str, Any]:
        """Convert instance to dict representation of it.

        Parameters:
            *args: Arguments will be ignored.
            **kwargs: Arguments will be ignored.

        Overridden from BaseModel so that when converting conditions to dict they don't suffer from being unhashable
        when placed in a set.
        """
        result = {}
        for attribute_name, attribute_value in self:
            if hasattr(attribute_value, "dict"):
                result[attribute_name] = attribute_value.dict()
            elif isinstance(attribute_value, (set, frozenset)):
                result[attribute_name] = list(attribute_value)

        return result

    def __repr__(self) -> str:
        """Return an instantiable representation of this object."""
        return (
            f"{self.__class__.__name__}(effective_action={self.effective_action}, "
            f"effective_resource={self.effective_resource}, "
            f"effective_principal={self.effective_principal}, "
            f"conditions={self.conditions})"
        )

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
