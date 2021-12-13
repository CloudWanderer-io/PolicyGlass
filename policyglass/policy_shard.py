"""PolicyShards are a simplified representation of policies."""

from typing import FrozenSet, List

from policyglass.effective_arp import EffectiveARP

from .action import Action
from .condition import Condition
from .principal import Principal
from .resource import Resource


class PolicyShard:
    """A PolicyShard is part of a policy broken down in such a way that it can be deduplicated and collapsed."""

    effective_action: EffectiveARP[Action]
    effective_resource: EffectiveARP[Resource]
    effective_principal: EffectiveARP[Principal]
    conditions: FrozenSet[Condition]

    def __init__(
        self,
        effective_action: EffectiveARP[Action],
        effective_resource: EffectiveARP[Resource],
        effective_principal: EffectiveARP[Principal],
        conditions: FrozenSet[Condition],
    ) -> None:
        self.effective_action = effective_action
        self.effective_resource = effective_resource
        self.effective_principal = effective_principal
        self.conditions = conditions

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
                effective_action=effective_action,
                effective_resource=effective_resource,
                effective_principal=effective_principal,
                conditions=self.conditions,
            )
            for effective_action in self.effective_action.union(other.effective_action)
            for effective_resource in self.effective_resource.union(other.effective_resource)
            for effective_principal in self.effective_principal.union(other.effective_principal)
        ]

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
