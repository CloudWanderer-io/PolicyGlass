"""PolicyShards are a simplified representation of policies."""

from typing import FrozenSet

from .action import EffectiveAction
from .condition import Condition
from .principal import EffectivePrincipal
from .resource import EffectiveResource


class PolicyShard:
    """A PolicyShard is part of a policy broken down in such a way that it can be deduplicated and collapsed."""

    effective_action: EffectiveAction
    effective_resource: EffectiveResource
    effective_principal: EffectivePrincipal
    conditions: FrozenSet[Condition]

    def __init__(
        self,
        effective_action: EffectiveAction,
        effective_resource: EffectiveResource,
        effective_principal: EffectivePrincipal,
        conditions: FrozenSet[Condition],
    ) -> None:
        self.effective_action = effective_action
        self.effective_resource = effective_resource
        self.effective_principal = effective_principal
        self.conditions = conditions

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
