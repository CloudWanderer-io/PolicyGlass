"""Action class."""
from fnmatch import fnmatch
from typing import FrozenSet, List, Optional

from .models import CaseInsensitiveString


class Action(CaseInsensitiveString):
    """Actions are case insensitive.

    "The prefix and the action name are case insensitive"
    `IAM JSON policy elements: Action
    <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html`__
    """

    def __contains__(self, other: object) -> bool:
        """Whether this object contains (but is not equal to) another object.

        Parameters:
            other: The object to determine if our object contains.

        Raises:
            ValueError: If the other object is not of the same type as this object.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot compare {self.__class__.__name__} and {other.__class__.__name__}")
        if self == other:
            return False
        return fnmatch(other.lower(), self.lower())


class EffectiveAction:
    """EffectiveActions are the representation of the difference between an Action and its exclusion.

    The allowed actions is the difference (subtraction) of the excluded Actions
    from the included action.
    """

    #: Inclusion must be a superset of any exclusions
    inclusion: Action

    #: Exclusions must always be a subset of the include and must not be subsets of each other
    exclusions: FrozenSet[Action]

    def __init__(self, inclusion: Action, exclusions: Optional[FrozenSet[Action]] = None) -> None:
        self.inclusion = inclusion
        self.exclusions = exclusions or frozenset()
        if not all([isinstance(action, Action) for action in [self.inclusion, *self.exclusions]]):
            raise ValueError("All inclusions and exclusions must be Actions")

    def union(self, other: object) -> List["EffectiveAction"]:
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot union {self.__class__.__name__} with {other.__class__.__name__}")
        print(f"{self.inclusion} in {other.inclusion}: ", self.inclusion in other.inclusion)
        if self.inclusion in other.inclusion:
            return [other]
        print(f"{other.inclusion} in {self.inclusion}: ", other.inclusion in self.inclusion)
        if other.inclusion in self.inclusion:
            return [self]
        return [self, other]

    def __eq__(self, other: object) -> bool:
        """Whether this object contains (but is not equal to) another object.

        Parameters:
            other: The object to determine if our object contains.

        Raises:
            ValueError: If the other object is not of the same type as this object.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot compare {self.__class__.__name__} and {other.__class__.__name__}")
        return self.inclusion == other.inclusion and self.exclusions == other.exclusions

    def __repr__(self) -> str:
        """Return an insantiable representation of this object."""
        return f"{self.__class__.__name__}(inclusion={self.inclusion}, exclusions={self.exclusions})"
