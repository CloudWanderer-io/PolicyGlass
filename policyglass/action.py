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

    def issubset(self, other: object) -> bool:
        """Whether this object contains all the elements of another object (i.e. is a subset of the other object).

        Parameters:
            other: The object to determine if our object contains.

        Raises:
            ValueError: If the other object is not of the same type as this object.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot compare {self.__class__.__name__} and {other.__class__.__name__}")
        return fnmatch(self.lower(), other.lower())

    def __lt__(self, other: object) -> bool:
        """Whether this object contains but is not equal to (i.e. a proper subset) another object.

        Parameters:
            other: The object to determine if our object contains (but is not equal to).

        Raises:
            ValueError: If the other object is not of the same type as this object.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot compare {self.__class__.__name__} and {other.__class__.__name__}")
        if self == other:
            return False
        return self.issubset(other)

    def __contains__(self, other: object) -> bool:
        """Not Implemented.

        Parameters:
            other: The object to see if this object contains.

        Raises:
            NotImplementedError: This method is not implemented.
        """
        raise NotImplementedError()


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
        if self.inclusion.issubset(other.inclusion) and not other.in_exclusions(self.inclusion):
            return [other]
        if other.inclusion.issubset(self.inclusion) and not self.in_exclusions(other.inclusion):
            return [self]
        return [self, other]

    def difference(self, other: object) -> List["EffectiveAction"]:
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot union {self.__class__.__name__} with {other.__class__.__name__}")
        if self.inclusion.issubset(other.inclusion):
            return []
        if not other.inclusion.issubset(self.inclusion):
            return [self]
        if self.in_exclusions(other.inclusion):
            return [self]
        if not other.exclusions:
            # Just add the other's inclusion to self's exclusions
            return [self.__class__(self.inclusion, frozenset(set(self.exclusions).union(set({other.inclusion}))))]
        # If the other has its own exclusions we need to represent this as two seperate items
        # We need to add the inclusion from other to the exclusions of self and create new items for
        # each exclusion of other.
        # See docs for more details.
        new_self = self.__class__(self.inclusion, frozenset(set(self.exclusions).union(set({other.inclusion}))))
        new_others = [self.__class__(other_exclusion) for other_exclusion in other.exclusions]
        return [new_self, *new_others]

    def in_exclusions(self, other: Action) -> bool:
        """Check if the Action is contained within or equal to any of the exclusions.

        Parameters:
            other: The object to look for in the exclusions of this object.
        """
        return any(other.issubset(exclusion) for exclusion in self.exclusions)

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
