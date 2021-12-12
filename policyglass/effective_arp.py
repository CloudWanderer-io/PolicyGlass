"""Parent class for EffectiveAction, EffectiveResource, EffectivePrincipal."""
from typing import FrozenSet, Generic, List, Optional, Type, TypeVar

from .protocols import ARPProtocol

T = TypeVar("T", bound=ARPProtocol)


class EffectiveARP(Generic[T]):
    """EffectiveARPs are the representation of the difference between an ARP and its exclusion.

    The allowed actions is the difference (subtraction) of the excluded ARPs
    from the included ARP.
    """

    #: Inclusion must be a superset of any exclusions
    inclusion: T

    #: Exclusions must always be a subset of the include and must not be subsets of each other
    exclusions: FrozenSet[T]

    #: The type of ARP we're subclassed for.
    _arp_type: Type[T]

    def __init__(self, inclusion: T, exclusions: Optional[FrozenSet[T]] = None) -> None:
        self.inclusion = inclusion
        self.exclusions = exclusions or frozenset()
        if not all([isinstance(action, self._arp_type) for action in [self.inclusion, *self.exclusions]]):
            raise ValueError(f"All inclusions and exclusions must be {self.__class__.__name__}")

    def union(self, other: object) -> List["EffectiveARP"]:
        """Combine this object with another object of the same type.

        Parameters:
            other: The object to combine with this one.

        Raises:
            ValueError: If ``other`` is not the same type as this object.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot union {self.__class__.__name__} with {other.__class__.__name__}")
        if self.inclusion.issubset(other.inclusion) and not other.in_exclusions(self.inclusion):
            return [other]
        if other.inclusion.issubset(self.inclusion) and not self.in_exclusions(other.inclusion):
            return [self]
        return [self, other]

    def difference(self, other: object) -> List["EffectiveARP"]:
        """Calculate the difference between this and another object of the same type.

        Effectively subtracts the inclusions of ``other`` from ``self``.
        This is useful when applying denies (``other``) to allows (``self``).

        Parameters:
            other: The object to subtract from this one.

        Raises:
            ValueError: If ``other`` is not the same type as this object.
        """
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

    def in_exclusions(self, other: T) -> bool:
        """Check if the ARP is contained within or equal to any of the exclusions.

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
