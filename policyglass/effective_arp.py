"""Parent class for EffectiveAction, EffectiveResource, EffectivePrincipal."""
from typing import Any, Callable, Dict, FrozenSet, Generic, Iterator, List, Optional, Type, TypeVar, Union

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
        if not all([isinstance(arp, self._arp_type) for arp in [self.inclusion, *self.exclusions]]):
            raise ValueError(f"All inclusions and exclusions must be type {self._arp_type.__name__}")
        if not (all(exclusion < self.inclusion for exclusion in self.exclusions)):
            bad_exclusions = [exclusion for exclusion in self.exclusions if not exclusion.issubset(self.inclusion)]
            raise ValueError(f"Exclusions ({bad_exclusions}) are not within the inclusion ({repr(self.inclusion)})")

    def union(self, other: object) -> List["EffectiveARP[T]"]:
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

    def difference(self, other: object) -> List["EffectiveARP[T]"]:
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
        if self.inclusion.issubset(other.inclusion):
            if other.exclusions:
                return [
                    arp
                    for arp in [self.__class__.factory(exclusion) for exclusion in other.exclusions]
                    if arp is not None
                ]
            return []
        if not other.inclusion.issubset(self.inclusion):
            return [self]
        if self.in_exclusions(other.inclusion):
            return [self]
        if not other.exclusions:
            # Just add the other's inclusion to self's exclusions
            arp = self.__class__.factory(self.inclusion, frozenset(set(self.exclusions).union(set({other.inclusion}))))
            return [arp] if arp else []
        # If the other has its own exclusions we need to represent this as two seperate items
        # We need to add the inclusion from other to the exclusions of self and create new items for
        # each exclusion of other.
        # See docs for more details.
        new_self = self.__class__.factory(self.inclusion, frozenset(set(self.exclusions).union(set({other.inclusion}))))
        new_others = [self.__class__.factory(other_exclusion) for other_exclusion in other.exclusions]
        return [arp for arp in [new_self, *new_others] if arp is not None]

    def intersection(self, other: object) -> Optional["EffectiveARP[T]"]:
        """Calculate the intersection between this object and another object of the same type.

        Parameters:
            other: The object to intersect with this one.

        Raises:
            ValueError: if ``other`` is not the same type as this object.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot intersect {self.__class__.__name__} with {other.__class__.__name__}")

        if not self.inclusion.issubset(other.inclusion) and not other.inclusion.issubset(self.inclusion):
            return None
        if self.in_exclusions(other.inclusion):
            return None
        if self.inclusion.issubset(other.inclusion):
            if not other.exclusions:
                return self
            self_with_others_exclusions_added = self.__class__.factory(
                self.inclusion,
                frozenset(
                    [
                        exclusion
                        for exclusion in set(self.exclusions).union(set(other.exclusions))
                        if exclusion.issubset(self.inclusion)
                    ]
                ),
            )
            return self_with_others_exclusions_added

        other_with_self_exclusions_added = self.__class__.factory(
            other.inclusion,
            frozenset(
                [
                    exclusion
                    for exclusion in self.exclusions.union(set(other.exclusions))
                    if exclusion.issubset(other.inclusion)
                ]
            ),
        )

        return other_with_self_exclusions_added

    def issubset(self, other: object) -> bool:
        """Whether this object contains all the elements of another object (i.e. is a subset of the other object).

        Parameters:
            other: The object to determine if our object contains.

        Raises:
            ValueError: If the other object is not of the same type as this object.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot compare {self.__class__.__name__} and {other.__class__.__name__}")
        if self == other:
            return True
        if not self.inclusion.issubset(other.inclusion):
            return False
        if other.in_exclusions(self.inclusion):
            return False
        if self.in_exclusions(other.inclusion) or any(
            self_exclusion.issubset(other_exclusion)
            for self_exclusion in self.exclusions
            for other_exclusion in other.exclusions
        ):
            return False

        for other_exclusion in other.exclusions:
            # If any of other's exclusions excludes something self DOESN'T then self is not a subset of other.
            if other_exclusion.issubset(self.inclusion) and not any(
                other_exclusion.issubset(self_exclusion) for self_exclusion in self.exclusions
            ):
                return False
        return True

    def in_exclusions(self, other: T) -> bool:
        """Check if the ARP is contained within or equal to any of the exclusions.

        Parameters:
            other: The object to look for in the exclusions of this object.
        """
        return any(other.issubset(exclusion) for exclusion in self.exclusions)

    @classmethod
    def factory(cls, inclusion: T, exclusions: Optional[FrozenSet[T]] = None) -> Optional["EffectiveARP[T]"]:
        """Return an EffectiveARP[T] based on the inclusion and exclusion.

        This handles the ValueError if we accidentally pass an invalid inclusion/exclusion combo.

        Parameters:
            inclusion: The <T> that that is in effect.
            exclusions: The list of <T>s that are excluded from the effect.
        """
        try:
            return cls(inclusion, exclusions)
        except ValueError:
            return None

    def __eq__(self, other: object) -> bool:
        """Whether this object is not equal to another object.

        Parameters:
            other: The object to determine if our object is equal to.

        Raises:
            ValueError: If the other object is not of the same type as this object.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot compare {self.__class__.__name__} and {other.__class__.__name__}")
        return self.inclusion == other.inclusion and self.exclusions == other.exclusions

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

    def __repr__(self) -> str:
        """Return an insantiable representation of this object."""
        return f"{self.__class__.__name__}(inclusion={repr(self.inclusion)}, exclusions={self.exclusions})"

    def dict(self, *args, **kwargs) -> Dict[str, Any]:
        """Return a dictionary representation of this object.

        Parameters:
            *args: Arguments to Pydantic dict method.
            **kwargs: Arguments to Pydantic dict method.

        """
        result: Dict[str, Union[T, FrozenSet[T]]] = {"inclusion": self.inclusion}
        if not kwargs.get("exclude_defaults") or self.exclusions != frozenset():
            result.update({"exclusions": self.exclusions})
        return result

    @classmethod
    def __get_validators__(cls) -> Iterator[Callable]:
        """Return noop validator as we don't particularly need validation.

        We just need Pydantic to accept this as a valid type to populate in PolicyShard.
        """
        yield lambda x: x
