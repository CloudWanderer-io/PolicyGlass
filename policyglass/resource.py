"""Resource class."""
from fnmatch import fnmatch
from typing import List

from .effective_arp import EffectiveARP


class Resource(str):
    """A resource ARN may be case sensitive or case insensitive depending on the resource type."""

    def __lt__(self, other: object) -> bool:
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
        return fnmatch(self, other)

    def issubset(self, other: object) -> bool:
        """Whether this object contains all the elements of another object (i.e. is a subset of the other object).

        Parameters:
            other: The object to determine if our object contains.

        Raises:
            ValueError: If the other object is not of the same type as this object.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot compare {self.__class__.__name__} and {other.__class__.__name__}")
        for self_element, other_element in zip(self.arn_elements, other.arn_elements):
            if not fnmatch(self_element, other_element):
                return False
        return True

    @property
    def arn_elements(self) -> List[str]:
        """Return a list of arn elements, replacing blanks with ``*``."""
        return [element or "*" for element in self.split(":")]

    def __contains__(self, other: object) -> bool:
        """Not Implemented.

        Parameters:
            other: The object to see if this object contains.

        Raises:
            NotImplementedError: This method is not implemented.
        """
        raise NotImplementedError()

    def __repr__(self) -> str:
        """Return an instantiable representation of this object."""
        return f"{self.__class__.__name__}('{self}')"


class EffectiveResource(EffectiveARP[Resource]):
    """EffectiveResources are the representation of the difference between an Resource and its exclusion.

    The allowed Resource is the difference (subtraction) of the excluded Resources
    from the included Resource.
    """

    _arp_type = Resource
