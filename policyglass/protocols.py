"""Protocol types used by PolicyGlass."""
import sys

if sys.version_info >= (3, 8):
    from typing import Protocol
else:
    from typing_extensions import Protocol


class ARPProtocol(Protocol):
    """Protocol which Actions, Resources, and Principals must implement."""

    def __eq__(self, other: object) -> bool:
        """Determine whether this object and another object are equal.

        Parameters:
            other: The object to compare this one to.
        """
        ...

    def issubset(self, other: object) -> bool:
        """Whether this object contains all the elements of another object (i.e. is a subset of the other object).

        Parameters:
            other: The object to determine if our object contains.
        """
        ...

    def __lt__(self, other: object) -> bool:
        """Whether this object contains but is not equal to (i.e. a proper subset) another object.

        Parameters:
            other: The object to determine if our object contains (but is not equal to).
        """
        ...
