"""Resource class."""
from fnmatch import fnmatch


class Resource(str):
    """A resource ARN may be case sensitive or case insensitive depending on the resource type."""

    def __contains__(self, other: object) -> bool:
        """Whether this object contains (but is not equal to) another object.

        Parameters:
            other: The object to determine if our object contains.

        Raises:
            ValueError: If the other object is not of the same type as this object.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot compare {self.__class__.__name__} and {other.__class__.__name__}")
        return self != other and fnmatch(other, self)
