"""Generic Models."""


class CaseInsensitiveString(str):
    """A case insensitive string to aid comparison."""

    def __eq__(self, other: object) -> bool:
        """Determine whether this object and another object are equal.

        Parameters:
            other: The object to compare this one to.

        Raises:
            ValueError: When the object we are compared with is not of the same type.
        """
        if not isinstance(other, (self.__class__, str)):
            raise ValueError(f"Cannot compare {self.__class__.__name__} and {other.__class__.__name__}")
        return self.lower() == other.lower()

    def __hash__(self) -> int:
        """Compute the hash for this object."""
        return super().__hash__()

    def __repr__(self) -> str:
        """Return an instantiable representation of this object."""
        return f"{self.__class__.__name__}('{self}')"
