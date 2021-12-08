"""Action class."""
from fnmatch import fnmatch

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
        return self != other and fnmatch(other, self)
