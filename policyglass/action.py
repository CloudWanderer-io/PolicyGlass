"""Action class."""
from fnmatch import fnmatch

from .effective_arp import EffectiveARP
from .models import CaseInsensitiveString


class Action(CaseInsensitiveString):
    """Actions are case insensitive.

    .. epigraph::

        "The prefix and the action name are case insensitive"

        -- `IAM JSON policy elements: Action
        <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html>`__
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


class EffectiveAction(EffectiveARP[Action]):
    """EffectiveActions are the representation of the difference between an Action and its exclusion.

    The allowed actions is the difference (subtraction) of the excluded Actions
    from the included action.
    """

    _arp_type = Action
