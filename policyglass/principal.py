"""Principal classes."""
import json


class PrincipalType(str):
    """A principal type, e.g. Federated or AWS.

    See `AWS JSON policy elements: Principal
    <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html>`__
    for more.
    """


class PrincipalValue(str):
    """An ARN of wildcard of an policy Principal.

    See `AWS JSON policy elements: Principal
    <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html>`__
    for more.
    """


class Principal(dict[PrincipalType, PrincipalValue]):
    """A collection of Principals of different types, unique to PolicyGlass."""

    def __hash__(self) -> int:  # type: ignore[override]
        """Generate a hash for this principal."""
        return hash(json.dumps({"candidate": 5, "data": 1}, sort_keys=True))

    def __lt__(self, other: object) -> bool:
        """There is no scenario inn which a Principal can be said to contain another object.

        "You cannot use a wildcard to match part of a principal name or ARN."
        `AWS JSON policy elements: Principal
        <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html>`__

        Parameters:
            other: The object to see if this principal contains.
        """
        return False

    def __contains__(self, other: object) -> bool:
        """Not Implemented.

        Parameters:
            other: The object to see if this object contains.

        Raises:
            NotImplementedError: This method is not implemented.
        """
        raise NotImplementedError()
