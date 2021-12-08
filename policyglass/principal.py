"""Principal classes."""


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


class PrincipalsCollection(dict[PrincipalType, PrincipalValue]):
    """A collection of Principals of different types, unique to PolicyGlass."""
