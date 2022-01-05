"""Statement Condition classes."""


from typing import Dict, FrozenSet, List, NamedTuple, Optional

from pydantic import BaseModel

from .models import CaseInsensitiveString


class ConditionKey(CaseInsensitiveString):
    """Condition Keys are case insensitive.

    "Condition key names are not case-sensitive."
    - `IAM Reference Policy Elements
    <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html>`__
    """

    ...


class ConditionOperator(CaseInsensitiveString):
    """Condition Operator.

    See `IAM JSON policy elements: Condition operators
    <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html>`__
    for more.
    """


#: A list of operators and their opposite.
OPERATOR_REVERSAL_INDEX = {
    ConditionOperator("StringEquals"): ConditionOperator("StringNotEquals"),
    ConditionOperator("StringEqualsIfExists"): ConditionOperator("StringNotEqualsIfExists"),
    ConditionOperator("StringNotEquals"): ConditionOperator("StringEquals"),
    ConditionOperator("StringNotEqualsIfExists"): ConditionOperator("StringEqualsIfExists"),
    ConditionOperator("StringEqualsIgnoreCase"): ConditionOperator("StringNotEqualsIgnoreCase"),
    ConditionOperator("StringEqualsIgnoreCaseIfExists"): ConditionOperator("StringNotEqualsIgnoreCaseIfExists"),
    ConditionOperator("StringNotEqualsIgnoreCase"): ConditionOperator("StringEqualsIgnoreCase"),
    ConditionOperator("StringNotEqualsIgnoreCaseIfExists"): ConditionOperator("StringEqualsIgnoreCaseIfExists"),
    ConditionOperator("StringLike"): ConditionOperator("StringNotLike"),
    ConditionOperator("StringLikeIfExists"): ConditionOperator("StringNotLikeIfExists"),
    ConditionOperator("StringNotLike"): ConditionOperator("StringLike"),
    ConditionOperator("StringNotLikeIfExists"): ConditionOperator("StringLikeIfExists"),
    ConditionOperator("NumericEquals"): ConditionOperator("NumericNotEquals"),
    ConditionOperator("NumericEqualsIfExists"): ConditionOperator("NumericNotEqualsIfExists"),
    ConditionOperator("NumericNotEquals"): ConditionOperator("NumericEquals"),
    ConditionOperator("NumericNotEqualsIfExists"): ConditionOperator("NumericEqualsIfExists"),
    ConditionOperator("NumericLessThan"): ConditionOperator("NumericGreaterThanEquals"),
    ConditionOperator("NumericLessThanIfExists"): ConditionOperator("NumericGreaterThanEqualsIfExists"),
    ConditionOperator("NumericGreaterThan"): ConditionOperator("NumericLessThanEquals"),
    ConditionOperator("NumericGreaterThanIfExists"): ConditionOperator("NumericLessThanEqualsIfExists"),
    ConditionOperator("NumericLessThanEquals"): ConditionOperator("NumericGreaterThan"),
    ConditionOperator("NumericLessThanEqualsIfExists"): ConditionOperator("NumericGreaterThanIfExists"),
    ConditionOperator("NumericGreaterThanEquals"): ConditionOperator("NumericLessThan"),
    ConditionOperator("NumericGreaterThanEqualsIfExists"): ConditionOperator("NumericLessThanIfExists"),
    ConditionOperator("DateEquals"): ConditionOperator("DateNotEquals"),
    ConditionOperator("DateEqualsIfExists"): ConditionOperator("DateNotEqualsIfExists"),
    ConditionOperator("DateNotEquals"): ConditionOperator("DateEquals"),
    ConditionOperator("DateNotEqualsIfExists"): ConditionOperator("DateEqualsIfExists"),
    ConditionOperator("DateLessThan"): ConditionOperator("DateGreaterThanEquals"),
    ConditionOperator("DateLessThanIfExists"): ConditionOperator("DateGreaterThanEqualsIfExists"),
    ConditionOperator("DateGreaterThan"): ConditionOperator("DateLessThanEquals"),
    ConditionOperator("DateGreaterThanIfExists"): ConditionOperator("DateLessThanEqualsIfExists"),
    ConditionOperator("DateLessThanEquals"): ConditionOperator("DateGreaterThan"),
    ConditionOperator("DateLessThanEqualsIfExists"): ConditionOperator("DateGreaterThanIfExists"),
    ConditionOperator("DateGreaterThanEquals"): ConditionOperator("DateLessThan"),
    ConditionOperator("DateGreaterThanEqualsIfExists"): ConditionOperator("DateLessThanIfExists"),
    ConditionOperator("IpAddress"): ConditionOperator("NotIpAddress"),
    ConditionOperator("IpAddressIfExists"): ConditionOperator("NotIpAddressIfExists"),
    ConditionOperator("NotIpAddress"): ConditionOperator("IpAddress"),
    ConditionOperator("NotIpAddressIfExists"): ConditionOperator("IpAddressIfExists"),
    ConditionOperator("ArnEquals"): ConditionOperator("ArnNotEquals"),
    ConditionOperator("ArnEqualsIfExists"): ConditionOperator("ArnNotEqualsIfExists"),
    ConditionOperator("ArnNotEquals"): ConditionOperator("ArnEquals"),
    ConditionOperator("ArnNotEqualsIfExists"): ConditionOperator("ArnEqualsIfExists"),
    ConditionOperator("ArnLike"): ConditionOperator("ArnNotLike"),
    ConditionOperator("ArnLikeIfExists"): ConditionOperator("ArnNotLikeIfExists"),
    ConditionOperator("ArnNotLike"): ConditionOperator("ArnLike"),
    ConditionOperator("ArnNotLikeIfExists"): ConditionOperator("ArnLikeIfExists"),
}


class ConditionValue(str):
    """Condition values may or may not be case sensitive depending on the operator."""


class Condition(BaseModel):
    """A representation of part of a statement condition in order to facilitate comparison."""

    key: ConditionKey
    operator: ConditionOperator
    values: List[ConditionValue]

    def __init__(self, key: ConditionKey, operator: ConditionOperator, values: List[ConditionValue]) -> None:
        super().__init__(
            key=ConditionKey(key),
            operator=ConditionOperator(operator),
            values=[ConditionValue(value) for value in values],
        )

    @property
    def reverse(self) -> "Condition":
        """Return a new condition which is the opposite of this condition.

        Raises:
            ValueError: If the operator is a type that cannot be reversed.
        """
        if self.operator in OPERATOR_REVERSAL_INDEX:
            return self.__class__(key=self.key, operator=OPERATOR_REVERSAL_INDEX[self.operator], values=self.values)
        raise ValueError(f"Cannot reverse conditions with operator {self.operator}")

    @classmethod
    def factory(cls, condition_collection: "RawConditionCollection") -> "FrozenSet[Condition]":
        result = set()
        for operator, operator_values in condition_collection.items():
            for key, values in operator_values.items():
                result.add(
                    cls(
                        key=ConditionKey(key),
                        operator=ConditionOperator(operator),
                        values=[ConditionValue(value) for value in values],
                    )
                )
        return frozenset(result)

    def __eq__(self, other: object) -> bool:
        """Determine whether this object and another object are equal.

        Parameters:
            other: The object to compare this one to.

        Raises:
            ValueError: When the object we are compared with is not of the same type.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot compare {self.__class__.__name__} and {other.__class__.__name__}")
        return self.key == other.key and self.operator == other.operator and self.values == other.values

    def __repr__(self) -> str:
        """Return an instantiable representation of the object."""
        return (
            f"{self.__class__.__name__}(" f"key='{self.key}', " f"operator='{self.operator}', " f"values={self.values})"
        )

    def __hash__(self) -> int:
        """Return a hash representation of this object."""
        return hash((self.key, self.operator, tuple(self.values)))

    def __str__(self) -> str:
        """Return a string representation of this object."""
        return f"{self.key} {self.operator} {self.values}"


class EffectiveCondition(NamedTuple):
    """A pair of sets for inclusions and exclusion conditions."""

    #: Conditions which must be met
    inclusions: FrozenSet[Condition]
    #: Conditions which must NOT be met
    exclusions: FrozenSet[Condition]

    @classmethod
    def factory(
        cls, inclusions: Optional[FrozenSet[Condition]] = None, exclusions: Optional[FrozenSet[Condition]] = None
    ) -> "EffectiveCondition":
        """Convert ``not_conditions`` to ``conditions`` if possible.

        Parameters:
            inclusions: The conditions that must be met.
            exclusions: The conditions that must NOT be met.
        """
        normalised_inclusions = set(inclusions or {})
        normalised_exclusions = set()

        for not_condition in exclusions or {}:
            try:
                normalised_inclusions.add(not_condition.reverse)
            except ValueError:
                normalised_exclusions.add(not_condition)
        return EffectiveCondition(frozenset(normalised_inclusions), frozenset(normalised_exclusions))


class RawConditionCollection(Dict[ConditionKey, Dict[ConditionOperator, List[ConditionValue]]]):
    """A representation of a statement condition."""

    @property
    def conditions(self) -> FrozenSet[Condition]:
        """Return a list of Condition Shards."""
        return Condition.factory(self)

    def __eq__(self, other: object) -> bool:
        """Determine whether this object and another object are equal.

        Parameters:
            other: The object to compare this one to.

        Raises:
            ValueError: When the object we are compared with is not of the same type.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot compare {self.__class__.__name__} and {other.__class__.__name__}")
        return self.conditions == other.conditions
