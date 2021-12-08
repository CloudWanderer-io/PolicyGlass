"""Statement Condition classes."""


from typing import List

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


class ConditionValue(str):
    """Condition values may or may not be case sensitive depending on the operator."""


class ConditionShard:
    """A representation of part of a statement condition in order to faciltate comparison."""

    def __init__(self, key: ConditionKey, operator: ConditionOperator, values: List[ConditionValue]) -> None:
        self.key = key
        self.operator = operator
        self.values = values

    @classmethod
    def factory(cls, condition: "Condition") -> List["ConditionShard"]:
        result = []
        for key, operator_values in condition.items():
            for operator, values in operator_values.items():
                result.append(
                    ConditionShard(
                        ConditionKey(key), ConditionOperator(operator), [ConditionValue(value) for value in values]
                    )
                )
        return result

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


class Condition(dict[ConditionKey, dict[ConditionOperator, List[ConditionValue]]]):
    """A representation of a statement condition."""

    @property
    def condition_shards(self) -> List[ConditionShard]:
        """Return a list of Condition Shards."""
        return ConditionShard.factory(self)

    def __eq__(self, other: object) -> bool:
        """Determine whether this object and another object are equal.

        Parameters:
            other: The object to compare this one to.

        Raises:
            ValueError: When the object we are compared with is not of the same type.
        """
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot compare {self.__class__.__name__} and {other.__class__.__name__}")
        return self.condition_shards == other.condition_shards
