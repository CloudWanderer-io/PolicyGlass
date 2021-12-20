"""Statement Condition classes."""


from typing import Dict, List

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


class ConditionValue(str):
    """Condition values may or may not be case sensitive depending on the operator."""


class Condition(BaseModel):
    """A representation of part of a statement condition in order to facilitate comparison."""

    key: ConditionKey
    operator: ConditionOperator
    values: List[ConditionValue]

    def __init__(self, key: ConditionKey, operator: ConditionOperator, values: List[ConditionValue]) -> None:
        super().__init__(
            key=key,
            operator=operator,
            values=values,
        )

    @classmethod
    def factory(cls, condition_collection: "ConditionCollection") -> List["Condition"]:
        result = []
        for operator, operator_values in condition_collection.items():
            for key, values in operator_values.items():
                result.append(
                    cls(
                        key=ConditionKey(key),
                        operator=ConditionOperator(operator),
                        values=[ConditionValue(value) for value in values],
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

    def __hash__(self) -> int:
        """Return a hash representation of this object."""
        return hash(self.__repr__())

    def __str__(self) -> str:
        """Return a string representation of this object."""
        return f"{self.key} {self.operator} {self.values}"


class ConditionCollection(Dict[ConditionKey, Dict[ConditionOperator, List[ConditionValue]]]):
    """A representation of a statement condition."""

    @property
    def conditions(self) -> List[Condition]:
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
