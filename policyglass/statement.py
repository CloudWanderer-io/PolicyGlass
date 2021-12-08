"""Statement class."""

from fnmatch import fnmatch
from typing import Dict, List, Optional, TypeVar, Union

from pydantic import BaseModel, validator

from .models import CaseInsensitiveString
from .utils import to_pascal

T = TypeVar("T")


class Effect(str):
    """Allow or Deny."""

    ...


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


class Resource(str):
    """A resource ARN may be case sensitive or case insensitive depending on the resource type."""


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


class Statement(BaseModel):
    """A Policy Statement."""

    effect: Effect
    action: Optional[List[Action]]
    not_action: Optional[List[Action]]
    resource: Optional[List[Resource]]
    not_resource: Optional[List[Resource]]
    principal: Optional[PrincipalsCollection]
    not_principal: Optional[PrincipalsCollection]
    condition: Optional[Condition]

    class Config:
        """Configure the Pydantic BaseModel."""

        alias_generator = to_pascal

    def policy_json(self) -> str:
        return self.json(by_alias=True, exclude_none=True)

    @validator("action", "not_action", "resource", "not_resource", pre=True)
    def ensure_list(cls, v: T) -> List[T]:
        if isinstance(v, list):
            return v
        return [v]

    @validator("condition", pre=True)
    def ensure_condition_value_list(
        cls, v: Dict[ConditionKey, Dict[ConditionOperator, Union[ConditionValue, List[ConditionValue]]]]
    ) -> Dict[ConditionKey, Dict[ConditionOperator, List[ConditionValue]]]:
        output: Dict = {}
        for operator, key_and_values in v.items():
            output[operator] = {}
            for key, values in key_and_values.items():
                if isinstance(values, list):
                    output[operator][key] = values
                else:
                    output[operator][key] = [values]
        return output

    @validator("principal", "not_principal", pre=True)
    def ensure_principal_dict(
        cls, v: Union[PrincipalValue, Dict[PrincipalType, Union[PrincipalValue, List[PrincipalValue]]]]
    ) -> Dict[PrincipalType, List[PrincipalValue]]:
        if not isinstance(v, dict):
            return {PrincipalType("AWS"): [PrincipalValue(v)]}
        output = dict()
        for principal_type, principals in v.items():
            if isinstance(principals, list):
                output[principal_type] = principals
            else:
                output[principal_type] = [principals]
        return output
