from typing import Dict, List, Optional, TypeVar, Union
from pydantic import BaseModel, validator

from .utils import to_camel


class Effect(str):
    ...


class CaseInsensitiveString(str):
    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            raise ValueError(f"Cannot compare {self.__class__} and {other.__class__}")
        return self.lower() == other.lower()


class Action(CaseInsensitiveString):
    """Actions are case insensitive.

    "The prefix and the action name are case insensitive"
    `IAM JSON policy elements: Action <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html`__
    """


class Resource(str):
    """A resource ARN may be case sensitive or case insensitive depending on the resource type."""


class PrincipalType(str):
    ...


class PrincipalValue(str):
    ...


class PrincipalsCollection(dict[PrincipalType, PrincipalValue]):
    ...


class ConditionKey(CaseInsensitiveString):
    """Condition Keys are case insensitive.

    "Condition key names are not case-sensitive."
    - `IAM Reference Policy Elements <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition.html>`__
    """

    ...


class ConditionOperator(CaseInsensitiveString):
    ...


class ConditionValue(str):
    """Condition values may or may not be case sensitive depending on the operator."""

    ...


class ConditionShard:
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

    def __eq__(self, other: "ConditionShard") -> bool:
        return self.key == other.key and self.operator == other.operator and self.values == other.values

    def __repr__(self):
        return (
            f"{self.__class__.__name__}(" f"key='{self.key}', " f"operator='{self.operator}', " f"values={self.values})"
        )


class Condition(dict[ConditionKey, dict[ConditionKey, List[ConditionValue]]]):
    @property
    def condition_shards(self) -> List[ConditionShard]:
        return ConditionShard.factory(self)

    def __eq__(self, other: "Condition") -> bool:
        return self.condition_shards == other.condition_shards


class Statement(BaseModel):
    effect: Effect
    action: Optional[List[Action]]
    not_action: Optional[List[Action]]
    resource: Optional[List[Resource]]
    not_resource: Optional[List[Resource]]
    principal: Optional[PrincipalsCollection[PrincipalType, List[PrincipalValue]]]
    not_principal: Optional[PrincipalsCollection[PrincipalType, List[PrincipalValue]]]
    condition: Optional[Condition[ConditionKey, dict[ConditionKey, List[ConditionValue]]]]

    class Config:
        alias_generator = to_camel

    def policy_json(self):
        return self.json(by_alias=True, exclude_none=True)

    @validator("action", "not_action", "resource", "not_resource", pre=True)
    def ensure_list(cls, v):
        if isinstance(v, list):
            return v
        return [v]

    @validator("condition", pre=True)
    def ensure_condition_value_list(cls, v):
        output = {}
        for operator, key_and_values in v.items():
            output[operator] = {}
            for key, values in key_and_values.items():
                if isinstance(values, list):
                    output[operator][key] = values
                else:
                    output[operator][key] = [values]
        return output

    @validator("principal", "not_principal", pre=True)
    def ensure_principal_dict(cls, v):
        if not isinstance(v, dict):
            return {"AWS", [v]}
        output = {}
        for principal_type, principals in v.items():
            if isinstance(principals, list):
                output[principal_type] = principals
            else:
                output[principal_type] = [principals]
        return output
