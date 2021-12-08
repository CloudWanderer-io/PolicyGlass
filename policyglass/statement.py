"""Statement class."""

from typing import Dict, List, Optional, TypeVar, Union

from pydantic import BaseModel, validator

from .action import Action
from .condition import Condition, ConditionKey, ConditionOperator, ConditionValue
from .principal import Principal, PrincipalType, PrincipalValue
from .resource import Resource
from .utils import to_pascal

T = TypeVar("T")


class Effect(str):
    """Allow or Deny."""

    ...


class Statement(BaseModel):
    """A Policy Statement."""

    effect: Effect
    action: Optional[List[Action]]
    not_action: Optional[List[Action]]
    resource: Optional[List[Resource]]
    not_resource: Optional[List[Resource]]
    principal: Optional[Principal]
    not_principal: Optional[Principal]
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
