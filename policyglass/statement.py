from typing import Dict, List, Optional, Union
from pydantic import BaseModel, validator
from .utils import to_camel


class RawEffect(str):
    ...


class RawAction(str):
    ...


class RawResource(str):
    ...


class RawPrincipal(str):
    ...


class RawConditionKey(str):
    ...


class RawConditionOperator(str):
    ...


class RawConditionValue(str):
    ...


class Condition(BaseModel):
    __root__: Dict[str, Dict[str, Union[str, List[str]]]]


class Statement(BaseModel):
    effect: RawEffect
    action: Optional[List[RawAction]]
    not_action: Optional[List[RawAction]]
    resource: Optional[List[RawResource]]
    not_resource: Optional[List[RawResource]]
    condition: Optional[Dict[RawConditionOperator, Dict[RawConditionKey, List[RawConditionValue]]]]
    principal: Optional[Dict[str, List[RawPrincipal]]]
    not_principal: Optional[Dict[str, List[RawPrincipal]]]

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
