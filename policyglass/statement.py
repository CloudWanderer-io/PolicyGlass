"""Statement class."""

from typing import Dict, FrozenSet, List, Optional, Tuple, TypeVar, Union

from pydantic import BaseModel, validator

from .action import Action, EffectiveAction
from .condition import Condition, ConditionCollection, ConditionKey, ConditionOperator, ConditionValue
from .policy_shard import PolicyShard
from .principal import EffectivePrincipal, Principal, PrincipalCollection, PrincipalType, PrincipalValue
from .resource import EffectiveResource, Resource
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
    principal: Optional[PrincipalCollection]
    not_principal: Optional[PrincipalCollection]
    condition: Optional[ConditionCollection]

    class Config:
        """Configure the Pydantic BaseModel."""

        alias_generator = to_pascal

    def policy_json(self) -> str:
        return self.json(by_alias=True, exclude_none=True)

    @property
    def policy_shards(self) -> List[PolicyShard]:
        conditions: FrozenSet[Condition] = frozenset({})
        not_principals: FrozenSet[Principal] = frozenset({})
        if self.condition:
            conditions = frozenset(self.condition.conditions)
        if self.not_principal:
            not_principals = frozenset(self.not_principal.principals)
        result = []
        arps = []
        for action in self.action or [Action("*")]:
            if self.principal:
                principals = self.principal.principals
            else:
                principals = [Principal(PrincipalType("AWS"), PrincipalValue("*"))]
            for principal in principals:
                for resource in self.resource or [Resource("*")]:
                    arp: Tuple[Action, Resource, Principal] = (action, resource, principal)
                    arps.append(arp)

        for action, resource, principal in arps:
            result.append(
                PolicyShard(
                    effect=self.effect,
                    effective_action=EffectiveAction(
                        action,
                        exclusions=frozenset(self.not_action or {}),
                    ),
                    effective_resource=EffectiveResource(
                        resource,
                        exclusions=frozenset(self.not_resource or {}),
                    ),
                    effective_principal=EffectivePrincipal(principal, exclusions=not_principals),
                    conditions=conditions,
                )
            )
        return result

    @validator("action", "not_action", pre=True)
    def ensure_action_list(cls, v: T) -> List[Action]:
        if isinstance(v, list):
            return [Action(action) for action in v]
        return [Action(v)]

    @validator("resource", "not_resource", pre=True)
    def ensure_resource_list(cls, v: T) -> List[Resource]:
        if isinstance(v, list):
            return [Resource(resource) for resource in v]
        return [Resource(v)]

    @validator("condition", pre=True)
    def ensure_condition_value_list(
        cls, v: Dict[ConditionKey, Dict[ConditionOperator, Union[ConditionValue, List[ConditionValue]]]]
    ) -> ConditionCollection:
        output: Dict = {}
        for operator, key_and_values in v.items():
            output[operator] = {}
            for key, values in key_and_values.items():
                if isinstance(values, list):
                    output[ConditionOperator(operator)][ConditionKey(key)] = values
                else:
                    output[ConditionOperator(operator)][ConditionKey(key)] = [values]
        return ConditionCollection(output)

    @validator("principal", "not_principal", pre=True)
    def ensure_principal_dict(
        cls, v: Union[PrincipalValue, Dict[PrincipalType, Union[PrincipalValue, List[PrincipalValue]]]]
    ) -> PrincipalCollection:
        if not isinstance(v, dict):
            return PrincipalCollection({PrincipalType("AWS"): [PrincipalValue(v)]})
        output = dict()
        for principal_type, principals in v.items():
            if isinstance(principals, list):
                output[principal_type] = principals
            else:
                output[principal_type] = [principals]
        return PrincipalCollection(output)
