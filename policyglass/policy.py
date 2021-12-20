"""Core Policy class."""
from typing import List, Optional

from pydantic import BaseModel

from .policy_shard import PolicyShard
from .statement import Statement
from .utils import to_pascal


class Policy(BaseModel):
    """Main policy class.

    Example:
        Create a policy from a dictionary.

            >>> from policyglass import Policy
            >>> Policy(**{
            ...     "Version": "2012-10-17",
            ...     "Statement": [
            ...         {
            ...             "Effect": "Allow",
            ...             "Action": [
            ...                 "s3:*"
            ...             ],
            ...             "Resource": "*"
            ...         }
            ...     ]
            ... })
            Policy(version='2012-10-17',
                statement=[Statement(effect='Allow',
                    action=[Action('s3:*')],
                    not_action=None,
                    resource=[Resource('*')],
                    not_resource=None, principal=None,
                    not_principal=None,
                    condition=None)])
    """

    version: Optional[str]
    statement: List[Statement]

    class Config:
        """Configure the pydantic BaseModel."""

        alias_generator = to_pascal

    @property
    def policy_shards(self) -> List[PolicyShard]:
        """Shatter this policy into a number :class:`policyglass.policy_shard` objects."""
        result = []
        for statement in self.statement:
            result.extend(statement.policy_shards)
        return result

    def policy_json(self) -> str:
        """Return a valid policy JSON from this policy."""
        return self.json(by_alias=True, exclude_none=True)
