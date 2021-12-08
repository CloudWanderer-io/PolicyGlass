"""Core Policy class."""
from typing import List

from pydantic import BaseModel

from .statement import Statement
from .utils import to_pascal


class Policy(BaseModel):
    """Main policy class."""

    version: str
    statement: List[Statement]

    class Config:
        """Configure the pydantic BaseModel."""

        alias_generator = to_pascal

    def policy_json(self) -> str:
        return self.json(by_alias=True, exclude_none=True)
