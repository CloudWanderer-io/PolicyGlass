from typing import List
from pydantic import BaseModel
from .statement import Statement
from .utils import to_camel


class Policy(BaseModel):
    version: str
    statement: List[Statement]

    class Config:
        alias_generator = to_camel

    def policy_json(self):
        return self.json(by_alias=True, exclude_none=True)
