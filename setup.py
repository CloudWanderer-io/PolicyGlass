#!/usr/bin/env python
"""Setup CloudWanderer package."""
import re
from os import path

from setuptools import find_packages, setup

this_directory = path.abspath(path.dirname(__file__))
with open(path.join(this_directory, "README.rst"), encoding="utf-8") as f:
    long_description = re.sub(r"..\s+doctest\s+::", ".. code-block ::", f.read())

setup(
    version="0.1.0",
    python_requires=">=3.6.0",
    name="policyglass",
    packages=find_packages(include=["policyglass", "policyglass.*"]),
    description="Understand the effective permissions of your policies",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    author="Sam Martin",
    author_email="samjackmartin+policyglass@gmail.com",
    url="https://github.com/CloudWanderer-io/PolicyGlass",
    install_requires=["pydantic"],
    package_data={
        "": ["py.typed"],
    },
)
