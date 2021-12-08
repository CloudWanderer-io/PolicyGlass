"""Utilities for PolicyGlass."""


def to_pascal(string: str) -> str:
    """Convert a snake_case string into a PascalCase string.

    Parameters:
        string: The string to convert to PascalCase.
    """
    return "".join(word.capitalize() for word in string.split("_"))
