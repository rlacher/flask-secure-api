# Copyright 2025 René Lacher

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Validators for user input."""
import logging
from re import (
    compile,
    Pattern
)
from typing import Final

USERNAME_PATTERN: Final[Pattern] = compile(
    r'^[a-zA-Z0-9_]{3,20}$'
)
PASSWORD_PATTERN: Final[Pattern] = compile(
    r'^(?=.*[a-zA-Z])'  # At least one letter
    r'(?=.*[0-9])'  # At least one digit
    r'(?=.*[!@#$%^&*?_-])'  # At least one special char
    r'[a-zA-Z0-9!@#$%^&*?_-]{8,64}$'  # 8-64 total chars
)
TOKEN_PATTERN: Final[Pattern] = compile(
    r'^[0-9a-fA-F]{32}$'
)

logger = logging.getLogger(__name__)


def _validate_regex(input: str, pattern: Pattern, error_info: str) -> str:
    """Validates input against a regular expression.

    Args:
        input (str): The input to validate.
        pattern (Pattern): The compiled regular expression pattern to apply.
        info (str): Human-readable description of the expected input format.
    Returns:
        The validated input.
    Raises:
        TypeError: If input is not a string.
        ValueError: If input does not match the pattern.
    """
    if not isinstance(input, str):
        raise TypeError(
            f"Must be a string, but got {type(input).__name__}"
        )

    if not pattern.fullmatch(input):
        raise ValueError(f"Must be {error_info}")

    logger.debug(f"Input matches pattern: {input}")
    return input


def validate_username(username: str) -> str:
    """Validates a username.

    Internally delegates to _validate_regex().

    Args:
        username (str): The username to validate.
    Returns:
        The validated username.
    Raises:
        TypeError: If the username is not a string.
        ValueError: If the username is invalid.
    """
    return _validate_regex(
        username,
        USERNAME_PATTERN,
        "3-20 alphanumeric characters or underscore"
    )


def validate_password(password: str) -> str:
    """Validates a password.

    Internally delegates to _validate_regex().

    Args:
        password (str): The password to validate.
    Returns:
        The validated password.
    Raises:
        TypeError: If the password is not a string.
        ValueError: If the password is invalid.
    """
    return _validate_regex(
        password,
        PASSWORD_PATTERN,
        "8-64 characters, including letter, digit, special (!@#$%^&*?_-)"
    )


def validate_token(token: str) -> str:
    """Validates a token.

    Internally delegates to _validate_regex().

    Args:
        token (str): The token to validate.
    Returns:
        The validated token.
    Raises:
        TypeError: If the token is not a string.
        ValueError: If the token is invalid.
    """
    return _validate_regex(
        token,
        TOKEN_PATTERN,
        "32-character hexadecimal string"
    )
