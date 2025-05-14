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
    error as re_error,
    compile
)
from typing import Final

logger = logging.getLogger(__name__)


def validate_regex(input: str, regex: str, info: str = None) -> str:
    """Validates input against a regular expression.

    Args:
        input (str): The input to validate.
        regex (str): The regular expression.
        info (str): Description of the expected pattern (optional).

    Returns:
        The validated input.

    Raises:
        TypeError: If input is not a string.
        re.error: If regex is not a valid regular expression.
        ValueError: If input does not match the pattern.
    """
    if not isinstance(input, str):
        raise TypeError(
            f"Must be a string, but got {type(input).__name__}"
        )

    # Relies on built-in caching
    compiled_pattern = compile(regex)

    if not compiled_pattern.fullmatch(input):
        value_error_message = "Invalid input"
        if info:
            value_error_message = f"Must be {info}"
        raise ValueError(value_error_message)

    logger.debug(f"input matches pattern: {input}")
    return input


def validate_username(username: str) -> str:
    """Validates a username.

    Internally delegates to validate_regex.

    Args:
        username (str): The username to validate.

    Returns:
        The validated username.

    Raises:
        TypeError: If the username is not a string.
        ValueError: If the username does not match the required pattern.
        (Implied from validate_regex)
    """
    USERNAME_REGEX: Final[str] = r'^[a-zA-Z0-9_]{3,20}$'
    USERNAME_INFO: Final[str] = "3-20 alphanumeric characters or underscore"

    try:
        validated_username = validate_regex(
            username,
            USERNAME_REGEX,
            USERNAME_INFO
        )
    except re_error as exception:
        logger.critical(
            f"Failed to compile regular expression: {USERNAME_REGEX}"
        )
        raise RuntimeError(
            "Internally-provided regular expression failed to compile."
        ) from exception

    return validated_username


def validate_password(password: str) -> str:
    """Validates a password.

    Internally delegates to validate_regex.

    Args:
        password (str): The password to validate.

    Returns:
        The validated password.

    Raises:
        TypeError: If the password is not a string.
        ValueError: If the password does not match the required pattern.
        (Implied from validate_regex)
    """
    PASSWORD_REGEX: Final[str] = (
        r'^(?=.*[a-zA-Z])'  # At least one letter
        r'(?=.*[0-9])'  # At least one digit
        r'(?=.*[!@#$%^&*?_-])'  # At least one special char
        r'[a-zA-Z0-9!@#$%^&*?_-]{8,64}$'  # 8-64 total chars
    )
    PASSWORD_INFO: Final[str] = (
        "8-64 characters, include a letter, digit, "
        "and special character (!@#$%^&*?_-)"
    )

    try:
        validated_password = validate_regex(
            password,
            PASSWORD_REGEX,
            PASSWORD_INFO
        )
    except re_error as exception:
        logger.critical(
            f"Failed to compile regular expression: {PASSWORD_REGEX}"
        )
        raise RuntimeError(
            "Internally-provided regular expression failed to compile."
        ) from exception

    return validated_password
