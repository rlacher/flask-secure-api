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
"""Request validators for http-level validation of incoming requests."""
from typing import Any
from dataclasses import dataclass

from flask import Request

from auth.exceptions import ValidationError


@dataclass
class Credentials:
    """Encapsulates the credentials from an incoming request."""
    username: str
    password: str


def validate_authorisation_header(auth_header: str) -> str:
    """Extracts and validates the Authorization header.

    Validation covers the existence and format of the 'Bearer ' prefix.

    Raises:
        ValidationError: If 'Authorization' header is missing or does not
        follow Bearer <token> format.

    Returns:
        str: The extracted token.
    """
    if not auth_header:
        raise ValidationError("Authorization header required")

    if not auth_header.startswith("Bearer "):
        raise ValidationError(
            "Authorization header must start with 'Bearer '."
        )

    token = auth_header.removeprefix("Bearer ").strip()
    if not token:
        raise ValidationError("Authorization token required")

    return token


def validate_credentials_payload(request: Request) -> Credentials:
    """Validates user credentials from a request's payload.

    Wraps _validate_json_payload() for the specific use case of
    validating and extracting user credentials from the JSON payload.

    Args:
        request: The incoming Flask request object.
    Returns:
        Credentials: The parsed and validated credentials in a dedicated
        data class.
    """
    data = _validate_json_payload(
        request,
        ("username", "password"),
        (str, str)
    )
    return Credentials(**data)


def _validate_json_payload(
    request: Request,
    required_keys: list[str],
    required_types: list[type]
) -> dict[str, Any]:
    """
    Validates the JSON payload of an incoming request.

    Ensures that all required keys are present and have the expected types.

    Args:
        request: The incoming Flask request object.
        required_keys: List of expected keys in the payload.
        required_types: Corresponding list of expected types.

    Raises:
        ValidationError: If the request body is not valid JSON, any
        required key is missing or of the wrong type.

    Returns:
        dict[str, Any]: The parsed and validated JSON payload as a dictionary.
    """
    payload = request.get_json()
    if payload is None:
        raise ValidationError("Request body must be a valid JSON object.")

    for key, expected_type in zip(required_keys, required_types):
        if key not in payload:
            raise ValidationError(f"Missing required field: {key}")
        if not isinstance(payload[key], expected_type):
            raise ValidationError(
                f"Field '{key}' must be of type {expected_type.__name__}."
            )
    return payload
