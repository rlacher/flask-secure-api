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
"""Unit tests for the request validators module."""
from unittest.mock import MagicMock
from pytest import raises
import pytest

from auth.validators.request import (
    Credentials,
    validate_authorisation_header,
    validate_credentials_payload,
)


class TestValidateAuthorisationHeader:
    """Unit tests for the validate_authorisation_header function."""

    @pytest.mark.parametrize(
        "auth_header, expected_token",
        [
            ("Bearer valid_token", "valid_token"),
            ("Bearer    valid_token  ", "valid_token"),  # Extra spaces
        ],
    )
    def test_valid_header(self, auth_header, expected_token):
        """Tests that a valid Authorization header is parsed correctly."""
        token = validate_authorisation_header(auth_header)
        assert token == expected_token

    @pytest.mark.parametrize(
        "invalid_auth_header, error_type",
        [
            (None, TypeError),  # Missing header
            ("token_no_prefix", ValueError),  # Missing Bearer prefix
            ("Bearer ", ValueError)  # Missing token
        ]
    )
    def test_invalid_header(self, invalid_auth_header, error_type):
        """Tests invalid Authorization headers raise correct error."""
        with raises(error_type):
            validate_authorisation_header(invalid_auth_header)


class TestValidateCredentialsPayload:
    """Unit tests for the validate_credentials_payload function.

    Testing the public interface, tests also implicitly verify non-mocked
    _validate_json_payload() function.
    """

    def test_valid_payload(self):
        """Tests valid JSON payload parsing into a Credentials object."""
        mock_request = MagicMock()
        valid_payload = {
            "username": "test_user",
            "password": "test_password"
        }
        mock_request.get_json.return_value = valid_payload

        validated_credentials = validate_credentials_payload(mock_request)

        assert validated_credentials == Credentials(**valid_payload)

    @pytest.mark.parametrize(
        "invalid_payload, error_type",
        [
            (None, TypeError),  # Missing payload
            ({}, ValueError),  # Empty payload
            ({"username": "valid_user"}, ValueError),  # Missing key
            ({"username": 1, "password": "pw"}, ValueError)  # Wrong type
        ]
    )
    def test_invalid_payload(self, invalid_payload, error_type):
        """Tests that invalid JSON payloads raise the correct error."""
        mock_request = MagicMock()
        mock_request.get_json.return_value = invalid_payload
        with raises(error_type):
            validate_credentials_payload(mock_request)
