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
"""Integration tests for user registration."""
from http import HTTPStatus

from flask.testing import FlaskClient
from unittest.mock import patch, MagicMock

from auth import services
from auth.validators import domain as domain_validators


class TestRegisterEndpoint:
    """Tests the user registration process.

    Verifies control and data flow between /register and register_user().
    """

    def test_user_registration_success(
        self,
        client: FlaskClient,
        valid_credentials
    ):
        """Tests user registration with valid credentials."""
        spied_register_user = MagicMock(wraps=services.user.register_user)

        with patch('auth.services.user.register_user', spied_register_user):
            response = client.post("/register", json=valid_credentials)

            assert response.status_code == HTTPStatus.CREATED
            assert response.content_type == "application/json"
            spied_register_user.assert_called_once_with(
                valid_credentials['username'],
                valid_credentials['password']
            )

    def test_user_registration_invalid_username(
        self,
        client: FlaskClient
    ):
        """Tests the failure to register with an invalid username."""
        invalid_username_credentials = {
            "username": "invalid$username",
            "password": "valid_password1"
        }
        spied_validate_username = MagicMock(
            wraps=domain_validators.validate_username
        )

        with patch(
            'auth.routes.user.domain_validators.validate_username',
            spied_validate_username
        ):
            response = client.post(
                "/register", json=invalid_username_credentials
            )

            assert response.status_code == HTTPStatus.BAD_REQUEST
            assert response.content_type == "application/json"
            spied_validate_username.assert_called_once_with(
                invalid_username_credentials['username']
            )

    def test_user_registration_invalid_password(
        self,
        client: FlaskClient
    ):
        """Tests the failure to register with an invalid password."""
        invalid_password_credentials = {
            "username": "valid_username",
            "password": "invalidpassword"
        }
        spied_validate_password = MagicMock(
            wraps=domain_validators.validate_password
        )

        with patch(
            'auth.routes.user.domain_validators.validate_password',
            spied_validate_password
        ):
            response = client.post(
                "/register", json=invalid_password_credentials
            )

            assert response.status_code == HTTPStatus.BAD_REQUEST
            assert response.content_type == "application/json"
            spied_validate_password.assert_called_once_with(
                invalid_password_credentials['password']
            )

    def test_user_registration_duplicate(
        self,
        client: FlaskClient,
        valid_credentials
    ):
        """Tests the rejection of duplicate user registration."""
        spied_register_user = MagicMock(wraps=services.user.register_user)

        with patch('auth.services.user.register_user', spied_register_user):
            first_response = client.post(
                "/register", json=valid_credentials
            )
            second_response = client.post(
                "/register", json=valid_credentials
            )

            assert first_response.status_code == HTTPStatus.CREATED
            assert second_response.status_code == HTTPStatus.CONFLICT
            assert spied_register_user.call_count == 2
