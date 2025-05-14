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
"""Integration tests for user login."""
from http import HTTPStatus

import pytest
from flask.testing import FlaskClient
from unittest.mock import patch, ANY, MagicMock

from auth import services
from auth.models import memory_store
from auth.validators import (
    validate_username,
    validate_password
)


class TestUserLogin:
    """Tests the user login process.

    Verifies control and data flow between /login and login_user().
    """

    @pytest.fixture(autouse=True)
    def populate_user_store(self):
        memory_store.users["valid_username"] = "unused_password_hash"

    def test_user_login_success(
        self,
        client: FlaskClient,
        valid_credentials
    ):
        """Tests user login with valid credentials."""
        spied_login_user = MagicMock(wraps=services.user.login_user)
        mock_check_password_hash = MagicMock()
        mock_check_password_hash.return_value = True

        with (
            patch(
                'auth.services.user.login_user',
                spied_login_user
            ),
            patch(
                'auth.services.user.check_password_hash',
                mock_check_password_hash
            )
        ):
            response = client.post(
                "/login", json=valid_credentials
            )

            assert response.status_code == HTTPStatus.OK
            mock_check_password_hash.assert_called_once_with(
                memory_store.users[valid_credentials['username']],
                valid_credentials['password']
            )
            spied_login_user.assert_called_once_with(
                valid_credentials['username'],
                valid_credentials['password'],
                ANY
            )

    def test_user_login_invalid_username(
        self,
        client: FlaskClient
    ):
        """Tests user login with an invalid username."""
        spied_login_user = MagicMock(wraps=services.user.login_user)
        spied_validate_username = MagicMock(wraps=validate_username)
        invalid_username_credentials = {
            "username": "invalid$username",
            "password": "valid_password1"
        }

        with (
            patch(
                'auth.services.user.login_user',
                spied_login_user
            ),
            patch(
                'auth.routes.user.validate_username',
                spied_validate_username
            )
        ):
            reponse = client.post(
                "/login", json=invalid_username_credentials
            )

            assert reponse.status_code == HTTPStatus.BAD_REQUEST
            spied_validate_username.assert_called_once_with(
                invalid_username_credentials['username']
            )
            assert spied_login_user.call_count == 0

    def test_user_login_invalid_password(
        self,
        client: FlaskClient
    ):
        """Tests user login with an invalid username."""
        spied_login_user = MagicMock(wraps=services.user.login_user)
        spied_validate_password = MagicMock(wraps=validate_password)
        invalid_password_credentials = {
            "username": "valid_username",
            "password": "invalidpassword"
        }

        with (
            patch(
                'auth.services.user.login_user',
                spied_login_user
            ),
            patch(
                'auth.routes.user.validate_password',
                spied_validate_password
            )
        ):
            reponse = client.post(
                "/login", json=invalid_password_credentials
            )

            assert reponse.status_code == HTTPStatus.BAD_REQUEST
            spied_validate_password.assert_called_once_with(
                invalid_password_credentials['password']
            )
            assert spied_login_user.call_count == 0

    def test_user_login_unknown(
        self,
        client: FlaskClient
    ):
        """Tests user login with an unknown username."""
        spied_login_user = MagicMock(wraps=services.user.login_user)
        unknown_user_credentials = {
            "username": "unknown_user",
            "password": "valid_password1"
        }

        with patch(
            'auth.services.user.login_user',
            spied_login_user
        ):
            reponse = client.post(
                "/login", json=unknown_user_credentials
            )

            assert reponse.status_code == HTTPStatus.UNAUTHORIZED
            spied_login_user.assert_called_once_with(
                unknown_user_credentials['username'],
                unknown_user_credentials['password'],
                ANY
            )
