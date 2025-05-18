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
"""Integration tests for protected data access."""
from http import HTTPStatus

import pytest
from flask.testing import FlaskClient
from unittest.mock import patch, MagicMock
from werkzeug.security import generate_password_hash

from auth import services
from auth.models import (
    session_store,
    user_store
)
from auth.validators import validate_token


class TestProtectedAccess:
    """Tests the authenticated access to protected data.

    Verifies control and data flow between /protected and access_protected().
    """

    @pytest.fixture(autouse=True)
    def populate_user_store(self, valid_credentials):
        hashed_password = generate_password_hash(
            valid_credentials['password']
        )
        is_added = user_store.add_user(
            valid_credentials['username'],
            hashed_password
        )
        if not is_added:
            pytest.fail(
                "Failed to add user to user store during setup: " +
                valid_credentials['username']
            )

    @pytest.fixture
    def valid_session_token(self, valid_credentials):
        return "0" * 32

    @pytest.fixture(autouse=True)
    def populate_session_store(self, valid_credentials, valid_session_token):
        session_created = session_store.create_session(
            valid_credentials['username'],
            valid_session_token
        )
        if not session_created:
            pytest.fail(
                "Failed to create session during setup: " +
                f"{valid_credentials['username']}, {valid_session_token}"
            )

    def test_get_protected_data_success(
            self,
            client: FlaskClient,
            valid_session_token
    ):
        """Tests access of protected data with valid session token."""
        spied_validate_token = MagicMock(wraps=validate_token)
        spied_get_protected_data = MagicMock(
            wraps=services.user.get_protected_data
        )
        spied_get_username_from_token = MagicMock(
            wraps=session_store.get_username_from_token
        )

        with (
            patch(
                'auth.routes.user.validate_token',
                spied_validate_token
            ),
            patch(
                'auth.services.user.get_protected_data',
                spied_get_protected_data
            ),
            patch(
                'auth.services.user.session_store.get_username_from_token',
                spied_get_username_from_token
            )
        ):
            authorisation_header_value = f"Bearer {valid_session_token}"
            authorisation_header = {
                "Authorization": authorisation_header_value
            }
            response = client.get(
                "/protected", headers=authorisation_header
            )

            assert response.status_code == HTTPStatus.OK
            assert "message" in response.json
            assert b"Hello" in response.data
            spied_validate_token.assert_called_once_with(
                valid_session_token
            )
            spied_get_username_from_token.assert_called_once_with(
                valid_session_token
            )
            spied_get_protected_data.assert_called_once_with(
                valid_session_token
            )
