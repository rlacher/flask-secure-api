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

from flask.testing import FlaskClient
from unittest.mock import patch, MagicMock

from auth import services
from auth.exceptions import SessionNotFoundError
from auth.models import session_store
from auth.validators import domain as domain_validators


class TestProtectedDataEndpoint:
    """Tests the /protected endpoint for authenticated access.

    This class verifies control and data flow between the /protected route
    and the underlying authentication services.
    """

    def test_get_protected_data_success(
            self,
            client: FlaskClient,
            valid_session_token,
            valid_auth_header,
            populate_user_store,
            populate_session_store
    ):
        """Retrieves protected data with a valid session token."""
        spied_validate_token = MagicMock(
            wraps=domain_validators.validate_token
        )
        spied_get_protected_data = MagicMock(
            wraps=services.user.get_protected_data
        )
        spied_get_username_from_token = MagicMock(
            wraps=session_store.get_username_from_token
        )

        with (
            patch(
                'auth.routes.user.domain_validators.validate_token',
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
            response = client.get(
                "/protected", headers=valid_auth_header
            )

            assert response.status_code == HTTPStatus.OK
            assert response.content_type == "application/json"
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

    def test_get_protected_data_empty_session_store(
            self,
            client: FlaskClient,
            valid_session_token,
            valid_auth_header
    ):
        """Denies access to protected data without active session."""
        spied_get_protected_data = MagicMock(
            wraps=services.user.get_protected_data
        )
        spied_get_username_from_token = MagicMock(
            wraps=session_store.get_username_from_token
        )

        with (
            patch(
                'auth.services.user.get_protected_data',
                spied_get_protected_data
            ),
            patch(
                'auth.services.user.session_store.get_username_from_token',
                spied_get_username_from_token
            )
        ):
            response = client.get(
                "/protected", headers=valid_auth_header
            )

            assert response.status_code == HTTPStatus.UNAUTHORIZED
            assert response.content_type == "application/json"
            assert "error" in response.json
            error_data = SessionNotFoundError.description.encode('utf-8')
            assert error_data in response.data
            spied_get_username_from_token.assert_called_once_with(
                valid_session_token
            )
            spied_get_protected_data.assert_called_once_with(
                valid_session_token
            )
