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
"""Integration tests for user logout."""
from http import HTTPStatus

from flask.testing import FlaskClient
from unittest.mock import patch, MagicMock

from auth import services
from auth.models import session_store
from auth.validators import (
    domain as domain_validators,
    request as request_validators
)


class TestLogoutEndpoint:
    """Tests the /logout endpoint for user logout functionality.

    This class verifies the control and data flow for the /logout endpoint,
    ensuring that user sessions are correctly terminated.
    """

    def test_logout_success(
            self,
            client: FlaskClient,
            valid_session_token,
            valid_auth_header,
            populate_session_store
    ):
        """Logs out a user with a valid session token."""
        spied_validate_token = MagicMock(
            wraps=domain_validators.validate_token
        )
        spied_logout_user = MagicMock(
            wraps=services.user.logout_user
        )
        spied_delete_session = MagicMock(
            wraps=session_store.delete_session
        )

        with (
            patch(
                'auth.routes.user.domain_validators.validate_token',
                spied_validate_token
            ),
            patch(
                'auth.services.user.logout_user',
                spied_logout_user
            ),
            patch(
                'auth.services.user.session_store.delete_session',
                spied_delete_session
            )
        ):
            response = client.post(
                "/logout", headers=valid_auth_header
            )

            assert response.status_code == HTTPStatus.OK
            assert response.content_type == "application/json"
            assert "message" in response.json
            assert b"Logged out successfully." in response.data
            spied_validate_token.assert_called_once_with(
                valid_session_token
            )
            spied_delete_session.assert_called_once_with(
                valid_session_token
            )
            spied_logout_user.assert_called_once_with(
                valid_session_token
            )

    def test_logout_blank_auth_header(
            self,
            client: FlaskClient
    ):
        """Rejects logout request with an invalid Authorization header."""
        spied_validate_auth_header = MagicMock(
            wraps=request_validators.validate_authorisation_header
        )
        spied_logout_user = MagicMock(
            wraps=services.user.logout_user
        )

        with (
            patch(
                'auth.routes.user.request_validators.' +
                'validate_authorisation_header',
                spied_validate_auth_header
            ),
            patch(
                'auth.services.user.logout_user',
                spied_logout_user
            )
        ):
            blank_auth_header = " "
            authorisation_header = {"Authorization": blank_auth_header}
            response = client.post(
                "/logout", headers=authorisation_header
            )

            assert response.status_code == HTTPStatus.BAD_REQUEST
            assert response.content_type == "application/json"
            assert "error" in response.json
            assert b"Authorization header must start with" in response.data
            spied_validate_auth_header.assert_called_once_with(
                 blank_auth_header
            )
            spied_logout_user.assert_not_called()
