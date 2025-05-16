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

"""Unit tests for the user routes in the authentication package.

Tests registration, login, and other user operations, ensuring correct
responses for both successful and error scenarios.

Note that these tests involve interaction with the Flask test client to
simulate HTTP requests, so they have a degree of framework involvement.
The internal dependencies (e.g. services) are mocked to isolate the route
handler's logic.
"""
from http import HTTPStatus

from flask import Flask
from flask.testing import FlaskClient
import pytest
from unittest.mock import patch
from werkzeug.exceptions import BadRequest, Conflict, Unauthorized

from auth import routes
from auth.exceptions import (
    UserAlreadyExistsError,
    WrongPasswordError
)


@patch('auth.routes.user.validate_username')
@patch('auth.routes.user.validate_password')
@patch('auth.routes.user.abort')
class TestRoutesAuthentication:
    """Tests the user registration and login routes."""

    def create_app_for_testing(self):
        """Create application for testing (no custom error handler)."""
        app = Flask(__name__)
        app.register_blueprint(routes.user.auth_bp)
        return app

    def get_service_method_target(self, endpoint: str):
        if endpoint == "/register":
            return "auth.services.user.register_user"
        elif endpoint == "/login":
            return "auth.services.user.login_user"
        return None

    def get_http_status_success(self, endpoint: str):
        if endpoint == "/register":
            return HTTPStatus.CREATED
        elif endpoint == "/login":
            return HTTPStatus.OK
        return None

    def get_http_status_failure(self, endpoint: str):
        if endpoint == "/register":
            return HTTPStatus.CONFLICT
        elif endpoint == "/login":
            return HTTPStatus.UNAUTHORIZED
        return None

    @pytest.fixture
    def client(self):
        """Fixture to create a test client."""
        app = self.create_app_for_testing()
        return app.test_client()

    @pytest.fixture
    def user_credentials(self):
        """Fixture to provide user credentials for authentication."""
        return {"username": "new_user", "password": "secure_password1"}

    @pytest.mark.parametrize(
        "endpoint",
        [
            "/register",
            "/login",
        ]
    )
    def test_service_method_success(
            self,
            mock_abort,
            mock_validate_password,
            mock_validate_username,
            client: FlaskClient,
            user_credentials: dict,
            endpoint: str,
    ):
        """Tests successful authentication using service methods."""
        mock_validate_username.return_value = user_credentials['username']
        mock_validate_password.return_value = user_credentials['password']
        service_method_target = self.get_service_method_target(endpoint)

        with patch(service_method_target) as mock_service:
            response = client.post(endpoint, json=user_credentials)

            assert response.status_code == \
                self.get_http_status_success(endpoint)
            assert mock_abort.call_count == 0
            mock_validate_username.assert_called_once_with(
                user_credentials['username']
            )
            mock_validate_password.assert_called_once_with(
                user_credentials['password']
            )
            mock_service.assert_called_once_with(
                user_credentials["username"],
                user_credentials["password"]
            )

    def test_register_user_already_exists(
            self,
            mock_abort,
            mock_validate_password,
            mock_validate_username,
            client: FlaskClient,
            user_credentials: dict,
    ):
        """Tests registration when user already exists."""
        mock_validate_username.return_value = user_credentials['username']
        mock_validate_password.return_value = user_credentials['password']
        mock_abort.side_effect = Conflict(description="User already exists")

        with patch("auth.services.user.register_user") as mock_register_user:
            mock_register_user.side_effect = UserAlreadyExistsError()

            response = client.post(
                '/register',
                json=user_credentials
            )

            mock_register_user.assert_called_once_with(
                user_credentials["username"],
                user_credentials["password"]
            )
            assert mock_abort.call_count == 1
            mock_validate_username.assert_called_once_with(
                user_credentials['username']
            )
            mock_validate_password.assert_called_once_with(
                user_credentials['password']
            )
            assert response.status_code == HTTPStatus.CONFLICT

    def test_login_wrong_password(
            self,
            mock_abort,
            mock_validate_password,
            mock_validate_username,
            client: FlaskClient,
            user_credentials: dict
    ):
        """Tests login with an incorrect password.

        From a route handler perspective, no distinction is necessary
        between a non-existent user and a wrong password.
        """
        mock_validate_username.return_value = user_credentials['username']
        mock_validate_password.return_value = user_credentials['password']
        mock_abort.side_effect = Unauthorized(
            description="Invalid credentials (for testing)"
        )

        with patch("auth.services.user.login_user") as mock_login_user:
            mock_login_user.side_effect = WrongPasswordError()

            response = client.post('/login', json=user_credentials)

            mock_validate_username.assert_called_once_with(
                user_credentials['username']
            )
            mock_validate_password.assert_called_once_with(
                user_credentials['password']
            )
            mock_login_user.assert_called_once_with(
                user_credentials["username"],
                user_credentials["password"]
            )
            assert mock_abort.call_count == 1
            assert response.status_code == HTTPStatus.UNAUTHORIZED

    @pytest.mark.parametrize(
        "endpoint",
        [
            "/register",
            "/login",
        ]
    )
    def test_service_method_missing_username(
            self,
            mock_abort,
            mock_validate_password,
            mock_validate_username,
            client: FlaskClient,
            user_credentials: dict,
            endpoint: str
    ):
        """Tests service methods with missing username."""
        mock_abort.side_effect = BadRequest(description="Username is required")
        service_method_target = self.get_service_method_target(endpoint)

        with patch(service_method_target) as mock_service:
            response = client.post(
                endpoint,
                json={'password': user_credentials['password']}
            )

        assert mock_abort.call_count == 1
        assert mock_service.call_count == 0
        assert mock_validate_username.call_count == 0
        assert mock_validate_password.call_count == 0
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert b"Username is required" in response.data

    @pytest.mark.parametrize(
        "endpoint",
        [
            "/register",
            "/login",
        ]
    )
    def test_service_method_missing_password(
            self,
            mock_abort,
            mock_validate_password,
            mock_validate_username,
            client: FlaskClient,
            user_credentials: dict,
            endpoint: str
    ):
        """Tests service methods with missing password."""
        mock_abort.side_effect = BadRequest(description="Password is required")
        service_method_target = self.get_service_method_target(endpoint)

        with patch(service_method_target) as mock_service:
            response = client.post(
                endpoint,
                json={'username': user_credentials['username']}
            )

        assert mock_abort.call_count == 1
        assert mock_service.call_count == 0
        assert mock_validate_username.call_count == 0
        assert mock_validate_password.call_count == 0
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert b"Password is required" in response.data

    @pytest.mark.parametrize(
        "endpoint",
        [
            "/register",
            "/login",
        ]
    )
    def test_service_method_non_string_username(
            self,
            mock_abort,
            mock_validate_password,
            mock_validate_username,
            client: FlaskClient,
            user_credentials: dict,
            endpoint: str
    ):
        """Tests service methods with a non-string username."""
        non_string_username_credentials = {
            "username": 123,
            "password": user_credentials['password']
        }
        mock_validate_username.side_effect = \
            TypeError("Must be a string (for testing)")
        abort_message = "Invalid username (for testing)"
        mock_abort.side_effect = BadRequest(description=abort_message)
        service_method_target = self.get_service_method_target(endpoint)

        with patch(service_method_target) as mock_service:
            response = client.post(
                endpoint,
                json=non_string_username_credentials
            )

            mock_validate_username.assert_called_once_with(
                non_string_username_credentials['username']
            )
            assert mock_abort.call_count == 1
            assert mock_service.call_count == 0
            assert response.status_code == HTTPStatus.BAD_REQUEST
            assert abort_message.encode('utf-8') in response.data

    @pytest.mark.parametrize(
        "endpoint",
        [
            "/register",
            "/login",
        ]
    )
    def test_service_method_non_string_password(
            self,
            mock_abort,
            mock_validate_password,
            mock_validate_username,
            client: FlaskClient,
            user_credentials: dict,
            endpoint: str
    ):
        """Tests service methods with a non-string password."""
        non_string_username_credentials = {
            "username": user_credentials['username'],
            "password": 1.23
        }
        mock_validate_password.side_effect = \
            TypeError("Must be a string (for testing)")
        abort_message = "Invalid password (for testing)"
        mock_abort.side_effect = BadRequest(description=abort_message)
        service_method_target = self.get_service_method_target(endpoint)

        with patch(service_method_target) as mock_service:
            response = client.post(
                endpoint,
                json=non_string_username_credentials
            )

            mock_validate_password.assert_called_once_with(
                non_string_username_credentials['password']
            )
            assert mock_abort.call_count == 1
            assert mock_service.call_count == 0
            assert response.status_code == HTTPStatus.BAD_REQUEST
            assert abort_message.encode('utf-8') in response.data
