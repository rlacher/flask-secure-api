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
from unittest.mock import patch, ANY
from werkzeug.exceptions import BadRequest, Conflict, Unauthorized

from auth import routes
from auth.exceptions import (
    SessionNotFoundError,
    UserAlreadyExistsError,
    WrongPasswordError
)
from auth.validators.request import Credentials


@patch('auth.routes.user.request_validators.validate_credentials_payload')
@patch('auth.routes.user.domain_validators.validate_username')
@patch('auth.routes.user.domain_validators.validate_password')
@patch('auth.routes.user.abort')
class TestAuthenticationRoutes:
    """Tests the user registration and login routes."""

    @staticmethod
    def create_app_for_testing():
        """Creates a test application with the authentication routes."""
        app = Flask(__name__)
        app.register_blueprint(routes.user.auth_bp)
        return app

    def get_service_method_target(self, endpoint: str):
        if endpoint == "/register":
            return "auth.services.user.register_user"
        elif endpoint == "/login":
            return "auth.services.user.login_user"
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
        app = TestAuthenticationRoutes.create_app_for_testing()
        return app.test_client()

    @pytest.fixture
    def user_credentials(self):
        """Fixture to provide user credentials for authentication."""
        return {"username": "new_user", "password": "secure_password1"}

    def test_register_user_success(
            self,
            mock_abort,
            mock_validate_password,
            mock_validate_username,
            mock_validate_credentials_payload,
            client: FlaskClient,
            user_credentials: dict,
    ):
        """Returns 201 if registration is successful."""
        mock_validate_credentials_payload.return_value = Credentials(
            **user_credentials
        )
        mock_validate_username.return_value = user_credentials['username']
        mock_validate_password.return_value = user_credentials['password']

        with patch('auth.services.user.register_user') as mock_register_user:
            response = client.post('/register', json=user_credentials)

            assert response.status_code == HTTPStatus.CREATED
            assert mock_abort.call_count == 0
            mock_validate_credentials_payload.assert_called_once()
            mock_validate_username.assert_called_once_with(
                user_credentials['username']
            )
            mock_validate_password.assert_called_once_with(
                user_credentials['password']
            )
            mock_register_user.assert_called_once_with(
                user_credentials["username"],
                user_credentials["password"]
            )

    @patch('auth.services.user.login_user', return_value="valid_token")
    def test_login_user_success(
            self,
            mock_login_user,
            mock_abort,
            mock_validate_password,
            mock_validate_username,
            mock_validate_credentials_payload,
            client: FlaskClient,
            user_credentials: dict,
    ):
        """Returns 200 if login is successful."""
        mock_validate_credentials_payload.return_value = Credentials(
            **user_credentials
        )
        mock_validate_username.return_value = user_credentials['username']
        mock_validate_password.return_value = user_credentials['password']

        response = client.post('/login', json=user_credentials)

        assert response.status_code == HTTPStatus.OK
        assert mock_abort.call_count == 0
        mock_validate_credentials_payload.assert_called_once()
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

    def test_register_user_already_exists(
            self,
            mock_abort,
            mock_validate_password,
            mock_validate_username,
            mock_validate_credentials_payload,
            client: FlaskClient,
            user_credentials: dict,
    ):
        """Returns 409 if the user already exists."""
        mock_validate_credentials_payload.return_value = Credentials(
            **user_credentials
        )
        mock_validate_username.return_value = user_credentials['username']
        mock_validate_password.return_value = user_credentials['password']
        mock_abort.side_effect = Conflict(description="User already exists")

        with patch("auth.services.user.register_user") as mock_register_user:
            mock_register_user.side_effect = UserAlreadyExistsError()

            response = client.post(
                '/register',
                json=user_credentials
            )

            mock_validate_credentials_payload.assert_called_once()
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
            mock_validate_credentials_payload,
            client: FlaskClient,
            user_credentials: dict
    ):
        """Returns 401 if the password is incorrect.

        From a route handler perspective, no distinction is necessary
        between a non-existent user and a wrong password.
        """
        mock_validate_credentials_payload.return_value = Credentials(
            **user_credentials
        )
        mock_validate_username.return_value = user_credentials['username']
        mock_validate_password.return_value = user_credentials['password']
        mock_abort.side_effect = Unauthorized(
            description="Invalid credentials (for testing)"
        )

        with patch("auth.services.user.login_user") as mock_login_user:
            mock_login_user.side_effect = WrongPasswordError()

            response = client.post('/login', json=user_credentials)

            mock_validate_credentials_payload.assert_called_once()
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
            mock_validate_credentials_payload,
            client: FlaskClient,
            user_credentials: dict,
            endpoint: str
    ):
        """Returns 400 if username is missing."""
        mock_validate_credentials_payload.side_effect = \
            ValueError("Missing required field: username")
        mock_abort.side_effect = BadRequest(description="Username is required")
        service_method_target = self.get_service_method_target(endpoint)

        with patch(service_method_target) as mock_service:
            response = client.post(
                endpoint,
                json={'password': user_credentials['password']}
            )

        assert mock_validate_credentials_payload.call_count == 1
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
            mock_validate_credentials_payload,
            client: FlaskClient,
            user_credentials: dict,
            endpoint: str
    ):
        """Returns 400 if password is missing."""
        mock_validate_credentials_payload.side_effect = \
            ValueError("Missing required field: password")
        mock_abort.side_effect = BadRequest(description="Password is required")
        service_method_target = self.get_service_method_target(endpoint)

        with patch(service_method_target) as mock_service:
            response = client.post(
                endpoint,
                json={'username': user_credentials['username']}
            )

        assert mock_validate_credentials_payload.call_count == 1
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
            mock_validate_credentials_payload,
            client: FlaskClient,
            user_credentials: dict,
            endpoint: str
    ):
        """Returns 400 if username is not a string."""
        non_string_username_credentials = {
            "username": 123,
            "password": user_credentials['password']
        }
        mock_validate_credentials_payload.side_effect = \
            ValueError("Field 'username' must be of type str.")
        abort_message = "Invalid username (for testing)"
        mock_abort.side_effect = BadRequest(description=abort_message)
        service_method_target = self.get_service_method_target(endpoint)

        with patch(service_method_target) as mock_service:
            response = client.post(
                endpoint,
                json=non_string_username_credentials
            )

            assert mock_validate_credentials_payload.call_count == 1
            assert mock_validate_username.call_count == 0
            assert mock_validate_password.call_count == 0
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
            mock_validate_credentials_payload,
            client: FlaskClient,
            user_credentials: dict,
            endpoint: str
    ):
        """Returns 400 if password is not a string."""
        non_string_username_credentials = {
            "username": user_credentials['username'],
            "password": 1.23
        }
        mock_validate_credentials_payload.side_effect = \
            ValueError("Field 'password' must be of type str.")
        abort_message = "Invalid password (for testing)"
        mock_abort.side_effect = BadRequest(description=abort_message)
        service_method_target = self.get_service_method_target(endpoint)

        with patch(service_method_target) as mock_service:
            response = client.post(
                endpoint,
                json=non_string_username_credentials
            )

            assert mock_validate_credentials_payload.call_count == 1
            assert mock_validate_password.call_count == 0
            assert mock_validate_username.call_count == 0
            assert mock_abort.call_count == 1
            assert mock_service.call_count == 0
            assert response.status_code == HTTPStatus.BAD_REQUEST
            assert abort_message.encode('utf-8') in response.data


@patch('auth.routes.user.request_validators.validate_authorisation_header')
@patch('auth.routes.user.domain_validators.validate_token')
@patch('auth.routes.user.abort')
class TestProtectedRoutes:
    """Tests the protected data access route."""

    @staticmethod
    def create_app_for_testing():
        """Creates a test application with the protected route."""
        app = Flask(__name__)
        app.register_blueprint(routes.user.protected_bp)
        return app

    @pytest.fixture
    def client(self):
        """Fixture to create a test client."""
        app = TestProtectedRoutes.create_app_for_testing()
        return app.test_client()

    @patch('auth.services.user.get_protected_data')
    def test_protected_success(
        self,
        mock_get_protected_data,
        mock_abort,
        mock_validate_token,
        mock_validate_auth_header,
        client: FlaskClient
    ):
        """Tests successful protected resource access."""
        mock_validate_auth_header.return_value = "token"
        mock_validate_token.return_value = "validated_token"
        mock_get_protected_data.return_value = "protected_message"

        response = client.get(
            '/protected',
            headers={"Authorization": "Bearer token"}
        )

        assert response.status_code == HTTPStatus.OK
        assert response.content_type == "application/json"
        assert "message" in response.json
        assert b"protected_message" in response.data
        mock_abort.assert_not_called()
        mock_validate_auth_header.assert_called_once_with("Bearer token")
        mock_validate_token.assert_called_once_with("token")
        mock_get_protected_data.assert_called_once_with("validated_token")

    @patch('auth.services.user.get_protected_data')
    def test_protected_missing_auth_header(
        self,
        mock_get_protected_data,
        mock_abort,
        mock_validate_token,
        mock_validate_auth_header,
        client: FlaskClient
    ):
        """Tests handling of missing Authorization header."""
        mock_validate_auth_header.side_effect = TypeError(
            "Authorization header is required."
        )
        mock_abort.side_effect = BadRequest()

        response = client.get('/protected')  # No Authorization header

        mock_abort.assert_called_once_with(
            HTTPStatus.BAD_REQUEST,
            "Authorization header is required."
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        mock_validate_token.assert_not_called()
        mock_get_protected_data.assert_not_called()

    @patch('auth.services.user.get_protected_data')
    def test_protected_no_bearer_prefix(
        self,
        mock_get_protected_data,
        mock_abort,
        mock_validate_token,
        mock_validate_auth_header,
        client: FlaskClient
    ):
        """Tests handling of missing 'Bearer ' prefix."""
        mock_validate_auth_header.side_effect = ValueError(
            "Authorization header must start with 'Bearer '."
        )
        mock_abort.side_effect = BadRequest()

        response = client.get(
            '/protected',
            headers={"Authorization": "token"}
        )

        mock_abort.assert_called_once_with(
            HTTPStatus.BAD_REQUEST,
            "Authorization header must start with 'Bearer '."
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        mock_validate_token.assert_not_called()
        mock_get_protected_data.assert_not_called()

    @patch('auth.services.user.get_protected_data')
    def test_protected_invalid_token(
        self,
        mock_get_protected_data,
        mock_abort,
        mock_validate_token,
        mock_validate_auth_header,
        client: FlaskClient
    ):
        """Tests handling of an invalid token format."""
        mock_validate_auth_header.return_value = "token"
        mock_validate_token.side_effect = ValueError("Invalid token")
        mock_abort.side_effect = BadRequest()

        response = client.get(
            '/protected',
            headers={"Authorization": "Bearer token"}
        )

        mock_abort.assert_called_once_with(
            HTTPStatus.BAD_REQUEST,
            ANY
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        mock_validate_token.assert_called_once_with("token")
        mock_get_protected_data.assert_not_called()

    @patch('auth.services.user.get_protected_data')
    def test_protected_unauthorised(
        self,
        mock_get_protected_data,
        mock_abort,
        mock_validate_token,
        mock_validate_auth_header,
        client: FlaskClient
    ):
        """Returns 401 if no valid session is found."""
        mock_validate_auth_header.return_value = "token"
        mock_get_protected_data.side_effect = SessionNotFoundError()
        mock_abort.side_effect = Unauthorized()

        response = client.get(
            '/protected',
            headers={"Authorization": "Bearer token"}
        )

        mock_abort.assert_called_once_with(
            HTTPStatus.UNAUTHORIZED,
            ANY
        )
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        mock_validate_token.assert_called_once_with("token")
        mock_get_protected_data.assert_called_once()

    @patch('auth.services.user.logout_user')
    def test_logout_success(
        self,
        mock_logout_user,
        mock_abort,
        mock_validate_token,
        mock_validate_auth_header,
        client: FlaskClient
    ):
        """Returns 200 if logout is successful."""
        mock_validate_auth_header.return_value = "token"
        mock_validate_token.return_value = "validated_token"

        response = client.post(
            '/logout',
            headers={"Authorization": "Bearer token"}
        )

        assert response.status_code == HTTPStatus.OK
        assert response.content_type == "application/json"
        assert "message" in response.json
        assert b"Logged out successfully." in response.data
        mock_abort.assert_not_called()
        mock_validate_auth_header.assert_called_once_with("Bearer token")
        mock_validate_token.assert_called_once_with("token")
        mock_logout_user.assert_called_once_with("validated_token")

    @patch('auth.services.user.logout_user')
    def test_logout_unauthorised(
        self,
        mock_logout_user,
        mock_abort,
        mock_validate_token,
        mock_validate_auth_header,
        client: FlaskClient
    ):
        """Returns 401 if no valid session is found."""
        mock_validate_auth_header.return_value = "token"
        mock_validate_token.return_value = "validated_token"
        mock_logout_user.side_effect = SessionNotFoundError()
        mock_abort.side_effect = Unauthorized()

        response = client.post(
            '/logout',
            headers={"Authorization": "Bearer token"}
        )

        mock_abort.assert_called_once_with(
            HTTPStatus.UNAUTHORIZED,
            ANY
        )
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        mock_validate_token.assert_called_once_with("token")
        mock_logout_user.assert_called_once_with(
            "validated_token"
        )
