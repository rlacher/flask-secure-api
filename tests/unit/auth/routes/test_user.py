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


def create_app_for_testing():
    """Create application for testing (no custom error handler)."""
    app = Flask(__name__)
    app.register_blueprint(routes.user.auth_bp)
    return app


class TestRoutesUserRegister:
    """Tests the user registration route."""

    @pytest.fixture
    def client(self):
        """Fixture to create a test client."""
        app = create_app_for_testing()
        return app.test_client()

    @pytest.fixture
    def registration_credentials(self):
        """Fixture to provide registration credentials."""
        return {"username": "new_user", "password": "secure_password"}

    @patch('auth.services.user.register_user')
    def test_register_success(self,
                              mock_register_user,
                              client: FlaskClient,
                              registration_credentials: dict):
        """Tests successful registration."""
        message = "User successfully registered"
        mock_register_user.return_value = (True, message)

        response = client.post('/register', json=registration_credentials)

        assert response.status_code == HTTPStatus.CREATED
        assert message.encode('utf-8') in response.data
        mock_register_user.assert_called_once_with(
            registration_credentials["username"],
            registration_credentials["password"],
            ANY
        )

    @patch('auth.services.user.register_user')
    @patch(
        'auth.routes.user.abort',
        side_effect=BadRequest(description="Username is required")
    )
    def test_register_missing_username(self,
                                       mock_abort,
                                       mock_register_user,
                                       client: FlaskClient,
                                       registration_credentials: dict):
        """Tests registration with missing username."""
        message = "Username is required"
        mock_register_user.return_value = (False, message)

        response = client.post(
            '/register',
            json={'password': registration_credentials['password']}
        )

        assert mock_abort.call_count == 1
        assert mock_register_user.call_count == 0
        assert response.status_code == HTTPStatus.BAD_REQUEST

    @patch('auth.services.user.register_user')
    @patch(
        'auth.routes.user.abort',
        side_effect=BadRequest(description="Password is required")
    )
    def test_register_missing_password(self,
                                       mock_abort,
                                       mock_register_user,
                                       client: FlaskClient,
                                       registration_credentials: dict):
        """Tests registration with missing password."""
        message = "Password is required"
        mock_register_user.return_value = (False, message)

        response = client.post(
            '/register',
            json={'username': registration_credentials['username']}
        )

        assert mock_abort.call_count == 1
        assert mock_register_user.call_count == 0
        assert response.status_code == HTTPStatus.BAD_REQUEST

    @patch('auth.services.user.register_user')
    @patch(
        'auth.routes.user.abort',
        side_effect=Conflict(description="User already exists")
    )
    def test_register_user_already_exists(self,
                                          mock_abort,
                                          mock_register_user,
                                          client: FlaskClient,
                                          registration_credentials: dict):
        """Tests registration when user already exists."""
        message = "User already exists"
        mock_register_user.return_value = (False, message)

        response = client.post('/register', json=registration_credentials)

        mock_register_user.assert_called_once_with(
            registration_credentials["username"],
            registration_credentials["password"],
            ANY,
        )
        assert mock_abort.call_count == 1
        assert response.status_code == HTTPStatus.CONFLICT


class TestRoutesUserLogin:
    """Tests the user login route."""

    @pytest.fixture
    def client(self):
        """Fixture to create a test client."""
        app = create_app_for_testing()
        return app.test_client()

    @pytest.fixture
    def login_credentials(self):
        """Fixture to provide login credentials."""
        return {"username": "test_user", "password": "secure_password"}

    @patch('auth.services.user.login_user')
    def test_login_success(self,
                           mock_login_user,
                           client: FlaskClient,
                           login_credentials: dict):
        """Tests successful login."""
        message = "Login successful"
        mock_login_user.return_value = (True, message)

        response = client.post('/login', json=login_credentials)

        assert response.status_code == HTTPStatus.OK
        assert message.encode('utf-8') in response.data
        mock_login_user.assert_called_once_with(
            login_credentials["username"],
            login_credentials["password"],
            ANY,
        )

    @patch('auth.services.user.login_user')
    @patch(
        'auth.routes.user.abort',
        side_effect=BadRequest(description="Username is required")
    )
    def test_login_missing_username(self,
                                    mock_abort,
                                    mock_login_user,
                                    client: FlaskClient,
                                    login_credentials: dict):
        """Tests login with missing username."""
        message = "Username is required"
        mock_login_user.return_value = (False, message)

        response = client.post(
            '/login',
            json={'password': login_credentials['password']}
        )

        assert mock_abort.call_count == 1
        assert mock_login_user.call_count == 0
        assert response.status_code == HTTPStatus.BAD_REQUEST

    @patch('auth.services.user.login_user')
    @patch(
        'auth.routes.user.abort',
        side_effect=BadRequest(description="Password is required")
    )
    def test_login_missing_password(self,
                                    mock_abort,
                                    mock_login_user,
                                    client: FlaskClient,
                                    login_credentials: dict):
        """Tests login with missing password."""
        message = "Password is required"
        mock_login_user.return_value = (False, message)

        response = client.post(
            '/login',
            json={'username': login_credentials['username']}
        )

        assert mock_abort.call_count == 1
        assert mock_login_user.call_count == 0
        assert response.status_code == HTTPStatus.BAD_REQUEST

    @patch('auth.services.user.login_user')
    @patch(
        'auth.routes.user.abort',
        side_effect=Unauthorized(description="Invalid credentials")
    )
    def test_login_invalid_credentials(self,
                                       mock_abort,
                                       mock_login_user,
                                       client: FlaskClient,
                                       login_credentials: dict):
        """Tests login with invalid credentials.

        From a route handler perspective, no distinction is necessary
        between a non-existent user and an invalid password.
        """
        message = "Invalid credentials"
        mock_login_user.return_value = (False, message)

        response = client.post('/login', json=login_credentials)

        mock_login_user.assert_called_once_with(
            login_credentials["username"],
            login_credentials["password"],
            ANY,
        )
        assert mock_abort.call_count == 1
        assert response.status_code == HTTPStatus.UNAUTHORIZED
