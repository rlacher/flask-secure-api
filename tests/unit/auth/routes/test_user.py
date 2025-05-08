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

from flask.testing import FlaskClient
import pytest
from unittest.mock import patch

from auth import create_app


class TestRoutesUserRegister:
    """Tests the user registration route."""

    @pytest.fixture
    def client(self):
        """Fixture to create a test client."""
        app = create_app()
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
        """Tests the registration route."""
        message = "User successfully registered"
        mock_register_user.return_value = (True, message)

        response = client.post('/register', json={
            'username': registration_credentials['username'],
            'password': registration_credentials['password']
        })

        assert response.status_code == HTTPStatus.CREATED
        assert message.encode('utf-8') in response.data
        assert mock_register_user.call_count == 1
        assert mock_register_user.call_args[0] == \
            (registration_credentials['username'],
             registration_credentials['password'])

    @patch('auth.services.user.register_user')
    def test_register_missing_username(self,
                                       mock_register_user,
                                       client: FlaskClient,
                                       registration_credentials: dict):
        """Tests the registration route with missing username."""
        message = "Username is required"
        mock_register_user.return_value = (False, message)

        response = client.post('/register', json={
            'password': registration_credentials['password']
        })

        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert message.encode('utf-8') in response.data
        assert mock_register_user.call_count == 0

    @patch('auth.services.user.register_user')
    def test_register_missing_password(self,
                                       mock_register_user,
                                       client: FlaskClient,
                                       registration_credentials: dict):
        """Tests the registration route with missing password."""
        message = "Password is required"
        mock_register_user.return_value = (False, message)

        response = client.post('/register', json={
            'username': registration_credentials['username']
        })

        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert message.encode('utf-8') in response.data
        assert mock_register_user.call_count == 0

    @patch('auth.services.user.register_user')
    def test_register_user_already_exists(self,
                                          mock_register_user,
                                          client: FlaskClient,
                                          registration_credentials: dict):
        """Tests the registration route when user already exists."""
        message = "User already exists"
        mock_register_user.return_value = (False, message)

        response = client.post('/register', json={
            'username': registration_credentials['username'],
            'password': registration_credentials['password']
        })

        assert response.status_code == HTTPStatus.CONFLICT
        assert message.encode('utf-8') in response.data
        assert mock_register_user.call_count == 1
        assert mock_register_user.call_args[0] == \
            (registration_credentials['username'],
             registration_credentials['password'])


class TestRoutesUserLogin:
    """Tests the user login route."""

    @pytest.fixture
    def client(self):
        """Fixture to create a test client."""
        app = create_app()
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
        """Tests the login route."""
        message = "Login successful"
        mock_login_user.return_value = (True, message)

        response = client.post('/login', json={
            'username': login_credentials['username'],
            'password': login_credentials['password']
        })

        assert response.status_code == HTTPStatus.OK
        assert message.encode('utf-8') in response.data
        assert mock_login_user.call_count == 1
        assert mock_login_user.call_args[0] == \
            (login_credentials['username'],
             login_credentials['password'])

    @patch('auth.services.user.login_user')
    def test_login_missing_username(self,
                                    mock_login_user,
                                    client: FlaskClient,
                                    login_credentials: dict):
        """Tests the login route with missing username."""
        message = "Username is required"
        mock_login_user.return_value = (False, message)

        response = client.post('/login', json={
            'password': login_credentials['password']
        })

        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert message.encode('utf-8') in response.data
        assert mock_login_user.call_count == 0

    @patch('auth.services.user.login_user')
    def test_login_missing_password(self,
                                    mock_login_user,
                                    client: FlaskClient,
                                    login_credentials: dict):
        """Tests the login route with missing password."""
        message = "Password is required"
        mock_login_user.return_value = (False, message)

        response = client.post('/login', json={
            'username': login_credentials['username']
        })

        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert message.encode('utf-8') in response.data
        assert mock_login_user.call_count == 0

    @patch('auth.services.user.login_user')
    def test_login_invalid_credentials(self,
                                       mock_login_user,
                                       client: FlaskClient,
                                       login_credentials: dict):
        """Tests the login route with invalid credentials.

        From a route handler perspective, no distinction is necessary
        between a non-existent user and an invalid password.
        """
        message = "Invalid credentials"
        mock_login_user.return_value = (False, message)

        response = client.post('/login', json={
            'username': login_credentials['username'],
            'password': login_credentials['password']
        })

        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert message.encode('utf-8') in response.data
        assert mock_login_user.call_count == 1
        assert mock_login_user.call_args[0] == \
            (login_credentials['username'],
             login_credentials['password'])
