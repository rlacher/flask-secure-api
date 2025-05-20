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
"""Unit tests for the user services in the authentication package.

Tests user registration, login and data access, verifying correct
responses for both successful and error scenarios.
"""
from unittest.mock import patch
from pytest import raises

from auth import services
from auth.exceptions import (
    SessionNotFoundError,
    UserAlreadyExistsError,
    UserDoesNotExistError,
    WrongPasswordError
)


class TestRegisterUser:
    """Tests the user registration functionality.

    This class contains test cases to verify the behaviour of the
    `register_user` function in different scenarios, including
    successful registration and handling of duplicate usernames.
    """

    @patch('auth.services.user.user_store.add_user', return_value=True)
    @patch(
        'auth.services.user.generate_password_hash',
        return_value="hashed_password"
    )
    def test_register_user_success(
        self,
        mock_generate_password_hash,
        mock_add_user
    ):
        """Tests the successful registration of a new user."""
        username = "new_user"
        password = "valid_password1"
        services.user.register_user(username,
                                    password)

        mock_generate_password_hash.assert_called_once_with(
            password
        )
        mock_add_user.assert_called_once_with(
            username,
            "hashed_password"
        )

    @patch('auth.services.user.user_store.add_user')
    def test_register_user_duplicate_username(self, mock_add_user):
        """Tests the registration of a user with an existing username."""
        mock_add_user.return_value = False
        with raises(UserAlreadyExistsError):
            services.user.register_user('existing_user',
                                        'password')


class TestLoginUser:
    """Tests the user login functionality.

    This class contains test cases to verify the behaviour of the
    `login_user` function in different scenarios, including successful
    login, wrong password, and non-existent user.
    """

    def test_login_user_success(self):
        """Tests the successful login of a user."""
        with (
            patch('auth.services.user.user_store.get_hashed_password')
            as mock_get_hashed_password,
            patch('auth.services.user.check_password_hash')
            as mock_check_password_hash
        ):
            mock_get_hashed_password.return_value = "hashed_password"
            mock_check_password_hash.return_value = True
            services.user.login_user('test_user',
                                     'correct_password')
            mock_check_password_hash.assert_called_once_with(
                'hashed_password',
                'correct_password'
            )

    def test_login_user_invalid_password(self):
        """Tests the login of a user with a wrong password."""
        with (
            patch('auth.services.user.user_store.get_hashed_password')
            as mock_get_hashed_password,
            patch('auth.services.user.check_password_hash')
            as mock_check_password_hash
        ):
            mock_get_hashed_password.return_value = "hashed_password"
            mock_check_password_hash.return_value = False
            with raises(WrongPasswordError):
                services.user.login_user('test_user',
                                         'wrong_password')
            mock_check_password_hash.assert_called_once_with(
                'hashed_password',
                'wrong_password'
            )

    def test_login_user_non_existent_user(self):
        """Tests the login of a non-existent user."""
        with raises(UserDoesNotExistError):
            services.user.login_user(
                'non_existent_user',
                'password'
            )

    @patch('auth.services.user.user_store.get_hashed_password')
    @patch('auth.services.user.check_password_hash')
    @patch('auth.services.user.session_store.create_session')
    def test_login_user_session_creation_fails(
        self,
        mock_create_session,
        mock_check_password_hash,
        mock_get_hashed_password
    ):
        """Tests login_user raises RuntimeError on session fail."""
        mock_get_hashed_password.return_value = "hashed_password"
        mock_check_password_hash.return_value = True
        mock_create_session.return_value = False

        with raises(RuntimeError):
            services.user.login_user(
                'valid_user',
                'valid_password'
            )


class TestGetProtectedData():
    """Tests the access to protected data.

    This class verifies get_protected_data() retrieves data for valid
    tokens and raises SessionNotFoundError for invalid ones.
    """

    @patch('auth.services.user.session_store.get_username_from_token')
    def test_get_protected_data_valid_token(self, mock_get_username):
        mock_get_username.return_value = "test_user"
        result = services.user.get_protected_data("token123")
        assert "Hello" in result and "test_user" in result
        mock_get_username.assert_called_once_with("token123")

    @patch(
        'auth.services.user.session_store.get_username_from_token',
        return_value=None
    )
    def test_get_protected_data_invalid_token(self, mock_get_username):
        with raises(SessionNotFoundError):
            services.user.get_protected_data("invalid_token")
        mock_get_username.assert_called_once_with("invalid_token")


class TestLogoutUser:
    "Tests the user logout functionality."""

    @patch(
        'auth.services.user.session_store.delete_session',
        return_value=True
    )
    def test_logout_user_success(self, mock_delete_session):
        """Tests the successful logout of a user."""
        token = "valid_token"
        services.user.logout_user(token)
        mock_delete_session.assert_called_once_with(token)

    @patch(
        'auth.services.user.session_store.delete_session',
        return_value=False
    )
    def test_logout_user_session_not_found(self, mock_delete_session):
        """Tests SessionNotFoundError is raised when token is not found."""
        token = "invalid_token"
        with raises(SessionNotFoundError):
            services.user.logout_user(token)
        mock_delete_session.assert_called_once_with(token)
