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

"""Unit tests for the `user` services in the authentication package.

Tests the user registration and login functionality, verifying correct
responses for both successful and error scenarios.
"""
from unittest.mock import patch
from auth import services


class TestServicesUserRegisterUser:
    """Tests the user registration functionality.

    This class contains test cases to verify the behaviour of the
    `register_user` function in different scenarios, including
    successful registration and handling of duplicate usernames.
    """

    def test_register_user_success(self):
        """Tests the successful registration of a new user."""
        empty_user_store = {}
        success, message = services.user.register_user('new_user',
                                                       'password',
                                                       empty_user_store)
        assert success is True
        assert message == 'User successfully registered'

    def test_register_user_duplicate_username(self):
        """Tests the registration of a user with an existing username."""
        user_store_with_user = {'existing_user': 'hashed_password'}
        success, message = services.user.register_user('existing_user',
                                                       'password',
                                                       user_store_with_user)
        assert success is False
        assert message == 'User already exists'


class TestServicesUserLoginUser:
    """Tests the user login functionality.

    This class contains test cases to verify the behaviour of the
    `login_user` function in different scenarios, including successful
    login, invalid password, and non-existent user.
    """

    def test_login_user_success(self):
        """Tests the successful login of a user."""
        user_store_with_user = {'test_user': 'hashed_password'}
        with patch('auth.services.user.check_password_hash') as mock_check:
            mock_check.return_value = True
            success, message = services.user.login_user('test_user',
                                                        'correct_password',
                                                        user_store_with_user)
            assert success is True
            assert message == 'Login successful'
            mock_check.assert_called_once_with('hashed_password',
                                               'correct_password')

    def test_login_user_invalid_password(self):
        """Tests the login of a user with an invalid password."""
        user_store_with_user = {'test_user': 'hashed_password'}
        with patch('auth.services.user.check_password_hash') as mock_check:
            mock_check.return_value = False
            success, message = services.user.login_user('test_user',
                                                        'wrong_password',
                                                        user_store_with_user)
            assert success is False
            assert message == 'Invalid password'
            mock_check.assert_called_once_with('hashed_password',
                                               'wrong_password')

    def test_login_user_non_existent_user(self):
        """Tests the login of a non-existent user."""
        empty_user_store = {}
        success, message = services.user.login_user('non_existent_user',
                                                    'password',
                                                    empty_user_store)
        assert success is False
        assert message == 'User does not exist'
