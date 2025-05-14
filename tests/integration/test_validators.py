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
"""Integration tests for the validators module."""
import pytest

from auth.validators import (
    validate_username,
    validate_password
)


class TestValidateUsername:
    """Tests for the validate_username function."""

    @pytest.mark.parametrize(
        "valid_username",
        [
            "valid_user_123",
            "usernameusernameuser",  # 20 chars (maximum length)
            "usr"  # 3 chars (minimum length)
        ],
    )
    def test_valid_username(self, valid_username):
        """Integration tests with valid usernames.

        Test that validate_username() returns the username for valid
        usernames.
        """
        assert validate_username(valid_username) == valid_username

    @pytest.mark.parametrize(
        "invalid_username",
        [
            "invalid-user",  # Hyphen
            "user!with$symbols",  # Symbols
            "very_long_username_exceeding_limit",  # Length > 20
            "ab",  # Length < 3
            "",  # Empty string
        ],
    )
    def test_invalid_username(self, invalid_username):
        """Integration tests for invalid usernames.

        Test that validate_username() raises ValueError for invalid
        usernames.
        """
        with pytest.raises(ValueError):
            validate_username(invalid_username)

    def test_username_none(self):
        """Integration test for undefined username.

        Tests that validate_username() raises TypeError when the
        username is None.
        """
        with pytest.raises(TypeError):
            validate_username(None)


class TestValidatePassword:
    """Tests for the validate_password function."""

    @pytest.mark.parametrize(
        "valid_password",
        [
            "password_1",
            "Password!2",
            "passworD3%",
            "PASSWORd^4",
            "5PASSword&",
            "*paSSwoRD6",
            "pass?-7WORD",
            "password#8",
            "1234$abcd",
            "12e456-8",  # 8 chars (minimum length)
            "Passw0rd-Passw0rd-Passw0rd-Passw0rd-Passw0rd-Passw0rd-" +
            "Passw0rd-P"  # 64 chars (maximum length)
        ],
    )
    def test_valid_password(self, valid_password):
        """Integration tests with valid passwords.

        Test that validate_password() returns the password for valid passwords.
        """
        assert validate_password(valid_password) == valid_password

    @pytest.mark.parametrize(
        "invalid_password",
        [
            "onlyletters",  # Only letters
            "onlylettersanddigit1",  # Only letters and digits
            "ONLYUPPERCASE",  # Only Uppercase
            "12345678",  # Only numbers
            "--------",  # Only symbols
            "invalid(specialchar",  # Prohibited special character
            "sh0rt-",  # Too short
            "too1long_too1long_too1long_too1long_too1long_too1long_" +
            "too1long_too1long",  # Too long
        ],
    )
    def test_invalid_password(self, invalid_password):
        """Integration tests for invalid passwords.

        Test that validate_password() raises ValueError for invalid passwords.
        """
        with pytest.raises(ValueError):
            validate_password(invalid_password)

    def test_password_none(self):
        """Integration test for undefined password.

        Test that validate_password() raises TypeError when the
        password is None.
        """
        with pytest.raises(TypeError):
            validate_password(None)
