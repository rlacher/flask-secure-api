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
"""Unit tests for the domain validators module.

Tests exercise public functions, implicitly verifying regex validation
via non-mocked _validate_regex() calls.
"""
import pytest

from auth.validators.domain import (
    validate_username,
    validate_password,
    validate_token
)


class TestValidateUsername:
    """Tests the validate_username function."""

    @pytest.mark.parametrize(
        "valid_username",
        [
            "valid_user_123",
            "usernameusernameuser",  # 20 chars (maximum length)
            "usr"  # 3 chars (minimum length)
        ],
    )
    def test_valid_username(self, valid_username):
        """Returns input for valid usernames."""
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
        """Raises ValueError for invalid usernames."""
        with pytest.raises(ValueError):
            validate_username(invalid_username)

    @pytest.mark.parametrize(
        "non_string_username",
        [
            None,
            123,
            4.56,
            True
        ],
    )
    def test_username_non_string(self, non_string_username):
        """Raises TypeError when username is not a string."""
        with pytest.raises(TypeError):
            validate_username(non_string_username)


class TestValidatePassword:
    """Tests the validate_password function."""

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
        """Returns input for valid passwords."""
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
        """Raises ValueError for invalid passwords."""
        with pytest.raises(ValueError):
            validate_password(invalid_password)

    @pytest.mark.parametrize(
        "non_string_password",
        [
            None,
            123,
            4.56,
            True
        ],
    )
    def test_password_non_string(self, non_string_password):
        """Raises TypeError when password is not a string."""
        with pytest.raises(TypeError):
            validate_password(non_string_password)


class TestValidateToken:
    """Tests the validate_token function."""

    @pytest.mark.parametrize(
        "valid_token",
        [
            "00000000000000000000000000000000",
            "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d",
            "abcdef0123456789fedcba9876543210",
            "99887766554433221100aabbccddeeff",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "1234567890abcdef1234567890abcdeF",
        ],
    )
    def test_valid_token(self, valid_token):
        """Returns input for valid tokens."""
        assert validate_token(valid_token) == valid_token

    @pytest.mark.parametrize(
        "invalid_token",
        [
            "",  # Empty string
            "1234567890abcdef1234567890abcd",  # Too short (31 chars)
            "1234567890abcdef1234567890abcdefg",  # Too long (33 chars)
            "invalid_chars_here!!!!_____",  # Invalid characters
        ],
    )
    def test_invalid_token(self, invalid_token):
        """Raises ValueError for invalid tokens."""
        with pytest.raises(ValueError):
            validate_token(invalid_token)

    @pytest.mark.parametrize(
        "non_string_token",
        [
            None,
            123,
            4.56,
            True
        ],
    )
    def test_token_non_string(self, non_string_token):
        """Raises TypeError when token is not a string."""
        with pytest.raises(TypeError):
            validate_token(non_string_token)
