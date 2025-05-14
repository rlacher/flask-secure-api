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
"""Unit tests for the validators module."""

from re import error as re_error

import pytest
from unittest.mock import patch

from auth.validators import (
    validate_regex,
    validate_username,
    validate_password
)


class TestValidateRegex:
    """Unit tests for the validate_regex function."""

    @pytest.mark.parametrize("text, regex, expected", [
        ("abc", r"^[a-z]+$", "abc"),
        ("123", r"^\d+$", "123"),
        ("a_b-c", r"^[a-zA-Z0-9_-]+$", "a_b-c"),
        ("abcd", r"[a-z]{4}", "abcd")
    ])
    def test_validate_regex_valid_text(
        self, text, regex, expected
    ):
        """Test with valid text and regex."""
        assert validate_regex(text, regex) == expected

    def test_validate_regex_invalid_text(self):
        """Test with text that does not match the regex."""
        with pytest.raises(ValueError):
            validate_regex("123", r"^[a-z]+$", info="lowercase letters")

        with pytest.raises(ValueError):
            validate_regex("abc", r"^\d+$")

    def test_validate_regex_invalid_regex(self):
        """Test with an invalid regular expression."""
        with pytest.raises(re_error):
            invalid_regex = r'***'
            validate_regex("abc", invalid_regex)

    def test_validate_regex_non_string_text(self):
        """Test with text that is not a string."""
        with pytest.raises(
            TypeError,
            match="Must be a string, but got int"
        ):
            validate_regex(123, r"^[a-z]+$")

        with pytest.raises(
            TypeError,
            match="Must be a string, but got list"
        ):
            validate_regex(["a", "b"], r"^[a-z]+$")


class TestValidateUsername:
    """Unit tests for the validate_username function."""

    @patch('auth.validators.validate_regex')
    def test_validate_username_success(
        self, mock_validate_regex
    ):
        """Tests a successful username validation."""
        mock_validate_regex.return_value = "validated_username"
        assert validate_username("username") == "validated_username"

    @patch('auth.validators.validate_regex',
           side_effect=ValueError())
    def test_validate_username_invalid_username(
        self, mock_validate_regex
    ):
        """Test an unsuccessful username validation."""
        with pytest.raises(ValueError):
            validate_username("invalid_username_for_mock")

    @patch('auth.validators.validate_regex',
           side_effect=re_error("Failing regex compilation (for testing)"))
    def test_validate_username_invalid_regex(
        self, mock_validate_regex
    ):
        """Tests a regex compilation failure."""
        with pytest.raises(RuntimeError):
            validate_username("username")


class TestValidatePassword:
    """Unit tests for the validate_password function."""

    @patch('auth.validators.validate_regex')
    def test_validate_password_success(self, mock_validate_regex):
        """Tests a successful password validation."""
        mock_validate_regex.return_value = "validated_password"
        assert validate_password("password") == "validated_password"

    @patch('auth.validators.validate_regex',
           side_effect=ValueError())
    def test_validate_password_invalid_password(
        self, mock_validate_regex
    ):
        """Test an unsuccessful password validation."""
        with pytest.raises(ValueError):
            validate_password("invalid_password_for_mock")

    @patch('auth.validators.validate_regex',
           side_effect=re_error("Failing regex compilation (for testing)"))
    def test_validate_password_invalid_regex(
        self, mock_validate_regex
    ):
        """Tests a regex compilation failure."""
        with pytest.raises(RuntimeError):
            validate_password("password")
