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

"""Unit tests for custom exceptions"""
from auth.exceptions import (
    ServiceError,
    UserAlreadyExistsError,
    InvalidPasswordError
)


class TestServiceErrorBase:
    """Tests the ServiceError base class and its subclasses."""
    def test_init_default_message(self):
        """Tests the the constructor uses the provided message."""
        err = ServiceError("An error occurred")
        assert str(err) == "An error occurred"

    def test_str_custom_subclass_description(self):
        """Tests that str() uses the default description."""
        err = UserAlreadyExistsError()
        assert str(err) == "User already exists"
        assert isinstance(err, ServiceError)

    def test_init_override_default_message(self):
        """Tests overwrite of error message in subclass."""
        err = InvalidPasswordError("Custom error")
        assert str(err) == "Custom error"
