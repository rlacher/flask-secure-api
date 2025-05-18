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

"""Defines custom exception types"""
import logging


logger = logging.getLogger(__name__)


class ServiceError(Exception):
    """Base class for service-related errors."""
    description = "A service error occurred."

    def __init__(self, message=None):
        """Initialises the ServiceError instance."""
        self.message = message or self.__class__.description
        super().__init__(self.message)

    def __str__(self):
        """Returns a string representation of the error."""
        return self.message


class UserAlreadyExistsError(ServiceError):
    """Raised when registration fails because a user already exists."""
    description = "User already exists"


class UserDoesNotExistError(ServiceError):
    """Raised when a user cannot be found on login attempt."""
    description = "User does not exist"


class WrongPasswordError(ServiceError):
    """Raised when a user's password is wrong."""
    description = "Wrong password"


class DuplicateSessionTokenError(ServiceError):
    """Raised when a generated token already exists."""
    description = "Failed to generate a unique session token."


class SessionNotFoundError(ServiceError):
    """Raised when no session exists for the provided token."""
    description = "No session found for the given token."
