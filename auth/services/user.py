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

"""
Encapsulates core authentication services.

This module handles user registration, login and other
authentication-related tasks.
"""
import logging

from werkzeug.security import generate_password_hash, check_password_hash

from auth.exceptions import (
    UserAlreadyExistsError,
    UserDoesNotExistError,
    InvalidPasswordError
)


logger = logging.getLogger(__name__)


def register_user(username: str,
                  password: str,
                  user_store: dict):
    """Registers a new user with the given username and password.

    The password is hashed before storage. The username must be unique.
    The user is stored in a dictionary.

    Args:
        username (str): The username of the user.
        password (str): The password of the user.
        user_store (dict): The dictionary to store user data.

    Raises:
        UserAlreadyExistsError: If user_store already contains username.
    """
    if username in user_store:
        raise UserAlreadyExistsError()

    user_store[username] = generate_password_hash(password)
    logger.info(f"User registered: {username}")


def login_user(
        username: str,
        password: str,
        user_store: dict):
    """Logs in a user with the given username and password.

    The password is checked against the stored hash.
    The user must exist in the dictionary.

    Args:
        username (str): The username of the user.
        password (str): The password of the user.
        user_store (dict): The dictionary to access user data.

    Raises:
        UserDoesNotExistError: If the username does not exist in user_store.
        InvalidPasswordError: If the password for username does not match.
    """
    hashed_password = user_store.get(username)

    if not hashed_password:
        raise UserDoesNotExistError()

    if not check_password_hash(hashed_password, password):
        raise InvalidPasswordError()

    logger.info(f"User logged in: {username}")
