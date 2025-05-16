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
Provides an in-memory user store for authentication.

This module implements a lightweight storage mechanism using a Python
dictionary to manage user credentials. This store is not persistent.
"""
import logging

logger = logging.getLogger(__name__)
_users: dict[str, str] = {}


def add_user(username: str, hashed_password: str) -> bool:
    """Adds a new user to the user store.

    Associates the provided username with its hashed password within the
    in-memory user store.

    Route handlers are responsible for input validation.

    Args:
        username (str): The username to add.
        hashed_password (str): The user's hashed password.

    Returns:
        True if the user was added, false otherwise.
    """
    if username in _users:
        logger.debug(f"Username already in user store: {username}")
        return False

    _users[username] = hashed_password
    return True


def clear_users():
    """Removes all users from the user store.

    This function clears the underlying dictionary, effectively deleting
    all user data.
    """
    _users.clear()


def get_hashed_password(username: str) -> str | None:
    """Retrieves the hashed password for a given username.

    Looks up the provided username in the user store and returns its
    associated hashed password.

    Route handlers are responsible for input validation.

    Args:
        username (str): The username for which to lookup the hashed password.
    Returns:
        str: The hashed password for the given username.
        None: If the username is not found.
    """
    if username not in _users:
        logger.debug(
            f"Username not found to get hashed password for: {username}"
        )
        return None

    return _users[username]
