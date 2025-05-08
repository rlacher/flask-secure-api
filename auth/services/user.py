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
from werkzeug.security import generate_password_hash, check_password_hash

from auth.models import memory_store


def register_user(username, password):
    """Registers a new user with the given username and password.

    The password is hashed before storage. The username must be unique.

    Args:
        username (str): The username of the user.
        password (str): The password of the user.

    Returns:
        bool: True if registration is successful, False otherwise.
    """
    if username in memory_store.users:
        return False, 'User already exists'

    memory_store.users[username] = generate_password_hash(password)
    return True, 'User successfully registered'


def login_user(username, password):
    """Logs in a user with the given username and password.

    The password is checked against the stored hash.

    Args:
        username (str): The username of the user.
        password (str): The password of the user.

    Returns:
        bool: True if login is successful, False otherwise.
    """
    hashed_password = memory_store.users.get(username)

    if not hashed_password:
        return False, 'User does not exist'

    if not check_password_hash(hashed_password, password):
        return False, 'Invalid password'

    return True, 'Login successful'
