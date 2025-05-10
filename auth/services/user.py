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

    Returns:
        bool: True if registration is successful, False otherwise.
    """
    if username in user_store:
        return False, 'User already exists'

    user_store[username] = generate_password_hash(password)
    return True, 'User successfully registered'


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

    Returns:
        bool: True if login is successful, False otherwise.
    """
    hashed_password = user_store.get(username)

    if not hashed_password:
        return False, 'User does not exist'

    if not check_password_hash(hashed_password, password):
        return False, 'Invalid password'

    return True, 'Login successful'
