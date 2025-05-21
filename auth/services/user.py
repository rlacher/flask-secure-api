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
import secrets

from werkzeug.security import generate_password_hash, check_password_hash

from auth.exceptions import (
    DuplicateSessionTokenError,
    SessionNotFoundError,
    UserAlreadyExistsError,
    UserDoesNotExistError,
    WrongPasswordError
)
from auth.models import (
    session_store,
    user_store
)

SESSION_TOKEN_LENGTH_BYTES = 16

logger = logging.getLogger(__name__)


def register_user(username: str,
                  password: str):
    """Registers a new user with the given username and password.

    The password is hashed before storage. The username must be unique.
    Uses the data layer to store the new user.

    Args:
        username (str): The username of the user.
        password (str): The password of the user.

    Raises:
        UserAlreadyExistsError: If user_store already contains username.
    """
    hashed_password = generate_password_hash(password)

    if not user_store.add_user(username, hashed_password):
        raise UserAlreadyExistsError()

    logger.info(f"User registered: {username}")


def login_user(
        username: str,
        password: str) -> str:
    """Logs in a user with the given username and password.

    The password is checked against the stored hash.
    Uses the data layer to retrieve the user's password for authentication.

    Args:
        username (str): The username of the user.
        password (str): The password of the user.
    Returns:
        str: Session token on successful login.
    Raises:
        UserDoesNotExistError: If the username does not exist in user_store.
        WrongPasswordError: If the password does not match the stored hash.
        RuntimeError: If an unexpected internal error occurs during the login
        process, such as a failure to create a unique session.
    """
    hashed_password = user_store.get_hashed_password(username)

    if not hashed_password:
        raise UserDoesNotExistError()

    if not check_password_hash(hashed_password, password):
        raise WrongPasswordError()

    try:
        token = secrets.token_hex(SESSION_TOKEN_LENGTH_BYTES)
        if not session_store.create_session(username, token):
            raise DuplicateSessionTokenError()
        logger.info(f"User '{username}' logged in.")
        return token
    except DuplicateSessionTokenError as exception:
        raise RuntimeError(
            "An unexpected error occurred during login."
        ) from exception


def get_protected_data(token: str) -> str:
    """Retrieve protected data for a user with a valid session token.

    Args:
        token (str): The session token for authenticated access.
    Returns:
        str: The protected resource.
    Raises:
        SessionNotFoundError: If the token is not associated with
        any active session.
    """
    username = session_store.get_username_from_token(token)
    if not username:
        raise SessionNotFoundError()

    protected_message = f"Hello {username}. Here is your protected data."
    return protected_message


def logout_user(token: str):
    """Logs out a user by its session token.

    Deletes the session identified by the session token.

    Args:
        token (str): The provided session token.
    Raises:
        SessionNotFoundError: If the token is not associated with
        any active session.
    """
    is_deleted = session_store.delete_session(token)
    if not is_deleted:
        raise SessionNotFoundError()
