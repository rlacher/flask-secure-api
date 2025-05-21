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
Provides an in-memory session store for session management.

This module implements a lightweight storage mechanism using a Python
dictionary to manage session tokens. This store is not persistent.
"""
import logging

logger = logging.getLogger(__name__)
_sessions: dict[str, str] = {}


def create_session(username: str, token: str) -> bool:
    """Creates a new session.

    Route handlers are responsible for input validation.

    Args:
        username (str): The username for whom a session is created.
        token (str): The session token identifying the user's session.
    Returns:
        True if a new session was created, False if the token already
        exists.
    """
    if token in _sessions:
        return False
    else:
        _sessions[token] = username
        return True


def get_username_from_token(token: str) -> str | None:
    """Retrieves the username for a given session token.

    Route handlers are responsible for input validation.

    Args:
        token (str): The session token corresponding to a user.
    Returns:
        The username if the token is found, otherwise None.
    """
    return _sessions.get(token)


def delete_session(token: str) -> bool:
    """Deletes an existing session identified by its token.

    Route handlers are responsible for input validation.

    Args:
        token (str): The provided session token.
    Returns:
        True if the session was removed, False otherwise.
    """
    if token not in _sessions:
        logger.warning("Attempt to delete non-existent session.")
        return False

    del _sessions[token]
    return True
