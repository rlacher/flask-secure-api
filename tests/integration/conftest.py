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
"""Provides test fixtures for all integration tests."""
import pytest
from werkzeug.security import generate_password_hash

from auth import create_app
from auth.models import (
    session_store,
    user_store
)


@pytest.fixture
def client():
    """Provides test client."""
    app = create_app()
    return app.test_client()


@pytest.fixture(autouse=True)
def reset_user_store():
    """Ensures clean memory state."""
    user_store.clear_users()


@pytest.fixture
def valid_credentials():
    """Supplies user credentials for registration."""
    return {
        "username": "valid_username",
        "password": "valid_password1"
    }


@pytest.fixture
def valid_session_token():
    """Creates a valid 32-char dummy token."""
    return "0" * 32


@pytest.fixture()
def populate_user_store(valid_credentials):
    """Populates the user store before each test."""
    hashed_password = generate_password_hash(
        valid_credentials['password']
    )
    is_added = user_store.add_user(
        valid_credentials['username'],
        hashed_password
    )
    if not is_added:
        pytest.fail(
            "Failed to add user to user store during setup: " +
            valid_credentials['username']
        )


@pytest.fixture()
def populate_session_store(valid_credentials, valid_session_token):
    """Populates the session store before each test."""
    session_created = session_store.create_session(
        valid_credentials['username'],
        valid_session_token
    )
    if not session_created:
        pytest.fail(
            "Failed to create session during setup: " +
            f"{valid_credentials['username']}, {valid_session_token}"
        )
    yield


@pytest.fixture(autouse=True)
def clear_session_store(valid_session_token):
    """Clears the session store."""
    yield
    session_store.delete_session(valid_session_token)


@pytest.fixture
def valid_auth_header(valid_session_token) -> dict:
    """Creates a valid Authorization header for testing."""
    return {"Authorization": f"Bearer {valid_session_token}"}
