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
"""Unit tests for the user_store module."""
from unittest.mock import patch

from auth.models.user_store import (
    add_user,
    get_hashed_password,
    clear_users,
    _users  # Import for assertions
)


class TestUserStore():

    @patch.dict(
            "auth.models.user_store._users",
            {"existing_user": "retrieved_hash"},
            clear=True
    )
    def test_get_hashed_password_success(self):
        """Test retrieving an existing user's hashed password."""
        retrieved = get_hashed_password("existing_user")
        assert retrieved == "retrieved_hash"

    @patch.dict(
            "auth.models.user_store._users",
            clear=True
    )
    def test_get_hashed_password_not_found(self):
        """Test for retrieving a non-existent user's hashed password."""
        retrieved = get_hashed_password("unknown_user")
        assert retrieved is None

    def test_add_user_success(self):
        """Test for adding a new user."""
        username = "test_user"
        hashed_password = "hashed_password"

        with patch.dict(
            "auth.models.user_store._users",
            clear=True
        ) as mock_users:
            result = add_user(username, hashed_password)
            assert result
            assert username in mock_users
            assert mock_users[username] == hashed_password

    def test_add_user_duplicate(self):
        """Test for adding a duplicate user."""
        with patch.dict(
            "auth.models.user_store._users",
            {"existing_user": "hashed_password1"},
            clear=True
        ) as mock_users:
            result = add_user("existing_user", "hashed_password2")
            assert not result
            assert mock_users["existing_user"] == "hashed_password1"

    def test_clear_users(self):
        """Test for clearing all users from the store."""
        with patch.dict(
            "auth.models.user_store._users",
            {"user1": "hash1", "user2": "hash2"},
            clear=True
        ) as mock_users:
            assert len(mock_users) == 2
            assert "user1" in mock_users
            assert "user2" in mock_users
            clear_users()
            assert not _users
