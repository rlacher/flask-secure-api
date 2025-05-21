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
"""Unit tests for the session_store module."""
from unittest.mock import patch
from auth.models import session_store


class TestSessionStore:
    """Tests for the session_store module."""

    def test_create_session_new_token(self):
        """Test creating a session with a new token."""
        with patch.dict(session_store._sessions, {}, clear=True):
            session_created = session_store.create_session(
                'test_user',
                'new_token'
            )

            assert session_created
            assert session_store._sessions['new_token'] == 'test_user'

    def test_create_session_existing_token(self):
        """Test creating a session with an existing token."""
        with patch.dict(
            session_store._sessions,
            {'existing_token': 'another_user'},
            clear=True
        ):
            session_created = session_store.create_session(
                'test_user',
                'existing_token'
            )
            assert not session_created
            assert session_store._sessions['existing_token'] == 'another_user'

    def test_get_username_from_token_exists(self):
        """Test retrieving username for an existing token."""
        with patch.dict(
            session_store._sessions,
            {'valid_token': 'test_user'},
            clear=True
        ):
            username_from_token = session_store.get_username_from_token(
                'valid_token'
            )
            assert username_from_token == 'test_user'

    def test_get_username_from_token_not_exists(self):
        """Test retrieving username for a non-existent token."""
        with patch.dict(session_store._sessions, {}, clear=True):
            no_username = session_store.get_username_from_token(
                'invalid_token'
            )
            assert no_username is None

    def test_delete_session_success(self):
        """Test deleting a session given a valid token."""
        with patch.dict(
            session_store._sessions,
            {'removable_token': 'some_user'},
            clear=True
        ):
            is_deleted = session_store.delete_session('removable_token')

            assert is_deleted
            assert 'removable_token' not in session_store._sessions

    def test_delete_session_empty_store(self):
        """Test deleting a session from an empty session store."""
        with patch.dict(session_store._sessions, {}, clear=True):
            is_deleted = session_store.delete_session('any_token')

            assert not is_deleted
            assert len(session_store._sessions) == 0
