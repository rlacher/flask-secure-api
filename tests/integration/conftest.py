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

from auth import create_app
from auth.models import memory_store


@pytest.fixture
def client():
    """Provides test client."""
    app = create_app()
    return app.test_client()


@pytest.fixture(autouse=True)
def reset_user_store():
    """Ensures clean memory state."""
    memory_store.users.clear()


@pytest.fixture
def valid_credentials():
    """Supplies user credentials for registration."""
    return {
        "username": "valid_username",
        "password": "valid_password1"
    }
