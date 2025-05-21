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
"""Unit tests for TLS discovery."""
from unittest.mock import patch

from auth import tls


class TestGetSslContext:
    """Tests SSL context creation based on certificate availability."""

    def test_get_ssl_context_with_certificates(self):
        """Return cert and key file paths if both certificate files exist."""
        with patch("auth.tls.path.exists", return_value=True):
            result = tls.get_ssl_context()
            assert result == (tls.CERT_FILE, tls.KEY_FILE)

    def test_get_ssl_context_missing_cert_file(self):
        """Return None if certificate file is missing."""
        with patch("auth.tls.path.exists", side_effect=[False, True]):
            result = tls.get_ssl_context()
            assert result is None

    def test_get_ssl_context_missing_key_file(self):
        """Return None if key file is missing."""
        with patch("auth.tls.path.exists", side_effect=[True, False]):
            result = tls.get_ssl_context()
            assert result is None
