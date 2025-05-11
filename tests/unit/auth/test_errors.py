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

"""Unit tests for the errors module."""
from http import HTTPStatus

from pytest import raises
from unittest.mock import patch, MagicMock
from auth.errors import handle_http_exception
from werkzeug.exceptions import BadRequest


class TestErrors:
    """Provides tests for custom error handling."""

    @patch('auth.errors.jsonify')
    def test_handle_http_exception_happy_path(self, mock_jsonify):
        """Test handling a standard BadRequest exception.

        Mocks the jsonify function to return a mock response object.
        """
        exception = BadRequest("Invalid input")
        mock_response = MagicMock()
        mock_jsonify.return_value = mock_response

        result = handle_http_exception(exception)

        mock_jsonify.assert_called_once_with({'error': 'Invalid input'})
        assert result is mock_response
        assert result.status_code == HTTPStatus.BAD_REQUEST
        assert result.content_type == 'application/json'

    def test_handle_http_exception_non_http_exception(self):
        """Test handling a non-HTTP exception

        This test checks that a TypeError is raised when a non-HTTP
        exception is passed to the handle_http_exception().
        """
        mock_exception = MagicMock(spec=Exception)

        with raises(TypeError):
            handle_http_exception(mock_exception)
