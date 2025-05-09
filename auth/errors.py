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

"""Defines global custom exception handlers.

This module provides custom exception handlers for HTTP errors that
occur within the application.
"""
from flask import jsonify
from werkzeug.exceptions import HTTPException


def handle_http_exception(e: HTTPException):
    """Handle HTTP exceptions and return a JSON response.

    This handler formats HTTP errors as JSON, including the error
    description and appropriate status code.

    Args:
        e (HTTPException): The HTTP exception to handle.
    Returns:
        Response: A JSON response with the error message and status code.
    Raises:
        RuntimeError: If the provided exception is not an HTTPException.
    """
    if not isinstance(e, HTTPException):
        raise RuntimeError(
            "Must be an HTTPException, but got: {}".format(type(e).__name__)
        )

    response = jsonify(
        {'error': e.description if hasattr(e, 'description') else str(e)}
    )
    response.content_type = "application/json"
    response.status_code = e.code if hasattr(e, 'code') else 500
    return response
