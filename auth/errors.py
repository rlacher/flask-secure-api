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
from http import HTTPStatus
import logging

from flask import jsonify
from werkzeug.exceptions import HTTPException

from auth.exceptions import (
    ServiceError,
    ValidationError
)


logger = logging.getLogger(__name__)


def handle_http_exception(exception: HTTPException):
    """Handle HTTP exceptions and return a JSON response.

    This handler formats HTTP errors as JSON, including the error
    description and appropriate status code.

    Args:
        e (HTTPException): The HTTP exception to handle.
    Returns:
        Response: A JSON response with the error message and status code.
    Raises:
        TypeError: If the provided exception is not an HTTPException.
    """
    if not isinstance(exception, HTTPException):
        raise TypeError(
            f"Must be an HTTPException, but got: {type(exception).__name__}"
        )

    logger.warning(
        f"Handling HTTP exception: {type(exception).__name__} - {exception}"
    )

    response = jsonify({'error': exception.description})
    response.status_code = exception.code
    response.content_type = "application/json"
    return response


def handle_validation_error(exception: ValidationError):
    """Handle domain and request validation errors.

    Returns:
        Response: A 400 JSON response with an error message.
    """
    logger.debug(
        f"Handling validation error: {type(exception).__name__} - {exception}"
    )

    response = jsonify({'error': str(exception)})
    response.status_code = HTTPStatus.BAD_REQUEST
    response.content_type = "application/json"
    return response


def handle_service_error(exception: ServiceError):
    """Handle service-layer exceptions by returning a JSON error response.

    Handles domain-specific errors by returning a structured JSON response
    with the relevant status code and message.

    Args:
        exception (ServiceError): The raised service-layer exception.

    Returns:
        Response: A JSON response with the error message and HTTP status code.
    """
    logger.info(
        f"Handling service error: {type(exception).__name__} - {exception}"
    )

    response = jsonify({'error': str(exception)})
    response.status_code = exception.status_code
    response.content_type = "application/json"
    return response
