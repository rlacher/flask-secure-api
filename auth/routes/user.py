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
Sets up API route handlers for user authentication.

This module defines the Flask routes for user registration and login,
providing the primary authentication interface for the API.
"""
from http import HTTPStatus
import logging

from flask import abort, Blueprint, jsonify, request

from auth.services import user
from auth.exceptions import ServiceError
from auth.validators import (
    validate_username,
    validate_password
)


logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/register', methods=['POST'])
def register():
    """Registers a new user.

    Accepts a JSON request with 'username' and 'password' fields.

    Returns:
        A JSON response containing the registration status or an error.
    ---
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              username:
                type: string
                description: Username for registration.
              password:
                type: string
                description: Password for registration.
    responses:
      201:
        description: On successful user registration (CREATED).
        content:
          application/json:
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: User successfully registered.
      400:
        description: |
          If required fields are missing or malformatted,
          handled directly in the route (BAD_REQUEST).
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
                  example: Username is required.
      409:
        description: |
          If the registration was unsuccessful, determined by the
          service (CONFLICT).
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
                  example: User already exists.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username:
        logger.debug("Username is required")
        abort(HTTPStatus.BAD_REQUEST, 'Username is required')

    if not password:
        logger.debug(f"Password required for: {username}")
        abort(HTTPStatus.BAD_REQUEST, 'Password is required')

    try:
        validated_username = validate_username(username)
    except TypeError as type_error:
        abort(
            HTTPStatus.BAD_REQUEST,
            f'Invalid username: {type_error.args[0]}'
        )
    except ValueError as value_error:
        abort(
            HTTPStatus.BAD_REQUEST,
            f'Invalid username: {value_error.args[0]}'
        )

    try:
        validated_password = validate_password(password)
    except TypeError as type_error:
        abort(
            HTTPStatus.BAD_REQUEST,
            f'Invalid password: {type_error.args[0]}'
        )
    except ValueError as value_error:
        abort(
            HTTPStatus.BAD_REQUEST,
            f'Invalid password: {value_error.args[0]}'
        )

    try:
        user.register_user(validated_username, validated_password)
    except ServiceError as service_error:
        abort(HTTPStatus.CONFLICT, str(service_error))

    return jsonify(
        {'message': "User successfully registered"}
    ), HTTPStatus.CREATED


@auth_bp.route('/login', methods=['POST'])
def login():
    """Logs in a user.

    Accepts a JSON request with 'username' and 'password' fields.

    Returns:
        A JSON response containing the login status or an error.
    ---
    requestBody:
      required: true
      content:
        application/json:
          schema:
            type: object
            properties:
              username:
                type: string
                description: Username for login.
              password:
                type: string
                description: Password for login.
    responses:
      200:
        description: On successful login (OK).
        content:
          application/json:
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: Login successful.
      400:
        description: |
          If required fields are missing or malformatted,
          handled directly in the route (BAD_REQUEST).
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
                  example: Username is required.
      401:
        description: |
          If the login was unsuccessful, determined by the service
          (UNAUTHORIZED).
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
                  example: Wrong password.
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username:
        logger.debug("Username is required")
        abort(HTTPStatus.BAD_REQUEST, 'Username is required')

    if not password:
        logger.debug(f"Password required for: {username}")
        abort(HTTPStatus.BAD_REQUEST, 'Password is required')

    try:
        validated_username = validate_username(username)
    except TypeError as type_error:
        abort(
            HTTPStatus.BAD_REQUEST,
            f'Invalid username: {type_error.args[0]}'
        )
    except ValueError as value_error:
        abort(
            HTTPStatus.BAD_REQUEST,
            f'Invalid username: {value_error.args[0]}'
        )

    try:
        validated_password = validate_password(password)
    except TypeError as type_error:
        abort(
            HTTPStatus.BAD_REQUEST,
            f'Invalid password: {type_error.args[0]}'
        )
    except ValueError as value_error:
        abort(
            HTTPStatus.BAD_REQUEST,
            f'Invalid password: {value_error.args[0]}'
        )

    try:
        token = user.login_user(validated_username, validated_password)
    except ServiceError as service_error:
        abort(HTTPStatus.UNAUTHORIZED, str(service_error))

    return jsonify({'session_token': token}), HTTPStatus.OK
