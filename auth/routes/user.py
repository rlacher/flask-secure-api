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

from flask import abort, Blueprint, jsonify, request

from auth.services import user
from auth.models.memory_store import users as user_store

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/register', methods=['POST'])
def register():
    """Registers a new user.

    Accepts a JSON request with 'username' and 'password' fields.

    Returns:
        A JSON response with HTTP status codes as determined by the
        `register_user()` service:
            - 201 (CREATED):
              On successful user registration.
            - 400 (BAD_REQUEST):
              If the request lacks required fields
              (handled directly in the route).
            - 409 (CONFLICT):
              If the username already exists
              (determined by the service).
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username:
        abort(HTTPStatus.BAD_REQUEST, 'Username is required')

    if not password:
        abort(HTTPStatus.BAD_REQUEST, 'Password is required')

    success, message = user.register_user(username, password, user_store)
    if not success:
        abort(HTTPStatus.CONFLICT, message)

    return jsonify({'message': message}), \
        HTTPStatus.CREATED


@auth_bp.route('/login', methods=['POST'])
def login():
    """Logs in a user.

    Accepts a JSON request with 'username' and 'password' fields.

    Returns:
        A JSON response with HTTP status codes as determined by the
        `login_user()` service:
            - 200 (OK):
              On successful login.
            - 400 (BAD_REQUEST):
              Contains an 'error' key with a description of the missing fields
              (handled directly in the route).
            - 401 (UNAUTHORIZED):
              - Contains an 'error' key indicating a failed login attempt
              with a description of the reason (determined by the service).
    """
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username:
        abort(HTTPStatus.BAD_REQUEST, 'Username is required')

    if not password:
        abort(HTTPStatus.BAD_REQUEST, 'Password is required')

    success, message = user.login_user(username, password, user_store)
    if not success:
        abort(HTTPStatus.UNAUTHORIZED, message)

    return jsonify({'message': message}), HTTPStatus.OK
