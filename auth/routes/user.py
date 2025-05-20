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
Authentication route handlers for user registration, login, protected
data access and logout.

This module provides the primary authentication interface for the API.
"""
from http import HTTPStatus
import logging

from flask import Blueprint, jsonify, request

from auth.validators import (
    domain as domain_validators,
    request as request_validators
)
from auth.services import user as user_services


logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__)
protected_bp = Blueprint('protected', __name__)


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
                description: "Password for registration."
    responses:
      201:
        description: Successful user registration.
        content:
          application/json:
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: "User successfully registered."
      400:
        description: Missing or invalid input.
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
                  example: "Username is required."
      409:
        description: Registration failed, determined by the service.
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
                  example: "User already exists."
    """
    credentials = request_validators.validate_credentials_payload(request)
    validated_username = domain_validators.validate_username(
        credentials.username
    )
    validated_password = domain_validators.validate_password(
        credentials.password
    )
    user_services.register_user(validated_username, validated_password)

    return jsonify(
        {'message': "User successfully registered"}
    ), HTTPStatus.CREATED


@auth_bp.route('/login', methods=['POST'])
def login():
    """Logs in an existing user and return a session token.

    Accepts a JSON request with 'username' and 'password' fields.

    Returns:
        A JSON response containing the session token or an error.
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
                description: "Password for login."
    responses:
      200:
        description: Successful login.
        content:
          application/json:
            schema:
              type: object
              properties:
                session_token:
                  type: string
                  example: "5d59516c29d8ad8443c1c2e6d3da51ac"
      400:
        description: Missing or invalid input.
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
                  example: "Username is required."
      401:
        description: Authentication failed, determined by the service.
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
                  example: "Wrong password."
    """
    credentials = request_validators.validate_credentials_payload(request)
    validated_username = domain_validators.validate_username(
        credentials.username
    )
    validated_password = domain_validators.validate_password(
        credentials.password
    )
    token = user_services.login_user(validated_username, validated_password)

    return jsonify({'session_token': token}), HTTPStatus.OK


@protected_bp.route('/protected', methods=["GET"])
def protected():
    """Access protected resource with a valid session token.

    Requires a valid session token in the 'Authorization' header.

    Returns:
        JSON response with protected data on success or an error message.
    ---
    security:
      - BearerAuth: []
    responses:
      200:
        description: Protected data retrieved.
        content:
          application/json:
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: "Hello user. Here is your protected data."
      400:
        description: Missing authorization header or invalid token.
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
                  example: "Authorization header is required."
      401:
        description: Unauthorized access, determined by the service.
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
                  example: "Session token not found."
    """
    auth_header = request.headers.get("Authorization")
    token = request_validators.validate_authorisation_header(auth_header)
    validated_token = domain_validators.validate_token(token)
    protected_message = user_services.get_protected_data(validated_token)

    return jsonify({"message": protected_message}), HTTPStatus.OK


@protected_bp.route('/logout', methods=["POST"])
def logout():
    """Logs the user out, invalidating the session token.

    Requires a valid session token in the 'Authorization' header.

    Returns:
        JSON response confirming successful logout or an error message.
    ---
    security:
      - BearerAuth: []
    responses:
      200:
        description: Successful logout.
        content:
          application/json:
            schema:
              type: object
              properties:
                message:
                  type: string
                  example: "Logged out successfully."
      400:
        description: Missing authorization header or invalid token.
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
                  example: "Authorization header is required."
      401:
        description: Unauthorized access, determined by the service.
        content:
          application/json:
            schema:
              type: object
              properties:
                error:
                  type: string
                  example: "Session token not found."
    """
    auth_header = request.headers.get("Authorization")
    token = request_validators.validate_authorisation_header(auth_header)
    validated_token = domain_validators.validate_token(token)
    user_services.logout_user(validated_token)
    logger.info("User logged out successfully.")

    return jsonify({"message": "Logged out successfully."}), HTTPStatus.OK
