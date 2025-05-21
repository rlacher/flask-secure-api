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
Authentication package.

Provides the authentication Blueprint for API routes, and core
functionality for user login and session management.

Configures the root logger for stdout output.
"""
import sys
import logging

from flask import Flask
from werkzeug.exceptions import HTTPException
from flasgger import Swagger

from auth.routes import user as user_routes
from auth.errors import (
    handle_http_exception,
    handle_service_error,
    handle_validation_error
)
from .exceptions import (
    ServiceError,
    ValidationError
)


def configure_logging():
    """Configure basic console logging for the application."""
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    if not logger.hasHandlers():
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            '%(asctime)s %(name)s %(levelname)s %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)


def create_app():
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.register_blueprint(user_routes.auth_bp)
    app.register_blueprint(user_routes.protected_bp)
    app.register_error_handler(HTTPException, handle_http_exception)
    app.register_error_handler(ValidationError, handle_validation_error)
    app.register_error_handler(ServiceError, handle_service_error)
    Swagger(app)
    return app


configure_logging()
