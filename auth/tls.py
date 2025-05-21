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
"""Encapsulates TLS certificate detection logic."""
import logging
from os import path

CERT_FOLDER = "certs"
CERT_FILE = path.join(CERT_FOLDER, "cert.pem")
KEY_FILE = path.join(CERT_FOLDER, "key.pem")

logger = logging.getLogger(__name__)


def get_ssl_context():
    """Check for TLS certificates and return appropriate context."""
    if path.exists(CERT_FILE) and path.exists(KEY_FILE):
        return (CERT_FILE, KEY_FILE)
    logger.warning("TLS certificates missing, running in HTTP mode.")
    return None
