# Flask Secure API

<!-- Badges -->
[![flake8](https://img.shields.io/github/actions/workflow/status/rlacher/flask-secure-api/lint.yml?label=flake8&style=flat)](https://github.com/rlacher/flask-secure-api/actions/workflows/lint.yml)
[![pytest](https://img.shields.io/github/actions/workflow/status/rlacher/flask-secure-api/test.yml?label=pytest&style=flat)](https://github.com/rlacher/flask-secure-api/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/rlacher/flask-secure-api/branch/main/graph/badge.svg?token=I2HID42T6X)](https://app.codecov.io/gh/rlacher/flask-secure-api/tree/main)
[![license](https://img.shields.io/badge/license-Apache%202.0-lightgrey.svg)](http://www.apache.org/licenses/LICENSE-2.0)

A minimal authentication API built with Python and Flask, focused on showcasing secure API development principles.

## Key Features

- **User Authentication:** Secure credential handling for registration and login.
- **Session Management:**  Token-based session control for managing login state.
- **Transport Security:** HTTPS support via self-signed TLS certificate.
- **Input Validation:** Strict validation logic to guard against malicious input.
- **Modular Design:** Organised, extensible codebase with clean architecture.
- **Encapsulated Storage:** Abstracted in-memory store, replaceable with a persistent database.
- **Comprehensive Testing:** Unit and integration tests to verify endpoint reliability.
- **Developer Documentation:** OpenAPI specification and inline Python docstrings.

## Quick Start

Before starting, ensure you have Python 3.12 or higher and the latest pip installed on your system. Windows users who wish to enable HTTPS must also install OpenSSL to support certificate generation.

Run the authentication API locally:

1.  **Clone repository:**
    ```bash
    git clone https://github.com/rlacher/flask-secure-api.git
    ```
2.  **Navigate to project directory:**
    ```bash
    cd flask-secure-api
    ```
3.  **Set up a virtual environment (recommended):**
    ```bash
    python3 -m venv venv && source venv/bin/activate  # Linux/macOS
    python3 -m venv venv && .\venv\Scripts\activate   # Windows
    ```
4.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
5. **Create self-signed certificate (recommended):**
    ```bash
    mkdir certs
    openssl req -x509 -newkey rsa:4096 -nodes -keyout certs/key.pem -out certs/cert.pem -days 365
    ```
6.  **Run the API:**
    ```bash
    python3 run.py
    ```

## API Usage

Below are examples of interacting with key API endpoints.

### Register a new user

```bash
curl -k -X POST \
  -H "Content-Type: application/json" \
  -d '{"username": "new_user", "password": "secure_password1"}' \
  https://localhost:5000/register
```
Example response: `{"message": "User successfully registered"}`

### Log in an existing user

```bash
curl -k -X POST \
  -H "Content-Type: application/json" \
  -d '{"username": "new_user", "password": "secure_password1"}' \
  https://localhost:5000/login
```
Example response: `{"session_token": "5d59516c29d8ad8443c1c2e6d3da51ac"}`.

### Accessing protected data

```bash
curl -k -X GET \
  -H "Authorization: Bearer 5d59516c29d8ad8443c1c2e6d3da51ac" \
  https://localhost:5000/protected
```
Example response: `{"message": "Hello new_user. Here is your protected data."}`.

### Log out from session

```bash
curl -k -X POST \
  -H "Authorization: Bearer 5d59516c29d8ad8443c1c2e6d3da51ac" \
  https://localhost:5000/logout
```
Example response: `{"message": "Logged out successfully"}`.

### Error Handling

The API provides informative error responses for various failure scenarios. For instance, registering with an invalid username returns a `400 Bad Request` with a JSON body detailing the validation error:

```bash
curl -k -X POST \
  -H "Content-Type: application/json" \
  -d '{"username": "invalid$username", "password": "secure_password1"}' \
  https://localhost:5000/register
```
Example response: `{"error": "Username must be a string, 3-20 alphanumeric character or underscore."}`

This table summarises the implemented fault conditions.

| Endpoint    | Fault Condition            | HTTP Status Code   |
| :---------- | :------------------------- | :----------------- |
| /register   | Missing username/password  | `400 Bad Request`  |
| /register   | Invalid credentials        | `400 Bad Request`  |
| /register   | Duplicate username         | `409 Conflict`     |
| /login      | Missing username/password  | `400 Bad Request`  |
| /login      | Invalid credentials        | `400 Bad Request`  |
| /login      | Unknown username           | `401 Unauthorized` |
| /login      | Incorrect password         | `401 Unauthorized` |
| /protected  | Missing/invalid token      | `400 Bad Request`  |
| /protected  | Session not found          | `401 Unauthorized` |
| /logout     | Missing/invalid token      | `400 Bad Request`  |
| /logout     | Session not found          | `401 Unauthorized` |

Flask handles standard errors (e.g. incorrect request method) automatically. These are omitted here.

## Documentation

This section outlines how to access the project's  Python docstrings and auto-generated OpenAPI specification.

### Python Docstrings

Project documentation is embedded in the code as docstrings. Access it
using Python's built-in `help()` function:

```python
>>> import auth
>>> help(auth)
```

For help on modules/functions, type the following:

```python
>>> from auth import routes
>>> help(auth.routes)
>>> help(auth.routes.user.register) # Help for register() function
```

### API Specification (OpenAPI)

API documentation is automatically generated in OpenAPI format.

For interactive exploration using the Swagger UI:

1.  Ensure the Flask application is running.
2.  Navigate your web browser to `https://localhost:5000/apidocs/`.

Your browser may flag the self-signed certificate as untrusted. It is safe to bypass when developing locally.

## Test

This project is thoroughly unit and integration tested, with a test suite comprising 120 automated test cases to guarantee API integrity.

### Execution

Ensure your virtual environment is activated and project dependencies are installed. To run the test suite from your project root:

```bash
pytest
```

### Coverage

To generate a detailed coverage report, including both statement and branch coverage, use the following command:

```bash
pytest --cov=auth --cov-branch --cov-report html tests/
```
After the tests complete, open `htmlcov/index.html` in a web browser to inspect the code coverage.

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.

## Author

Created by [René Lacher](https://github.com/rlacher).
