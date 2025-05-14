# Flask Secure API

<!-- Badges -->
[![flake8](https://img.shields.io/github/actions/workflow/status/rlacher/flask-secure-api/lint.yml?label=flake8&style=flat)](https://github.com/rlacher/flask-secure-api/actions/workflows/lint.yml)
[![pytest](https://img.shields.io/github/actions/workflow/status/rlacher/flask-secure-api/test.yml?label=pytest&style=flat)](https://github.com/rlacher/flask-secure-api/actions/workflows/test.yml)
[![codecov](https://img.shields.io/codecov/c/github/rlacher/flask-secure-api?style=flat&label=codecov)](https://app.codecov.io/gh/rlacher/flake-secure-api)
[![license](https://img.shields.io/badge/license-Apache%202.0-lightgrey.svg)](http://www.apache.org/licenses/LICENSE-2.0)

A minimal authentication API built with Python and Flask, focused on showcasing secure API development principles.

## Key Features

- **Basic Authentication:** Essential user registration and login functionality.
- **Input Validation:** Robust input validation to prevent malicious data entry.
- **Modular Design:** Maintainable and extensible organised codebase.
- **Clear Documentation:** API endpoint description and Python Docstrings.
- **Comprehensive Testing:** Unit and integration tests ensure high API resilience.
- **Memory-Based:** Simple in-memory store demonstrating core API logic.

## Quick Start

Before starting, ensure you have Python 3.12 or higher and the latest pip installed on your system.

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
5.  **Run the API:**
    ```bash
    ./run.py
    ```

## API Usage

Below are examples of interacting with key API endpoints.

### Register a new user

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"username": "new_user", "password": "secure_password1"}' \
  http://localhost:5000/register
```
Example response: `{"message": "User successfully registered"}`

### Log in an existing user

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"username": "new_user", "password": "secure_password1"}' \
  http://localhost:5000/login
```
Example response: `{"message": "Login successful"}`

### Error Handling

The API provides informative error responses for various failure scenarios. For instance, registering with an invalid username returns a `400 Bad Request` with a JSON body detailing the validation error:

```bash
curl -X POST \
  -H "Content-Type: application/json" \
  -d '{"username": "invalid$username", "password": "secure_password1"}' \
  http://localhost:5000/register
```
Example response: `{"error": "Invalid username: Must be 3-20 alphanumeric characters or underscore"}`

Similarly, providing an invalid password will also result in a 400 Bad Request. Attempting to register with a duplicate or log in with a non-existent user will yield a `409 Conflict` and `401 Unauthorized` error, respectively. 

## Documentation

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

## Test

This project includes automated unit and integration tests to guarantee API integrity.

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
