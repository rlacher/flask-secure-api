# Flask Secure API

A minimal authentication API built with Python and Flask, focused on showcasing secure API development principles.

## Key Features

- **Basic Authentication:** Essential user registration and login functionality.
- **Session Security:** Token-based protection for dummy data.
- **Modular Design:** Maintainable and extensible organised codebase.
- **Clear Documentation:** API endpoint description and Python Docstrings.
- **Comprehensive Testing:** Both unit and integration tests for API reliability.
- **Memory-Based:** Simple in-memory data store for demonstration purposes.

## Quick Start

Get the demonstration API running:

1.  **Clone:**
	```bash
	git clone https://github.com/rlacher/flask-secure-api.git
	```
2.  **Set up a virtual environment (recommended):**
    ```bash
    python3 -m venv venv && source venv/bin/activate  # Linux/macOS
    python3 -m venv venv && .\venv\Scripts\activate   # Windows
    ```
3.  **Install dependencies:**
	```bash
	pip install -r requirements.txt
	```
4.  **Run:**
	```bash
	flask --app api run
	```

## Documentation

Project documentation is embedded in the code as docstrings. Access it
using Python's built-in `help()` function:

```python
>>> import auth
>>> help(auth)
```

For help on modules, type the following:

```python
>>> from auth import routes
>>> help(auth.routes)
```

## Testing

After activating the virtual environment, navigate to the project root and execute the test runner:

```bash
pytest
```

*Note:* Project dependencies must be installed for test execution.

## License

This project is licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for details.

## Author

Created by [René Lacher](https://github.com/rlacher).
