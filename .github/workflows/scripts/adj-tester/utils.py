"""Utility helpers for printing, logging and JSON loading.

This module provides small helper functions used by the test-suite and
CLI utilities, including colored printing for statuses, simple logging,
JSON loading with clear error messages, and basic IPv4 validation.
"""

import json
import ipaddress
from pathlib import Path
from jsonschema import Draft7Validator


def print_header(header: str):
    """Print a simple boxed header to stdout.

    The header is printed with a fixed width underline/overline for
    visual separation in CLI output.

    Args:
        header: The header text to print.
    """

    header_len = 40
    print("=" * header_len)
    print("· " + header)
    print("=" * header_len)


def print_status(message: str, validated: bool = False):
    """Print a single-line status message.

    The `validated` flag controls whether the status is shown as
    a green "Passed" (True) or a red "Failed" (False).

    Args:
        message: Human-readable message or label to print before status.
        validated: If True, prints a green "Passed"; otherwise prints a
                   red "Failed".
    """

    # ANSI color codes used for terminal output
    if not validated:
        result = "\033[31mFailed\033[0m"  # red
    elif validated:
        result = "\033[32mPassed\033[0m"  # green

    print(f"{message} {result}")


def log_message(message: str, status: int = 0):
    """
    status:
      -1 → error (red)
       0 → normal
       1 → success (green)
    """
    """Log a message with optional color depending on status.

    Args:
        message: Message text to print.
        status: Controls color: -1 -> red (error), 0 -> normal, 1 -> green
                (success).
    """

    colors = {-1: "\033[31m", 1: "\033[32m"}
    color = colors.get(status, "")
    reset = "\033[0m" if color else ""
    print(f"{color}{message}{reset}")


def load_json(path: Path):
    """Load and parse a JSON file from the given path.

    Raises a RuntimeError with a clear message when the file is missing
    or when the JSON cannot be decoded.

    Args:
        path: Path to the JSON file to load.

    Returns:
        The parsed JSON object.
    """

    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        # Normalize file-not-found into a runtime error for callers
        raise RuntimeError(f"File not found: {path}")
    except json.JSONDecodeError as e:
        # Provide the underlying JSON error message to help debugging
        raise RuntimeError(f"JSON malformed in {path}: {e}")


def is_valid_ipv4(address: str) -> bool:
    """Return True if the given string is a valid IPv4 address.

    Uses the stdlib ipaddress module to validate the textual address.
    """

    try:
        ipaddress.IPv4Address(address)
        return True
    except ipaddress.AddressValueError:
        return False


def print_results(file, is_valid, error_list):
    """Print validation results for a file.

    The function prints an overall status line and then any detailed
    error messages indented on subsequent lines.

    Args:
        file: File name or identifier to show in the status line.
        is_valid: Boolean indicating whether the file passed validation.
        error_list: Iterable of error message strings.
    """

    print_status(file, is_valid)
    for error in error_list:
        # Indent errors for readability in CLI output
        print("\t|\t" + error)


def logError(label: str, path: str, message: str):
    """Return a formatted, red-colored error string.

    This helper is handy for tests or logging in contexts that prefer a
    single formatted string instead of printing directly.
    """

    return f"\033[31m{label}: {path} → {message}\033[0m"


# Schema validation


def validate_with_schema(data, schema, label: str) -> bool:
    validator = Draft7Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: e.path)
    error_list = []
    if errors:

        error_list = [
            logError(label, ".".join(map(str, e.path)) or "<root>", e.message)
            for e in errors
        ]

        return False, error_list

    return True, []
