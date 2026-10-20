"""Utility helpers for printing, logging and JSON loading.

This module providessmall helper functions used by the test-suite and
CLI utilities, including colored printing for statuses, simple logging,
JSON loading with clear error messages, and basic IPv4 validation.
"""
import re
from math import isfinite
import json
import ipaddress
from pathlib import Path
from jsonschema import Draft7Validator

# Global switch to control whether ANSI colors are used in output.
# This is controlled from CLI via the `--no-color` flag.
ENABLE_COLOR = True


def set_color_enabled(enabled: bool):
    """Enable or disable ANSI color output.

    Args:
        enabled: If False, all helper output functions will omit ANSI
                 escape sequences.
    """

    global ENABLE_COLOR
    ENABLE_COLOR = enabled


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


def format_status(message: str, validated: bool = False):
    """Print a single-line status message.

    The `validated` flag controls whether the status is shown as
    a green "Passed" (True) or a red "Failed" (False).

    Args:
        message: Human-readable message or label to print before status.
        validated: If True, prints a green "Passed"; otherwise prints a
                   red "Failed".
    """

    if not ENABLE_COLOR:
        result = "Passed" if validated else "Failed"
        return f"{message} {result}"

    # ANSI color codes used for terminal output
    if not validated:
        result = "\033[31mFailed\033[0m"  # red
    else:
        result = "\033[32mPassed\033[0m"  # green

    return f"{message} {result}"


def info_message(message: str):
    """format to blue color and return the message string."""

    if not ENABLE_COLOR:
        return message

    return f"\033[34m{message}\033[0m"


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

    if not ENABLE_COLOR:
        print(message)
        return

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
    
    # ipadress does not throw error for addresses like " 192.168.1.2 " or "19216813"
    if not isinstance(address, str) or address.count('.') != 3:
        return False
    if not set(address).issubset("0123456789."):
        return False

    try:
        ipaddress.IPv4Address(address)
        return True
    except ipaddress.AddressValueError, ValueError:
        return False

def is_valid_mac(address: str) -> bool:
    """Return True if the given string is a valid MAC address.
    It only supports valid addresses in the from XX:XX:XX:XX:XX:XX
    """
    # Syntax check
    if not isinstance(address, str) or not re.match(r"^([0-9A-F]{2}:){5}([0-9A-F]{2})$", address):
        return False

    # Normalize to int list
    octets = [int(b, 16) for b in address.split(":")]

    # Discard null and broadcast
    if all(b == 0x00 for b in octets): # 00:00:00:00:00:00
        return False
    if all(b == 0xFF for b in octets): # FF:FF:FF:FF:FF:FF
        return False

    first_oct = octets[0]
    is_multicast = (first_oct & 0x01) != 0
    
    if is_multicast:
        return False

    return True

INT_RANGES = {
    "uint8": (0, 2**8 - 1),       "uint16": (0, 2**16 - 1),
    "uint32": (0, 2**32 - 1),     "uint64": (0, 2**64 - 1),
    "int8": (-2**7, 2**7 - 1),    "int16": (-2**15, 2**15 - 1),
    "int32": (-2**31, 2**31 - 1), "int64": (-2**63, 2**63 - 1),
    "bool": (0, 1),
}

def is_valid_protection(
    prot: dict,
    prot_types: dict,
    path: str,
    meas_id: int,
    measure: dict,
) -> tuple[bool, list[str]]:
    """Validate a single protection definition against general_info rules.

    Args:
        prot: Protection dictionary.
        prot_types: Dict of allowed protection types from general_info.json.
        path: File path for error reporting.
        meas_id: ID of the parent measurement.

    Returns:
        tuple[bool, list[str]]: (is_valid, error_list)
    """
    error_list = []
    is_valid = True

    p_type = prot.get("type")
    p_vals = prot.get("value")

    if not isinstance(p_type, str) or not isinstance(p_vals, list):
        error_list.append(
            logError(
                path,
                f"id {meas_id}.protections",
                "Protection entry must contain 'type' (string) and 'value' (array)",
            )
        )
        return False, error_list

    if p_type not in prot_types:
        error_list.append(
            logError(
                path,
                f"id {meas_id}.protections.type",
                f"Protection type '{p_type}' is not defined in general_info.json",
            )
        )
        return False, error_list

    if "time" in prot and "textTime" not in prot_types[p_type]:
        error_list.append(
            logError(
                path, 
                f"id {meas_id}.protections.time",
                f"Type '{p_type}' has 'time' but no 'textTime' in protectionTypes")
        )
        is_valid = False
    
    if not all(isinstance(v, (int, float)) and not isinstance(v, bool) and isfinite(v) for v in p_vals): # bool is an int subclass :/
        error_list.append(logError(path, f"id {meas_id}.protections.value",
                               "All values must be numbers"))
        return False, error_list

    expects_range = prot_types[p_type].get("range", False)
    expected_len = 2 if expects_range else 1

    if len(p_vals) != expected_len:
        expected_desc = "2 values [min, max]" if expects_range else "exactly 1 value"
        error_list.append(
            logError(
                path,
                f"id {meas_id}.protections.value",
                f"Type '{p_type}' requires {expected_desc}, got {len(p_vals)}",
            )
        )
        is_valid = False

    if len(p_vals) == 2 and p_vals[0] > p_vals[1]:
        error_list.append(
            logError(
                path,
                f"id {meas_id}.protections.value",
                f"Lower bound ({p_vals[0]}) cannot be greater than upper bound ({p_vals[1]})",
            )
        )
        is_valid = False

    mtype = measure.get("type")

    for v in p_vals:
        if mtype == "enum":
            n = len(measure.get("enumValues", []))
            ok = float(v).is_integer() and 0 <= v < n
            reason = f"enum index must be in [0, {n - 1}]"
        elif mtype in INT_RANGES:
            lo, hi = INT_RANGES[mtype]
            ok = float(v).is_integer() and lo <= v <= hi
            reason = f"{mtype} requires an integer in [{lo}, {hi}]"
        else:
            continue  # float32/float64
        if not ok:
            error_list.append(logError(
                path, f"id {meas_id}.protections.value",
                f"Value {v} does not fit measurement type '{mtype}' ({reason})"))
            is_valid = False

    return is_valid, error_list    

def print_results(file, is_valid, error_list, type=None, prefix=""):
    """Print validation results for a file.

    The function prints an overall status line and then any detailed
    error messages indented on subsequent lines.

    Args:
        file: File name or identifier to show in the status line.
        is_valid: Boolean indicating whether the file passed validation.
        error_list: Iterable of error message strings.
    """

    out = format_status(file, is_valid)

    if type != None:
        out = f"{out} {info_message(type)}"

    print(prefix + out)

    for error in error_list:
        # Indent errors for readability in CLI output
        print("\t|\t" + error)


def logError(label: str, path: str, message: str):
    """Return a formatted, red-colored error string.

    This helper is handy for tests or logging in contexts that prefer a
    single formatted string instead of printing directly.
    """

    if not ENABLE_COLOR:
        return f"{label}: {path} → {message}"

    return f"\033[31m{label}: {path} → {message}\033[0m"


# Schema validation
def validate_with_schema(data, schema, label: str) -> tuple[bool, list[str]]:
    validator = Draft7Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: [str(p) for p in e.path])
    error_list = []
    if errors:

        error_list = [
            logError(label, ".".join(map(str, e.path)) or "<root>", e.message)
            for e in errors
        ]

        return False, error_list

    return True, []
