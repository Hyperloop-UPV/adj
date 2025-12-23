#!/usr/bin/env python3

import json
import sys
import ipaddress
from pathlib import Path
from jsonschema import Draft7Validator


# =========================
# CONFIG
# =========================

BASE_DIR_JSON = Path("test")
BASE_DIR_SCHEMA = Path("schema")


# =========================
# UTILS
# =========================


def print_header(header: str):
    print("=" * 40)
    print("· " + header)
    print("=" * 40)


def print_status(message: str, validated: bool = False):

    if not validated:
        result = "\033[31mFailed\033[0m"
    elif validated:
        result = "\033[32mPassed\033[0m"

    print("· " + message + " " + result)


def log_message(message: str, status: int = 0):
    """
    status:
      -1 → error (red)
       0 → normal
       1 → success (green)
    """
    colors = {-1: "\033[31m", 1: "\033[32m"}
    color = colors.get(status, "")
    reset = "\033[0m" if color else ""
    print(f"{color}{message}{reset}")


def load_json(path: Path):
    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise RuntimeError(f"File not found: {path}")
    except json.JSONDecodeError as e:
        raise RuntimeError(f"JSON malformed in {path}: {e}")


def is_valid_ipv4(address: str) -> bool:
    try:
        ipaddress.IPv4Address(address)
        return True
    except ipaddress.AddressValueError:
        return False


def print_results(file, is_valid, error_list):
    print_status(file, is_valid)
    for error in error_list:
        print("\t" + error)


def open_json(relative_path: str):
    return load_json(BASE_DIR_JSON / relative_path)


def open_schema(relative_path: str):
    return load_json(BASE_DIR_SCHEMA / relative_path)


def logError(label: str, path: str, message: str):
    return f"\033[31m{label}: {path} → {message}\033[0m"


def logSuccess(label: str):
    log_message(f"{label}: validation passed", status=1)


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


# =========================
# VARIABLES
# =========================

unique_board_ids = set()
unique_board_ip = set()

# =========================
# VALIDATORS
# =========================


def check_boards_json():

    is_valid = True
    error_list = []
    boards = None

    try:
        boards = open_json("boards.json")

        if not isinstance(boards, dict):
            error_list.append(
                logError("boards.json", "<root>", "boards.json must be a dictionary")
            )
            is_valid = False
        else:
            for board, path in boards.items():
                if not isinstance(board, str):
                    error_list.append(
                        logError(
                            "boards.json",
                            "<board name>",
                            f"Board names must be strings and '{board}' is not a string",
                        )
                    )
                    is_valid = False

                if not isinstance(path, str):
                    error_list.append(
                        logError(
                            "boards.json",
                            f"boards.{board}",
                            f"Path for board '{board}' must be a string",
                        )
                    )
                    is_valid = False
                elif not path.endswith(".json"):
                    error_list.append(
                        logError(
                            "boards.json",
                            f"boards.{board}",
                            f"Path for board '{board}' must end with .json",
                        )
                    )
                    is_valid = False
    except RuntimeError as e:
        error_list.append(logError("boards.json", "<load>", str(e)))
        is_valid = False

    print_results("boards.json", is_valid, error_list)

    return boards


def check_general_info_json():

    error_list = []
    is_valid = True
    try:
        general_info = open_json("general_info.json")
        schema = open_schema("general_info.schema.json")

        is_valid, schema_errors = validate_with_schema(
            general_info, schema, "general_info.json"
        )
        if not is_valid:
            error_list.extend(schema_errors)

        # Additional custom validations

        # IPv4 validation (schema already checks format, this is defensive)
        for name, address in general_info["addresses"].items():
            if not is_valid_ipv4(address):
                error_list.append(
                    logError(
                        "general_info.json",
                        f"addresses.{name}",
                        f"Invalid IPv4 address: {address}",
                    )
                )
                is_valid = False

        # Message IDs must be unique
        ids_seen = set()
        for message, msg_id in general_info["message_ids"].items():
            if msg_id in ids_seen:
                error_list.append(
                    logError(
                        "general_info.json",
                        f"message_ids.{message}",
                        f"Duplicate message ID {msg_id}",
                    )
                )
                is_valid = False
            ids_seen.add(msg_id)
    except RuntimeError as e:
        error_list.append(logError("general_info.json", "<load>", str(e)))
        is_valid = False

    print_results("general_info.json", is_valid, error_list)

    return is_valid


def check_board_json(path: str):

    error_list = []
    is_valid = True

    try:
        board = open_json(path)
        schema = open_schema("board.schema.json")

        is_valid, schema_errors = validate_with_schema(board, schema, path)
        if not is_valid:
            error_list.extend(schema_errors)

        # check if ip and id are unique
        board_id = board["board_id"]
        board_ip = board["board_ip"]
        if board_id in unique_board_ids:
            error_list.append(
                logError(
                    path,
                    "board_id",
                    f"Duplicate board_id {board_id}",
                )
            )
            is_valid = False
        else:
            unique_board_ids.add(board_id)

        if board_ip in unique_board_ip:
            error_list.append(
                logError(
                    path,
                    "ip_address",
                    f"Duplicate ip_address {board_ip}",
                )
            )
            is_valid = False
        else:
            unique_board_ip.add(board_ip)

        # Check if board_ip is a valid IPv4 address
        if not is_valid_ipv4(board_ip):
            error_list.append(
                logError(
                    path,
                    "board_ip",
                    f"Invalid IPv4 address: {board_ip}",
                )
            )
            is_valid = False
    except RuntimeError as e:
        error_list.append(logError(path, "<load>", str(e)))
        is_valid = False
    print_results(path, is_valid, error_list)

    if is_valid:
        return board
    else:
        return None


def check_measurement_json(path: str, previous_ids=None):

    error_list = []
    is_valid = True

    try:
        measurement = open_json(path)
        schema = open_schema("measurements.schema.json")

        is_valid, schema_errors = validate_with_schema(measurement, schema, path)
        if not is_valid:
            error_list.extend(schema_errors)

        # Check that all mesuraments ids are unique within the measurement and if  type="enum" there is a enumValues field with unique values

        for measure in measurement:
            mesurament_id = measure["id"]
            # id
            if mesurament_id in previous_ids:

                error_list.append(
                    logError(
                        path,
                        "id",
                        f"Duplicate id {mesurament_id} within the measurement",
                    )
                )
                is_valid = False

            # type enum
            if measure["type"] == "enum":
                if "enumValues" not in measure:
                    error_list.append(
                        logError(
                            path,
                            f"id {mesurament_id}",
                            f"id {mesurament_id} is of type 'enum' but 'enumValues' field is missing",
                        )
                    )
                    is_valid = False
                else:
                    # check unique enum values
                    enum_values = measure["enumValues"]
                    if len(enum_values) != len(set(enum_values)):
                        error_list.append(
                            logError(
                                path,
                                f"id {mesurament_id}",
                                f"'enumValues' for id {mesurament_id} contains duplicate values",
                            )
                        )
                        is_valid = False
                # if is not enum type must not have enumValues field
                if measure["type"] != "enum" and "enumValues" in measure:
                    error_list.append(
                        logError(
                            path,
                            f"id {mesurament_id}",
                            f"id {mesurament_id} is of type '{measure['type']}' but has 'enumValues' field",
                        )
                    )
                    is_valid = False
            else:
                previous_ids.add(mesurament_id)

    except RuntimeError as e:
        error_list.append(logError(path, "<load>", str(e)))
        is_valid = False
    print_results("\t" + path, is_valid, error_list)


# =========================
# MAIN
# =========================


def main():
    print_header("JSON Validation Script")

    check_general_info_json()
    boards = check_boards_json()
    if boards is None:
        sys.exit(1)

    print_header("Validating individual board JSON files")

    for board_name, board_path in boards.items():
        board = check_board_json(board_path)

        # if board is not none continue with further processing
        if board is not None:
            measurement_ids = set()
            for measurement_path in board.get("measurements", []):
                check_measurement_json(
                    f"boards/{board_name}/{measurement_path}", measurement_ids
                )

    log_message("All JSON files validated successfully", status=1)


if __name__ == "__main__":
    main()
