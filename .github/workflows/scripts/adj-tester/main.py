"""

ADJ Validator

Version: 1.1.0

JavierRibaldelRio

Entrypoint script for validating project JSON files against schemas.

This script coordinates several checks over files in the test/
directory using JSON Schema validation and project-specific rules
(e.g. uniqueness constraints and IPv4 validation).
"""

import sys
from pathlib import Path

from utils import (
    print_header,
    log_message,
    load_json,
    is_valid_ipv4,
    print_results,
    logError,
    info_message,
    validate_with_schema,
)


# =========================
# CONFIG
# =========================

# Comment while development
SCRIPT_DIR = Path(__file__).resolve().parent

BASE_DIR_JSON = SCRIPT_DIR.parent.parent.parent.parent
BASE_DIR_SCHEMA = SCRIPT_DIR / "schema"

# comment while production
# BASE_DIR_JSON =  "test"
# BASE_DIR_SCHEMA =  "schema"

# =========================
# UTILS
# =========================


def open_json(relative_path: str):
    """Load a JSON file from the `test/` directory.

    Args:
        relative_path: Path relative to `test/` (e.g. "boards.json").

    Returns:
        The parsed JSON structure.
    """

    return load_json(BASE_DIR_JSON / relative_path)


def open_schema(relative_path: str):
    """Load a JSON Schema file from the `schema/` directory.

    Args:
        relative_path: Path relative to `schema/` (e.g. "board.schema.json").

    Returns:
        The parsed JSON Schema as a dictionary.
    """

    return load_json(BASE_DIR_SCHEMA / relative_path)


# =========================
# VARIABLES
# =========================

unique_board_ids = set()
unique_board_ip = set()
unique_packet_ids = set()
units = set()

# =========================
# VALIDATORS
# =========================


def check_boards_json():
    """Validate the top-level `boards.json` index file.

    Verifies that `boards.json` is a mapping of board name (string) to a
    relative JSON filename (string ending with .json).

    Returns the parsed boards mapping (dict) on success, otherwise None.
    """

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
    """Validate `general_info.json` and apply additional project rules.

    Performs schema validation and extra checks such as IPv4 format
    validation for addresses, uniqueness of message IDs, and
    accumulation/uniqueness checks for measurement units.
    Returns True on success, False otherwise.
    """

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

        # measurement must be unique
        for measurement, _ in general_info["units"].items():
            if measurement in units:
                error_list.append(
                    logError(
                        "general_info.json",
                        f"units.{measurement}",
                        f"Duplicate measurement {measurement}",
                    )
                )
                is_valid = False
            units.add(measurement)
    except RuntimeError as e:
        error_list.append(logError("general_info.json", "<load>", str(e)))
        is_valid = False

    print_results("general_info.json", is_valid, error_list)

    return is_valid


def check_board_json(path: str):
    """Validate a single board JSON file.

    Ensures schema conformance and enforces global uniqueness for
    `board_id` and `board_ip`. Also verifies the IPv4 format of
    the board IP address.
    Returns the parsed board dict on success, otherwise None.
    """

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
    print_results(path, is_valid, error_list, type="(Board)")

    if is_valid:
        return board
    else:
        return None


def check_measurement_json(path: str, previous_ids=None):
    """Validate a measurements JSON file.

    Checks include schema validation, uniqueness of measurement IDs
    within the current board (`previous_ids`), verification that any
    referenced units exist in `general_info.json`, and validation of
    enum-related constraints.

    Returns True if valid, False otherwise.
    """

    error_list = []
    is_valid = True

    try:
        measurement = open_json(path)
        schema = open_schema("measurements.schema.json")

        # Schema validation
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
            else:
                previous_ids.add(mesurament_id)

            # units
            # Check that the podUnits and DisplayUnits are in units
            podUnit = measure.get("podUnits", "")
            if podUnit != "" and podUnit not in units:
                error_list.append(
                    logError(
                        path,
                        f"id {mesurament_id}",
                        f"podUnit '{podUnit}' for id {mesurament_id} is not defined in general_info.json",
                    )
                )
                is_valid = False

            displayUnit = measure.get("displayUnits", "")
            if displayUnit != "" and displayUnit not in units:
                error_list.append(
                    logError(
                        path,
                        f"id {mesurament_id}",
                        f"displayUnit '{displayUnit}' for id {mesurament_id} is not defined in general_info.json",
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

    except RuntimeError as e:
        error_list.append(logError(path, "<load>", str(e)))
        is_valid = False
    print_results(path, is_valid, error_list, type="(Measurements)", prefix="\t")
    return is_valid


def check_packet_json(path: str, sockets: set, measurement_ids=None):
    """Validate a packet JSON file.

    Ensures schema conformance, global uniqueness of packet IDs
    (with 0 often allowed as special case) and that referenced
    measurement IDs exist in `measurement_ids`.

    Returns True if valid, False otherwise.
    """

    error_list = []
    is_valid = True

    try:
        packet = open_json(path)
        schema = open_schema("packet.schema.json")

        # Schema validation
        is_valid, schema_errors = validate_with_schema(packet, schema, path)
        if not is_valid:
            error_list.extend(schema_errors)

        # Ensure packet id is unique across all packets
        for pkt in packet:
            pkt_id = pkt["id"]
            if pkt_id in unique_packet_ids and pkt_id != 0:
                error_list.append(
                    logError(
                        path,
                        "id",
                        f"Duplicate id {pkt_id} across packets",
                    )
                )
                is_valid = False
            else:
                unique_packet_ids.add(pkt_id)

            # Ensure all measurement ids in the packet are defined in the measurements
            for meas_id in pkt.get("variables", []):
                if meas_id not in measurement_ids:
                    error_list.append(
                        logError(
                            path,
                            f"id {pkt_id}",
                            f"measurement_id {meas_id} in id {pkt_id} is not defined in measurements",
                        )
                    )
                    is_valid = False

            # Ensure that socket is defined in the sockets
            socket_name = pkt.get("socket", "")
            if socket_name != "" and socket_name not in sockets:
                error_list.append(
                    logError(
                        path,
                        f"id {pkt_id}",
                        f"socket '{socket_name}' in id {pkt_id} is not defined in sockets",
                    )
                )
                is_valid = False

    except RuntimeError as e:
        error_list.append(logError(path, "<load>", str(e)))
        is_valid = False
    print_results(path, is_valid, error_list, type="(Packets/Orders)", prefix="\t")
    return is_valid


def check_socket_json(path: str, sockets_name: set):

    error_list = []
    is_valid = True
    try:
        # Open json and Schema
        sockets = open_json(path)
        schema = open_schema("socket.schema.json")

        # Schema validation
        is_valid, schema_errors = validate_with_schema(sockets, schema, path)
        if not is_valid:
            error_list.extend(schema_errors)

        for socket in sockets:
            # ensure socket name is unique across all sockets
            socket_name = socket["name"]
            if socket_name in sockets_name:
                error_list.append(
                    logError(
                        path,
                        "name",
                        f"Duplicate socket name '{socket_name}' across sockets",
                    )
                )
                is_valid = False
            else:
                sockets_name.add(socket_name)

            # check that remote_ip is valid (remote_ip is optional) and it is defined only for type=="DatagramSocket" || type=="Socket"
            if (
                socket["type"] not in ["DatagramSocket", "Socket"]
                and "remote_ip" in socket
            ):
                error_list.append(
                    logError(
                        path,
                        f"name {socket_name}",
                        f"remote_ip is only allowed for type 'DatagramSocket' or 'Socket', but socket '{socket_name}' has type '{socket['type']}'",
                    )
                )
                is_valid = False

            else:
                socket_ip = socket.get("remote_ip", "")
                if socket_ip != "" and not is_valid_ipv4(socket_ip):
                    error_list.append(
                        logError(
                            path,
                            f"name {socket_name}",
                            f"Invalid IPv4 address: {socket_ip}",
                        )
                    )
                    is_valid = False

            # check that port is only definied if type=="ServerSocket" || type=="DatagramSocket"

            if socket.get("port", None) is not None and socket["type"] not in [
                "ServerSocket",
                "DatagramSocket",
            ]:
                error_list.append(
                    logError(
                        path,
                        f"name {socket_name}",
                        f"Port is only allowed for type 'ServerSocket' or 'DatagramSocket', but socket '{socket_name}' has type '{socket['type']}'",
                    )
                )
                is_valid = False

            # check that local_port is only used for type=="Socket"
            if (
                socket.get("local_port", None) is not None
                and socket["type"] != "Socket"
            ):
                error_list.append(
                    logError(
                        path,
                        f"name {socket_name}",
                        f"local_port is only allowed for type 'Socket', but socket '{socket_name}' has type '{socket['type']}'",
                    )
                )
                is_valid = False

            # checck thath remote_port is only used for type=="Socket"
            if (
                socket.get("remote_port", None) is not None
                and socket["type"] != "Socket"
            ):
                error_list.append(
                    logError(
                        path,
                        f"name {socket_name}",
                        f"remote_port is only allowed for type 'Socket', but socket '{socket_name}' has type '{socket['type']}'",
                    )
                )
                is_valid = False

    except RuntimeError as e:
        error_list.append(logError(path, "<load>", str(e)))
        is_valid = False
    print_results(path, is_valid, error_list, type="(Socket)", prefix="\t")
    return is_valid


# =========================
# MAIN
# =========================


def main():
    """Main orchestration function.

    Performs the full validation flow and exits the process with a
    non-zero status code if any validation step fails.
    """

    # App header
    print_header("JSON Validation Script")

    # Validate general_info.json
    valid = check_general_info_json()

    # Get boards and validate json
    boards = check_boards_json()
    if boards is None or not valid:
        log_message("Aborting due to previous errors", status=-1)
        sys.exit(1)

    # Validate individual board JSON files
    print_header("Validating individual board JSON files")

    for board_name, board_path in boards.items():

        # Validate board JSON, board is an arrya of measurements and packets paths
        board = check_board_json(board_path)

        # if board is not none continue with further processing
        if board is not None:

            # measurements are unique within a board
            measurement_ids = set()

            # sockets are unique
            sockets_name = set()

            # Validate socket JSON files
            for socket_path in board.get("sockets", []):
                valid = (
                    check_socket_json(
                        f"boards/{board_name}/{socket_path}", sockets_name
                    )
                    and valid
                )

            # Validate measurements JSON files
            for measurement_path in board.get("measurements", []):
                valid = (
                    check_measurement_json(
                        f"boards/{board_name}/{measurement_path}",
                        measurement_ids,
                    )
                    and valid
                )

            # Validate packets JSON files (remember that orders are processed as packets)
            for packets_path in board.get("packets", []):
                valid = (
                    check_packet_json(
                        f"boards/{board_name}/{packets_path}",
                        sockets_name,
                        measurement_ids,
                    )
                    and valid
                )
        else:
            log_message(
                f"Skipping measurements and packets validation for board {board_name} due to previous errors",
                status=-1,
            )
            valid = False

    if not valid:
        log_message("Validation completed with errors", status=-1)
        sys.exit(1)
    else:
        log_message("All JSON files validated successfully", status=1)


if __name__ == "__main__":
    main()
