# Adj Tester

Adj Tester is a JSON validation tool used by the HyperLoop project to verify that files under the `test/` directory conform to their JSON Schemas and to additional project rules (e.g. unique IDs, IPv4 format, and unit consistency).

## Requirements
- Python 3.13+
- Dependencies:
  - jsonschema

Install dependencies:
```bash
pip install jsonschema
```

## Relevant structure
- `main.py` — Entry point that orchestrates validations.
- `utils.py` — Helper functions (JSON loading, IPv4 validation, logging).
- `schema/` — JSON Schemas (e.g. `board.schema.json`, `measurements.schema.json`).

## Usage
Run from the `adj` folder:
```bash
python main.py
```

The script:
- Validates `general_info.json`, applying schema checks and extra rules (IPs, message IDs, units).
- Validates `boards.json` (mapping board name → file).
- For each board, validates `board.json`, its `measurements` and `packets`.

## Exit codes
- `0` — Success (no validation errors).
- `1` — Validation errors detected.

## Output
Console text shows `Passed`/`Failed` statuses and detailed error messages. Errors are printed in red and include the file path and description.

## Contributing
- Add or update schemas in `schema/`.
- Add tests/data in `test/`.
- Keep `boards.json` and `general_info.json` consistent.
- Run `python main.py` and fix reported issues.

