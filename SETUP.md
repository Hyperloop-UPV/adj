## Development Setup

### Prerequisites

- **Node.js** (v18+ recommended) and npm
- **Python 3.13**
- **[uv](https://github.com/astral-sh/uv)** – Python package manager (used by adj-tester) for multiplatform support.

### Install

`pip install uv` or `brew install uv` - To install uv in case you don't have it.

`npm install` - This installs Husky and configures Git hooks. The prepare script runs automatically.

### Pre-commit Hook (Husky)

On each git commit, the pre-commit hook runs:

> Note: I tested it only with git commit from cli and Cursor IDE Git integration. Possibly doesn't work with Github Desktop.

1.  **npm install** – Ensures dependencies are installed
2.  **lint-staged** – Formats staged JSON/JSONC files with Prettier
3.  **adj-tester** – Validates all ADJ config files

If any step fails, the commit is aborted.

### Tools

| Tool        | Purpose                                              |
| ----------- | ---------------------------------------------------- |
| Husky       | Manages Git hooks (pre-commit)                       |
| lint-staged | Runs Prettier only on staged files                   |
| Prettier    | Formats _.json and _.jsonc                           |
| adj-tester  | Validates boards, measurements, packets, units, etc. |

### Manual Commands

```bash
# Format all JSON/JSONC files
npm run format

# Check formatting without writing
npm run format:check

# Run ADJ validation (from repo root)
npm run test
```

### CI

The ADJ Validator GitHub Action runs the same adj-tester checks on every push and pull request.
