# Overview
Sentinel is a virus scanner capable of scanning a directory of files comparing their contents against a database of known malware signatures, and providing a comprehensive security report.

## Package Manager
Use uv exclusively for Python package management in this project.

## Package Management Commands
- All Python dependencies **must be installed, synchronized, and locked** using uv
- Never use pip, pip-tools, poetry, or conda directly for dependency management

Use these commands:

- Install dependencies: `uv add <package>`
- Remove dependencies: `uv remove <package>`
- Sync environment: `uv sync`
- Lock dependencies: `uv lock`

## Running Python Code
- Run a Python script with `uv run <script-name>.py`
- Run Python tools with `uv run <tool>` (e.g. `uv run pytest`, `uv run ruff`, `uv run mypy`, `uv run pre-commit`)
- Launch a Python REPL with `uv run python`

## Security report
Generate a log file detailing infected paths, threat levels, and timestamps.


## Tackling Hiding strategy scope
- File extension trick
- Archive nesting, Packing/compression (using containerization technique to execute the decompression and run the scanner)

# Design pattern
This repository follows strictly the concept of Domain Driven Design to focuses on modeling software to match a complex business domain, prioritizing collaboration between developers and domain experts.

## Layers
- infrastructure/: Tools and external connections
- repository/: Fetching and saving data.
- application/: The workflow and logic steps.
- presentation/: How the user talks to the app

