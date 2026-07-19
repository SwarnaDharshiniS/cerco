# cerco
cerco is a Python source analysis toolkit for inspecting code structure, control flow, and security-relevant patterns.

## Features
- **AST serialization** – Convert Python source into a JSON-serializable AST tree.
- **CFG generation** – Build control-flow graphs for modules and functions.
- **Taint analysis** – Detect dangerous data flows and report findings.
- **Capability analysis** – Identify potentially sensitive capabilities used by code.
- **Resource analysis** – Estimate resource risk from loops, recursion, and call depth.
- **Safety manifests** – Generate deterministic safety manifests from source code.
- **Safety IR** – Emit a compiler-inspired intermediate representation for analysis pipelines.

## Command-line usage
cerco is driven through `main.py` with subcommands:
```bash
python3 main.py ast --src "x = 1 + 2"
python3 main.py ast myfile.py
python3 main.py cfg --src "for i in range(3): print(i)"
python3 main.py cfg myfile.py --function myFunc
python3 main.py cfg myfile.py --function "*"
python3 main.py taint --src "import os; os.system(input())"
python3 main.py taint myfile.py
python3 main.py caps myfile.py
python3 main.py resource myfile.py
python3 main.py manifest myfile.py
python3 main.py safety-ir myfile.py
```

## Available commands

### `ast`
Serialize Python source into a JSON AST representation.

### `cfg`
Build a control-flow graph for a module or a specific function and emit JSON.

### `taint`
Run taint analysis and print either a human-readable summary or JSON with `--json`.

### `caps`
Run capability analysis to detect usage patterns such as filesystem, network, process, and dynamic execution features. Use `--json` for a machine-readable report.

### `resource`
Estimate resource risk and report heuristics such as loop depth, recursion, and call depth. Use `--json` for a machine-readable report.

### `manifest`
Generate a deterministic safety manifest with a verdict, digest, and rejection reasons. Use `--json` for the full manifest. Optional flags: `--analysis-version` (default: `1.0.0`) and `--timestamp` (RFC3339 UTC; defaults to deterministic epoch).

### `safety-ir`
Generate a structured safety IR JSON document for downstream tooling. Optional flags: `--analysis-version` (default: `1.0.0`) and `--timestamp` (RFC3339 UTC; default: `1970-01-01T00:00:00Z`).

## Project structure
- `main.py` – CLI entry point and command dispatcher
- `parser/` – Python AST parsing and serialization helpers
- `cfg/` – Control-flow graph construction
- `analysis/` – Static analysis modules
- `examples/` – Example inputs and usage samples
- `tests/` – Test suite

## Output formats
`ast`, `cfg`, and `safety-ir` always emit JSON. `taint`, `caps`, `resource`, and `manifest` print a human-readable summary by default; pass `--json` for machine-readable output.

## Requirements
This project uses Python and depends on packages required by the parser and analysis modules, including:
- `networkx`
