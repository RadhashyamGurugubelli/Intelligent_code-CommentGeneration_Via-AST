# Security Policy

## Static Analysis Safety Guarantee

AST Studio operates primarily as a **static program analysis** platform. Source code submitted by users for inspection, AST visualization, security flaw detection, or automated docstring generation is parsed into an Abstract Syntax Tree via Python's standard library (`ast`, `symtable`, `tokenize`) and is **never executed** by default.

### Execution Boundaries
1. **Default Mode (Static Analysis)**:
   - Dynamic evaluation primitives such as `eval()`, `exec()`, or direct bytecode dispatch are prohibited on submitted user code.
   - All quality rules, vulnerability heuristics, and structural transforms operate strictly on the abstract syntax tree and token streams.

2. **Isolated Verification Runner (`ALLOW_PROJECT_TEST_EXECUTION`)**:
   - Dynamic test execution is **disabled by default** (`ALLOW_PROJECT_TEST_EXECUTION=false`).
   - If explicitly enabled by an operator in `.env`, test execution is confined to a disposable, unprivileged subprocess (`python -I`) with stripped credential variables (`API_KEY`, tokens), resource limits, strict timeouts (30s), and network isolation.

## Reporting Security Issues

If you discover a security vulnerability or execution escape in AST Studio:
1. Do not open a public issue on GitHub.
2. Submit details and a minimal reproducible example privately to the project maintainers.
