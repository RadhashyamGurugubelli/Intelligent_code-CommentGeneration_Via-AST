# Reproducible Evaluation Report

This evaluation verifies AST Studio's deterministic parsing, security scanning, docstring generation, and syntax validation across the curated suite in `sample example/`.

> **To reproduce this evaluation locally:**
> ```bash
> python scripts/evaluate_samples.py
> ```

## Summary of Results

| Sample File | Lines | Findings Detected | Docstrings Generated | Validation | Generation Source | Analysis Notes |
| :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| `sample1.py` | 4 | 2 | 1 | PASS | `deterministic` | 2 warning(s) caught |
| `sample10_unsafe_credentials.py` | 7 | 3 | 1 | PASS | `deterministic` | 3 warning(s) caught |
| `sample2.py` | 13 | 0 | 1 | PASS | `deterministic` | Clean AST parsing |
| `sample3.py` | 5 | 0 | 1 | PASS | `deterministic` | Clean AST parsing |
| `sample4.py` | 26 | 0 | 5 | PASS | `deterministic` | Clean AST parsing |
| `sample5.py` | 21 | 0 | 1 | PASS | `deterministic` | Clean AST parsing |
| `sample6_low_quality.py` | 74 | 5 | 1 | PASS | `deterministic` | 5 warning(s) caught |
| `sample7_undefined_name.py` | 3 | 1 | 1 | PASS | `deterministic` | 1 warning(s) caught |
| `sample8_syntax_error.py` | 5 | 1 | 0 | PASS (Syntax Error Correctly Rejected) | `deterministic` | Intentional syntax error caught: expected ':' |
| `sample9_division_by_zero.py` | 2 | 2 | 1 | PASS | `deterministic` | 2 warning(s) caught |

## Aggregate Metrics

- **Total Test Files Evaluated**: 10
- **Validation Success Rate**: 10/10 (100% of valid files pass AST compile validation; invalid files correctly caught)
- **Total Security & Quality Findings Flagged**: 14
- **Total Documented Function/Class Blocks**: 13
- **Execution Paradigm**: Deterministic AST standard-library analysis (Air-gapped)

## Observations
1. **Syntax Errors (`sample8_syntax_error.py`)**: Safely rejected at the parser boundary without executing invalid bytecodes.
2. **Security Vulnerabilities (`sample1.py`, `sample10_unsafe_credentials.py`)**: High-risk injection sinks and credentials flagged with exact line and column numbers.
3. **Code Validation**: Every synthesized candidate passes AST round-trip compilation and structural equivalence verification.
