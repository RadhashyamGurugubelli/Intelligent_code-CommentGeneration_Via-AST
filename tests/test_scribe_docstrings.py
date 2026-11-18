"""Tests for SCRIBE (DocstringAgent) model-backed generation and AST-grounded fallback."""

import ast
import copy
from pathlib import Path
from types import SimpleNamespace
from typing import Any, List

import pytest

from backend.agentic.agents.specialists import (
    DocstringAgent,
    _extract_documented_params,
    _missing_callable_docstrings,
)
from backend.agentic.session import SessionManager
from backend.agentic.tools import create_standard_tool_registry
from backend.validator import _strip_docstrings, validate_generated_code


class ScriptedDocstringModelClient:
    """Mock model client returning pre-scripted responses."""

    def __init__(self, responses: List[str]) -> None:
        self.responses = list(responses)
        self.call_history: List[List[dict]] = []

    @property
    def chat(self) -> Any:
        return SimpleNamespace(completions=SimpleNamespace(create=self._create_completion))

    def _create_completion(self, *args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get("messages", [])
        self.call_history.append(messages)
        if not self.responses:
            content = '{"docstring": "Default docstring."}'
        else:
            content = self.responses.pop(0)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=content))]
        )


def _dump_ast_stripped(source: str) -> str:
    tree = copy.deepcopy(ast.parse(source))
    return ast.dump(_strip_docstrings(tree), include_attributes=False)


GOLDEN_SAMPLES = [
    "sample1.py",
    "sample2.py",
    "sample3.py",
    "sample4.py",
    "sample5.py",
    "sample10_unsafe_credentials.py",
]


@pytest.mark.parametrize("sample_name", GOLDEN_SAMPLES)
def test_golden_samples_compile_and_preserve_executable_ast(sample_name: str) -> None:
    sample_path = Path("sample example") / sample_name
    original_code = sample_path.read_text(encoding="utf-8")

    registry = create_standard_tool_registry()
    scribe = DocstringAgent(registry)
    manager = SessionManager()
    session = manager.create_session(original_code, "Generate docstrings")

    result = scribe.deterministic_turn(session, "generate docstrings")
    candidate_code = result.get("candidate_code") or original_code

    # 1. Output must compile cleanly
    compile(candidate_code, f"<{sample_name}_output>", "exec")

    # 2. Executable AST must be strictly preserved
    assert _dump_ast_stripped(original_code) == _dump_ast_stripped(candidate_code)

    # 3. Code validator must pass
    validation = validate_generated_code(original_code, candidate_code)
    assert validation.get("is_valid") is True, f"Validation failed: {validation.get('issues')}"

    # 4. Each finding in deterministic turn must have source == 'deterministic'
    for finding in result.get("findings", []):
        if "function" in finding:
            assert finding.get("source") == "deterministic"


def test_extract_documented_params_across_styles() -> None:
    google_doc = (
        "Calculate total price.\n\n"
        "Args:\n"
        "    price (float): Base price.\n"
        "    tax_rate: Tax percentage.\n"
        "    discount (float, optional): Discount.\n\n"
        "Returns:\n"
        "    float: Final price."
    )
    assert _extract_documented_params(google_doc) == {"price", "tax_rate", "discount"}

    sphinx_doc = (
        "Calculate total price.\n\n"
        ":param float price: Base price.\n"
        ":param tax_rate: Tax percentage.\n"
        ":param discount: Discount.\n"
        ":returns: Final price."
    )
    assert _extract_documented_params(sphinx_doc) == {"price", "tax_rate", "discount"}

    numpy_doc = (
        "Calculate total price.\n\n"
        "Parameters\n"
        "----------\n"
        "price : float\n"
        "    Base price.\n"
        "tax_rate : float\n"
        "    Tax percentage.\n"
        "discount : float\n"
        "    Discount.\n\n"
        "Returns\n"
        "-------\n"
        "float\n"
        "    Final price."
    )
    assert _extract_documented_params(numpy_doc) == {"price", "tax_rate", "discount"}


def test_missing_callable_docstrings_finds_classes_and_functions() -> None:
    code = (
        "class Worker:\n"
        "    def run(self, job):\n"
        "        return job\n"
        "\n"
        "def standalone(x):\n"
        "    return x\n"
    )
    missing = _missing_callable_docstrings(code)
    names = [item["name"] for item in missing]
    assert "Worker" in names
    assert "run" in names
    assert "standalone" in names


def test_scribe_model_mode_generates_valid_docstring_with_source_model() -> None:
    code = "def calculate_total(prices, tax_rate):\n    return sum(prices) * (1 + tax_rate)\n"
    model_response = (
        '{"docstring": "Calculate total order cost.\\n\\n'
        'Args:\\n'
        '    prices (list): List of item prices.\\n'
        '    tax_rate (float): Applied tax rate.\\n\\n'
        'Returns:\\n'
        '    float: Total calculated price."}'
    )
    fake_client = ScriptedDocstringModelClient([model_response])
    registry = create_standard_tool_registry()
    scribe = DocstringAgent(registry, model_client=fake_client)
    manager = SessionManager()
    session = manager.create_session(code, "Document code")

    result = scribe.finish_from_observations(session, task_id="t1", execution_mode="model")
    candidate = result.get("candidate_code")
    assert candidate is not None
    assert "Calculate total order cost." in candidate
    assert compile(candidate, "<test>", "exec")

    # Check finding source is 'model'
    findings = result.get("findings", [])
    func_findings = [f for f in findings if f.get("function") == "calculate_total"]
    assert len(func_findings) == 1
    assert func_findings[0]["source"] == "model"
    assert result["candidate_execution_mode"] == "model"


def test_scribe_model_mode_rejects_hallucinated_param_and_retries() -> None:
    code = "def calculate_total(price, tax):\n    return price + tax\n"
    hallucinated_resp = (
        '{"docstring": "Calculate total.\\n\\n'
        'Args:\\n'
        '    price (float): Base price.\\n'
        '    tax (float): Tax amount.\\n'
        '    discount (float): Hallucinated discount amount.\\n\\n'
        'Returns:\\n'
        '    float: Total price."}'
    )
    clean_resp = (
        '{"docstring": "Calculate total price.\\n\\n'
        'Args:\\n'
        '    price (float): Base price.\\n'
        '    tax (float): Tax amount.\\n\\n'
        'Returns:\\n'
        '    float: Total price."}'
    )
    fake_client = ScriptedDocstringModelClient([hallucinated_resp, clean_resp])
    registry = create_standard_tool_registry()
    scribe = DocstringAgent(registry, model_client=fake_client)
    manager = SessionManager()
    session = manager.create_session(code, "Document code")

    result = scribe.finish_from_observations(session, task_id="t1", execution_mode="model")
    assert len(fake_client.call_history) == 2

    # Check that retry prompt mentioned the hallucinated parameter
    retry_prompt = fake_client.call_history[1][-1]["content"]
    assert "discount" in retry_prompt

    candidate = result.get("candidate_code")
    assert candidate is not None
    assert "discount" not in candidate
    assert "Calculate total price." in candidate

    func_findings = [f for f in result.get("findings", []) if f.get("function") == "calculate_total"]
    assert len(func_findings) == 1
    assert func_findings[0]["source"] == "model"


def test_scribe_model_mode_falls_back_when_hallucination_persists() -> None:
    code = "def calculate_total(price, tax):\n    return price + tax\n"
    hallucinated_resp1 = (
        '{"docstring": "Calculate total.\\n\\n'
        'Args:\\n'
        '    price (float): Base price.\\n'
        '    tax (float): Tax amount.\\n'
        '    discount (float): Hallucinated.\\n\\n'
        'Returns:\\n'
        '    float: Total."}'
    )
    hallucinated_resp2 = (
        '{"docstring": "Calculate total.\\n\\n'
        'Args:\\n'
        '    price (float): Base price.\\n'
        '    tax (float): Tax amount.\\n'
        '    coupon (str): Another hallucinated parameter.\\n\\n'
        'Returns:\\n'
        '    float: Total."}'
    )
    fake_client = ScriptedDocstringModelClient([hallucinated_resp1, hallucinated_resp2])
    registry = create_standard_tool_registry()
    scribe = DocstringAgent(registry, model_client=fake_client)
    manager = SessionManager()
    session = manager.create_session(code, "Document code")

    result = scribe.finish_from_observations(session, task_id="t1", execution_mode="model")
    assert len(fake_client.call_history) == 2

    candidate = result.get("candidate_code")
    assert candidate is not None
    # Must have fallen back to deterministic docstring
    func_findings = [f for f in result.get("findings", []) if f.get("function") == "calculate_total"]
    assert len(func_findings) == 1
    assert func_findings[0]["source"] == "deterministic"


def test_scribe_model_mode_falls_back_when_model_output_invalidates_code() -> None:
    code = "def compute(val):\n    return val * 2\n"
    # Docstring containing syntax-breaking quotes or malformed construct
    invalid_resp = '{"docstring": "Compute value.\'\'\'"""\\n    broken docstring'
    fake_client = ScriptedDocstringModelClient([invalid_resp, invalid_resp])
    registry = create_standard_tool_registry()
    scribe = DocstringAgent(registry, model_client=fake_client)
    manager = SessionManager()
    session = manager.create_session(code, "Document code")

    result = scribe.finish_from_observations(session, task_id="t1", execution_mode="model")
    candidate = result.get("candidate_code")
    assert candidate is not None
    compile(candidate, "<test>", "exec")
    func_findings = [f for f in result.get("findings", []) if f.get("function") == "compute"]
    assert len(func_findings) == 1
    assert func_findings[0]["source"] == "deterministic"
