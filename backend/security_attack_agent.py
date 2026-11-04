"""AI-driven and AST-grounded Code Security Attack Simulation Agent (Red Team)."""

import ast
import re
from typing import Any

from backend.attack_guard import detect_attack
from backend.validator import validate_code

_SQL_KEYWORDS = re.compile(
    r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|FROM|WHERE)\b",
    re.IGNORECASE,
)

_INSECURE_XML_CALLS = {
    "xml.etree.ElementTree.parse",
    "xml.etree.ElementTree.fromstring",
    "xml.etree.ElementTree.XML",
    "xml.dom.minidom.parse",
    "xml.dom.minidom.parseString",
    "xml.sax.parse",
    "xml.sax.parseString",
    "xmlrpc.client.ServerProxy",
    "lxml.etree.parse",
    "lxml.etree.fromstring",
    "lxml.etree.XML",
    "ElementTree.parse",
    "ElementTree.fromstring",
    "ElementTree.XML",
    "minidom.parse",
    "minidom.parseString",
}

_SSRF_CALLS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.delete",
    "requests.patch",
    "requests.head",
    "requests.request",
    "urllib.request.urlopen",
    "urllib.request.Request",
    "httpx.get",
    "httpx.post",
}


def _import_aliases(tree: ast.AST) -> dict[str, str]:
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".")[0]
                aliases[local_name] = alias.name if alias.asname else local_name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                local_name = alias.asname or alias.name
                aliases[local_name] = ".".join(
                    part for part in (module, alias.name) if part
                )
    return aliases


def _canonical_call_name(node: ast.expr, aliases: dict[str, str]) -> str:
    if isinstance(node, ast.Name):
        return aliases.get(node.id, node.id)
    if isinstance(node, ast.Attribute):
        base = _canonical_call_name(node.value, aliases)
        return f"{base}.{node.attr}" if base else node.attr
    return ast.unparse(node)


def _has_dynamic_sql_value(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(value, ast.FormattedValue) for value in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return any(
            not isinstance(part, ast.Constant)
            for part in (node.left, node.right)
        )
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return node.func.attr == "format" and bool(node.args or node.keywords)
    return False


def _find_dynamic_sql(tree: ast.AST, source_code: str) -> list[dict[str, Any]]:
    """Detect SQL expressions that interpolate or concatenate non-literal values."""
    findings = []
    lines = source_code.splitlines()
    seen = set()

    for node in ast.walk(tree):
        text_repr = ast.unparse(node)
        if (
            not _has_dynamic_sql_value(node)
            or not _SQL_KEYWORDS.search(text_repr)
        ):
            continue
        key = (getattr(node, "lineno", 1), text_repr)
        if key in seen:
            continue
        seen.add(key)
        line_idx = getattr(node, "lineno", 1) - 1
        source_line = lines[line_idx] if 0 <= line_idx < len(lines) else text_repr
        findings.append({
            "line": getattr(node, "lineno", 1),
            "code": source_line.strip(),
            "expression": text_repr,
        })
    return findings


def _find_command_injections(tree: ast.AST, source_code: str) -> list[dict[str, Any]]:
    """Detect dynamic execution and shell-enabled subprocess calls."""
    findings = []
    lines = source_code.splitlines()
    aliases = _import_aliases(tree)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = _canonical_call_name(node.func, aliases)

            if call_name in {"eval", "exec", "compile", "os.system", "os.popen"}:
                line_idx = getattr(node, "lineno", 1) - 1
                source_line = lines[line_idx] if 0 <= line_idx < len(lines) else call_name
                findings.append({
                    "call": call_name,
                    "kind": "code_execution" if call_name in {"eval", "exec", "compile"} else "shell_execution",
                    "line": getattr(node, "lineno", 1),
                    "code": source_line.strip(),
                })
            elif (
                call_name.startswith("subprocess.")
                or call_name in {"Popen", "call", "check_call", "check_output", "run"}
            ):
                has_shell = any(
                    isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                    if kw.arg == "shell"
                )
                if has_shell:
                    line_idx = getattr(node, "lineno", 1) - 1
                    source_line = lines[line_idx] if 0 <= line_idx < len(lines) else call_name
                    findings.append({
                        "call": call_name,
                        "kind": "shell_execution",
                        "line": getattr(node, "lineno", 1),
                        "code": source_line.strip(),
                        "shell": True,
                    })
    return findings


def _find_path_traversals(tree: ast.AST, source_code: str) -> list[dict[str, Any]]:
    """Detect dynamic file operations that may allow directory traversal."""
    findings = []
    lines = source_code.splitlines()
    aliases = _import_aliases(tree)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = _canonical_call_name(node.func, aliases)

            if call_name in {"open", "os.path.join", "pathlib.Path"}:
                if node.args and isinstance(node.args[0], (ast.JoinedStr, ast.BinOp, ast.Name)):
                    line_idx = getattr(node, "lineno", 1) - 1
                    source_line = lines[line_idx] if 0 <= line_idx < len(lines) else call_name
                    unparsed = ast.unparse(node)
                    if "basename" not in unparsed and "resolve" not in unparsed:
                        if isinstance(node.args[0], ast.Name):
                            var_id = node.args[0].id
                            if any(
                                f"{var_id} =" in line and ("basename" in line or "resolve" in line)
                                for line in lines
                            ):
                                continue
                        findings.append({
                            "call": call_name,
                            "line": getattr(node, "lineno", 1),
                            "code": source_line.strip(),
                        })
    return findings


def _find_deserializations(tree: ast.AST, source_code: str) -> list[dict[str, Any]]:
    """Detect unsafe pickle or yaml deserialization."""
    findings = []
    lines = source_code.splitlines()
    aliases = _import_aliases(tree)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = _canonical_call_name(node.func, aliases)
            if call_name in {"pickle.loads", "pickle.load", "yaml.load"}:
                line_idx = getattr(node, "lineno", 1) - 1
                source_line = lines[line_idx] if 0 <= line_idx < len(lines) else call_name
                findings.append({
                    "call": call_name,
                    "line": getattr(node, "lineno", 1),
                    "code": source_line.strip(),
                })
    return findings


def _find_hardcoded_secrets(tree: ast.AST) -> list[dict[str, Any]]:
    """Detect plaintext tokens, passwords, and API keys."""
    findings = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                target_name = ast.unparse(target).lower()
                if any(k in target_name for k in ("token", "password", "secret", "api_key", "credential")):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        val = node.value.value.strip()
                        if val and not val.startswith("os.getenv") and len(val) >= 4:
                            findings.append({
                                "name": ast.unparse(target),
                                "line": getattr(node, "lineno", 1),
                                "code": "<credential assignment redacted>",
                            })
        elif isinstance(node, ast.AnnAssign):
            target_name = ast.unparse(node.target).lower()
            if (
                isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
                and node.value.value.strip()
                and len(node.value.value.strip()) >= 4
                and any(
                    key in target_name
                    for key in ("token", "password", "secret", "api_key", "credential")
                )
            ):
                findings.append({
                    "name": ast.unparse(node.target),
                    "line": getattr(node, "lineno", 1),
                    "code": "<credential assignment redacted>",
                })
    return findings


def _find_ssl_verification_disabled(tree: ast.AST, source_code: str) -> list[dict[str, Any]]:
    """Detect disabled SSL/TLS certificate verification in HTTP requests."""
    findings = []
    lines = source_code.splitlines()

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    line_idx = getattr(node, "lineno", 1) - 1
                    source_line = lines[line_idx] if 0 <= line_idx < len(lines) else "verify=False"
                    findings.append({
                        "line": getattr(node, "lineno", 1),
                        "code": source_line.strip(),
                    })
    return findings


def _find_insecure_xml(tree: ast.AST, source_code: str) -> list[dict[str, Any]]:
    """Detect standard XML parsers vulnerable to XML External Entity (XXE) expansion (CWE-611)."""
    findings = []
    lines = source_code.splitlines()
    aliases = _import_aliases(tree)

    if "defusedxml" in source_code:
        return []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = _canonical_call_name(node.func, aliases)
            if (
                call_name in _INSECURE_XML_CALLS
                or call_name.endswith("ElementTree.parse")
                or call_name.endswith("ElementTree.fromstring")
                or call_name.endswith("ElementTree.XML")
                or call_name.endswith("minidom.parse")
                or call_name.endswith("minidom.parseString")
            ):
                line_idx = getattr(node, "lineno", 1) - 1
                source_line = lines[line_idx] if 0 <= line_idx < len(lines) else call_name
                findings.append({
                    "call": call_name,
                    "line": getattr(node, "lineno", 1),
                    "code": source_line.strip(),
                })
    return findings


def _is_vulnerable_regex(pattern_str: str) -> bool:
    """Identify catastrophic backtracking ReDoS regex patterns (CWE-1333)."""
    if not isinstance(pattern_str, str) or len(pattern_str) < 3:
        return False
    # 1. Nested quantifiers: group with + or * having outer + or *
    # e.g. (a+)+, (a*)*, (x+x+)+, ([a-z]+)*, (\d+)+
    if re.search(r"\([^)]*?[+*][^)]*?\)[+*]", pattern_str):
        return True
    # 2. Ambiguous alternations with repetition: (a|aa)+, (a|a?)+, etc.
    if re.search(r"\(([a-zA-Z0-9_]+)\|\1[a-zA-Z0-9_]+\)[+*]", pattern_str):
        return True
    if re.search(r"\(([a-zA-Z0-9_]+)\?[a-zA-Z0-9_]*\|\1\)[+*]", pattern_str):
        return True
    if re.search(r"\([a-zA-Z0-9_]+(?:\?|\*|\+)\|[a-zA-Z0-9_]+(?:\?|\*|\+)\)[+*]", pattern_str):
        return True
    return False


def _find_redos_patterns(tree: ast.AST, source_code: str) -> list[dict[str, Any]]:
    """Detect regular expressions vulnerable to polynomial or exponential ReDoS (CWE-1333)."""
    findings = []
    lines = source_code.splitlines()

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_text = ast.unparse(node.func)
            if any(call_text.startswith(prefix) for prefix in ("re.", "regex.")):
                if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
                    pattern_str = node.args[0].value
                    if _is_vulnerable_regex(pattern_str):
                        line_idx = getattr(node, "lineno", 1) - 1
                        source_line = lines[line_idx] if 0 <= line_idx < len(lines) else pattern_str
                        findings.append({
                            "line": getattr(node, "lineno", 1),
                            "code": source_line.strip(),
                            "pattern": pattern_str,
                        })
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                target_name = ast.unparse(target).lower()
                if any(k in target_name for k in ("pattern", "regex", "redos")):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        pattern_str = node.value.value
                        if _is_vulnerable_regex(pattern_str):
                            line_idx = getattr(node, "lineno", 1) - 1
                            source_line = lines[line_idx] if 0 <= line_idx < len(lines) else pattern_str
                            findings.append({
                                "line": getattr(node, "lineno", 1),
                                "code": source_line.strip(),
                                "pattern": pattern_str,
                            })
    return findings


def _find_ssrf(tree: ast.AST, source_code: str) -> list[dict[str, Any]]:
    """Detect unvalidated variable URLs passed into outbound HTTP requests (CWE-918)."""
    findings = []
    lines = source_code.splitlines()
    aliases = _import_aliases(tree)

    has_validation = any(
        marker in source_code.lower()
        for marker in (
            "urlparse",
            "validate_url",
            "is_safe_url",
            "allowed_hosts",
            "whitelist",
            "startswith(('http",
            'startswith(("http',
            "startswith('http",
            'startswith("http',
        )
    )
    if has_validation:
        return []

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = _canonical_call_name(node.func, aliases)
            if call_name in _SSRF_CALLS or (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in {"get", "post", "put", "delete", "head", "patch", "urlopen"}
                and call_name.startswith(("requests.", "urllib.", "httpx."))
            ):
                if node.args:
                    first_arg = node.args[0]
                    if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
                        continue
                    line_idx = getattr(node, "lineno", 1) - 1
                    source_line = lines[line_idx] if 0 <= line_idx < len(lines) else call_name
                    findings.append({
                        "call": call_name,
                        "line": getattr(node, "lineno", 1),
                        "code": source_line.strip(),
                    })
    return findings


def _find_insecure_hashing(tree: ast.AST, source_code: str) -> list[dict[str, Any]]:
    """Detect cryptographically weak hash functions like MD5 and SHA-1 (CWE-327)."""
    findings = []
    lines = source_code.splitlines()
    aliases = _import_aliases(tree)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = _canonical_call_name(node.func, aliases)
            is_insecure = False
            if call_name in {"hashlib.md5", "hashlib.sha1", "md5", "sha1"}:
                is_insecure = True
            elif call_name == "hashlib.new" and node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.Constant) and str(first_arg.value).lower() in {"md5", "sha1"}:
                    is_insecure = True
            if is_insecure:
                line_idx = getattr(node, "lineno", 1) - 1
                source_line = lines[line_idx] if 0 <= line_idx < len(lines) else call_name
                findings.append({
                    "call": call_name,
                    "line": getattr(node, "lineno", 1),
                    "code": source_line.strip(),
                })
    return findings


def _find_insecure_tempfiles(tree: ast.AST, source_code: str) -> list[dict[str, Any]]:
    """Detect insecure temporary file creation via tempfile.mktemp (CWE-377)."""
    findings = []
    lines = source_code.splitlines()
    aliases = _import_aliases(tree)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            call_name = _canonical_call_name(node.func, aliases)
            if call_name in {"tempfile.mktemp", "mktemp"}:
                line_idx = getattr(node, "lineno", 1) - 1
                source_line = lines[line_idx] if 0 <= line_idx < len(lines) else call_name
                findings.append({
                    "call": call_name,
                    "line": getattr(node, "lineno", 1),
                    "code": source_line.strip(),
                })
    return findings


def _find_exposed_debug_mode(tree: ast.AST, source_code: str) -> list[dict[str, Any]]:
    """Detect exposed debug/development modes in production code (CWE-215)."""
    findings = []
    lines = source_code.splitlines()

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    line_idx = getattr(node, "lineno", 1) - 1
                    source_line = lines[line_idx] if 0 <= line_idx < len(lines) else "debug=True"
                    findings.append({
                        "line": getattr(node, "lineno", 1),
                        "code": source_line.strip(),
                        "call": ast.unparse(node.func),
                    })
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in {"DEBUG", "debug"}:
                    if isinstance(node.value, ast.Constant) and node.value.value is True:
                        line_idx = getattr(node, "lineno", 1) - 1
                        source_line = lines[line_idx] if 0 <= line_idx < len(lines) else "DEBUG = True"
                        findings.append({
                            "line": getattr(node, "lineno", 1),
                            "code": source_line.strip(),
                            "call": target.id,
                        })
    return findings


def simulate_attacks(source_code: str, model_client: Any = None) -> dict[str, Any]:
    """Statically assess Python source without executing it or its inputs."""
    del model_client  # Retained for compatibility with existing agent callers.
    valid = validate_code(source_code)
    if valid is not True:
        raise ValueError(f"Invalid Python source code: {valid}")

    tree = ast.parse(source_code)
    scenarios = []

    # 1. SQL Injection (CWE-89)
    sql_findings = _find_dynamic_sql(tree, source_code)
    for idx, f in enumerate(sql_findings, start=1):
        scenarios.append({
            "id": f"SIM-SQLI-{idx:03d}",
            "name": "Potential SQL Injection",
            "category": "SQL Injection",
            "cwe": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
            "severity": "critical",
            "risk_score": 95,
            "target_line": f["line"],
            "vulnerable_code": f["code"],
            "attack_payload": "Synthetic untrusted input marker (not executed)",
            "simulation_trace": (
                f"Static analysis found dynamic SQL expression '{f['expression']}'. "
                "No database connection or input payload was used."
            ),
            "impact": "User-controlled values may alter a query if interpolated into SQL.",
            "status": "vulnerable",
            "mitigation": "Use parameterized queries with placeholders (? or %s) instead of string formatting.",
        })

    # 2. Dynamic Code / Shell Execution (CWE-78 / CWE-94)
    cmd_findings = _find_command_injections(tree, source_code)
    for idx, f in enumerate(cmd_findings, start=1):
        call_name = f.get("call", "eval")
        is_code_execution = f.get("kind") == "code_execution"
        scenarios.append({
            "id": f"SIM-CMDI-{idx:03d}",
            "name": (
                "Dynamic Code Execution"
                if is_code_execution
                else "Shell Command Execution"
            ),
            "category": "Code Injection" if is_code_execution else "Command Injection",
            "cwe": (
                "CWE-94: Improper Control of Generation of Code"
                if is_code_execution
                else "CWE-78: Improper Neutralization of Special Elements used in an OS Command"
            ),
            "severity": "critical",
            "risk_score": 98,
            "target_line": f["line"],
            "vulnerable_code": f["code"],
            "attack_payload": "Synthetic untrusted input marker (not executed)",
            "simulation_trace": (
                f"Static analysis found a call to '{call_name}'. "
                "No source code, shell command, or payload was executed."
            ),
            "impact": "If supplied with untrusted data, this call may execute unintended code or commands.",
            "status": "vulnerable",
            "mitigation": "Avoid eval/exec; use ast.literal_eval for data parsing; use subprocess.run with argument list and shell=False.",
        })

    # 3. Path Traversal (CWE-22)
    path_findings = _find_path_traversals(tree, source_code)
    for idx, f in enumerate(path_findings, start=1):
        scenarios.append({
            "id": f"SIM-TRAV-{idx:03d}",
            "name": "Potential Path Traversal",
            "category": "Path Traversal",
            "cwe": "CWE-22: Improper Limitation of a Pathname to a Restricted Directory",
            "severity": "high",
            "risk_score": 85,
            "target_line": f["line"],
            "vulnerable_code": f["code"],
            "attack_payload": "Synthetic path input marker (not executed)",
            "simulation_trace": (
                "Static analysis found a path built from a dynamic value without a "
                "visible containment check. No filesystem path was opened."
            ),
            "impact": "An unchecked dynamic path may escape its intended directory.",
            "status": "vulnerable",
            "mitigation": "Use os.path.basename() or pathlib.Path.resolve() and verify the target path resides within an allowed directory.",
        })

    # 4. Insecure Deserialization (CWE-502)
    deser_findings = _find_deserializations(tree, source_code)
    for idx, f in enumerate(deser_findings, start=1):
        scenarios.append({
            "id": f"SIM-DESER-{idx:03d}",
            "name": "Potential Unsafe Deserialization",
            "category": "Insecure Deserialization",
            "cwe": "CWE-502: Deserialization of Untrusted Data",
            "severity": "critical",
            "risk_score": 95,
            "target_line": f["line"],
            "vulnerable_code": f["code"],
            "attack_payload": "Synthetic serialized-input marker (not executed)",
            "simulation_trace": (
                f"Static analysis found a call to '{f['call']}'. "
                "No serialized data was loaded."
            ),
            "impact": "Untrusted serialized data may execute code during deserialization.",
            "status": "vulnerable",
            "mitigation": "Replace pickle with safe serialization formats like json or yaml.safe_load.",
        })

    # 5. Hardcoded Credentials (CWE-798 / CWE-522)
    secret_findings = _find_hardcoded_secrets(tree)
    for idx, f in enumerate(secret_findings, start=1):
        scenarios.append({
            "id": f"SIM-CRED-{idx:03d}",
            "name": "Hardcoded Secret & Credential Disclosure",
            "category": "Credential Exposure",
            "cwe": "CWE-522: Insufficiently Protected Credentials / CWE-798: Use of Hard-coded Credentials",
            "severity": "high",
            "risk_score": 88,
            "target_line": f["line"],
            "vulnerable_code": f["code"],
            "attack_payload": "Synthetic secret-discovery marker (not executed)",
            "simulation_trace": (
                f"Static analysis found a string literal assigned to '{f['name']}'. "
                "The literal value is not included in this report."
            ),
            "impact": "A committed credential may be exposed to anyone with source access.",
            "status": "vulnerable",
            "mitigation": "Load secrets via environment variables (os.getenv) or a secrets manager.",
        })

    # 6. Disabled TLS / SSL Verification (CWE-295)
    ssl_findings = _find_ssl_verification_disabled(tree, source_code)
    for idx, f in enumerate(ssl_findings, start=1):
        scenarios.append({
            "id": f"SIM-SSL-{idx:03d}",
            "name": "TLS Verification Disabled",
            "category": "Transport Security",
            "cwe": "CWE-295: Improper Certificate Validation",
            "severity": "medium",
            "risk_score": 70,
            "target_line": f["line"],
            "vulnerable_code": f["code"],
            "attack_payload": "Synthetic certificate-validation marker (not executed)",
            "simulation_trace": (
                "Static analysis found TLS verification disabled. "
                "No network request or interception was performed."
            ),
            "impact": "Disabling certificate verification can expose connections to interception.",
            "status": "vulnerable",
            "mitigation": "Ensure SSL verification remains enabled (verify=True).",
        })

    # 7. XML External Entity (XXE) Injection (CWE-611)
    xml_findings = _find_insecure_xml(tree, source_code)
    for idx, f in enumerate(xml_findings, start=1):
        scenarios.append({
            "id": f"SIM-XXE-{idx:03d}",
            "name": "XML External Entity (XXE) Injection",
            "category": "XML Injection",
            "cwe": "CWE-611: Improper Restriction of XML External Entity Reference",
            "severity": "high",
            "risk_score": 86,
            "target_line": f["line"],
            "vulnerable_code": f["code"],
            "attack_payload": "Synthetic untrusted XML entity marker (not executed)",
            "simulation_trace": (
                f"Static analysis identified insecure XML parser call '{f['call']}'. "
                "Untrusted XML input may trigger entity expansion or arbitrary file read."
            ),
            "impact": "Malicious XML documents can abuse DTD entities to read local files or execute SSRF.",
            "status": "vulnerable",
            "mitigation": "Use defusedxml (e.g., defusedxml.ElementTree) or disable entity resolution in parser.",
        })

    # 8. Regular Expression Denial of Service (ReDoS) (CWE-1333)
    redos_findings = _find_redos_patterns(tree, source_code)
    for idx, f in enumerate(redos_findings, start=1):
        scenarios.append({
            "id": f"SIM-REDOS-{idx:03d}",
            "name": "Regular Expression Denial of Service (ReDoS)",
            "category": "Denial of Service",
            "cwe": "CWE-1333: Inefficient Regular Expression Complexity",
            "severity": "medium",
            "risk_score": 75,
            "target_line": f["line"],
            "vulnerable_code": f["code"],
            "attack_payload": "Synthetic catastrophic-backtracking input marker (not executed)",
            "simulation_trace": (
                f"Static analysis identified regex pattern '{f.get('pattern', '')}' with nested or ambiguous quantifiers. "
                "Unbounded backtracking can freeze execution."
            ),
            "impact": "Crafted input matching ambiguous sub-patterns triggers exponential backtracking, consuming 100% CPU.",
            "status": "vulnerable",
            "mitigation": "Refactor regular expression to remove nested quantifiers (e.g. rewrite (a+)+ to a+) or apply input length limits.",
        })

    # 9. Server-Side Request Forgery (SSRF) (CWE-918)
    ssrf_findings = _find_ssrf(tree, source_code)
    for idx, f in enumerate(ssrf_findings, start=1):
        scenarios.append({
            "id": f"SIM-SSRF-{idx:03d}",
            "name": "Server-Side Request Forgery (SSRF)",
            "category": "Server-Side Request Forgery",
            "cwe": "CWE-918: Server-Side Request Forgery (SSRF)",
            "severity": "high",
            "risk_score": 88,
            "target_line": f["line"],
            "vulnerable_code": f["code"],
            "attack_payload": "Synthetic internal-destination marker (not executed)",
            "simulation_trace": (
                f"Static analysis identified outbound HTTP request '{f['call']}' with dynamic unvalidated URL. "
                "Destination is not verified against an allowlist."
            ),
            "impact": "Attacker-controlled URLs allow internal network scanning or access to cloud metadata services.",
            "status": "vulnerable",
            "mitigation": "Validate target URLs against an allowlist of permitted domains/protocols, or use a strict URL validation wrapper.",
        })

    # 10. Insecure Cryptographic Hashing (CWE-327)
    hash_findings = _find_insecure_hashing(tree, source_code)
    for idx, f in enumerate(hash_findings, start=1):
        scenarios.append({
            "id": f"SIM-HASH-{idx:03d}",
            "name": "Weak Cryptographic Hash Function",
            "category": "Insecure Cryptography",
            "cwe": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
            "severity": "medium",
            "risk_score": 72,
            "target_line": f["line"],
            "vulnerable_code": f["code"],
            "attack_payload": "Synthetic collision/preimage marker (not executed)",
            "simulation_trace": (
                f"Static analysis found legacy broken hash algorithm '{f['call']}'. "
                "MD5 and SHA-1 suffer from collision and length-extension vulnerabilities."
            ),
            "impact": "Cryptographic collisions allow forged digital signatures, undetected tampering, or rapid password cracking.",
            "mitigation": "Upgrade to hashlib.sha256 or hashlib.sha3_256 for integrity verification, or argon2/bcrypt for passwords.",
        })

    # 11. Insecure Temporary Files (CWE-377)
    tmp_findings = _find_insecure_tempfiles(tree, source_code)
    for idx, f in enumerate(tmp_findings, start=1):
        scenarios.append({
            "id": f"SIM-TMP-{idx:03d}",
            "name": "Insecure Temporary File Creation",
            "category": "Insecure File Management",
            "cwe": "CWE-377: Insecure Temporary File",
            "severity": "medium",
            "risk_score": 68,
            "target_line": f["line"],
            "vulnerable_code": f["code"],
            "attack_payload": "Synthetic symlink race marker (not executed)",
            "simulation_trace": (
                f"Static analysis found '{f['call']}()' which generates filenames without atomicity, "
                "creating time-of-check to time-of-use (TOCTOU) race conditions."
            ),
            "impact": "A local attacker can create a symlink at the predicted filename before file open, leading to arbitrary file overwrite.",
            "mitigation": "Replace tempfile.mktemp() with tempfile.NamedTemporaryFile() or tempfile.mkstemp() to atomically create and open the file.",
        })

    # 12. Exposed Debug Mode (CWE-215)
    debug_findings = _find_exposed_debug_mode(tree, source_code)
    for idx, f in enumerate(debug_findings, start=1):
        scenarios.append({
            "id": f"SIM-DEBUG-{idx:03d}",
            "name": "Exposed Debug/Development Mode",
            "category": "Information Disclosure",
            "cwe": "CWE-215: Insertion of Sensitive Information Into Debugging Code",
            "severity": "high",
            "risk_score": 82,
            "target_line": f["line"],
            "vulnerable_code": f["code"],
            "attack_payload": "Synthetic interactive traceback marker (not executed)",
            "simulation_trace": (
                "Static analysis found debug mode explicitly enabled (debug=True / DEBUG = True). "
                "In web frameworks, debug mode exposes interactive tracebacks and console code execution."
            ),
            "impact": "Interactive debug consoles allow remote code execution, and stack traces reveal system internals and secrets.",
            "mitigation": "Set debug=False or configure debug mode via environment variable (e.g., os.getenv('DEBUG', 'False').lower() == 'true').",
        })

    # 13. Separate prompt-injection findings from generic static code-security findings.
    attack_detection = detect_attack(source_code, content_type="code")
    if attack_detection["detected"]:
        for category in attack_detection["categories"]:
            if category in {
                "code_security_risk",
                "sql_injection",
                "insecure_cryptography",
                "insecure_temporary_file",
                "xxe_injection",
                "redos_risk",
                "ssrf_risk",
                "exposed_debug_mode",
            } and scenarios:
                continue
            if category in {"code_security_risk", "sql_injection"}:
                display_category = "Static Code Security Risk"
                category_name = "Static Code Security"
                cwe = "CWE-89: SQL Injection" if category == "sql_injection" else "Static security analysis"
                impact = "Dynamic SQL construction allows query manipulation." if category == "sql_injection" else "A static security rule identified potentially unsafe code."
                mitigation = "Use parameterized queries with bind placeholders (? or %s)." if category == "sql_injection" else "Review the specific static security finding and apply its recommended mitigation."
            elif category in {"credential_exfiltration", "private_data_exfiltration", "sensitive_data_transfer"}:
                display_category = "Sensitive Data Handling Risk"
                category_name = "Sensitive Data Handling"
                cwe = "Sensitive data exposure risk"
                impact = "Source patterns may expose credentials or private information."
                mitigation = "Keep secrets in a secrets manager and prevent sensitive data from reaching untrusted outputs."
            else:
                display_category = "Untrusted Instruction or Data Risk"
                category_name = "Untrusted AI Input"
                cwe = "OWASP-LLM01: Prompt Injection"
                impact = "Untrusted text may influence an AI system or expose sensitive information."
                mitigation = "Treat source comments and strings as untrusted data; enforce instruction/data separation."
            scenarios.append({
                "id": f"SIM-INJ-{len(scenarios)+1:03d}",
                "name": f"{display_category}: {category.replace('_', ' ').title()}",
                "category": category_name,
                "cwe": cwe,
                "severity": attack_detection["severity"],
                "risk_score": attack_detection["risk_score"],
                "target_line": 0,
                "vulnerable_code": "# Untrusted source content detected; content omitted",
                "attack_payload": "Synthetic untrusted-content marker (not executed)",
                "simulation_trace": (
                    "Static analysis detected a risky source pattern. "
                    "No AI prompt, source code, or payload was executed."
                ),
                "impact": impact,
                "status": "vulnerable",
                "mitigation": mitigation,
            })

    total_checks = 13
    vulnerable_count = len(scenarios)

    if vulnerable_count == 0:
        resilience_score = 100
        defense_verdict = "No findings in these static checks (not a security certification)"
    else:
        penalty = sum(s["risk_score"] for s in scenarios)
        resilience_score = max(5, round(100 - (penalty / len(scenarios)) * (vulnerable_count / (vulnerable_count + 1))))
        defense_verdict = f"Vulnerable · {vulnerable_count} Simulated Attack Vector(s) Succeeded"

    risk_counts = {
        "critical": sum(1 for s in scenarios if s["severity"] == "critical"),
        "high": sum(1 for s in scenarios if s["severity"] == "high"),
        "medium": sum(1 for s in scenarios if s["severity"] == "medium"),
        "low": sum(1 for s in scenarios if s["severity"] == "low"),
    }

    return {
        "agent": "security_attack_simulation",
        "agent_name": "Static Python Security Analyzer",
        "status": "completed",
        "assessment_type": "static_analysis",
        "simulation_only": True,
        "execution_status": "not_executed",
        "total_simulations_run": total_checks,
        "total_checks_run": total_checks,
        "vulnerabilities_detected": vulnerable_count,
        "resilience_score": resilience_score,
        "defense_verdict": defense_verdict,
        "risk_breakdown": risk_counts,
        "attack_scenarios": scenarios,
        "is_vulnerable": vulnerable_count > 0,
        "summary": (
            f"Completed {total_checks} static security checks. "
            f"Detected {vulnerable_count} potential finding(s) "
            f"({risk_counts['critical']} Critical, {risk_counts['high']} High). "
            f"Static risk score: {resilience_score}/100; this is not a security certification."
        ),
    }
