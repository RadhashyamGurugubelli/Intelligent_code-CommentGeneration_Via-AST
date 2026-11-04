"""AST analysis, behavior summaries, and validated comment generation (Re-exports)."""

import ast
import logging
import textwrap

from backend.ast_analyzer import (
    CC_THRESHOLD,
    _describe_condition,
    _describe_function_semantics,
    _describe_sorted_call,
    _describe_value,
    _returns_in_statements,
    _safe_call_name,
    _walk_function_scope,
    analyze_code,
    build_smart_ast_explanations,
)
from backend.config import AppConfig
from backend.attack_guard import detect_attack
from backend.model_provider import MODEL_NAME, create_model_client
from backend.prompt_builder import build_ai_messages
from backend.prompt_builder import build_prompt_payload as _build_prompt_payload
from backend.validator import (
    has_added_comments,
    validate_code,
    validate_generated_code,
)

__all__ = [
    "CC_THRESHOLD",
    "_build_prompt_payload",
    "_fallback_comment_code",
    "analyze_code",
    "build_ai_messages",
    "build_smart_ast_explanations",
    "detect_attack",
    "has_added_comments",
    "validate_code",
    "validate_generated_code",
]

client = create_model_client()
logger = logging.getLogger(__name__)


class CommentGenerationError(RuntimeError):
    """Raised when the configured AI model cannot generate valid comments."""


def _assignment_description(node):
    value = node.value
    if value is None:
        return None
    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    target_names = ", ".join(ast.unparse(target) for target in targets)
    if isinstance(value, ast.Call):
        name = _safe_call_name(value.func)
        if name in {"np.array", "numpy.array"}:
            arg_str = ast.unparse(value.args[0]) if value.args else "input items"
            return f"# Constructs an N-dimensional NumPy array from {arg_str} and stores it in {target_names}."
        if name in {"np.zeros", "numpy.zeros"}:
            shape_str = ast.unparse(value.args[0]) if value.args else "specified shape"
            return f"# Allocates a zero-initialized NumPy array with shape {shape_str} and assigns to {target_names}."
        if name in {"np.ones", "numpy.ones"}:
            shape_str = ast.unparse(value.args[0]) if value.args else "specified shape"
            return f"# Allocates a one-initialized NumPy array with shape {shape_str} and assigns to {target_names}."
        if name in {"np.arange", "numpy.arange"}:
            return f"# Generates a sequential NumPy numerical range and stores it in {target_names}."
        if name in {"np.linspace", "numpy.linspace"}:
            return f"# Generates evenly spaced numerical samples and stores them in {target_names}."
        if name in {"pd.DataFrame", "pandas.DataFrame"}:
            return f"# Instantiates a 2D tabular DataFrame and assigns it to {target_names}."
        if name in {"pd.read_csv", "pandas.read_csv"}:
            return f"# Reads tabular CSV data into a Pandas DataFrame and assigns it to {target_names}."
        if name in {"pd.Series", "pandas.Series"}:
            return f"# Constructs a 1D Pandas Series object and assigns it to {target_names}."
        if name in {"math.sqrt"}:
            return f"# Computes the mathematical square root of {ast.unparse(value.args[0]) if value.args else 'value'} and stores it in {target_names}."
        if name == "input":
            return f"# Stores the result of {ast.unparse(value)} in {target_names}."
        if name in {"int", "float", "str", "bool", "list", "tuple", "set", "dict"}:
            return f"# Stores the result of {ast.unparse(value)} in {target_names}."
        if name == "sorted":
            return f"# {_describe_sorted_call(value).capitalize()} and stores it in {target_names}."
        return f"# Stores the result of {ast.unparse(value)} in {target_names}."
    if isinstance(value, ast.BinOp):
        return f"# Computes {ast.unparse(value)} and stores it in {target_names}."
    if isinstance(value, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
        return f"# Builds {target_names} from the comprehension expression {ast.unparse(value)}."
    return f"# Assigns {target_names} from {ast.unparse(value)}."


def _describe_comprehension(node):
    if isinstance(node, ast.DictComp):
        if node.value is None:
            return "a dictionary with no value expression"
        result = f"key-value pairs of {ast.unparse(node.key)} and {ast.unparse(node.value)}"
    elif isinstance(node, ast.SetComp):
        result = f"unique values of {ast.unparse(node.elt)}"
    elif isinstance(node, ast.GeneratorExp):
        result = ast.unparse(node.elt)
    else:
        result = ast.unparse(node.elt)

    clauses = []
    for generator in node.generators:
        clause = f"{ast.unparse(generator.target)} in {ast.unparse(generator.iter)}"
        if generator.ifs:
            conditions = " and ".join(ast.unparse(condition) for condition in generator.ifs)
            clause += f" that satisfy {conditions}"
        clauses.append(clause)
    if (
        not isinstance(node, ast.DictComp)
        and
        len(node.generators) == 1
        and isinstance(node.elt, ast.Name)
        and isinstance(node.generators[0].target, ast.Name)
        and node.elt.id == node.generators[0].target.id
        and node.generators[0].ifs
    ):
        return (
            f"values from {ast.unparse(node.generators[0].iter)} that satisfy "
            f"{' and '.join(ast.unparse(condition) for condition in node.generators[0].ifs)}"
        )
    return f"{result} for {'; '.join(clauses)}"


def _describe_docstring_step(node):
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        value = node.value
        if value is None:
            return None
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        target_names = ", ".join(ast.unparse(target) for target in targets)
        if isinstance(value, (ast.ListComp, ast.SetComp, ast.DictComp)):
            collection = {
                ast.ListComp: "a list",
                ast.SetComp: "a set",
                ast.DictComp: "a dictionary",
            }[type(value)]
            return (
                f"It builds {collection} of {_describe_comprehension(value)} "
                f"and stores the result in {target_names}."
            )
        if isinstance(value, ast.Call):
            name = _safe_call_name(value.func)
            if name in {"max", "min"} and value.args:
                direction = "largest" if name == "max" else "smallest"
                return (
                    f"It selects the {direction} value from "
                    f"{ast.unparse(value.args[0])} and stores it in {target_names}."
                )
            if name in {"len", "sum"} and value.args:
                detail = (
                    "number of elements"
                    if name == "len"
                    else "sum of the values"
                )
                return (
                    f"It calculates the {detail} in {ast.unparse(value.args[0])} "
                    f"and stores the result in {target_names}."
                )
            if name == "sorted":
                return (
                    f"It {_describe_sorted_call(value)} and stores the result "
                    f"in {target_names}."
                )
        if isinstance(value, ast.BinOp):
            return (
                f"It computes {_describe_value(value)} and stores the result "
                f"in {target_names}."
            )
        return None

    if isinstance(node, ast.If):
        condition = _describe_condition(node.test)
        branch_returns = _returns_in_statements(node.body)
        if branch_returns:
            return (
                f"If {condition}, it exits this path early and returns "
                f"{', '.join(branch_returns[:2])}."
            )
        return f"If {condition}, it performs the conditional work in this branch."

    if isinstance(node, (ast.For, ast.AsyncFor)):
        return (
            f"It iterates over {ast.unparse(node.iter)} using "
            f"{ast.unparse(node.target)} and processes each item in turn."
        )
    if isinstance(node, ast.While):
        return f"It repeats the loop while {ast.unparse(node.test)} remains true."
    if isinstance(node, (ast.With, ast.AsyncWith)):
        resources = ", ".join(
            ast.unparse(item.context_expr) for item in node.items
        )
        return (
            f"It manages {resources} as a context resource, ensuring the context "
            "is exited when the block finishes."
        )
    return None


def _extract_function_metadata(node):
    args_info = []
    pos_args = node.args.posonlyargs + node.args.args
    defaults_offset = len(pos_args) - len(node.args.defaults)
    for i, arg in enumerate(pos_args):
        if arg.arg in {"self", "cls"} and i == 0:
            continue
        type_str = ast.unparse(arg.annotation) if getattr(arg, "annotation", None) else None
        default_val = None
        if i >= defaults_offset:
            default_val = ast.unparse(node.args.defaults[i - defaults_offset])
        args_info.append({
            "name": arg.arg,
            "type": type_str,
            "default": default_val,
        })
    for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults):
        type_str = ast.unparse(arg.annotation) if getattr(arg, "annotation", None) else None
        default_val = ast.unparse(default) if default else None
        args_info.append({
            "name": arg.arg,
            "type": type_str,
            "default": default_val,
        })

    return_type = ast.unparse(node.returns) if getattr(node, "returns", None) else None
    return_exprs = _returns_in_statements(node.body)

    raises_info = []
    for child in _walk_function_scope(node):
        if isinstance(child, ast.If):
            for sub in child.body:
                if isinstance(sub, ast.Raise):
                    exc_name = "Exception"
                    if getattr(sub, "exc", None):
                        if isinstance(sub.exc, ast.Call):
                            exc_name = ast.unparse(sub.exc.func)
                        else:
                            exc_name = ast.unparse(sub.exc)
                    cond = _describe_condition(child.test)
                    raises_info.append({"exception": exc_name, "condition": cond})
        elif isinstance(child, ast.Raise):
            exc_name = "Exception"
            if getattr(child, "exc", None):
                if isinstance(child.exc, ast.Call):
                    exc_name = ast.unparse(child.exc.func)
                else:
                    exc_name = ast.unparse(child.exc)
            if not any(r["exception"] == exc_name for r in raises_info):
                raises_info.append({"exception": exc_name, "condition": "an error occurs"})

    return {
        "args": args_info,
        "return_type": return_type,
        "returns": return_exprs,
        "raises": raises_info,
    }


def _function_docstring(node, style=None, docstring_style=None):
    if style is None:
        style = docstring_style
    if style is None:
        style = getattr(AppConfig, "DOCSTRING_STYLE", "google")
    style = str(style).strip().lower()

    summary = _describe_function_semantics(node)
    summary = summary.replace(f"Function {node.name} accepts", "Accepts", 1)
    steps = [
        description
        for statement in node.body
        if (description := _describe_docstring_step(statement)) is not None
    ]
    meta = _extract_function_metadata(node)

    parts = [summary]
    if steps:
        parts.extend(steps)

    if style == "google":
        if meta["args"]:
            arg_lines = ["Args:"]
            for a in meta["args"]:
                if a["type"]:
                    t_str = f" ({a['type']}, optional)" if a["default"] is not None else f" ({a['type']})"
                else:
                    t_str = " (optional)" if a["default"] is not None else ""
                arg_lines.append(f"    {a['name']}{t_str}: Input {a['name']} value.")
            parts.append("\n".join(arg_lines))

        if meta["return_type"] or meta["returns"]:
            ret_type = meta["return_type"] or "Any"
            ret_desc = ", ".join(meta["returns"][:2]) if meta["returns"] else "Result of execution"
            parts.append(f"Returns:\n    {ret_type}: {ret_desc}.")

        if meta["raises"]:
            raise_lines = ["Raises:"]
            for r in meta["raises"]:
                raise_lines.append(f"    {r['exception']}: If {r['condition']}.")
            parts.append("\n".join(raise_lines))

    elif style == "sphinx":
        sphinx_lines = []
        for a in meta["args"]:
            sphinx_lines.append(f":param {a['name']}: Input {a['name']} value.")
            if a["type"]:
                sphinx_lines.append(f":type {a['name']}: {a['type']}")
        if meta["return_type"] or meta["returns"]:
            ret_desc = ", ".join(meta["returns"][:2]) if meta["returns"] else "Result of execution"
            sphinx_lines.append(f":returns: {ret_desc}.")
            if meta["return_type"]:
                sphinx_lines.append(f":rtype: {meta['return_type']}")
        for r in meta["raises"]:
            sphinx_lines.append(f":raises {r['exception']}: If {r['condition']}.")
        if sphinx_lines:
            parts.append("\n".join(sphinx_lines))

    elif style == "numpy":
        numpy_parts = []
        if meta["args"]:
            lines = ["Parameters", "----------"]
            for a in meta["args"]:
                t_str = f" : {a['type']}" if a['type'] else ""
                lines.append(f"{a['name']}{t_str}")
                lines.append(f"    Input {a['name']} value.")
            numpy_parts.append("\n".join(lines))
        if meta["return_type"] or meta["returns"]:
            lines = ["Returns", "-------"]
            ret_type = meta["return_type"] or "Any"
            lines.append(ret_type)
            ret_desc = ", ".join(meta["returns"][:2]) if meta["returns"] else "Result of execution"
            lines.append(f"    {ret_desc}.")
            numpy_parts.append("\n".join(lines))
        if meta["raises"]:
            lines = ["Raises", "------"]
            for r in meta["raises"]:
                lines.append(r["exception"])
                lines.append(f"    If {r['condition']}.")
            numpy_parts.append("\n".join(lines))
        if numpy_parts:
            parts.extend(numpy_parts)

    return "\n\n".join(parts)


def _format_docstring_lines(text, indentation, line_ending):
    escaped_text = text.replace("\\", "\\\\").replace('"""', '\\"\\"\\"')
    width = max(40, 88 - len(indentation) - 4)
    doc_lines = []
    for paragraph in escaped_text.split("\n\n"):
        if doc_lines:
            doc_lines.append("")
        if "\n" in paragraph:
            for subline in paragraph.splitlines():
                doc_lines.append(subline)
        else:
            doc_lines.extend(
                textwrap.wrap(
                    paragraph,
                    width=width,
                    break_long_words=False,
                    break_on_hyphens=False,
                )
                if paragraph
                else [""]
            )
    return [
        f'{indentation}"""{doc_lines[0]}{line_ending}',
        *(
            f"{indentation}    {line}{line_ending}" if line else line_ending
            for line in doc_lines[1:]
        ),
        f'{indentation}"""{line_ending}',
    ]


def _describe_import(node):
    """Generate detailed, domain-aware commentary for Python imports."""
    if isinstance(node, ast.Import):
        comments = []
        for alias in node.names:
            name = alias.name
            asname = alias.asname
            alias_part = f", aliased as '{asname}'" if asname else ""
            known = {
                "numpy": f"# Imports NumPy library for high-performance N-dimensional array processing and numerical computations{alias_part}.",
                "pandas": f"# Imports Pandas data analysis library for tabular DataFrames and structured data manipulation{alias_part}.",
                "matplotlib": f"# Imports Matplotlib visualization engine for charting and scientific graphics{alias_part}.",
                "matplotlib.pyplot": f"# Imports Matplotlib's pyplot interface for data visualization and figure rendering{alias_part}.",
                "torch": f"# Imports PyTorch deep learning framework for tensor computation and neural network modeling{alias_part}.",
                "tensorflow": f"# Imports TensorFlow platform for machine learning model training and inference{alias_part}.",
                "scipy": f"# Imports SciPy library for scientific computing, optimization, and linear algebra{alias_part}.",
                "sklearn": f"# Imports Scikit-Learn toolkit for predictive modeling and machine learning algorithms{alias_part}.",
                "requests": f"# Imports Requests HTTP client library for network communication and REST API requests{alias_part}.",
                "os": f"# Imports Python standard library 'os' module for portable operating system and file path operations{alias_part}.",
                "sys": f"# Imports Python standard library 'sys' module for system-specific parameters and runtime control{alias_part}.",
                "json": f"# Imports Python standard library 'json' module for encoding and decoding JSON structured data{alias_part}.",
                "re": f"# Imports Python standard library 're' module for regular expression parsing and string pattern matching{alias_part}.",
                "math": f"# Imports Python standard library 'math' module for mathematical functions and numeric constants{alias_part}.",
                "random": f"# Imports standard library 'random' module for pseudo-random number generation{alias_part}.",
                "datetime": f"# Imports standard library 'datetime' module for manipulating dates and timestamps{alias_part}.",
                "typing": f"# Imports standard library 'typing' module for runtime type annotations and static validation{alias_part}.",
                "pathlib": f"# Imports standard library 'pathlib' module for object-oriented filesystem paths{alias_part}.",
                "collections": f"# Imports standard library 'collections' module for specialized container datatypes{alias_part}.",
                "subprocess": f"# Imports standard library 'subprocess' module for spawning processes and communicating with OS pipes{alias_part}.",
            }
            if name in known:
                comments.append(known[name])
            else:
                comments.append(f"# Imports module '{name}'{alias_part} for external functionality.")
        return "\n".join(comments)

    if isinstance(node, ast.ImportFrom):
        mod = node.module or ""
        names = [f"{a.name} as {a.asname}" if a.asname else a.name for a in node.names]
        names_str = ", ".join(names[:4]) + ("..." if len(names) > 4 else "")
        known = {
            "math": f"# Imports {names_str} from 'math' module for mathematical computations.",
            "os": f"# Imports {names_str} from 'os' module for filesystem and environment interaction.",
            "pathlib": f"# Imports {names_str} from 'pathlib' for object-oriented path manipulation.",
            "typing": f"# Imports type hint symbols ({names_str}) from 'typing' for static type annotations.",
            "datetime": f"# Imports {names_str} from 'datetime' for date and time parsing.",
            "collections": f"# Imports container types ({names_str}) from 'collections'.",
        }
        if mod in known:
            return known[mod]
        return f"# Imports {names_str} from '{mod}' for domain-specific operations."
    return None


def _fallback_comment_code(source_code, analysis=None, docstring_style=None):
    """Generate AST-anchored comments without changing executable statements."""
    if isinstance(analysis, str) and docstring_style is None:
        docstring_style = analysis
        analysis = None
    if analysis is None:
        analysis = analyze_code(source_code)
    tree = ast.parse(source_code)
    comments_by_line = {}
    docstrings_by_line = {}

    def add_comment(node, text, priority):
        line_number = getattr(node, "lineno", None)
        if line_number is None and isinstance(node, ast.match_case):
            line_number = getattr(getattr(node, "pattern", None), "lineno", None)
            if line_number is None and getattr(node, "body", None):
                line_number = getattr(node.body[0], "lineno", None)
        decorators = getattr(node, "decorator_list", ())
        if decorators:
            line_number = min(
                line_number,
                *(decorator.lineno for decorator in decorators),
            )
        if line_number is None or not text:
            return
        current = comments_by_line.get(line_number)
        if current is None or priority < current[0]:
            comments_by_line[line_number] = (priority, text)

    function_nodes = (ast.FunctionDef, ast.AsyncFunctionDef)
    for type_error in analysis.get("type_errors", []):
        line_number = type_error.get("lineno")
        if line_number:
            current = comments_by_line.get(line_number)
            if current is None or current[0] > 1:
                comments_by_line[line_number] = (1, type_error["comment"])

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            desc = _describe_import(node)
            if desc:
                add_comment(node, desc, 20)
        elif isinstance(node, function_nodes):
            if ast.get_docstring(node, clean=False) is None:
                first_statement = node.body[0] if node.body else None
                if first_statement and first_statement.lineno > node.lineno:
                    docstrings_by_line[first_statement.lineno] = _function_docstring(
                        node, docstring_style=docstring_style
                    )
                else:
                    add_comment(
                        node,
                        f"# {_describe_function_semantics(node)}",
                        10,
                    )
        elif isinstance(node, ast.ClassDef):
            bases = [ast.unparse(base) for base in node.bases]
            detail = f" extending {', '.join(bases)}" if bases else ""
            add_comment(node, f"# Defines class {node.name}{detail}.", 10)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if isinstance(value, ast.Call) and _safe_call_name(value.func) == "sorted":
                add_comment(node, f"# {_describe_sorted_call(value).capitalize()}.", 15)
            else:
                add_comment(node, _assignment_description(node), 30)
        elif isinstance(node, ast.AugAssign):
            operator = {
                ast.Add: "adding",
                ast.Sub: "subtracting",
                ast.Mult: "multiplying by",
                ast.Div: "dividing by",
                ast.FloorDiv: "floor-dividing by",
                ast.Mod: "taking the remainder with",
                ast.Pow: "raising to the power of",
            }.get(type(node.op), "applying an operation with")
            add_comment(
                node,
                f"# Updates {ast.unparse(node.target)} by {operator} {ast.unparse(node.value)}.",
                30,
            )
        elif isinstance(node, ast.If):
            condition = _describe_condition(node.test)
            branch_returns = _returns_in_statements(node.body)
            if branch_returns:
                comment = f"# Branch: when {condition}, returns {', '.join(branch_returns[:2])}."
            else:
                comment = f"# Branch: runs this block only when {condition}."
            add_comment(node, comment, 20)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            add_comment(
                node,
                f"# Iterates over {ast.unparse(node.iter)} with {ast.unparse(node.target)}.",
                20,
            )
        elif isinstance(node, ast.While):
            add_comment(
                node,
                f"# Repeats this block while {ast.unparse(node.test)} is true.",
                20,
            )
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            resources = ", ".join(ast.unparse(item.context_expr) for item in node.items)
            add_comment(node, f"# Manages the {resources} resource for this block.", 20)
        elif isinstance(node, ast.Try):
            add_comment(
                node, "# Attempts this block and handles matching exceptions below.", 20
            )
        elif isinstance(node, ast.Assert):
            add_comment(node, f"# Checks that {ast.unparse(node.test)} is true.", 20)
        elif isinstance(node, ast.Raise):
            message = (
                f" with {ast.unparse(node.cause)} as its cause" if node.cause else ""
            )
            add_comment(
                node,
                f"# Raises {ast.unparse(node.exc) if node.exc else 'the active exception'}{message}.",
                20,
            )
        elif isinstance(node, ast.Match):
            add_comment(
                node, f"# Selects a case matching {ast.unparse(node.subject)}.", 20
            )
        elif isinstance(node, ast.match_case):
            add_comment(node, f"# Handles the pattern {ast.unparse(node.pattern)}.", 20)
        elif isinstance(node, ast.Call):
            call_name = _safe_call_name(node.func)
            if call_name in {
                "eval",
                "exec",
                "compile",
                "os.system",
                "subprocess.call",
                "subprocess.run",
                "subprocess.Popen",
                "subprocess.check_call",
            }:
                add_comment(
                    node,
                    f"# Security warning: {call_name} executes code or a system command.",
                    0,
                )
            elif call_name == "print":
                add_comment(node, "# Output: writes the current result or state.", 30)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            add_comment(
                node,
                f"# Calls {ast.unparse(node.value.func)} and discards its return value.",
                40,
            )

    output = []
    lines = source_code.splitlines(keepends=True)
    for line_number, raw_line in enumerate(lines, start=1):
        line = raw_line.rstrip("\r\n")
        line_ending = raw_line[len(line) :]
        comment = comments_by_line.get(line_number)
        docstring = docstrings_by_line.get(line_number)
        if docstring:
            indentation = line[: len(line) - len(line.lstrip())]
            output.extend(
                _format_docstring_lines(
                    docstring,
                    indentation,
                    line_ending or "\n",
                )
            )
        if comment:
            indentation = line[: len(line) - len(line.lstrip())]
            comment_ending = line_ending or "\n"
            output.extend(
                f"{indentation}{comment_line}{comment_ending}"
                for comment_line in comment[1].splitlines()
            )
        output.append(raw_line)
    return "".join(output)


def _generate_with_model(source_code, analysis):
    if not client:
        raise RuntimeError("AI service is unavailable in this environment.")

    messages = build_ai_messages(source_code, analysis)
    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=messages,
        max_tokens=4000,
        temperature=0.1,
        extra_body={"chat_template_kwargs": {"enable_thinking": False}},
    )

    commented = (response.choices[0].message.content or "").strip()
    if commented.startswith("```"):
        lines = commented.splitlines()
        commented = "\n".join(
            line for line in lines if not line.strip().startswith("```")
        )
    return commented.strip()


def generate_commented_code(source_code, analysis):
    """Generate model-backed comments, using AST comments for known type errors."""
    if not client:
        logger.info("No AI provider is configured; using deterministic AST comments.")
        return _fallback_comment_code(source_code, analysis), "ast"
    if analysis.get("type_errors"):
        return _fallback_comment_code(source_code, analysis), "ast"

    try:
        model_output = _generate_with_model(source_code, analysis)
    except Exception as exc:
        logger.warning(
            "AI provider comment generation failed (%s); using deterministic AST comments.",
            type(exc).__name__,
        )
        return _fallback_comment_code(source_code, analysis), "ast"

    validation = validate_generated_code(source_code, model_output)
    if not validation["is_valid"]:
        logger.warning(
            "Rejected AI-generated comments that failed code validation; "
            "using deterministic AST comments."
        )
        return _fallback_comment_code(source_code, analysis), "ast"
    original_attack = detect_attack(source_code, content_type="code")
    generated_attack = detect_attack(model_output, content_type="code")
    added_attack_categories = set(generated_attack["categories"]) - set(
        original_attack["categories"]
    )
    if added_attack_categories:
        logger.warning(
            "Rejected AI-generated comments with new security categories=%s",
            ",".join(sorted(added_attack_categories)),
        )
        return _fallback_comment_code(source_code, analysis), "ast"
    if not has_added_comments(source_code, model_output):
        logger.warning(
            "AI response added no comments; using deterministic AST comments."
        )
        return _fallback_comment_code(source_code, analysis), "ast"
    return model_output, "ai"
