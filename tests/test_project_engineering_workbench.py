"""Comprehensive test suite for the Project-Level Software Engineering Workbench.

Verifies:
1. Section A: Safe Archive Extraction, File Tree, Module Discovery, Dependency Graph,
   Circular Import Detection, Entry Points, Configs, README, and Architecture Report.
2. Section B: Code Intelligence (Project AST Analysis, Dead Code Detection, Duplicate Code,
   Maintainability Index, Complexity, Documentation Coverage).
3. Section C: Documentation Generation (Grounded Docstrings, README Draft, Architecture Docs,
   API Catalog, Dependency Inventory).
4. Section D: Engineering Tools (pytest isolation gating, ruff/mypy/bandit fallbacks).
5. Section E: Project Quality Health Report (composite score, grade, 8 dimensions).
6. Section F: Change Management (Multi-file diffs, Snapshots, Approval, Rollback, ZIP Export, REST APIs).
"""

import ast
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from backend.app import create_app
from backend.project.analyzer import ProjectAnalyzer
from backend.project.code_intelligence import ProjectCodeIntelligence
from backend.project.documentation_generator import (
    ProjectDocumentationGenerator,
    generate_class_docstring,
    generate_function_docstring,
)
from backend.project.engineering_tools import EngineeringToolsRunner
from backend.project.health_report import ProjectHealthReporter
from backend.project.workspace import (
    ArchiveSecurityError,
    ProjectWorkspace,
    SafeArchiveExtractor,
)


class ProjectWorkspaceAndExtractionSecurityTests(unittest.TestCase):
    """Test Suite A1: Safe Archive Extraction & Workspace Management."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.workspace = ProjectWorkspace(base_storage_dir=Path(self.tmp_dir.name))

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_safe_zip_extraction_and_file_tree(self):
        # Create a sample valid zip
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("myproject/__init__.py", "# package init\n")
            zf.writestr("myproject/main.py", "import os\n\ndef run(): pass\n")
            zf.writestr("myproject/utils.py", "def helper(x): return x * 2\n")
            zf.writestr("README.md", "# My Cool Project\nOverview here.\n")

        extracted = self.workspace.load_from_zip(buf.getvalue())
        self.assertEqual(len(extracted), 4)

        tree = self.workspace.get_file_tree()
        self.assertEqual(tree["type"], "directory")
        py_files = self.workspace.list_python_files()
        self.assertEqual(len(py_files), 3)

    def test_rejects_zip_path_traversal_zip_slip(self):
        # Malicious zip with path traversal ../../evil.py
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("../../evil.py", "malicious_code = True\n")

        with self.assertRaises(ArchiveSecurityError) as ctx:
            SafeArchiveExtractor.extract_zip(buf.getvalue(), self.workspace.project_dir)
        self.assertIn("traversal", str(ctx.exception).lower())

    def test_rejects_absolute_path_in_zip(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("/etc/passwd", "root:x:0:0...\n")

        with self.assertRaises(ArchiveSecurityError) as ctx:
            SafeArchiveExtractor.extract_zip(buf.getvalue(), self.workspace.project_dir)
        self.assertIn("traversal", str(ctx.exception).lower())

    def test_rejects_oversized_archive(self):
        oversized = b"0" * (26 * 1024 * 1024)  # 26 MB > 25 MB limit
        with self.assertRaises(ArchiveSecurityError) as ctx:
            SafeArchiveExtractor.extract_zip(oversized, self.workspace.project_dir)
        self.assertIn("compressed size", str(ctx.exception).lower())


class ProjectUnderstandingTests(unittest.TestCase):
    """Test Suite A2: Module Discovery, Dependency Graph, Entry Points, and Architecture."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.workspace = ProjectWorkspace(base_storage_dir=Path(self.tmp_dir.name))
        # Build a multi-file project workspace
        self.workspace.load_files_dict({
            "pkg/__init__.py": "from .core import Engine\n__all__ = ['Engine']\n",
            "pkg/core.py": "from .utils import add\nclass Engine:\n    def start(self): return add(1, 2)\n",
            "pkg/utils.py": "import math\ndef add(a, b): return a + b\n",
            "app.py": "from pkg.core import Engine\n\nif __name__ == '__main__':\n    e = Engine()\n    e.start()\n",
            "requirements.txt": "flask>=3.0.0\npytest>=8.0.0\n",
            "README.md": "# Sample Project\nOverview of the system.\n\n## Installation\npip install -r requirements.txt\n",
        })
        self.analyzer = ProjectAnalyzer(self.workspace)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_module_discovery(self):
        res = self.analyzer.discover_modules()
        self.assertGreaterEqual(res["total_modules"], 4)
        self.assertEqual(res["packages_count"], 1)
        self.assertIn("pkg", res["packages"])

    def test_dependency_graph_and_dependencies(self):
        deps = self.analyzer.build_dependency_graph()
        self.assertFalse(deps["has_circular_dependencies"])
        self.assertIn("math", deps["stdlib_dependencies"])
        # pkg.core imports pkg.utils
        self.assertIn("pkg.core", deps["internal_dependency_graph"])

    def test_circular_dependency_detection(self):
        # Create circular dependency: a -> b -> a
        circ_ws = ProjectWorkspace(base_storage_dir=Path(self.tmp_dir.name))
        circ_ws.load_files_dict({
            "mod_a.py": "import mod_b\ndef fa(): pass\n",
            "mod_b.py": "import mod_a\ndef fb(): pass\n",
        })
        analyzer = ProjectAnalyzer(circ_ws)
        deps = analyzer.build_dependency_graph()
        self.assertTrue(deps["has_circular_dependencies"])
        self.assertGreaterEqual(len(deps["circular_dependencies"]), 1)

    def test_entry_point_discovery(self):
        eps = self.analyzer.discover_entry_points()
        self.assertGreaterEqual(len(eps), 1)
        self.assertEqual(eps[0]["type"], "main_block")
        self.assertEqual(eps[0]["file_path"], "app.py")

    def test_architecture_report_generation(self):
        report = self.analyzer.generate_project_architecture_report()
        self.assertIn("architecture_type", report)
        self.assertEqual(report["total_packages"], 1)
        self.assertEqual(report["total_python_files"], 4)
        self.assertTrue(report["readme"]["found"])


class ProjectCodeIntelligenceTests(unittest.TestCase):
    """Test Suite B: Project-Scale Code Intelligence, Dead Code, and Duplicates."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.workspace = ProjectWorkspace(base_storage_dir=Path(self.tmp_dir.name))
        self.workspace.load_files_dict({
            "service.py": """def active_func():
    return 42

def unreferenced_dead_func():
    return "nobody calls me"
""",
            "caller.py": """from service import active_func

def main_caller():
    return active_func()
""",
            "duplicate_one.py": """def calculate_tax(amount):
    rate = 0.15
    fee = 2.50
    return (amount * rate) + fee
""",
            "duplicate_two.py": """def calculate_tax(amount):
    rate = 0.15
    fee = 2.50
    return (amount * rate) + fee
""",
        })
        self.intelligence = ProjectCodeIntelligence(self.workspace)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_dead_code_detection(self):
        dead = self.intelligence.detect_dead_code()
        dead_names = [d["name"] for d in dead]
        self.assertIn("unreferenced_dead_func", dead_names)
        self.assertNotIn("active_func", dead_names)

    def test_cross_file_duplicate_detection(self):
        dups = self.intelligence.detect_cross_file_duplicates()
        self.assertGreaterEqual(len(dups), 1)
        self.assertEqual(dups[0]["occurrences_count"], 2)

    def test_maintainability_metrics_and_documentation_coverage(self):
        metrics = self.intelligence.calculate_project_metrics()
        self.assertIn("maintainability_index", metrics)
        self.assertIn("documentation_coverage", metrics)
        self.assertIn("overall_percentage", metrics["documentation_coverage"])

    def test_nested_function_complexity_isolation(self):
        # Nested functions should not inflate outer function complexity
        code = """def outer(x):
    if x > 0:
        def inner(y):
            if y == 1:
                return 10
            elif y == 2:
                return 20
            return 0
        return inner(x)
    return -1
"""
        ws = ProjectWorkspace(base_storage_dir=Path(self.tmp_dir.name))
        ws.load_files_dict({"nested.py": code})
        intel = ProjectCodeIntelligence(ws)
        metrics = intel.calculate_project_metrics()
        # outer has: 1 base + 1 (if x > 0) = 2
        # inner has: 1 base + 2 (if y==1, elif y==2) = 3
        # Max complexity should be 3, not 5 (2 + 3)
        self.assertEqual(metrics["maximum_cyclomatic_complexity"], 3)

    def test_boolean_and_match_complexity(self):
        code = """def evaluate_conditions(a, b, c, mode):
    if a and b or c:
        match mode:
            case 1 if a:
                return "one_guarded"
            case 2:
                return "two"
            case _:
                return "other"
    return "none"
"""
        ws = ProjectWorkspace(base_storage_dir=Path(self.tmp_dir.name))
        ws.load_files_dict({"cond.py": code})
        intel = ProjectCodeIntelligence(ws)
        metrics = intel.calculate_project_metrics()
        # 1 (base) + 1 (if) + 2 (BoolOp: 3 values - 1) + 3 (match cases: 1, 2, _) + 1 (guard) = 8
        self.assertGreaterEqual(metrics["maximum_cyclomatic_complexity"], 7)

    def test_halstead_volume_varies_with_tokens(self):
        from backend.project.code_intelligence import _compute_halstead_volume
        short_code = "x = 1\n"
        complex_code = """
import math
def compute(values, scale=1.0):
    result = []
    for val in values:
        if val > 0:
            result.append(math.sqrt(val) * scale)
        else:
            result.append(0.0)
    return sum(result)
"""
        hv_short = _compute_halstead_volume(short_code)
        hv_complex = _compute_halstead_volume(complex_code)
        self.assertGreater(hv_complex, hv_short)


class DocumentationGeneratorTests(unittest.TestCase):
    """Test Suite C: Ground-Truth Documentation Generation."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.workspace = ProjectWorkspace(base_storage_dir=Path(self.tmp_dir.name))
        self.workspace.load_files_dict({
            "api.py": """def process_transaction(user_id: str, amount: float = 0.0) -> bool:
    if amount <= 0:
        raise ValueError("Invalid amount")
    return True
""",
            "models.py": """class UserRecord:
    def get_name(self): return "Alice"
""",
        })
        self.doc_gen = ProjectDocumentationGenerator(self.workspace)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_function_docstring_grounded_in_ast(self):
        tree = ast.parse(self.workspace.read_file("api.py"))
        fn_node = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)][0]
        doc = generate_function_docstring(fn_node)
        self.assertIn("Args:", doc)
        self.assertIn("user_id (str)", doc)
        self.assertIn("amount (float)", doc)
        self.assertIn("Defaults to 0.0", doc)
        self.assertIn("Returns:", doc)
        self.assertIn("bool", doc)
        self.assertIn("Raises:", doc)
        self.assertIn("ValueError", doc)

    def test_class_docstring_grounded_in_ast(self):
        tree = ast.parse(self.workspace.read_file("models.py"))
        cls_node = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)][0]
        doc = generate_class_docstring(cls_node)
        self.assertIn("UserRecord", doc)
        self.assertIn("get_name", doc)

    def test_readme_and_architecture_generation(self):
        readme = self.doc_gen.generate_readme_draft()
        self.assertIn("Architecture:", readme)
        self.assertIn("Installation", readme)

        arch_doc = self.doc_gen.generate_architecture_documentation()
        self.assertIn("```mermaid", arch_doc)
        self.assertIn("flowchart TD", arch_doc)

        api_doc = self.doc_gen.generate_api_documentation()
        self.assertIn("process_transaction()", api_doc)


class EngineeringToolsRunnerTests(unittest.TestCase):
    """Test Suite D: Sandboxed Developer Tools Execution."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.workspace = ProjectWorkspace(base_storage_dir=Path(self.tmp_dir.name))
        self.workspace.load_files_dict({
            "calc.py": "def add(a, b): return a + b\n",
            "tests/test_calc.py": "from calc import add\ndef test_add(): assert add(2, 3) == 5\n",
        })
        self.runner = EngineeringToolsRunner(self.workspace)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_pytest_reports_not_run_without_os_level_sandbox(self):
        with patch.object(
            self.runner,
            "_execute_sandboxed_command",
            side_effect=AssertionError("uploaded tests must not be executed"),
        ):
            res = self.runner.run_pytest(["tests/test_calc.py"])

        self.assertEqual(res["status"], "not_run_sandbox_unavailable")
        self.assertIsNone(res["passed"])
        self.assertIsNone(res["exit_code"])
        self.assertIsNone(res["test_count"])
        self.assertEqual(res["stdout"], "")
        self.assertEqual(res["stderr"], "")
        self.assertEqual(res["command"][-1], "tests/test_calc.py")
        self.assertIn("NOT RUN", res["message"])
        self.assertFalse(res["sandbox_isolated"])

    def test_uninstalled_tool_fallback_bandit_and_mypy(self):
        bandit_res = self.runner.run_bandit()
        self.assertIn("tool", bandit_res)
        self.assertIn("mode", bandit_res)

        mypy_res = self.runner.run_mypy()
        self.assertIn("tool", mypy_res)
        self.assertIn("mode", mypy_res)

    def test_mypy_not_installed_fallback_finds_type_errors(self):
        self.workspace.load_files_dict({
            "type_err.py": "def broken():\n    return 1 + 'string_literal'\n",
        })
        with patch.object(
            self.runner,
            "_execute_sandboxed_command",
            return_value={"not_installed": True, "stderr": "No module named mypy", "exit_code": 1},
        ):
            mypy_res = self.runner.run_mypy()

        self.assertEqual(mypy_res["tool"], "mypy")
        self.assertFalse(mypy_res["installed"])
        self.assertEqual(mypy_res["mode"], "ast_type_fallback")
        self.assertGreaterEqual(mypy_res["issues_count"], 1)
        messages = [issue["message"] for issue in mypy_res["issues"]]
        self.assertTrue(any("int + str" in m for m in messages))


class ProjectHealthReporterTests(unittest.TestCase):
    """Test Suite E: Project Health & Quality Auditing."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.workspace = ProjectWorkspace(base_storage_dir=Path(self.tmp_dir.name))
        self.workspace.load_files_dict({
            "main.py": "import os\ndef run(): return 42\n",
            "utils.py": "def helper(): return 1\n",
        })
        self.reporter = ProjectHealthReporter(self.workspace)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_generate_health_report(self):
        report = self.reporter.generate_health_report(run_tests=False)
        self.assertIn("composite_health_score", report)
        self.assertIn("overall_grade", report)
        self.assertIn("code_quality", report)
        self.assertIn("security", report)
        self.assertIn("complexity", report)
        self.assertIn("maintainability", report)
        self.assertIn("documentation_coverage", report)

    def test_markdown_health_report(self):
        md = self.reporter.generate_markdown_report(run_tests=False)
        self.assertIn("# Project Health & Engineering Audit", md)
        self.assertIn("Composite Health Score:", md)


class ProjectChangeManagementAndAPITests(unittest.TestCase):
    """Test Suite F: Reversible Change Management, Diffs, Rollback & REST API."""

    def setUp(self):
        self.app = create_app({"REQUIRE_API_KEY": False, "TESTING": True})
        self.client = self.app.test_client()

    def test_api_project_upload_tree_read_and_save(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as project_zip:
            project_zip.writestr("main.py", "def main():\n    return 'original'\n")
            project_zip.writestr("utils.py", "def helper():\n    return True\n")
            project_zip.writestr("tests/test_main.py", "def test_main():\n    assert True\n")

        upload = self.client.post(
            "/api/project/upload",
            data={"archive": (io.BytesIO(archive.getvalue()), "sample-project.zip")},
            content_type="multipart/form-data",
        )
        self.assertEqual(upload.status_code, 201)
        workspace_id = upload.get_json()["workspace_id"]

        try:
            tree = self.client.get(f"/api/project/{workspace_id}/tree")
            self.assertEqual(tree.status_code, 200)
            self.assertEqual(
                set(tree.get_json()["python_files"]),
                {"main.py", "utils.py", "tests/test_main.py"},
            )

            opened = self.client.get(
                f"/api/project/{workspace_id}/file",
                query_string={"path": "main.py"},
            )
            self.assertEqual(opened.status_code, 200)
            self.assertEqual(
                opened.get_json()["content"],
                "def main():\n    return 'original'\n",
            )

            saved_content = "def main():\n    return 'saved'\n"
            save = self.client.post(
                f"/api/project/{workspace_id}/file",
                json={"path": "main.py", "content": saved_content},
            )
            self.assertEqual(save.status_code, 200)
            reopened = self.client.get(
                f"/api/project/{workspace_id}/file",
                query_string={"path": "main.py"},
            )
            self.assertEqual(reopened.status_code, 200)
            self.assertEqual(reopened.get_json()["content"], saved_content)
        finally:
            from backend.project.routes import _ACTIVE_WORKSPACES

            workspace = _ACTIVE_WORKSPACES.pop(workspace_id, None)
            if workspace:
                workspace.cleanup()

    def test_api_project_create_tree_and_files(self):
        resp = self.client.post(
            "/api/project/create",
            json={
                "files": {
                    "main.py": "def start(): return True\n",
                    "config.py": "PORT = 8080\n",
                }
            },
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        ws_id = data["workspace_id"]

        # 1. Get file tree
        tree_resp = self.client.get(f"/api/project/{ws_id}/tree")
        self.assertEqual(tree_resp.status_code, 200)
        self.assertEqual(len(tree_resp.get_json()["python_files"]), 2)

        # 2. Read file
        file_resp = self.client.get(f"/api/project/{ws_id}/file?path=main.py")
        self.assertEqual(file_resp.status_code, 200)
        self.assertIn("def start():", file_resp.get_json()["content"])

        # 3. Update file
        write_resp = self.client.post(
            f"/api/project/{ws_id}/file",
            json={"path": "main.py", "content": "def start(): return False\n"},
        )
        self.assertEqual(write_resp.status_code, 200)

        # 4. Propose multi-file changes with approval workflow
        prop_resp = self.client.post(
            f"/api/project/{ws_id}/changes/propose",
            json={
                "changes": {
                    "main.py": "def start(): return 'updated'\n",
                },
                "author": "Test Author",
            },
        )
        self.assertEqual(prop_resp.status_code, 200)
        prop_data = prop_resp.get_json()
        proposal_id = prop_data["proposal_id"]
        self.assertTrue(prop_data["requires_approval"])
        self.assertIn("main.py", prop_data["diffs_by_file"])

        # 5. Approve changes
        appr_resp = self.client.post(
            f"/api/project/{ws_id}/changes/approve",
            json={"proposal_id": proposal_id},
        )
        self.assertEqual(appr_resp.status_code, 200)
        rollback_snap_id = appr_resp.get_json()["rollback_snapshot_id"]

        # 6. Verify modified content
        check_resp = self.client.get(f"/api/project/{ws_id}/file?path=main.py")
        self.assertIn("'updated'", check_resp.get_json()["content"])

        # 7. Rollback to pre-apply snapshot
        rb_resp = self.client.post(
            f"/api/project/{ws_id}/changes/rollback",
            json={"snapshot_id": rollback_snap_id},
        )
        self.assertEqual(rb_resp.status_code, 200)

        # 8. Verify content reverted
        reverted_resp = self.client.get(f"/api/project/{ws_id}/file?path=main.py")
        self.assertIn("return False", reverted_resp.get_json()["content"])

        # 9. Health report endpoint
        health_resp = self.client.get(f"/api/project/{ws_id}/health")
        self.assertEqual(health_resp.status_code, 200)
        self.assertIn("composite_health_score", health_resp.get_json())

        # 10. Export ZIP endpoint
        export_resp = self.client.get(f"/api/project/{ws_id}/export")
        self.assertEqual(export_resp.status_code, 200)
        self.assertEqual(export_resp.mimetype, "application/zip")

    def test_api_project_upload_large_archive_above_1mb_succeeds(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("app.py", "def run():\n    return 'ok'\n")
            # Write incompressible payload over 1 MB (so compressed archive is > 1MB)
            zf.writestr("large_data.bin", b"X" * 1024 + os.urandom(1_200_000))
        archive_data = buf.getvalue()
        self.assertGreater(len(archive_data), 1024 * 1024)

        resp = self.client.post(
            "/api/project/upload",
            data={"archive": (io.BytesIO(archive_data), "project.zip")},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 201)
        ws_id = resp.get_json()["workspace_id"]
        from backend.project.routes import _ACTIVE_WORKSPACES
        ws = _ACTIVE_WORKSPACES.pop(ws_id, None)
        if ws:
            ws.cleanup()

    def test_api_project_upload_exceeding_max_archive_rejected(self):
        oversized = b"PK\x05\x06" + b"\x00" * 18 + b"0" * (26 * 1024 * 1024)
        resp = self.client.post(
            "/api/project/upload",
            data={"archive": (io.BytesIO(oversized), "huge.zip")},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("error", resp.get_json())

    def test_api_project_upload_exceeding_flask_max_content_length_rejected_with_413(self):
        huge_payload = b"PK\x05\x06" + b"\x00" * 18 + b"0" * (31 * 1024 * 1024)
        resp = self.client.post(
            "/api/project/upload",
            data={"archive": (io.BytesIO(huge_payload), "massive.zip")},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 413)


if __name__ == "__main__":
    unittest.main()
