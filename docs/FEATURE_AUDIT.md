# AST Studio / NEXUS Feature Audit

Audit basis: the attached *AST Studio / NEXUS — Updated Source Audit & Same-Day
Repair Prompts* document was read in full, and findings were checked against this
working tree. The worktree already contains extensive uncommitted changes; this
audit does not treat them as changes made for this task.

## Core interaction and provider

| Control / feature | Status | Source-grounded finding |
|---|---|---|
| Upload Project ZIP | WORKING | `initProjectWorkspace()` and `uploadProjectArchive()` post the archive to `/api/project/upload`, retain the returned workspace ID, and load the tree. The project API extracts the archive into a `ProjectWorkspace`. |
| Project file tree / open Python file | WORKING | `loadProjectFileTree()` renders server-returned paths; `openProjectFile()` fetches `/api/project/<id>/file`, updates the existing textarea, and guards against stale responses. |
| Edit / Save project file | WORKING | The textarea input handler marks changed workspace content; `saveProjectFile()` posts it to the project file endpoint and clears the saved baseline only after a successful response. Unsaved-change confirmation is present. |
| Active tree selection / reload restoration | WORKING | The tree exposes selected state accessibly. Workspace and active-file identity are restored per tab from `sessionStorage`; focused frontend tests cover both behaviors. |
| Open local `.py` file | WORKING WITH LIMITATION | `openSelectedFile()` loads into the existing editor and identifies the local filename as single-file context. Related project files and backend persistence are unavailable until a project ZIP is uploaded. |
| Ask NEXUS | WORKING | Natural-language intent classification routes questions, explanations, debugging, project changes, security/architecture reviews, and test requests to the existing matching flows. Project and single-file chat support bounded history; classifier and dispatch tests cover these routes. |
| Project context for chat | WORKING | `chat_about_project()` reads the active Python file and bounded related project context server-side, redacts secrets, and returns the actual context-file list. Targeted service tests cover imports, bounds, paths, and redaction. |
| Propose code change | WORKING | Composer change requests are routed to staged proposals. A specialist candidate can also be staged through `/changes/propose-agentic-candidate`; both flows show actual diffs and require project-level approval before backend files change. Python candidates are path-checked and syntax-validated before staging. |
| Approve / Reject / Roll back | WORKING | The project change endpoints and frontend use proposal IDs, approval, rejection, snapshots, rollback, and editor reload. Existing project-assistant and browser E2E tests cover these flows. |
| Agentic candidate “Apply” | WORKING WITH LIMITATION | In a project workspace, the candidate is staged as a real proposal with a diff; it is not saved until project approval. The action checks that the editor still matches the candidate's source. With a local file, it copies only to the editor buffer and explicitly states it is not saved. |
| Require approval for specialist changes | WORKING | Automatic approval is rejected. Candidate generation stages a source-bound diff and pauses; approval is digest-bound to that exact candidate and unchanged baseline. Project files are only written after explicit approval. |
| Specialist plan / run context | WORKING | Preview and run carry workspace ID and active-file identity. The backend validates these identifiers and supplies bounded, redacted server-owned related files rather than trusting submitted editor source. |
| Specialist plan / Start Analysis | WORKING WITH LIMITATION | Project-aware specialist runs use read-only profiles and receive project context. Mutations are routed to the separate staged-proposal/approval path; this prevents a specialist review from silently changing files. |
| Project verification / Run tests | DISABLED BY DESIGN when isolation is unavailable | The project test runner reports `NOT RUN` without OS-level sandboxing. The existing test suite asserts uploaded tests are not executed in-process. |

## Provider connectivity

| Control / feature | Status | Source-grounded finding |
|---|---|---|
| Provider settings / Test Provider | PARTIAL | The settings UI invokes `POST /api/test-provider`, which sends a real small completion request. A direct GitHub Copilot / `gpt-4o` check succeeded earlier in this session; subsequent utility-model calls encountered provider rate limits, so current availability is not guaranteed. |
| Provider readiness / top health badge | WORKING WITH LIMITATION | Settings distinguish readiness/configuration from a successful live connection, and health reports the provider status. The connection result is process-local, so a multiworker deployment may not share the latest test state. |
| Provider test failure response | WORKING | Provider failures are mapped to sanitized user-facing messages rather than returning raw exception text. |
| Explicit AI Model workflow | WORKING WITH LIMITATION | Runtime requests use the provider adapter for error classification and redaction. A model-required run now fails with the provider error instead of silently completing via deterministic fallback; code remains unchanged when the model call fails. The active provider is currently rate-limited, so a successful live agent run is not verified. |
| Offline AST provider | WORKING | The deterministic AST mode is intentionally distinct from an external model call and the test endpoint identifies it as offline. |

## Other visible controls and safety states

| Control / feature | Status | Source-grounded finding |
|---|---|---|
| Format | DISABLED BY DESIGN | The button is disabled with a title explaining that automatic Python re-indentation is unavailable because it may change behavior. |
| Analyze AST / Generate comments / Quality actions | SOURCE-WIRED; UI UNVERIFIED | Existing handlers and endpoints are present and covered by static/API regression tests. Individual browser interaction remains unverified. |
| Security Lab and findings controls | SOURCE-WIRED; UI UNVERIFIED | Analysis/security handlers and API routes are present; browser behavior for each control remains unverified. |
| Diff, copy, download, report, and example controls | SOURCE-WIRED; UI UNVERIFIED | Relevant handlers/routes and static tests are present; every control state and failure path has not been exercised in a browser. |
| Workflow cancel / reconnect / approval controls | SOURCE-WIRED; UI UNVERIFIED | Session/cancellation endpoints and UI handlers are present. Focused API tests cover session approval/security, but browser interaction remains unverified. |

## Verification evidence and limitations

- Latest full default-suite run:
  `.venv\Scripts\python.exe -m pytest -q --durations=12`
- Result: **609 passed, 28 skipped in 29.01s** (637 tests collected). The slowest test was 1.58s; the former slow agentic API tests are now deterministic and avoid live-provider retries.
- The long-running full-suite failure was in Playwright initialization, not the application tests: `sync_playwright()` blocked before Chrome launched on this Windows/Python 3.15 environment. Browser modules are now opt-in via `pytest --run-browser-tests`; their behavior remains unverified here.
- A static scan found no visible ID-bearing HTML button lacking a script reference; the unmatched `btn-format` is explicitly disabled, and `btn-close-inspector` is hidden. This confirms source wiring only, not click behavior.
- The integrated browser timed out connecting to the local Flask server, and the desktop browser did not produce a targetable window. No workaround or successful browser interaction is claimed.
- Latest integrated regression run after the specialist-candidate adapter:
  `.venv\Scripts\python.exe -m pytest tests\test_project_assistant_service.py tests\test_project_engineering_workbench.py tests\test_agentic_project_context.py tests\test_agentic_core.py tests\test_nexus_intent_routing.py tests\test_frontend_assets.py tests\test_session_security_hardening.py -q`
- Result: **135 passed**. This includes staging/rejection without writes, persistence only after explicit approval, invalid-Python rejection, intent routing, workspace context, specialist approval, frontend wiring, and session security.
- Agentic API/security tests that only verify routing, approval, or ownership explicitly request deterministic execution. This prevents test runs from making provider calls just because a developer machine has a provider configured.
- Baseline command:
  `.venv\Scripts\python.exe -m pytest tests\test_provider_resilience.py tests\test_project_assistant_service.py tests\test_project_engineering_workbench.py tests\test_frontend_assets.py -q`
- Result: **56 passed**.
- Real provider check: an earlier `POST /api/test-provider` succeeded with provider `GitHub Copilot`, model `gpt-4o`; the latest direct connectivity check failed because inference was rate-limited. No project source was sent for that check. The latest full default suite made no provider requests.
- `tests/test_production_e2e_frontend.py` contains browser tests for upload/open/save and staged project changes. Those tests use a mocked completion provider and do not establish external provider availability.
- Playwright browser modules are opt-in via `pytest --run-browser-tests`. In the current Windows/Python 3.15 environment, `sync_playwright()` blocks before Chrome starts; normal pytest runs skip those modules rather than hanging. Browser validation remains outstanding.
- This is a source-grounded audit, not a claim that every visible control has been clicked and verified. Browser validation of the remaining toolbar, settings, security, and workflow controls remains outstanding.
