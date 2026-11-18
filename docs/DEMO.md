# AST Studio End-to-End Demo Script

This document provides a click-by-click walkthrough for demonstrating AST Studio's project workbench, autonomous multi-agent analysis, patch review, and snapshot rollback capabilities.

---

## Prerequisites
1. Start the local server:
   ```bash
   python run.py
   ```
2. Open your browser to `http://127.0.0.1:5000`.

---

## Step 1: Create a 2-File Sample Project Zip

On your machine or in a terminal, create a test zip containing two sample Python files:

**`main.py`**:
```python
import os

def run_backup(target_dir):
    """Perform system backup."""
    cmd = "tar -czf backup.tar.gz " + target_dir
    os.system(cmd)
    return 0
```

**`utils.py`**:
```python
def sanitize_path(path):
    return path.strip()
```

Compress both files into `demo_project.zip`.

---

## Step 2: Upload Project into the Workbench

1. Click the **"Open Project Folder"** or **"Upload Project (.zip)"** button in the top navigation bar.
2. Select `demo_project.zip`.
3. **Expected UI Result**:
   - A green toast appears: `Project workspace loaded: 2 files`.
   - The left sidebar displays the project file tree with `main.py` and `utils.py`.
   - `main.py` is loaded into the active editor buffer.

---

## Step 3: Trigger Multi-Agent Security Audit (NEXUS)

1. Navigate to the **NEXUS Command Center** tab or click the **Ask NEXUS** button.
2. Enter the task:
   `"Audit main.py for command injection vulnerabilities and propose a safe remediation"`
3. Click **Review Plan** / **Deploy Specialists**.
4. **Expected UI Result**:
   - The DAG plan preview visualizes:
     - **ATLAS**: Workspace indexer reads `main.py` and symbol table.
     - **SENTINEL**: Static security analyzer flags `os.system(cmd)` (CWE-78 Command Injection).
     - **REMEDY**: Proposes replacing `os.system` with safe `subprocess.run(shlex.split(...), shell=False)`.
     - **VERITY**: Verifies behavior preservation and syntax integrity.
   - Live activity events stream in real time into the terminal console.

---

## Step 4: Inspect Side-by-Side Diff & Approve Patch

1. Once the agents complete their proposal, the **Proposal Approval Card** renders in the project panel.
2. Review the side-by-side diff:
   - Red line: `os.system(cmd)`
   - Green lines: Safe `subprocess.run` invocation preserving `returncode` contract.
3. Click the green **"Approve & Apply"** button.
4. **Expected UI Result**:
   - A success toast appears with the snapshot ID: `Changes approved and committed. Snapshot: snap_<hash>`.
   - The editor reloads the updated file from disk with the clean, safe patch.
   - The proposal status badge updates to `Approved & Applied`.

---

## Step 5: Verify Rollback to Original Snapshot

1. On the same proposal card, click the blue **"Rollback"** button (or click **Rollback to Snapshot** in the workspace banner).
2. **Expected UI Result**:
   - An informative toast displays: `Workspace rolled back to snapshot snap_<hash>`.
   - The editor buffer instantly reverts to the original code containing `os.system(cmd)`.
   - The file tree status resets to clean.
