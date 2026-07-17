# Contributing to ShieldForge

## Git Workflow

```bash
# 1. Create branch
git checkout -b feature/your-module

# 2. Commit
git commit -m "feat(xss): implement reflected XSS detection"

# 3. Push and PR
git push origin feature/xss-scanner
# Open Pull Request on GitHub


Adding a Scanner
Copy modules/headers.py
Rename class, implement name, description, scan()
Engine auto-discovers it — no registry needed
Rules
Catch all exceptions in scan()
Use context.http_client — don't import requests
Return empty findings if nothing found
Use Severity: CRITICAL/HIGH/MEDIUM/LOW/INFO
