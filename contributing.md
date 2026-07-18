# Contributing

Thank you for your interest in contributing to **ShieldForge**.

ShieldForge is a modular web security testing framework developed as part of the ITSOLERA Summer Internship Program. Contributions that improve functionality, fix bugs, enhance documentation, or add tests are welcome.

---

# Getting Started

1. Fork the repository.
2. Clone your fork.

```bash
git clone https://github.com/<Ume-Habiba-0x>/shieldforge.git
cd shieldforge
```

3. Install the project dependencies.

```bash
pip install -r requirements.txt
```

4. Create a new branch for your work.

```bash
git checkout -b feature/your-feature
```

---

# Project Structure

```
core/       Framework engine and shared models
modules/    Security scanner modules
utils/      Shared utilities
reports/    Report generators
tests/      Unit tests
config/     Configuration and payload files
```

Each scanner should focus on a single responsibility and inherit from `BaseScanner`.

---

# Development Guidelines

* Work only on the files related to your assigned task.
* Keep changes focused and avoid unrelated refactoring.
* Reuse shared utilities instead of duplicating code.
* Use the project logger instead of `print()`.
* Handle exceptions gracefully.
* Add or update tests whenever possible.

---

# Branch Naming

Use descriptive branch names.

Examples:

```
feature/xss-scanner
feature/auth-module
feature/report-generator
fix/http-client
docs/readme
test/headers
```

---

# Commit Messages

Use clear and concise commit messages.

Examples:

```
feat(headers): implement security header analysis
feat(auth): add login form detection
fix(engine): handle scanner exceptions
docs: update README
test(xss): add reflected XSS tests
```

---

# Pull Requests

Before opening a Pull Request, make sure that:

* Your branch is up to date with `main`.
* The project runs without errors.
* New code follows the existing project structure.
* Tests pass if applicable.
* Your Pull Request describes the purpose of the change.

Keep Pull Requests focused on a single feature or fix.

---

# Code Review

All Pull Requests are reviewed for:

* Correctness
* Readability
* Maintainability
* Consistency with the existing architecture

Feedback is part of the development process and is intended to improve the project.

---

# Need Help?

If you have questions or ideas, feel free to open an Issue or start a GitHub Discussion before making significant architectural changes.

---

Thank you for contributing to **ShieldForge**.
