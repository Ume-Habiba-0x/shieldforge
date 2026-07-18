# Module Contract

This document defines the interface and development guidelines for scanner modules in **ShieldForge**.

All security scanners must follow this contract to ensure they integrate correctly with the framework.

---

## Overview

Each scanner is responsible for performing one specific security assessment.

The framework engine handles module discovery, execution, result collection, and report generation. Scanner modules should focus only on vulnerability detection.

Every scanner must inherit from `BaseScanner`.

---

## Directory

```
modules/
├── base.py
├── headers.py
├── auth.py
├── xss.py
├── sqli.py
└── disclosure.py
```

---

## Required Structure

Every scanner should provide:

* A class that inherits from `BaseScanner`
* A unique module name
* A short description
* A `scan()` method

Example:

```python
from modules.base import BaseScanner

class HeaderScanner(BaseScanner):
    name = "headers"
    description = "Analyze HTTP security headers"

    def scan(self, context):
        ...
```

---

## Responsibilities

A scanner should:

* Receive the shared execution context
* Perform its assigned security checks
* Create findings when issues are detected
* Return results to the framework

A scanner should **not**:

* Handle command-line arguments
* Generate reports
* Configure logging
* Modify other modules

---

## Shared Context

The framework provides a shared context containing common resources such as:

* Target URL
* HTTP client
* Configuration
* Logger

Use the provided context instead of creating your own instances.

---

## Error Handling

Scanners should handle expected exceptions gracefully and continue execution whenever possible.

Unexpected failures should be reported through the logger rather than stopping the framework.

---

## Logging

Use the shared project logger.

Avoid using `print()` for output.

---

## Testing

Each scanner should include a corresponding test file inside:

```
tests/test_scanners/
```

Example:

```
tests/test_scanners/test_headers.py
```

---

## Adding a New Scanner

1. Create a new file inside `modules/`.
2. Inherit from `BaseScanner`.
3. Implement the required scanner logic.
4. Add unit tests.
5. Verify the module integrates correctly with the framework.

---

Following this contract keeps all modules consistent and makes the framework easier to maintain and extend.
