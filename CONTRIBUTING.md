# Contributing to SecretSweep

Thank you for your interest in contributing to SecretSweep.

SecretSweep is a Python CLI tool for scanning repositories for leaked secrets, risky files, and unsafe environment configuration. The project should stay simple, safe, readable, and useful for developers.

---

## Ways to Contribute

You can help by:

- Improving secret detection rules
- Reducing false positives
- Adding tests
- Improving reports
- Improving CLI output
- Improving documentation
- Fixing bugs
- Adding safe configuration options

---

## Development Setup

```bash
git clone https://github.com/n-vim/secret-sweep.git
cd secret-sweep
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

On Windows:

```bash
.venv\Scripts\activate
python -m pip install -e ".[dev]"
```

---

## Run Tests

```bash
pytest
```

Run linting:

```bash
ruff check .
```

Run type checking:

```bash
mypy src
```

---

## Rule Guidelines

When adding a new detection rule:

- Keep the pattern focused
- Avoid broad patterns that create noisy reports
- Mask detected values
- Add tests for positive and negative cases
- Include a useful suggestion
- Avoid exposing real secrets in tests

Use fake values only.

---

## Pull Requests

A good pull request should:

- Have a clear purpose
- Stay focused
- Include tests when behavior changes
- Update documentation when needed
- Avoid unrelated formatting changes
- Keep the CLI simple and readable

---

## Security Work

Do not include real credentials in issues, tests, pull requests, screenshots, or logs.

If you find a security vulnerability in SecretSweep itself, follow `SECURITY.md`.

---

## License

By contributing, you agree that your contribution will be licensed under the MIT License.
