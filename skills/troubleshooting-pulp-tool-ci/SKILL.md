---
name: troubleshooting-pulp-tool-ci
description: >-
  Use when pre-commit hooks fail repeatedly, lint errors persist after make format,
  or local checks disagree with CI on pulp-tool.
---

# Troubleshooting pulp-tool CI / lint

## Pre-commit loop

```bash
pre-commit run --all-files
```

Fix **every** failure, then re-run until one full run passes with zero failures. Do not commit after a partial fix without a subsequent clean run.

Single hook: `pre-commit run <hook-id> --all-files`

## Lint quick reference

```bash
make lint          # All linters
make format        # Auto-fix Black
make lint-black    # Check formatting only
make lint-flake8
make lint-pylint
make lint-mypy
```

Prefer Makefile targets over invoking tools directly.

## Common issues

| Issue | Solution |
|-------|----------|
| Black vs Flake8 E203 | E203 ignored in `.flake8` — expected with Black |
| Mypy errors in specific modules | Check `[[tool.mypy.overrides]]` in `pyproject.toml` — may be intentional |
| Hooks fail on commit | Loop `pre-commit run --all-files` locally until clean |

## Config files

- `.pre-commit-config.yaml` — hooks
- `pyproject.toml` — Black, Pylint, Mypy
- `.flake8` — Flake8
- `Makefile` — targets

## Diff coverage

If the failure is uncovered changed lines, use **fixing-diff-cover-failures** skill instead of guessing from lint output.
