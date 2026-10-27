# Agent Instructions

Before starting any task in this repository:

1. Run `make agents/sync`. It writes the shared Plus3 IT instructions for this repository's tardigrade-ci version to `.agents/plus3it/AGENTS.md`.
2. Read `.agents/plus3it/AGENTS.md` and follow it together with this file. If the sync fails, tell the user, and don't guess the conventions.

These rules always apply, even without the shared instructions:

- Don't push, open pull requests, publish releases, or apply infrastructure changes unless the user asks. List those steps for a person in your final report.
- Don't edit files under `.agents/plus3it/`; they are generated and overwritten by the sync.

@.agents/plus3it/AGENTS.md

## Repository-specific

### Purpose

This Terraform module deploys a Python Lambda function that audits the IAM access keys in an account, notifies users that their keys are nearing expiration, and enforces key rotation. An EventBridge schedule triggers the function, and the module can send reports and emails through SES.

### Module-specific files

- `src/python/` — Source of the Lambda function, packaged by the module at plan time; `requirements.txt` lists the runtime packages and `requirements-dev.txt` the test packages
- `email_templates/` — Default HTML and text templates for the user and admin emails
- `modules/scheduled_event/` — Submodule that creates the EventBridge schedule rule that triggers the Lambda function
- `tests/python/` — Python unit tests for the Lambda function, configured by `pytest.ini`; `ruff.toml` and `.pylintrc` configure the Python linters, and the Makefile adds `src/python` to `PYTHONPATH` for pylint

### Deviations from the terraform-module profile

- The Python unit tests also run in CI, from `.github/workflows/test-python.yml`, which installs `src/python/requirements-dev.txt` with `uv` and runs `pytest tests/python/`. This is in addition to the mockstack Terraform tests described in the profile.
