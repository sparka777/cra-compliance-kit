# Contributing to CRA Compliance Kit

## Open Modules (MIT)

Contributions to the open-source modules are welcome:

- `cra_kit/identity.py`
- `cra_kit/firmware.py`
- `cra_kit/input_guard.py`
- `cra_kit/action_guard.py`
- `sbom/generator.py`

## Getting Started

1. Fork the repository.
2. Create a feature branch.
3. Run the self-tests: `python run_all_checks.py`
4. Submit a pull request.

## Guidelines

- **Zero external dependencies.** All open modules use stdlib only (SQLite, hashlib, hmac, re, json, etc.)
- **Type hints required.** All public functions must have type annotations.
- **Self-tests mandatory.** Every module needs a self-test that runs without external services.
- **No telemetry.** Do not add analytics, phone-home, or usage tracking.
- **Simple over clever.** These modules are audited by compliance teams. Readability trumps performance.

## Commercial Modules

The modules in the commercial tier (`provenance.py`, `guardian.py`, `baselines.py`, `signing.py`)
are not open source. If interested in licensing, contact sydney@starcaller.uk.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
