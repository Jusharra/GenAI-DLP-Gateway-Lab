# Coding Standards

- Use Python 3.11+.
- Format code with `black` and `isort`.
- Lint with `flake8` and type-check with `mypy` for production-intent labs.
- All ML labs:
  - Must include `tests/test_model_security.py`.
  - Must have a `model_card.yaml`.
- All projects:
  - Must map to at least one entry in `risk_register.yaml`.
  - Must implement at least one SOC 2 control from `soc2_controls.yaml`.
