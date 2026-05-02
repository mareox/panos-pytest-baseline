# Contributing

Contributions welcome. A few rules:

## No real configs

Never include real firewall XML, API keys, IP addresses, or any data from an actual production or lab environment in issues, PRs, or comments. Use synthetic data only.

## Adding a new control

1. Add `def test_<control_name>(fw):` to `tests/test_baseline.py`
2. Add a passing and failing case to `examples/fixtures/security-rules.xml`
3. Add a row to the control catalog in `docs/controls.md`
4. Run `PANOS_FIXTURE_DIR=examples/fixtures pytest tests/ -v` to verify

## Code style

Plain Python. No extra dependencies beyond pytest, requests, pyyaml.
