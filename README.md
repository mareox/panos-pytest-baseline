# PAN-OS Pytest Baseline Controls

[![PAN-OS Baseline Controls](https://github.com/mareox/panos-pytest-baseline/actions/workflows/baseline.yml/badge.svg)](https://github.com/mareox/panos-pytest-baseline/actions/workflows/baseline.yml)

Executable security baseline for PAN-OS firewalls as pytest tests. Every control is a test function. Pass means compliant. Fail means fix it. The fixture mode lets anyone run the full suite right now, no firewall required.

**Related post:** [Testing PAN-OS firewall baselines with pytest](https://mareox.github.io/homelab-journal/posts/2026/pytest-panos-firewall-testing/)

---

## Try it locally (no firewall needed)

Clone the repo, point at the bundled synthetic fixtures, and run:

```bash
git clone https://github.com/mareox/panos-pytest-baseline
cd panos-pytest-baseline
pip install uv
uv run --with pytest --with requests --with pyyaml pytest tests/ -v \
  --env PANOS_FIXTURE_DIR=examples/fixtures
```

Or with `uv sync` first:

```bash
uv sync
PANOS_FIXTURE_DIR=examples/fixtures uv run pytest tests/ -v
```

Expected output: **11 passed, 3 failed** (the failures are intentional — they model real-world gaps in the synthetic fixtures to show what the controls look for).

The 3 intentional failures:
- `test_allow_rules_have_security_profile_group` — two rules missing Content-ID inspection
- `test_allow_rules_have_log_forwarding` — two rules not forwarding logs to SIEM

---

## Controls

9 controls across smoke, security, and hygiene categories. Full catalog in [docs/controls.md](docs/controls.md).

| ID | Test | What it checks |
|---|---|---|
| BL-001 | `test_firewall_reachable` | API responds |
| BL-002 | `test_panos_version_meets_minimum` | PAN-OS >= 11.1 |
| BL-003 | `test_deny_all_exists_for_untrust_zone` | Explicit deny covers internet zone |
| BL-004 | `test_zone_protection_profile_applied` | Zone protection on every zone |
| BL-005 | `test_critical_rule_exists` | Critical rules not accidentally deleted |
| BL-006 | `test_no_unrestricted_allow_from_internet` | No allow-any from internet |
| BL-007 | `test_allow_rules_have_security_profile_group` | Content-ID on every allow rule |
| BL-008 | `test_allow_rules_have_log_forwarding` | Log forwarding on every allow rule |
| BL-009 | `test_service_objects_follow_naming_convention` | `tcp-PORT` / `udp-PORT` naming |

---

## Live mode (real firewall)

Create a read-only API user on the firewall, then:

```bash
export FW_HOST=192.0.2.1
export PANOS_KEY=your-ro-api-key
uv run pytest tests/ -v --tb=short
```

Or use a `.env` file (gitignored):

```
firewall-ip=192.0.2.1
ro-api-key=your-ro-api-key
```

Then just run `uv run pytest tests/ -v`.

The suite is read-only. It issues `show` config queries and `op` commands only. Nothing is committed to the firewall.

---

## Exception model

Some controls legitimately cannot be met immediately (vendor migration windows, legacy protocol incompatibilities). Document them in `tests/exceptions.yaml`:

```yaml
exceptions:
  - rule: ALLOW-Vendor-Temp
    control: test_allow_rules_have_security_profile_group
    owner: network-security
    ticket: CHG-12345
    expires: 2026-06-30
    reason: Vendor migration window, inspection incompatible with legacy protocol
```

Expired exceptions automatically resume failing. No manual cleanup needed. Every exception is tracked in version control with a ticket reference and expiry date.

---

## CI integration

### GitHub Actions

The included workflow runs daily in fixture mode and uploads the JUnit XML report as an artifact for audit evidence:

```yaml
# .github/workflows/baseline.yml
env:
  PANOS_FIXTURE_DIR: examples/fixtures
run: uv run pytest tests/ -v --tb=short --junit-xml=reports/baseline-report.xml
```

### Semaphore CI (for live mode)

To run against a real firewall from Semaphore:

1. Store `FW_HOST` and `PANOS_KEY` as Semaphore secrets
2. Create a task with:
   ```bash
   cd panos-pytest-baseline
   uv run pytest tests/ -v --tb=short --junit-xml=reports/baseline-report.xml
   ```
3. Schedule daily via Semaphore's scheduler

---

## Panorama fleet mode

To run the same controls across multiple firewalls, loop over a list of hosts:

```bash
for host in fw1.example.com fw2.example.com; do
  echo "=== $host ===" 
  FW_HOST=$host PANOS_KEY=$RO_KEY \
    uv run pytest tests/ -v --tb=line \
    --junit-xml=reports/baseline-$host.xml
done
```

Each firewall gets its own JUnit report. Collect and aggregate in your SIEM or CI dashboard.

---

## Adapting to your environment

Two constants at the top of `tests/test_baseline.py` control the environment-specific settings:

```python
ZONE_PROTECTION_PROFILES = {
    "L3-Outside": "zp-untrust",
    "L3-LAN10":   "zp-trust",
    # ... add your zones
}

CRITICAL_RULES = [
    "ALLOW-Proxy-Local",
    "ALLOW - INFRA-IntraZ",
    # ... add your must-exist rules
]
```

Update these to match your firewall's zone names and critical rules. Everything else is policy-agnostic.

---

## Disclaimer

Personal project. Not an official Palo Alto Networks product or tool. See [DISCLAIMER.md](DISCLAIMER.md).
